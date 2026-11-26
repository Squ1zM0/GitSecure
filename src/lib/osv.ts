// Dependency vulnerability lookup via OSV.dev (free, no key).
// https://api.osv.dev/v1/querybatch — POST { queries: [{ package: { name, ecosystem }, version }] }
// Ecosystems used: npm, PyPI, crates.io. Never sends secret values.
// If OSV is unreachable the scan continues and reports the check as unavailable.

import type { Dependency, Severity, Vulnerability } from "./types";

const OSV_URL = "https://api.osv.dev/v1/querybatch";

function severityFromCvss(score: number | null | undefined): Severity {
  if (score == null) return "medium";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function fixedVersion(vuln: Record<string, unknown>): string | null {
  const affected = (vuln.affected ?? []) as Record<string, unknown>[];
  for (const a of affected) {
    const ranges = (a.ranges ?? []) as Record<string, unknown>[];
    for (const r of ranges) {
      const events = (r.events ?? []) as Record<string, unknown>[];
      for (const e of events) {
        if (typeof e.fixed === "string") return e.fixed;
      }
    }
  }
  return null;
}

// OSV querybatch returns only vuln IDs (no summary, severity, or fixed
// version). Full detail needs GET /v1/vulns/{id} per advisory.
//
// Phase 5: NO list caps. Every advisory OSV returns is listed, however
// many there are. Full detail is fetched for EVERY unique advisory ID,
// in small parallel batches, inside a time budget (DETAIL_BUDGET_MS) —
// advisories past the budget are still listed, with ID + osv.dev link,
// and the report says how many got full detail and how many are ID-only.
// Likewise the query phase asks OSV about EVERY pinned dependency, in
// batches of QUERY_BATCH_SIZE, inside QUERY_BUDGET_MS. A repo with
// thousands of deps (DefinitelyTyped: 9,401 — measured: a 1,000-query
// batch takes ~3 s, a 100-query batch ~1.5 s, so big batches are far
// more efficient) cannot always be fully queried inside the 55 s scan
// timeout, so the query phase stops at its budget and the report says
// honestly how many dependencies were checked for flaws. Neither budget
// ever drops an advisory OSV already returned.
const QUERY_BATCH_SIZE = 1000;
const QUERY_BUDGET_MS = 15_000;
const DETAIL_BATCH = 8;
const DETAIL_BUDGET_MS = 12_000;

async function fetchVulnDetail(id: string): Promise<Record<string, unknown> | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    return (await res.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export async function checkDependencies(deps: Dependency[]): Promise<{ vulnerabilities: Vulnerability[]; unavailable: boolean; advisoriesFound: number; detailCapped: number; depsChecked: number; depsQueryable: number }> {
  const queryable = deps.filter((d) => d.version && !/[\^~><*]/.test(d.version) && d.name.length > 0);
  const empty = { vulnerabilities: [], unavailable: false, advisoriesFound: 0, detailCapped: 0, depsChecked: 0, depsQueryable: queryable.length };
  if (queryable.length === 0) return empty;
  const ecosystemMap: Record<string, string> = { npm: "npm", pypi: "PyPI", crates: "crates.io", go: "Go", ruby: "RubyGems", php: "Packagist", java: "Maven", dotnet: "NuGet", actions: "GitHub Actions" };
  // Query phase: every pinned dep, QUERY_BATCH_SIZE per querybatch call,
  // until the time budget runs out. At least one batch always runs.
  // Collect (dep, vuln id) pairs from every batch that answers.
  const pairs: { dep: Dependency; id: string }[] = [];
  const queryDeadline = Date.now() + QUERY_BUDGET_MS;
  let depsChecked = 0;
  let unavailable = false;
  try {
    for (let i = 0; i < queryable.length; i += QUERY_BATCH_SIZE) {
      if (i > 0 && Date.now() > queryDeadline) break;
      const batch = queryable.slice(i, i + QUERY_BATCH_SIZE);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 15000);
      let data: { results?: { vulns?: Record<string, unknown>[] }[] };
      try {
        const res = await fetch(OSV_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            queries: batch.map((d) => ({ package: { name: d.name, ecosystem: ecosystemMap[d.ecosystem] ?? d.ecosystem }, version: d.version })),
          }),
          signal: controller.signal,
        });
        clearTimeout(timer);
        if (!res.ok) {
          unavailable = true;
          break;
        }
        data = (await res.json()) as { results?: { vulns?: Record<string, unknown>[] }[] };
      } catch {
        clearTimeout(timer);
        unavailable = true;
        break;
      }
      depsChecked += batch.length;
      (data.results ?? []).forEach((result, j) => {
        const dep = batch[j];
        for (const v of result.vulns ?? []) pairs.push({ dep, id: String(v.id ?? "OSV-UNKNOWN") });
      });
    }
  } catch {
    return { ...empty, unavailable: true, depsChecked };
  }
  if (pairs.length === 0) return { vulnerabilities: [], unavailable, advisoriesFound: 0, detailCapped: 0, depsChecked, depsQueryable: queryable.length };
  // Detail phase: full detail for EVERY unique advisory ID, in small
  // parallel batches, until the time budget runs out. Advisories past
  // the budget are listed with ID only — never dropped.
  const uniqueIds = [...new Set(pairs.map((p) => p.id))];
  const detailDeadline = Date.now() + DETAIL_BUDGET_MS;
  const detailById = await (async () => {
    const map = new Map<string, Record<string, unknown>>();
    for (let i = 0; i < uniqueIds.length; i += DETAIL_BATCH) {
      if (i > 0 && Date.now() > detailDeadline) break;
      const batchIds = uniqueIds.slice(i, i + DETAIL_BATCH);
      const results = await Promise.all(batchIds.map((id) => fetchVulnDetail(id)));
      results.forEach((detail, j) => {
        if (detail) map.set(batchIds[j], detail);
      });
    }
    return map;
  })();
  const detailCapped = pairs.filter((p) => !detailById.has(p.id)).length;
  const vulnerabilities: Vulnerability[] = pairs.map(({ dep, id }) => {
    const detail = detailById.get(id);
    const summary = detail ? String(detail.summary ?? detail.details ?? "") : "";
    const severityList = ((detail?.severity ?? []) as { type?: string; score?: string }[]);
    const cvss = severityList.find((s) => s.type === "CVSS_V3" || s.type === "CVSS_V4");
    const severity = severityFromCvss(cvss?.score ? parseFloat(cvss.score) : null);
    const fixed = detail ? fixedVersion(detail) : null;
    return {
      id,
      packageName: dep.name,
      ecosystem: dep.ecosystem,
      installedVersion: dep.version,
      fixedVersion: fixed,
      severity,
      summary: summary ? summary.slice(0, 300) : `A known vulnerability (${id}) affects this package version. Full detail was not fetched for this advisory — see osv.dev/vulnerability/${id}.`,
      // Plain English, one line: what the flaw is (in the advisory's own
      // words), what it lets an attacker do, and what to upgrade to.
      // The advisory summary is the human-written description; the fix
      // line is ours. Keep it to one sentence of summary + the upgrade.
      plainEnglish: summary
        ? `${summary.endsWith(".") ? summary : `${summary}.`} This affects ${dep.name} ${dep.version ?? ""}. ${fixed ? `Upgrade to ${fixed} or later to fix it.` : "No fixed version was listed in the detail fetched — check the advisory before upgrading."}`
        : `${dep.name} ${dep.version ?? ""} has a known security flaw (${id}). ${fixed ? `Upgrade to ${fixed} or later to fix it.` : "No fixed version was listed in the detail fetched — check the advisory before upgrading."}`,
      upgrade: fixed ? `Upgrade ${dep.name} to ${fixed} or later.` : `Check advisory ${id} for ${dep.name} and upgrade to a patched version.`,
    };
  });
  return { vulnerabilities, unavailable, advisoriesFound: pairs.length, detailCapped, depsChecked, depsQueryable: queryable.length };
}
