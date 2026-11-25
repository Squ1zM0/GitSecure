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
// version). Full detail needs GET /v1/vulns/{id} per advisory. Phase 2
// fetches full detail (summary, CVSS, fixed version) for ALL advisories
// found, up to DETAIL_CAP, in small parallel batches — advisories beyond
// the cap are still listed, with their advisory ID and an osv.dev link,
// and the report says how many were detail-capped. The total listed per
// scan is capped at VULN_CAP so one bad dependency cannot flood a report.
const DETAIL_CAP = 50;
const VULN_CAP = 100;
const DETAIL_BATCH = 8;

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

/** Fetch detail for a list of advisory IDs, DETAIL_BATCH at a time. */
async function fetchDetailsBatched(ids: string[]): Promise<Map<string, Record<string, unknown>>> {
  const detailById = new Map<string, Record<string, unknown>>();
  for (let i = 0; i < ids.length; i += DETAIL_BATCH) {
    const batch = ids.slice(i, i + DETAIL_BATCH);
    const results = await Promise.all(batch.map((id) => fetchVulnDetail(id)));
    results.forEach((detail, j) => {
      if (detail) detailById.set(batch[j], detail);
    });
  }
  return detailById;
}

export async function checkDependencies(deps: Dependency[]): Promise<{ vulnerabilities: Vulnerability[]; unavailable: boolean; advisoriesFound: number; detailCapped: number }> {
  const queryable = deps.filter((d) => d.version && !/[\^~><*]/.test(d.version) && d.name.length > 0).slice(0, 60);
  if (queryable.length === 0) return { vulnerabilities: [], unavailable: false, advisoriesFound: 0, detailCapped: 0 };
  const ecosystemMap: Record<string, string> = { npm: "npm", pypi: "PyPI", crates: "crates.io", go: "Go", ruby: "RubyGems", php: "Packagist", java: "Maven", dotnet: "NuGet" };
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    const res = await fetch(OSV_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queries: queryable.map((d) => ({ package: { name: d.name, ecosystem: ecosystemMap[d.ecosystem] ?? d.ecosystem }, version: d.version })),
      }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return { vulnerabilities: [], unavailable: true, advisoriesFound: 0, detailCapped: 0 };
    const data = (await res.json()) as { results?: { vulns?: Record<string, unknown>[] }[] };
    // Collect (dep, vuln id) pairs, then fetch full detail for all of them
    // up to DETAIL_CAP; beyond that the advisory is listed without detail.
    const pairs: { dep: Dependency; id: string }[] = [];
    (data.results ?? []).forEach((result, i) => {
      const dep = queryable[i];
      for (const v of result.vulns ?? []) pairs.push({ dep, id: String(v.id ?? "OSV-UNKNOWN") });
    });
    const listed = pairs.slice(0, VULN_CAP);
    const detailIds = [...new Set(listed.slice(0, DETAIL_CAP).map((p) => p.id))];
    const detailById = await fetchDetailsBatched(detailIds);
    const detailCapped = Math.max(0, listed.length - DETAIL_CAP);
    const vulnerabilities: Vulnerability[] = listed.map(({ dep, id }) => {
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
    return { vulnerabilities, unavailable: false, advisoriesFound: pairs.length, detailCapped };
  } catch {
    return { vulnerabilities: [], unavailable: true, advisoriesFound: 0, detailCapped: 0 };
  }
}
