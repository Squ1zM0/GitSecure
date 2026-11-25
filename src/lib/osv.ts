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
// version). Full detail needs GET /v1/vulns/{id} per advisory. Fetching
// detail for every advisory would be slow, so the MVP fetches detail for
// the first DETAIL_LIMIT advisories and lists the rest with an honest
// "check the advisory" note instead of inventing a summary.
const DETAIL_LIMIT = 12;

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

export async function checkDependencies(deps: Dependency[]): Promise<{ vulnerabilities: Vulnerability[]; unavailable: boolean }> {
  const queryable = deps.filter((d) => d.version && !/[\^~><*]/.test(d.version) && d.name.length > 0).slice(0, 60);
  if (queryable.length === 0) return { vulnerabilities: [], unavailable: false };
  const ecosystemMap: Record<string, string> = { npm: "npm", pypi: "PyPI", crates: "crates.io" };
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
    if (!res.ok) return { vulnerabilities: [], unavailable: true };
    const data = (await res.json()) as { results?: { vulns?: Record<string, unknown>[] }[] };
    // Collect (dep, vuln id) pairs, then fetch full detail for the first few.
    const pairs: { dep: Dependency; id: string }[] = [];
    (data.results ?? []).forEach((result, i) => {
      const dep = queryable[i];
      for (const v of result.vulns ?? []) pairs.push({ dep, id: String(v.id ?? "OSV-UNKNOWN") });
    });
    const details = await Promise.all(pairs.slice(0, DETAIL_LIMIT).map((p) => fetchVulnDetail(p.id)));
    const detailById = new Map<string, Record<string, unknown>>();
    pairs.slice(0, DETAIL_LIMIT).forEach((p, i) => {
      if (details[i]) detailById.set(p.id, details[i] as Record<string, unknown>);
    });
    const vulnerabilities: Vulnerability[] = pairs.slice(0, 50).map(({ dep, id }) => {
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
        plainEnglish: `${dep.name} ${dep.version ?? ""} has a known security flaw (${id}). ${fixed ? `Upgrade to ${fixed} or later to fix it.` : "No fixed version was listed in the detail fetched — check the advisory before upgrading."}`,
        upgrade: fixed ? `Upgrade ${dep.name} to ${fixed} or later.` : `Check advisory ${id} for ${dep.name} and upgrade to a patched version.`,
      };
    });
    return { vulnerabilities, unavailable: false };
  } catch {
    return { vulnerabilities: [], unavailable: true };
  }
}
