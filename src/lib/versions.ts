// Pure version helpers (Phase 15 finding 15) - shared by the
// on-page VulnerabilitiesList and the downloadable Markdown report
// (src/lib/report-markdown.ts), so both reconcile the same way.
// No DOM, no React: unit-testable with tsx alone.

import type { Vulnerability } from "./types";

/** Version comparison for the fix reconciliation. Numeric segments
 *  compare numerically ("4.3.2" > "3.15.0", "4.3.2" > "4.3.1"); a
 *  trailing non-numeric segment is a pre-release and sorts below the
 *  release ("1.0.0-alpha" < "1.0.0"). Anything else falls back to
 *  lexical order. Display only - OSV data is never rewritten. */
export function compareVersions(a: string, b: string): number {
  const parts = (v: string) => v.replace(/^[vV]/, "").split(/[.+-]/);
  const pa = parts(a);
  const pb = parts(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const sa = pa[i];
    const sb = pb[i];
    if (sa === undefined && sb === undefined) return 0;
    if (sa === undefined) return /^\d+$/.test(sb) ? (Number(sb) === 0 ? 0 : -1) : 1;
    if (sb === undefined) return /^\d+$/.test(sa) ? (Number(sa) === 0 ? 0 : 1) : -1;
    const na = Number(sa);
    const nb = Number(sb);
    if (!Number.isNaN(na) && !Number.isNaN(nb)) {
      if (na !== nb) return na - nb;
    } else if (sa !== sb) {
      return sa < sb ? -1 : 1;
    }
  }
  return 0;
}

/** Per package + installed version, the single recommended fix
 *  version - the max of the advisory fixed versions - for groups
 *  where advisories disagree (TechDirect's js-yaml 4.1.1 carried four
 *  LOW findings saying 4.3.2, 3.15.0, 4.3.1, and 4.2.0). Groups with
 *  one distinct fixed version (or none) are absent: their Fix lines
 *  are already unambiguous. Presentation only - each row keeps its
 *  own id, severity, plainEnglish, and upgrade fields; only the
 *  rendered Fix line is reconciled. */
export function recommendedFixVersions(vulns: Vulnerability[]): Map<string, { recommended: string; advisoryCount: number }> {
  const groups = new Map<string, { fixed: Set<string>; count: number }>();
  for (const v of vulns) {
    const key = `${v.packageName}@${v.installedVersion ?? ""}`;
    const g = groups.get(key) ?? { fixed: new Set<string>(), count: 0 };
    g.count++;
    if (v.fixedVersion) g.fixed.add(v.fixedVersion);
    groups.set(key, g);
  }
  const out = new Map<string, { recommended: string; advisoryCount: number }>();
  for (const [key, g] of groups) {
    if (g.fixed.size <= 1) continue;
    let best: string | null = null;
    for (const f of g.fixed) if (best === null || compareVersions(f, best) > 0) best = f;
    if (best !== null) out.set(key, { recommended: best, advisoryCount: g.count });
  }
  return out;
}
