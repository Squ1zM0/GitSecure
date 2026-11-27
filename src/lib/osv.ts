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
// in small parallel batches.
// Phase 8: NO time budgets either. The query phase asks OSV about EVERY
// pinned dependency, in batches of QUERY_BATCH_SIZE, and the detail
// phase fetches full detail for EVERY unique advisory ID — neither
// phase stops early any more, so no advisory is ever left ID-only and
// no dependency is ever left unchecked for flaws. This only works
// because the scan now runs as a background job (see jobs.ts): the old
// 15 s query / 12 s detail budgets existed to fit the 55 s route
// timeout, and that timeout is gone. Callers that still need a budget
// (a test, a one-shot script) can pass one explicitly via opts — the
// default is no budget. A budget that runs out still never drops a
// finding from the list; the report says how many were checked / got
// full detail. onProgress reports depsChecked and advisoriesDetailed
// as each batch lands, so a running job can show honest progress.
const QUERY_BATCH_SIZE = 1000;
const DETAIL_BATCH = 8;

export interface OsvProgress {
  depsChecked: number;
  depsTotal: number;
  advisoriesDetailed: number;
  advisoriesTotal: number;
}

export interface CheckDependenciesOptions {
  /** Milliseconds the query phase may run, or null/undefined = no budget. */
  queryBudgetMs?: number | null;
  /** Milliseconds the detail phase may run, or null/undefined = no budget. */
  detailBudgetMs?: number | null;
  /** Phase 16 (Worker B): absolute wall-clock deadline (epoch ms)
   *  for the whole check, passed by the chunked driver (runScanLoop)
   *  via assembleReport. Caps both phases and each in-flight fetch
   *  (a query started with 1 s left must not run its full 15 s past
   *  the deadline). Unset = the old unbounded default. */
  deadlineMs?: number | null;
  onProgress?: (p: OsvProgress) => void;
}

async function fetchVulnDetail(id: string, timeoutMs: number = 8000): Promise<Record<string, unknown> | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    return (await res.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export async function checkDependencies(deps: Dependency[], opts: CheckDependenciesOptions = {}): Promise<{ vulnerabilities: Vulnerability[]; unavailable: boolean; advisoriesFound: number; detailCapped: number; depsChecked: number; depsQueryable: number }> {
  const queryable = deps.filter((d) => d.version && !/[\^~><*]/.test(d.version) && d.name.length > 0);
  const empty = { vulnerabilities: [], unavailable: false, advisoriesFound: 0, detailCapped: 0, depsChecked: 0, depsQueryable: queryable.length };
  if (queryable.length === 0) return empty;
  const ecosystemMap: Record<string, string> = { npm: "npm", pypi: "PyPI", crates: "crates.io", go: "Go", ruby: "RubyGems", php: "Packagist", java: "Maven", dotnet: "NuGet", actions: "GitHub Actions", pub: "Pub" };
  // Query phase: every pinned dep, QUERY_BATCH_SIZE per querybatch call.
  // No budget by default (Phase 8) — at least one batch always runs.
  // Collect (dep, vuln id) pairs from every batch that answers.
  const pairs: { dep: Dependency; id: string }[] = [];
  // Phase 16: a phase deadline is the earlier of its own budget and
  // the loop deadline (a duration vs an absolute time — both are
  // resolved to an absolute deadline here).
  const phaseDeadline = (budgetMs: number | null | undefined): number | null => {
    const fromBudget = budgetMs != null ? Date.now() + budgetMs : null;
    const fromLoop = opts.deadlineMs ?? null;
    if (fromBudget == null) return fromLoop;
    if (fromLoop == null) return fromBudget;
    return Math.min(fromBudget, fromLoop);
  };
  const queryDeadline = phaseDeadline(opts.queryBudgetMs);
  let depsChecked = 0;
  let unavailable = false;
  try {
    for (let i = 0; i < queryable.length; i += QUERY_BATCH_SIZE) {
      if (i > 0 && queryDeadline != null && Date.now() > queryDeadline) break;
      const batch = queryable.slice(i, i + QUERY_BATCH_SIZE);
      const controller = new AbortController();
      // Phase 16: an in-flight query is capped at the time left to
      // the loop deadline, not the full 15 s — otherwise a query
      // started just before the deadline overruns it by up to 15 s.
      const queryTimeout = opts.deadlineMs != null ? Math.min(15_000, Math.max(500, opts.deadlineMs - Date.now())) : 15_000;
      const timer = setTimeout(() => controller.abort(), queryTimeout);
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
      opts.onProgress?.({ depsChecked, depsTotal: queryable.length, advisoriesDetailed: 0, advisoriesTotal: 0 });
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
  // parallel batches. No budget by default (Phase 8) — advisories past
  // an explicit budget are listed with ID only, never dropped.
  const uniqueIds = [...new Set(pairs.map((p) => p.id))];
  const detailDeadline = phaseDeadline(opts.detailBudgetMs);
  const detailById = await (async () => {
    const map = new Map<string, Record<string, unknown>>();
    for (let i = 0; i < uniqueIds.length; i += DETAIL_BATCH) {
      if (i > 0 && detailDeadline != null && Date.now() > detailDeadline) break;
      const batchIds = uniqueIds.slice(i, i + DETAIL_BATCH);
      // Phase 16: same in-flight cap as the query phase (was 8 s).
      const detailTimeout = opts.deadlineMs != null ? Math.min(8_000, Math.max(500, opts.deadlineMs - Date.now())) : 8_000;
      const results = await Promise.all(batchIds.map((id) => fetchVulnDetail(id, detailTimeout)));
      results.forEach((detail, j) => {
        if (detail) map.set(batchIds[j], detail);
      });
      opts.onProgress?.({ depsChecked, depsTotal: queryable.length, advisoriesDetailed: map.size, advisoriesTotal: uniqueIds.length });
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
