// Phase 8 jobs test. Run: npm run test:jobs-phase8
//
// Proves, mostly with no network:
//   1. A scan that outlasts one invocation completes via the job/poll
//      path: a fake slow runner (progress updates, then a report after
//      a delay past a short fast-path wait) is startable, pollable
//      (live progress: step, files scanned so far, commits so far),
//      and finishes with the full report — the same flow the API and
//      the report page use.
//   2. Jobs dedupe by owner/repo (a second start returns the same
//      job), job IDs are random UUIDs that carry no owner/repo/secret,
//      unknown IDs are unknown, and finished jobs are evicted after
//      their TTL.
//   3. A failing scan becomes an error job with its plain-English
//      message, not a crash.
//   4. buildLimits (the rewritten "About this scan" copy): a complete
//      scan says so once with exact counts and no cap language; a
//      partial scan states exactly what it could not cover.
//   5. The report page shows live progress text while a job runs
//      (ScanProgress renders the step, "X of Y files scanned", and
//      the commits line from its progress prop).
//   6. OSV detail has no time budget any more: with every detail
//      fetch delayed so the old 12 s budget would have capped, all
//      160 advisories still get full detail (detailCapped 0).
//   7. Source checks: no 55 s timeout race, no arrayBuffer tarball
//      read (streaming guard instead), no OSV budget constants, no
//      "Scan limits" heading left in the report page.
//
// The fake runner stands in for scanRepo; the real scanRepo is
// exercised live by test:techdirect and test:mcp.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { renderToString } from "react-dom/server";
import React from "react";
import ScanProgress from "../src/components/ScanProgress";
import { getJob, getOrStartJob, jobSnapshot, setJobTtlForTests, waitForJob } from "../src/lib/jobs";
import { buildLimits } from "../src/lib/scan";
import { emptyProgress, type ScanProgress as ScanProgressType } from "../src/lib/progress";
import { checkDependencies } from "../src/lib/osv";
import type { FullReport } from "../src/lib/types";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

const ROOT = process.cwd();
const src = (p: string) => readFileSync(join(ROOT, p), "utf8");

const cannedReport = {
  kind: "full",
  repo: "slow",
  owner: "fake",
  branch: "main",
  commit: "abc1234",
  score: 83,
  grade: "B",
  counts: { secrets: 0, vulnerabilities: 0, frameworks: 0, dependencies: 0, postureIssues: 0, filesScanned: 2802, historyCommitsScanned: 62 },
  summary: "Test report.",
  scannedAt: new Date().toISOString(),
  historyDepth: "Full history, newest first.",
  limits: [],
  secrets: [],
  frameworks: [],
  dependencies: [],
  vulnerabilities: [],
  posture: [],
} as unknown as FullReport;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main() {
  // --- 1. Slow scan completes via job/poll -------------------------
  const slowRunner = async (_o: string, _r: string, onProgress: (p: ScanProgressType) => void) => {
    const p = emptyProgress();
    p.filesTotal = 2802;
    p.filesScanned = 1200;
    onProgress({ ...p });
    await sleep(300);
    p.filesScanned = 2802;
    p.step = "history";
    onProgress({ ...p });
    await sleep(300);
    p.commitsScanned = 62;
    p.step = "dependencies";
    onProgress({ ...p });
    await sleep(300);
    return cannedReport;
  };
  const job = getOrStartJob("fake", "slow", slowRunner);
  check("job id is a random UUID (no owner/repo/secret in it)", /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(job.id) && !job.id.includes("fake") && !job.id.includes("slow"));
  check("job starts running", job.status === "running");
  const early = await waitForJob(job, 100);
  check("short fast-path wait leaves the job running (202 case)", early.status === "running");
  check("live progress shows files scanned so far", early.progress.filesScanned >= 1200 && early.progress.filesTotal === 2802, `${early.progress.filesScanned} of ${early.progress.filesTotal}`);
  // Snapshot the running state NOW: the job object mutates when it
  // finishes, so a snapshot taken after completion would be "done".
  const runningSnap = jobSnapshot(early);
  check("running snapshot carries progress but no report", runningSnap.status === "running" && runningSnap.report === undefined && runningSnap.progress.filesTotal === 2802);
  const done = await waitForJob(job, 10_000);
  check("job finishes via polling", done.status === "done" && done.report === cannedReport);
  check("finished progress carries the true commit count", done.progress.commitsScanned === 62, `${done.progress.commitsScanned}`);
  const snap = jobSnapshot(done);
  check("done snapshot includes the full report", snap.status === "done" && snap.report?.score === 83);

  // --- 2. Dedupe, unknown IDs, TTL eviction ------------------------
  const again = getOrStartJob("fake", "slow", slowRunner);
  check("second start returns the same job (dedupe by owner/repo)", again.id === job.id);
  const other = getOrStartJob("fake", "other", slowRunner);
  check("a different repo gets a different job", other.id !== job.id);
  check("unknown job id is unknown", getJob("00000000-0000-0000-0000-000000000000") === undefined);
  setJobTtlForTests(0);
  await sleep(5);
  check("finished job is evicted after its TTL", getJob(job.id) === undefined);
  setJobTtlForTests(null);

  // --- 3. Failing scan becomes an error job ------------------------
  const failingRunner = async () => {
    await sleep(50);
    const err = new Error("Repository not found (or it is private). GitSecure scans public repos only.") as Error & { kind: string; status: number };
    err.kind = "not-found";
    err.status = 404;
    throw err;
  };
  const badJob = getOrStartJob("fake", "missing", failingRunner);
  const badDone = await waitForJob(badJob, 5000);
  check("failing scan becomes an error job", badDone.status === "error");
  check("error job keeps the plain-English message + status", badDone.error?.message.includes("not found") === true && badDone.error?.status === 404, badDone.error?.message ?? "");

  // --- 4. buildLimits: rewritten "About this scan" copy ------------
  const complete = buildLimits({
    filesScanned: 2802, filesTotal: 2802, historyOk: true, historyMethod: "api",
    historyCommitsScanned: 62, historyMs: 6000, historyNote: null,
    depsChecked: 2, depsQueryable: 2, depsTotal: 2, advisoriesTotal: 4,
    detailCapped: 0, treeTruncated: false, tarballFallback: false,
  });
  check("complete scan says it scanned all files, with the exact count", complete.some((l) => l === "Scanned all 2802 files in the tree (binary, dist, node_modules and .next skipped — generated/vendored paths, not source files)."), JSON.stringify(complete));
  check("complete scan states the history count + method", complete.some((l) => l.includes("History checked: 62 commits, newest first (GitHub API")));
  check("complete scan keeps the standing facts line", complete.some((l) => l === "Public repos only. No secret is ever stored, logged, or shown in full."));
  check("complete scan has no cap language at all", !/cap|budget|55|timeout|truncat/i.test(complete.join(" ")), complete.join(" | "));
  const partial = buildLimits({
    filesScanned: 2000, filesTotal: 2802, historyOk: true, historyMethod: "clone",
    historyCommitsScanned: 62, historyMs: 6000, historyNote: "GitHub API rate limit was hit — scanned 40 commits before stopping.",
    depsChecked: 100, depsQueryable: 9401, depsTotal: 9401, advisoriesTotal: 92,
    detailCapped: 5, treeTruncated: true, tarballFallback: true,
  });
  check("partial scan states the exact unfetched file count", partial.some((l) => l.includes("Fetched 2000 of 2802 files")));
  check("partial scan states the exact unchecked dep count", partial.some((l) => l.includes("100 of 9401 pinned dependencies were checked")));
  check("partial scan states the exact ID-only advisory count", partial.some((l) => l.includes("fetched for 87 of 92 listed advisories; 5 listed with advisory ID only")));
  check("partial scan keeps the history note verbatim", partial.some((l) => l.includes("scanned 40 commits before stopping")));
  check("partial scan still has no cap numbers of its own", !/1000 commits|50 MB|45s|12 s|15 s/i.test(partial.join(" ")), partial.join(" | "));

  // --- 5. Report page shows live progress text while a job runs ----
  const progressHtml = renderToString(
    React.createElement(ScanProgress, {
      jobId: "00000000-0000-0000-0000-000000000001",
      owner: "fake",
      repo: "slow",
      initial: { step: "history", filesScanned: 1200, filesTotal: 2802, commitsScanned: 0, depsChecked: 0, depsTotal: 0, advisoriesDetailed: 0, advisoriesTotal: 0 },
    }),
  ).replace(/<!-- -->/g, "");
  check("progress view names the current step", progressHtml.includes("Checking the full history, newest first"));
  check("progress view shows files scanned so far", progressHtml.includes("1,200 of 2,802 files scanned"), progressHtml.slice(0, 400));
  check("progress view says history is not checked yet (honest zero)", progressHtml.includes("History not checked yet"));
  check("progress view says the scan keeps running in the background", progressHtml.includes("keeps running in the background"));
  check("progress view polls the job endpoint", progressHtml.includes("/api/scan/jobs/") || src("src/components/ScanProgress.tsx").includes("/api/scan/jobs/${encodeURIComponent(jobId)}"));

  // --- 6. OSV detail has no time budget ----------------------------
  // Every detail fetch takes 700 ms; 160 advisories in batches of 8
  // is 20 sequential batches ≈ 14 s — past the old 12 s budget, which
  // would have left most advisories ID-only. The new code details all.
  const realFetch = globalThis.fetch;
  const ids = Array.from({ length: 160 }, (_, i) => `GHSA-test${i}`);
  globalThis.fetch = (async (url: string | URL) => {
    const u = String(url);
    if (u.includes("/v1/querybatch")) {
      return new Response(JSON.stringify({ results: ids.map((id) => ({ vulns: [{ id }] })) }), { status: 200 });
    }
    if (u.includes("/v1/vulns/")) {
      await sleep(700);
      const id = decodeURIComponent(u.split("/v1/vulns/")[1]);
      return new Response(JSON.stringify({
        id, summary: `Summary for ${id}.`,
        severity: [{ type: "CVSS_V3", score: "9.8" }],
        affected: [{ ranges: [{ events: [{ fixed: "2.0.0" }] }] }],
      }), { status: 200 });
    }
    throw new Error(`unexpected fetch ${u}`);
  }) as typeof fetch;
  try {
    const deps = ids.map((id, i) => ({ name: `pkg-${i}`, ecosystem: "npm" as const, version: "1.0.0", direct: true, sourceFile: "package.json" }));
    const started = Date.now();
    const osv = await checkDependencies(deps);
    const elapsed = Date.now() - started;
    check("OSV details every advisory despite the slow detail fetches", osv.detailCapped === 0 && osv.vulnerabilities.length === 160, `detailCapped=${osv.detailCapped} vulns=${osv.vulnerabilities.length} in ${(elapsed / 1000).toFixed(1)}s`);
    check("every advisory carries full detail (summary + fixed version)", osv.vulnerabilities.every((v) => v.summary.startsWith("Summary for ") && v.fixedVersion === "2.0.0"));
  } finally {
    globalThis.fetch = realFetch;
  }

  // --- 7. Source checks: caps/timeouts gone, streaming guard in ----
  const scanSrc = src("src/lib/scan.ts");
  check("no 55 s scan timeout race remains", !/SCAN_TIMEOUT_MS|scanRepoWithTimeout/.test(scanSrc));
  check("tarball download is streamed (getReader), not buffered whole", /getReader\(\)/.test(scanSrc) && !/await res\.arrayBuffer\(\)/.test(scanSrc));
  check("tarball guard still exists as a streaming memory guard", /TARBALL_MAX_BYTES/.test(scanSrc));
  const osvSrc = src("src/lib/osv.ts");
  check("OSV has no query/detail budget constants left", !/QUERY_BUDGET_MS|DETAIL_BUDGET_MS|DETAIL_CAP/.test(osvSrc));
  const page = src("src/app/[owner]/[repo]/page.tsx");
  check("report page has no 'Scan limits' heading", !/Scan limits/.test(page));
  check("report page has the rewritten 'About this scan' section", /About this scan/.test(page));
  check("report page renders live progress while a job runs", /ScanProgress/.test(page) && /jobId=\{runningJob\.id\}/.test(page));
  check("report page still renders the full report server-side on the fast path", /SecretsList secrets=\{full\.secrets\} owner=\{full\.owner\} repo=\{full\.repo\} branch=\{full\.branch\}/.test(page));
  const apiRoute = src("src/app/api/scan/[owner]/[repo]/route.ts");
  check("scan API answers 202 with a job when still running", /status: 202/.test(apiRoute) && /jobSnapshot/.test(apiRoute));
  check("scan API keeps the job alive past the response (after)", /after\(async/.test(apiRoute));
  const mcpSrc = src("src/lib/mcp.ts");
  check("MCP polls the job server-side instead of timing out", /waitForJob\(job, FAST_PATH_WAIT_MS\)/.test(mcpSrc) && /still running in the background/.test(mcpSrc));
  check("MCP notes state no history cap numbers", !/1,000 commits \/ 50 MB/.test(mcpSrc));
  check("MCP notes state no OSV time budget", !/time budget/.test(mcpSrc));
  check("job poll route exists", readFileSync(join(ROOT, "src/app/api/scan/jobs/[jobId]/route.ts"), "utf8").includes("job-not-found"));

  console.log(failures === 0 ? "\nAll Phase 8 job checks passed." : `\n${failures} check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
