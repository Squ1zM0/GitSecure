// Phase 21 (Workstream C) - compare pre-filter tests. Run: npm run test:phase21-compare
//
// Workstream B replaces the per-commit patch fetch inside
// `scanHistoryApiChunk` (src/lib/history.ts) with compare windows as
// a pre-filter: one compare call per 250 commits returns the
// window's aggregate diff, the aggregate is scanned for secret
// patterns, and only a window with a hit fetches the individual
// commit patches in that window to attribute each finding to its
// exact commit. Windows where compare truncates the diff keep the
// per-commit path.
//
// Covers, against a local mock GitHub API (never live):
//   1. Attribution is preserved exactly: chunked findings match the
//      uninterrupted per-commit scan, commit by commit.
//   2. Call count for a hit window: the aggregate diff carries no
//      per-commit signal, so a hit window fetches every commit patch
//      in the window to attribute each finding to its exact commit:
//      1 compare + 10 details for a 10-commit window.
//   3. A clean window costs 1 compare and zero detail fetches.
//   4. A truncated compare falls back to the per-commit path and
//      still attributes exactly.
//   5. A window ending at the root commit has no compare base, so
//      it falls back to the per-commit fetches.
//   6. Net-diff limitation (API path only): a secret added and then
//      removed inside the same window is invisible to the
//      pre-filter, because the aggregate diff is a net diff.
//
// The mock compare endpoint follows the real GitHub shape: GET
// /repos/{owner}/{repo}/compare/{base}...{head} returns
// { files: [{ filename, patch }], truncated } where the aggregate
// covers the commits after base up to and including head. The fake
// secrets below are assembled from fragments (never a literal
// secret-pattern string in this file), as in test-scanner.ts and
// test-history.ts.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { scanHistoryViaApi, scanHistoryApiChunk } from "../src/lib/history";
import { leaksSecret } from "../src/lib/redact";
import type { SecretFinding } from "../src/lib/types";

let failures = 0;
let total = 0;
function check(name: string, ok: boolean, extra = "") {
  total++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` - ${extra}` : ""}`);
  if (!ok) failures++;
}

const FAKE = "FAKE";
// Webhook URLs assembled from fragments at runtime. The mock patches
// contain these values; this file never holds either one whole.
const webhookFor = (id18: string) =>
  "https://discord.com/api/webhooks/" + id18 + "/" + FAKE.repeat(6) + "123456";

// 14 commits, newest first. Position 2 (index 1) plants webhook A in
// app.js; position 8 (index 7) plants webhook B in config.js; every
// other commit is a clean one-line change. Indices 12 and 13 are the
// clean tail: index 12 is the compare base for the clean window
// (indices 10-11), and index 13 is the root commit, so the window
// ending there has no compare base at all.
const N = 14;
const SHAS: string[] = Array.from({ length: N }, (_, i) => (i + 1).toString(16).padStart(7, "0") + "c".repeat(33));
const FAKE_A = webhookFor("333333333333333333");
const FAKE_B = webhookFor("444444444444444444");

function patchFor(sha: string): { filename: string; patch: string }[] {
  const idx = SHAS.indexOf(sha);
  if (idx === 1) {
    return [{ filename: "app.js", patch: `@@ -0,0 +1,2 @@\n+const HOOK = "${FAKE_A}";\n+module.exports = { HOOK };\n` }];
  }
  if (idx === 7) {
    return [{ filename: "config.js", patch: `@@ -0,0 +1,2 @@\n+const HOOK2 = "${FAKE_B}";\n+module.exports = { HOOK2 };\n` }];
  }
  return [{ filename: `notes${idx}.txt`, patch: `@@ -1,1 +1,2 @@\n context\n+change ${idx}\n` }];
}

function sortFindings(list: SecretFinding[]): SecretFinding[] {
  return [...list].sort((a, b) =>
    `${a.type}:${a.file}:${a.line}:${a.commit}`.localeCompare(`${b.type}:${b.file}:${b.line}:${b.commit}`),
  );
}

interface MockCounts {
  listCalls: number;
  compareCalls: number;
  detailCalls: number;
  compareRanges: string[];
}

/** Mock GitHub API serving the 12-commit fixture. When
 *  `compareTruncated` is true the compare endpoint answers
 *  truncated: true (the pre-filter cannot be trusted for that
 *  window, so the chunk must fall back to per-commit fetches). */
function startMockApi(compareTruncated: boolean, counts: MockCounts) {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    const base = `http://${req.headers.host}`;
    res.setHeader("Content-Type", "application/json");
    if (url.pathname === "/repos/testowner/testrepo/commits" && !/^\/repos\/testowner\/testrepo\/commits\/[0-9a-f]+$/.test(url.pathname)) {
      counts.listCalls++;
      res.end(JSON.stringify(SHAS.map((sha) => ({ sha }))));
      return;
    }
    const compareM = /^\/repos\/testowner\/testrepo\/compare\/(.+)$/.exec(url.pathname);
    if (compareM) {
      counts.compareCalls++;
      counts.compareRanges.push(decodeURIComponent(compareM[1]));
      const range = decodeURIComponent(compareM[1]);
      const [baseSha, headSha] = range.split("...");
      const headIdx = SHAS.indexOf(headSha ?? "");
      const baseIdx = baseSha ? SHAS.indexOf(baseSha) : -1;
      // GitHub compare semantics: commits after base, up to and
      // including head. An unknown base means the whole range back
      // to the oldest commit; an unknown head means no commits.
      let covered: string[] = [];
      if (headIdx >= 0) {
        const end = baseIdx >= 0 ? baseIdx : SHAS.length;
        covered = SHAS.slice(headIdx, end);
      }
      const byFile = new Map<string, string[]>();
      for (const sha of covered) {
        for (const f of patchFor(sha)) {
          byFile.set(f.filename, [...(byFile.get(f.filename) ?? []), f.patch]);
        }
      }
      const files = [...byFile.entries()].map(([filename, patches]) => ({ filename, patch: patches.join("") }));
      res.end(JSON.stringify({ files, truncated: compareTruncated }));
      return;
    }
    const detailM = /^\/repos\/testowner\/testrepo\/commits\/([0-9a-f]+)$/.exec(url.pathname);
    if (detailM) {
      counts.detailCalls++;
      const sha = detailM[1];
      res.end(JSON.stringify({ sha, files: patchFor(sha) }));
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  });
}

/** Net-diff mock for the same-window add/remove limitation (check
 *  6). Unlike startMockApi, which unions the per-commit patches into
 *  the aggregate, this mock answers compare with the NET diff from
 *  base to head, the way the real endpoint does: a file changed and
 *  reverted inside the window leaves no trace in it. The fixture
 *  plants a webhook added in one commit (index 1) and removed in the
 *  next commit of the same window (index 2), so the net diff carries
 *  no sign of it. The detail endpoint still serves the real
 *  per-commit patches, so the uninterrupted per-commit scan sees the
 *  webhook and the pre-filter does not. */
const NET_N = 5;
const NET_SHAS: string[] = Array.from({ length: NET_N }, (_, i) => (i + 1).toString(16).padStart(7, "0") + "d".repeat(33));
const FAKE_C = webhookFor("555555555555555555");

function netPatchFor(sha: string): { filename: string; patch: string }[] {
  const idx = NET_SHAS.indexOf(sha);
  if (idx === 1) {
    return [{ filename: "scratch.js", patch: `@@ -0,0 +1,2 @@\n+const HOOK = "${FAKE_C}";\n+module.exports = { HOOK };\n` }];
  }
  if (idx === 2) {
    // Removal only: no added lines, so the per-commit path scans
    // nothing here either. The secret is present in this patch only
    // as a removed line, which no detector ever reads.
    return [{ filename: "scratch.js", patch: `@@ -1,1 +1,0 @@\n-const HOOK = "${FAKE_C}";\n` }];
  }
  return [{ filename: `netnotes${idx}.txt`, patch: `@@ -1,1 +1,2 @@\n context\n+change ${idx}\n` }];
}

/** Net contribution of the covered commits to the window aggregate.
 *  The secret added at index 1 and removed at index 2 cancel out,
 *  so neither commit contributes anything to the net diff. */
function netCompareFiles(covered: string[]): { filename: string; patch: string }[] {
  const byFile = new Map<string, string[]>();
  for (const sha of covered) {
    const idx = NET_SHAS.indexOf(sha);
    if (idx === 1 || idx === 2) continue; // added then removed: net zero
    for (const f of netPatchFor(sha)) {
      byFile.set(f.filename, [...(byFile.get(f.filename) ?? []), f.patch]);
    }
  }
  return [...byFile.entries()].map(([filename, patches]) => ({ filename, patch: patches.join("") }));
}

function startMockApiNetDiff(counts: MockCounts) {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    res.setHeader("Content-Type", "application/json");
    if (url.pathname === "/repos/testowner/testrepo/commits" && !/^\/repos\/testowner\/testrepo\/commits\/[0-9a-f]+$/.test(url.pathname)) {
      counts.listCalls++;
      res.end(JSON.stringify(NET_SHAS.map((sha) => ({ sha }))));
      return;
    }
    const compareM = /^\/repos\/testowner\/testrepo\/compare\/(.+)$/.exec(url.pathname);
    if (compareM) {
      counts.compareCalls++;
      counts.compareRanges.push(decodeURIComponent(compareM[1]));
      const range = decodeURIComponent(compareM[1]);
      const [baseSha, headSha] = range.split("...");
      const headIdx = NET_SHAS.indexOf(headSha ?? "");
      const baseIdx = baseSha ? NET_SHAS.indexOf(baseSha) : -1;
      let covered: string[] = [];
      if (headIdx >= 0) {
        const end = baseIdx >= 0 ? baseIdx : NET_SHAS.length;
        covered = NET_SHAS.slice(headIdx, end);
      }
      res.end(JSON.stringify({ files: netCompareFiles(covered), truncated: false }));
      return;
    }
    const detailM = /^\/repos\/testowner\/testrepo\/commits\/([0-9a-f]+)$/.exec(url.pathname);
    if (detailM) {
      counts.detailCalls++;
      const sha = detailM[1];
      res.end(JSON.stringify({ sha, files: netPatchFor(sha) }));
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  });
}

async function main() {
  // --- Reference: the uninterrupted per-commit scan. ---
  const counts = { listCalls: 0, compareCalls: 0, detailCalls: 0, compareRanges: [] as string[] };
  const server = startMockApi(false, counts);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const apiBase = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const whole = await scanHistoryViaApi("testowner", "testrepo", "main", { apiBase });
    check("reference scan succeeds", whole.ok, whole.note ?? "");
    check("reference scan covers all 14 commits", whole.commitsScanned === 14, `${whole.commitsScanned} scanned`);
    const refHooks = sortFindings(whole.findings.filter((f) => f.type === "discord-webhook"));
    check("reference scan finds both planted webhooks", refHooks.length === 2, `${refHooks.length} found`);
    check(
      "reference webhook A attributed to its commit in app.js",
      refHooks.some((f) => f.file === "app.js" && f.commit === SHAS[1].slice(0, 7)),
      JSON.stringify(refHooks.map((f) => `${f.file}:${f.commit}`)),
    );
    check(
      "reference webhook B attributed to its commit in config.js",
      refHooks.some((f) => f.file === "config.js" && f.commit === SHAS[7].slice(0, 7)),
      JSON.stringify(refHooks.map((f) => `${f.file}:${f.commit}`)),
    );
    check("no full fake secret in reference findings", !leaksSecret(JSON.stringify(whole.findings), FAKE_A) && !leaksSecret(JSON.stringify(whole.findings), FAKE_B));

    // --- 1 + 2. One 10-commit chunk over the newest 10 commits. ---
    // Both planted webhooks sit inside this window (indices 1 and 7).
    const before = { ...counts, compareRanges: [...counts.compareRanges] };
    const chunk = await scanHistoryApiChunk(
      "testowner", "testrepo", "main",
      { page: 1, idx: 0, pageShas: SHAS },
      10,
      { apiBase },
    );
    const chunkCalls = chunk.restCalls;
    check("hit-window chunk does not fail", !chunk.failed && !chunk.rateLimited && !chunk.headMoved, chunk.note ?? "");
    check("hit-window chunk scans 10 commits", chunk.commitsScanned === 10, `${chunk.commitsScanned} scanned`);
    check(
      "hit-window chunk findings match the reference exactly (same commits, files, lines)",
      JSON.stringify(sortFindings(chunk.findings)) === JSON.stringify(refHooks),
      `${chunk.findings.length} vs ${refHooks.length} findings`,
    );
    check(
      "hit-window chunk attributed webhook A to its exact commit",
      chunk.findings.some((f) => f.type === "discord-webhook" && f.file === "app.js" && f.commit === SHAS[1].slice(0, 7)),
    );
    check(
      "hit-window chunk attributed webhook B to its exact commit",
      chunk.findings.some((f) => f.type === "discord-webhook" && f.file === "config.js" && f.commit === SHAS[7].slice(0, 7)),
    );
    check("no full fake secret in hit-window chunk findings", !leaksSecret(JSON.stringify(chunk.findings), FAKE_A) && !leaksSecret(JSON.stringify(chunk.findings), FAKE_B));
    // Call-count expectations for workstream B: the chunk's own
    // restCalls, and the mock's counters, must show the pre-filter.
    // A hit window cannot be cheap: the aggregate diff carries no
    // per-commit signal, so attributing each finding to its exact
    // commit needs every commit patch in the window. The saving is
    // on clean windows, which cost 1 compare and nothing else.
    const comparesInChunk = counts.compareCalls - before.compareCalls;
    const detailsInChunk = counts.detailCalls - before.detailCalls;
    check("hit-window chunk calls compare at least once", comparesInChunk >= 1, `${comparesInChunk} compare calls`);
    check(
      "hit-window chunk costs 1 compare plus one detail fetch per commit in the window",
      chunkCalls === 11,
      `${chunkCalls} restCalls for 10 commits (1 compare + 10 details; the aggregate diff cannot attribute by itself)`,
    );
    check(
      "hit-window chunk fetches details for every commit in the hit window",
      detailsInChunk === 10,
      `${detailsInChunk} detail fetches (all 10, to attribute each finding to its exact commit)`,
    );

    // --- 3. A clean window that does NOT end at the root: the next 2
    // commits (indices 10-11). Its base is commit 12, which exists,
    // so compare can cover the window.
    const cleanBefore = { ...counts };
    const cleanState = { page: chunk.nextPage, idx: chunk.nextIdx, pageShas: chunk.nextPageShas };
    const clean = await scanHistoryApiChunk("testowner", "testrepo", "main", cleanState, 2, { apiBase });
    check("clean-window chunk does not fail", !clean.failed && !clean.rateLimited && !clean.headMoved, clean.note ?? "");
    check("clean-window chunk scans the 2 commits", clean.commitsScanned === 2, `${clean.commitsScanned} scanned`);
    check("clean-window chunk finds nothing", clean.findings.length === 0, `${clean.findings.length} findings`);
    check("clean-window chunk does not finish the history yet", clean.done === false, `done=${clean.done}`);
    const cleanCompares = counts.compareCalls - cleanBefore.compareCalls;
    const cleanDetails = counts.detailCalls - cleanBefore.detailCalls;
    check("clean-window chunk calls compare once", cleanCompares === 1, `${cleanCompares} compare calls`);
    check("clean-window chunk fetches zero commit details", cleanDetails === 0, `${cleanDetails} detail fetches (per-commit path fetches 2)`);
    check("clean-window chunk costs 1 REST call total", clean.restCalls === 1, `${clean.restCalls} restCalls`);

    // --- 3b. A window ending at the root: the last 2 commits
    // (indices 12-13). The root has no parent, so no compare base
    // exists for this window and the chunk must fall back to the
    // per-commit fetches. This is the correct behavior, not a
    // failure of the pre-filter: compare cannot express a root
    // commit's own diff.
    const rootBefore = { ...counts };
    const rootState = { page: clean.nextPage, idx: clean.nextIdx, pageShas: clean.nextPageShas };
    const root = await scanHistoryApiChunk("testowner", "testrepo", "main", rootState, 2, { apiBase });
    check("root-ending chunk does not fail", !root.failed && !root.rateLimited && !root.headMoved, root.note ?? "");
    check("root-ending chunk scans the remaining 2 commits", root.commitsScanned === 2, `${root.commitsScanned} scanned`);
    check("root-ending chunk finds nothing", root.findings.length === 0, `${root.findings.length} findings`);
    check("root-ending chunk finishes the history", root.done === true, `done=${root.done}`);
    const rootCompares = counts.compareCalls - rootBefore.compareCalls;
    const rootDetails = counts.detailCalls - rootBefore.detailCalls;
    check("root-ending chunk calls compare zero times (no base exists)", rootCompares === 0, `${rootCompares} compare calls`);
    check("root-ending chunk falls back to one detail fetch per commit", rootDetails === 2, `${rootDetails} detail fetches`);
    check("root-ending chunk costs 2 REST calls total", root.restCalls === 2, `${root.restCalls} restCalls`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  // --- 4. Truncated compare falls back to the per-commit path. ---
  const truncCounts: MockCounts = { listCalls: 0, compareCalls: 0, detailCalls: 0, compareRanges: [] };
  const truncServer = startMockApi(true, truncCounts);
  await new Promise<void>((resolve) => truncServer.listen(0, "127.0.0.1", resolve));
  const truncBase = `http://127.0.0.1:${(truncServer.address() as { port: number }).port}`;
  try {
    const trunc = await scanHistoryApiChunk(
      "testowner", "testrepo", "main",
      { page: 1, idx: 0, pageShas: SHAS },
      10,
      { apiBase: truncBase },
    );
    check("truncated-compare chunk does not fail", !trunc.failed && !trunc.rateLimited && !trunc.headMoved, trunc.note ?? "");
    check("truncated-compare chunk scans 10 commits", trunc.commitsScanned === 10, `${trunc.commitsScanned} scanned`);
    check(
      "truncated-compare chunk still attributes both webhooks exactly",
      trunc.findings.filter((f) => f.type === "discord-webhook").length === 2 &&
        trunc.findings.some((f) => f.file === "app.js" && f.commit === SHAS[1].slice(0, 7)) &&
        trunc.findings.some((f) => f.file === "config.js" && f.commit === SHAS[7].slice(0, 7)),
      JSON.stringify(trunc.findings.map((f) => `${f.file}:${f.commit}`)),
    );
    check("truncated-compare chunk tried compare first", truncCounts.compareCalls >= 1, `${truncCounts.compareCalls} compare calls`);
    check(
      "truncated-compare chunk fell back to a detail fetch per commit",
      truncCounts.detailCalls === 10,
      `${truncCounts.detailCalls} detail fetches (fallback must fetch all 10)`,
    );
    check("no full fake secret in truncated-compare findings", !leaksSecret(JSON.stringify(trunc.findings), FAKE_A) && !leaksSecret(JSON.stringify(trunc.findings), FAKE_B));
  } finally {
    await new Promise<void>((resolve) => truncServer.close(() => resolve()));
  }

  // --- 5. Net-diff limitation: a secret added and then removed
  // inside the SAME compare window is invisible to the pre-filter.
  // The aggregate diff is a net diff from base to head, so an add
  // followed by a remove in one window leaves no trace in it. This
  // is a DOCUMENTED LIMITATION of the API path only: the git path
  // walks each commit's own diff and has no such hole. The exposure
  // is bounded by the window size (the chunk's own take, default 10,
  // max 100). This test pins the current accepted behavior so a
  // future change cannot silently alter it.
  const netCounts: MockCounts = { listCalls: 0, compareCalls: 0, detailCalls: 0, compareRanges: [] };
  const netServer = startMockApiNetDiff(netCounts);
  await new Promise<void>((resolve) => netServer.listen(0, "127.0.0.1", resolve));
  const netBase = `http://127.0.0.1:${(netServer.address() as { port: number }).port}`;
  try {
    const netWhole = await scanHistoryViaApi("testowner", "testrepo", "main", { apiBase: netBase });
    check("net-diff reference scan succeeds", netWhole.ok, netWhole.note ?? "");
    check("net-diff reference scan covers all 5 commits", netWhole.commitsScanned === 5, `${netWhole.commitsScanned} scanned`);
    const netRefHooks = netWhole.findings.filter((f) => f.type === "discord-webhook");
    check(
      "net-diff reference scan finds the planted webhook (the per-commit path sees it)",
      netRefHooks.length === 1 && netRefHooks[0]?.commit === NET_SHAS[1].slice(0, 7),
      JSON.stringify(netRefHooks.map((f) => `${f.file}:${f.commit}`)),
    );
    check("no full fake secret in net-diff reference findings", !leaksSecret(JSON.stringify(netWhole.findings), FAKE_C));
    const netBefore = { ...netCounts };
    const netChunk = await scanHistoryApiChunk(
      "testowner", "testrepo", "main",
      { page: 1, idx: 0, pageShas: NET_SHAS },
      4,
      { apiBase: netBase },
    );
    check("net-diff chunk does not fail", !netChunk.failed && !netChunk.rateLimited && !netChunk.headMoved, netChunk.note ?? "");
    check("net-diff chunk scans 4 commits", netChunk.commitsScanned === 4, `${netChunk.commitsScanned} scanned`);
    check(
      "net-diff chunk misses the add-then-remove webhook (documented limitation)",
      netChunk.findings.length === 0,
      `${netChunk.findings.length} findings`,
    );
    const netCompares = netCounts.compareCalls - netBefore.compareCalls;
    const netDetails = netCounts.detailCalls - netBefore.detailCalls;
    check(
      "net-diff chunk calls compare once and trusts the clean aggregate",
      netCompares === 1 && netDetails === 0,
      `${netCompares} compare calls, ${netDetails} detail fetches`,
    );
    check("net-diff chunk costs 1 REST call total", netChunk.restCalls === 1, `${netChunk.restCalls} restCalls`);
    check("no full fake secret in net-diff chunk findings", !leaksSecret(JSON.stringify(netChunk.findings), FAKE_C));
  } finally {
    await new Promise<void>((resolve) => netServer.close(() => resolve()));
  }

  // --- 6. This file carries no literal secret-pattern values. ---
  const self = await readFile(new URL(import.meta.url).pathname, "utf8");
  const leaked = ["AKIA" + "IOSFODNN7EXAMPLE", "ghp_" + "FAKE".repeat(8) + "1234"].some((s) => self.includes(s));
  check("No literal secret-pattern values in this file", !leaked);
  check("No em dashes in this file", !self.includes("\u2014"));
}

main()
  .then(() => {
    console.log(failures === 0 ? `\nPASS ${total}/${total}` : `\n${failures} test(s) FAILED out of ${total}.`);
    process.exit(failures === 0 ? 0 : 1);
  })
  .catch((err) => {
    console.error("Phase 21 compare test crashed:", err instanceof Error ? err.message : err);
    process.exit(1);
  });
