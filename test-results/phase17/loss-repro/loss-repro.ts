// GitSecure Phase 17, Part 1 — LOSS REPRO (Worker A design work).
//
// Proves the history-findings accumulation hole with real code, no live
// GitHub: a mock GitHub API server (same pattern as
// scripts/test-cursor-phase9.ts §2a) serves a 6-commit repo with a
// distinct fake Discord webhook planted in commits 1, 3 and 5
// (newest-first), one commit per history chunk, so each secret lands
// in a DIFFERENT chunk.
//
// Two caller paths are driven against the REAL chunk driver:
//
//   Path A — POST /api/scan/chunk caller: advanceScan() once per chunk,
//     the caller appends each chunk's `chunkFindings` to its own
//     accumulation and passes the whole array at assemble time.
//     (This is what the browser driver does via sessionStorage, and
//     what the chunk route's `historyFindings` body field is for.)
//
//   Path B — GET /api/scan/[owner]/[repo] and MCP caller:
//     Invocation 1 is a GENUINE runScanLoop() call in exactly the
//     production shape — { cursor, budgetMs: 40000 }, no
//     historyFindings, no head — against a mock whose commit-detail
//     responses sleep 8 s, so one history chunk costs ~8 s and the
//     Phase 16 start floor (budget − 21 s = 19 s) stops the loop after
//     3 chunks (~24 s elapsed, ~16 s left < 19 s floor). Its returned
//     `historyFindings` are recorded and then DISCARDED, the way the
//     GET route (which returns only cursor/partial/progress/note) and
//     mcp.ts resumeScan/fullScan (which keep only progress + cursor)
//     discard them. Invocation 2 resumes from the cursor alone with a
//     FRESH accumulation (exactly what a fresh runScanLoop does — it
//     initialises `historyFindings = [...(opts.historyFindings ?? [])]`
//     = []) and runs the remaining chunks via advanceScan, the exact
//     primitive runScanLoop calls per iteration.
//
// Assemble in both paths is assembleReport() directly — the exact
// function advanceScan's assemble stage calls — because advanceScan's
// assemble stage also calls fetchHeadSha() against the real
// api.github.com, which cannot answer for this mock repo. The loss is
// decided BEFORE assemble, in what `historyFindings` the caller can
// supply; assembleReport is given exactly that. (Same substitution as
// test-cursor-phase9.ts §4, synthetic HEAD with zero dependencies so
// no OSV network is needed.)
//
// Fake secrets are assembled from fragments, never a literal
// secret-pattern string in this file. Nothing here is a real secret.
//
// Run:  npx tsx test-results/phase17/loss-repro/loss-repro.ts
// Exit: 0 when the loss is reproduced exactly as predicted
//       (A = 3 findings, B = 1 finding — the last invocation's only),
//       1 otherwise.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { advanceScan, runScanLoop, API_FAST_PATH_WAIT_MS } from "../../../src/lib/chunks";
import { encodeCursor, initialHistoryCursor, decodeCursor } from "../../../src/lib/cursor";
import { assembleReport } from "../../../src/lib/scan";
import { leaksSecret } from "../../../src/lib/redact";
import type { HeadPartial, SecretFinding } from "../../../src/lib/types";

const FAKE = "FAKE";
const sha = (c: string) => c.repeat(40);

// 6 commits, newest-first. Secrets in chunks 1, 3, 5.
const SHA_NEW = sha("3"); // chunk 1 — webhook A
const SHA_C2 = sha("2"); // chunk 2 — clean
const SHA_C3 = sha("4"); // chunk 3 — webhook B
const SHA_C4 = sha("5"); // chunk 4 — clean
const SHA_C5 = sha("6"); // chunk 5 — webhook C
const SHA_OLD = sha("1"); // chunk 6 — clean
const SHAS = [SHA_NEW, SHA_C2, SHA_C3, SHA_C4, SHA_C5, SHA_OLD];
const webhook = (id: string) =>
  "https://discord.com/api/webhooks/" + id + "/" + FAKE.repeat(6) + "123456";
const HOOK_A = webhook("111111111111111111");
const HOOK_B = webhook("222222222222222222");
const HOOK_C = webhook("333333333333333333");

const PATCHES: Record<string, { filename: string; patch: string }[]> = {
  [SHA_NEW]: [{ filename: "app.js", patch: `@@ -0,0 +1,2 @@\n+const HOOK = "${HOOK_A}";\n+module.exports = { HOOK };\n` }],
  [SHA_C2]: [{ filename: "notes.txt", patch: "@@ -1,1 +1,2 @@\n context\n+unrelated change\n" }],
  [SHA_C3]: [{ filename: "config.js", patch: `@@ -0,0 +1,1 @@\n+const HOOK = "${HOOK_B}";\n` }],
  [SHA_C4]: [{ filename: "notes.txt", patch: "@@ -1,1 +1,2 @@\n context\n+another unrelated change\n" }],
  [SHA_C5]: [{ filename: "keys.txt", patch: `@@ -0,0 +1,1 @@\n+const HOOK = "${HOOK_C}";\n` }],
  [SHA_OLD]: [{ filename: "readme.md", patch: "@@ -0,0 +1,1 @@\n+# hello\n" }],
};

// Detail-response delay (ms), toggled per phase. 8000 makes one API
// history chunk cost ~8 s, so a 40 s loop floor-stops after 3 chunks.
let detailDelayMs = 0;
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  if (url.pathname === "/repos/testowner/testrepo/commits") {
    if (url.searchParams.get("per_page") === "1") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify([{ sha: SHA_NEW }])); // HEAD check
      return;
    }
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(SHAS.map((s) => ({ sha: s }))));
    return;
  }
  const m = /^\/repos\/testowner\/testrepo\/commits\/([0-9a-f]+)$/.exec(url.pathname);
  if (m) {
    if (detailDelayMs > 0) await sleep(detailDelayMs);
    if (res.writableEnded) return;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ sha: m[1], files: PATCHES[m[1]] ?? [] }));
    return;
  }
  res.statusCode = 404;
  res.end("not found");
});

// Synthetic HEAD: zero secrets, zero dependencies (no OSV network),
// one posture item so the score has something besides secrets.
const HEAD: HeadPartial = {
  owner: "testowner", repo: "testrepo", branch: "main", headSha: SHA_NEW,
  filesScanned: 3, filesTotal: 3, treeTruncated: false, tarballFallback: false,
  secrets: [], frameworks: [], dependencies: [],
  posture: [{ id: "no-security-md", title: "No SECURITY.md", severity: "low", detail: "No SECURITY.md.", fix: "Add one." }],
  unpinnedCount: 0, historyMethod: "api", retainedIncomplete: false,
};

const ids = (fs: SecretFinding[]) =>
  fs.map((f) => `${f.id}@${(f.commit ?? "?").slice(0, 7)}:${f.fragment}`).sort();

async function main() {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const apiBase = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const startCursor = encodeCursor(
    initialHistoryCursor({ owner: "testowner", repo: "testrepo", branch: "main", headSha: SHA_NEW, historyMethod: "api" }),
  );
  const results: Record<string, unknown> = {
    repo: "testowner/testrepo (mock GitHub API server, localhost)",
    commits: 6, chunkCommits: 1, secretsPlanted: 3,
    planted: { A: "chunk 1 (newest commit)", B: "chunk 3", C: "chunk 5" },
    productionBudgetMs: API_FAST_PATH_WAIT_MS,
  };
  try {
    // ---------- Path A: POST-chunk caller carries the accumulation ----------
    detailDelayMs = 0;
    let cursorA: string | null = startCursor;
    const accumulated: SecretFinding[] = [];
    const perChunkA: { chunk: number; findings: string[] }[] = [];
    let chunksA = 0;
    while (cursorA) {
      chunksA++;
      const r = await advanceScan({ owner: "testowner", repo: "testrepo", cursor: cursorA, apiBase, chunkCommits: 1 });
      if (r.status === "done") throw new Error("Path A: unexpected done before assemble stage");
      perChunkA.push({ chunk: chunksA, findings: ids(r.chunkFindings) });
      accumulated.push(...r.chunkFindings);
      if (decodeCursor(r.cursor, "testowner", "testrepo").stage === "assemble") break;
      cursorA = r.cursor;
      if (chunksA > 10) throw new Error("Path A: did not reach assemble");
    }
    const reportA = await assembleReport(HEAD, {
      findings: accumulated, commitsScanned: 6, ok: true, method: "api", note: null,
    });
    results.pathA = {
      caller: "POST /api/scan/chunk (advanceScan, caller accumulates chunkFindings)",
      chunks: chunksA, perChunkFindings: perChunkA,
      accumulatedCount: accumulated.length, accumulatedIds: ids(accumulated),
      reportSecrets: reportA.counts.secrets, reportHistoryCommits: reportA.counts.historyCommitsScanned,
      reportScore: reportA.score, reportGrade: reportA.grade,
      reportSecretIds: reportA.secrets.map((f) => `${f.id}@${(f.commit ?? "?").slice(0, 7)}`).sort(),
      historyLimitLine: reportA.limits.find((l) => l.startsWith("History checked")),
    };

    // ---------- Path B, invocation 1: genuine runScanLoop, production shape ----------
    detailDelayMs = 8000;
    const inv1Started = Date.now();
    const inv1 = await runScanLoop("testowner", "testrepo", {
      cursor: startCursor, budgetMs: API_FAST_PATH_WAIT_MS, apiBase, chunkCommits: 1,
    });
    const inv1Ms = Date.now() - inv1Started;
    if (inv1.status !== "partial" || !inv1.cursor) throw new Error(`Path B inv1: expected partial, got ${inv1.status}`);
    const inv1Cursor = decodeCursor(inv1.cursor, "testowner", "testrepo");
    if (inv1Cursor.stage !== "history" || inv1Cursor.histScanned !== 3) {
      throw new Error(`Path B inv1: expected floor-stop after 3 chunks, got stage=${inv1Cursor.stage} scanned=${inv1Cursor.histScanned} in ${inv1Ms}ms`);
    }
    const inv1Findings = inv1.historyFindings ?? [];
    // The GET route returns { cursor, partial, progress, note } and
    // mcp.ts keeps only progress + cursor: inv1's findings die here.
    const inv1Returned = ids(inv1Findings);

    // ---------- Path B, invocation 2: fresh accumulation, remaining chunks ----------
    detailDelayMs = 0;
    let cursorB: string | null = inv1.cursor;
    const inv2Findings: SecretFinding[] = []; // fresh: runScanLoop starts from []
    let chunksB2 = 0;
    while (cursorB) {
      chunksB2++;
      const r = await advanceScan({ owner: "testowner", repo: "testrepo", cursor: cursorB, apiBase, chunkCommits: 1 });
      if (r.status === "done") throw new Error("Path B inv2: unexpected done before assemble stage");
      inv2Findings.push(...r.chunkFindings);
      if (decodeCursor(r.cursor, "testowner", "testrepo").stage === "assemble") break;
      cursorB = r.cursor;
      if (chunksB2 > 10) throw new Error("Path B inv2: did not reach assemble");
    }
    const reportB = await assembleReport(HEAD, {
      findings: inv2Findings, commitsScanned: 6, ok: true, method: "api", note: null,
    });
    const lost = ids(accumulated).filter((id) => !ids(inv2Findings).includes(id));
    results.pathB = {
      caller: "GET /api/scan/[owner]/[repo] and MCP resume_scan (runScanLoop fresh per invocation, no historyFindings)",
      invocation1: {
        driver: "genuine runScanLoop({ cursor, budgetMs: 40000, apiBase, chunkCommits: 1 }) — the exact GET-route / mcp.ts call shape",
        wallMs: inv1Ms, chunksRun: 3, floorStopped: true,
        returnedHistoryFindings: inv1Returned,
        note: "GET route returns only { cursor, partial, progress, note }; mcp.ts keeps only progress + cursor — these findings are discarded by the caller",
      },
      invocation2: {
        driver: "fresh accumulation ([]) + advanceScan per chunk — the exact primitive runScanLoop calls",
        chunksRun: chunksB2, findings: ids(inv2Findings),
      },
      assembleSuppliedCount: inv2Findings.length, assembleSuppliedIds: ids(inv2Findings),
      reportSecrets: reportB.counts.secrets, reportHistoryCommits: reportB.counts.historyCommitsScanned,
      reportScore: reportB.score, reportGrade: reportB.grade,
      reportSecretIds: reportB.secrets.map((f) => `${f.id}@${(f.commit ?? "?").slice(0, 7)}`).sort(),
      historyLimitLine: reportB.limits.find((l) => l.startsWith("History checked")),
      lostFindingIds: lost,
    };

    // ---------- Verdict ----------
    const aCount = (results.pathA as { reportSecrets: number }).reportSecrets;
    const bCount = (results.pathB as { reportSecrets: number }).reportSecrets;
    results.verdict = {
      lossReproduced: aCount === 3 && bCount === 1,
      findingsLost: aCount - bCount,
      lostIds: lost,
      // The report still claims the history was checked — the count is
      // honest, the findings are silently gone, and the score is wrong.
      silentMisreport: (results.pathB as { historyLimitLine: string }).historyLimitLine,
      scoreInflation: `${(results.pathB as { reportScore: number }).reportScore}/${(results.pathB as { reportGrade: string }).reportGrade} (B, 1 secret) vs ${(results.pathA as { reportScore: number }).reportScore}/${(results.pathA as { reportGrade: string }).reportGrade} (A, 3 secrets)`,
      payloadBytes: {
        accumulatedFindingsJson: Buffer.byteLength(JSON.stringify(accumulated), "utf8"),
        perFindingJsonApprox: Math.round(Buffer.byteLength(JSON.stringify(accumulated), "utf8") / Math.max(1, accumulated.length)),
      },
      mechanism: [
        "runScanLoop() accumulates historyFindings in-process only (chunks.ts).",
        "GET route (src/app/api/scan/[owner]/[repo]/route.ts) calls runScanLoop({cursor, budgetMs}) and its 202 body carries only cursor/partial/progress/note — result.historyFindings is never returned.",
        "mcp.ts fullScan/resumeScan call runScanLoop the same way and keep only progress + cursor in the still-running text.",
        "The next invocation starts with historyFindings = [] — earlier chunks' findings exist nowhere.",
        "Phase 16 assemble exemption (chunks.ts ~line 547) only saves the case where history + assemble fit in ONE invocation.",
        "Cursor must NEVER carry findings (cursor.ts) — so the findings have no ride across invocations today.",
      ],
    };
    const allOut = JSON.stringify(results);
    results.noFullSecretLeaked =
      !leaksSecret(allOut, HOOK_A) && !leaksSecret(allOut, HOOK_B) && !leaksSecret(allOut, HOOK_C);

    console.log(JSON.stringify(results, null, 2));
    writeFileSync(join(process.cwd(), "test-results/phase17/loss-repro/results.json"), JSON.stringify(results, null, 2) + "\n");
    if (!(results.verdict as { lossReproduced: boolean }).lossReproduced) {
      console.error("LOSS NOT REPRODUCED AS PREDICTED — expected A=3, B=1");
      process.exitCode = 1;
    } else {
      console.log("LOSS REPRODUCED: Path A reports 3/3 history secrets, Path B reports 1/3 (2 lost: the first invocation's findings).");
    }
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
