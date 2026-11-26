// Phase 16 (Worker B) — API ceiling-risk audit test.
// Run: npm run test:phase16-worker-b
//
// Proves a single runScanLoop invocation stays within its budget
// (and so under Vercel's 60 s function ceiling) even when a chunk
// is slow, and that the fast path still completes:
//
//   1. Budget arithmetic: the API/MCP loop budget (40 s) plus the
//      worst late-chunk overrun the start floor allows (git prefix
//      ~30 s − 20 s floor) plus unwind (~2 s) stays under the ~55 s
//      headroom below the 60 s ceiling.
//   2. Slow API history (mock GitHub API that sleeps 15 s per
//      request): runScanLoop with a 2 s budget returns partial +
//      cursor in ~2 s, not after the 12 s per-fetch aborts the old
//      code paid. The cursor still points at the unscanned commit.
//   3. API chunk deadline unit: scanHistoryApiChunk with a deadline
//      in the past returns at once, same position, never failed.
//   4. Slow git clone (mock smart-HTTP server that stalls 30 s on
//      git-upload-pack): the clone aborts at the loop deadline and
//      the loop returns partial + cursor in ~2 s — the pre-fix code
//      would have waited out the 30 s clone (no timeout on it) and
//      then walked on past the budget.
//   5. Fast path still completes: a stubbed fetch (fake tarball) +
//      fast mock API drives a full loop to done — the deadline
//      threading does not break a small repo answering in one call.
//   6. Contract/source checks: the API route and MCP pass the
//      tightened budget, the 202 + cursor shape is untouched, and
//      the report page's 50 s constant (Worker A's surface) is
//      unchanged.
//   7. Assemble is exempt from the start floor: with a history chunk
//      that finishes after the 21 s floor (a 22 s delayed mock API
//      list), the loop must still assemble in the same call —
//      stopping before assemble would strand the scan across
//      invocations, where GET / MCP callers cannot carry the
//      accumulated history findings back and the first call's
//      history findings would be lost from the finished report
//      (live proof: cold MCP scan_repo GitSecure resumed to 18
//      secrets instead of 37 before this fix).
//
// No live GitHub calls except one fast-failing clone of a
// nonexistent repo (the git-path fallback in test 5); no quota
// burned, no secrets anywhere in this file (the fixtures carry
// plain text only).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { execFile, spawn } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { gzipSync } from "node:zlib";
import { decodeCursor, encodeCursor, type ScanCursorData } from "../src/lib/cursor";
import { advanceScan, runScanLoop, API_FAST_PATH_WAIT_MS, GIT_HISTORY_CHUNK_BUDGET_MS, FAST_PATH_WAIT_MS } from "../src/lib/chunks";
import { scanHistoryApiChunk, setRemoteHeadResolverForTests } from "../src/lib/history";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

const ROOT = process.cwd();
const src = (p: string) => readFileSync(join(ROOT, p), "utf8");
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function git(cwd: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile("git", args, { cwd }, (err, stdout) => {
      if (err) reject(new Error(`git ${args.join(" ")} failed: ${err.message}`));
      else resolve(stdout.trim());
    });
  });
}

const SHA = "a".repeat(40);

function apiHistoryCursor(): string {
  const data: ScanCursorData = {
    v: 1, owner: "testowner", repo: "testrepo", branch: "main", headSha: SHA,
    stage: "history", historyMethod: "api", histScanned: 0, histResumeAfter: null,
    histPage: 1, histIdx: 0, histPageShas: [], histDone: false, histStop: null, histNote: null,
  };
  return encodeCursor(data);
}

function gitHistoryCursor(headSha: string): string {
  const data: ScanCursorData = {
    v: 1, owner: "gitowner", repo: "gitrepo", branch: "main", headSha,
    stage: "history", historyMethod: "git", histScanned: 0, histResumeAfter: null,
    histPage: 1, histIdx: 0, histPageShas: [], histDone: false, histStop: null, histNote: null,
  };
  return encodeCursor(data);
}

async function main() {
  // --- 1. Budget arithmetic. ---
  check("API/MCP loop budget is 40 s", API_FAST_PATH_WAIT_MS === 40_000, `${API_FAST_PATH_WAIT_MS} ms`);
  check("report page fast-path constant is untouched at 50 s", FAST_PATH_WAIT_MS === 50_000, `${FAST_PATH_WAIT_MS} ms`);
  // Worst case for one invocation, in ms: the budget, minus the
  // start floor (budget − 21 s, floored at 0), plus a late chunk's
  // worst ~32 s (its uncapped prefix — clone + git.log parse,
  // measured ~29 s locally on vinta/awesome-python — or its 30 s
  // walk budget, plus ~2 s unwind). The floor is budget − 21 s
  // precisely so the total lands at ~53 s for any budget. Must stay
  // under the ~55 s headroom below Vercel's 60 s ceiling.
  const worstCaseMs = (budgetMs: number) =>
    budgetMs - Math.max(0, budgetMs - 21_000) + Math.max(GIT_HISTORY_CHUNK_BUDGET_MS, 29_000) + 2_000;
  for (const b of [10_000, 40_000, 50_000]) {
    check(
      `worst-case invocation stays under the 55 s headroom (budget ${b / 1000} s)`,
      worstCaseMs(b) <= 55_000,
      `${worstCaseMs(b)} ms`,
    );
  }
  // The assemble exemption (section 7) adds a bounded ~2 s tail past
  // the chunk bound — assemble is deadline-capped OSV + scoring, and
  // its deadline has already passed by then, so it returns at once.
  // The full worst case still stays under the 60 s ceiling.
  for (const b of [40_000, 50_000]) {
    check(
      `worst case including the assemble tail stays under 60 s (budget ${b / 1000} s)`,
      worstCaseMs(b) + 2_000 <= 57_000,
      `${worstCaseMs(b) + 2_000} ms`,
    );
  }

  // --- 2. Slow API history: runScanLoop returns partial promptly. ---
  // Every request sleeps 15 s, then 404s. The 2 s loop budget must
  // end the invocation at ~2 s: the HEAD-check fetch aborts at the
  // time left, and the list fetch never starts (no time left).
  // Pre-fix this took 12 s + 12 s of per-fetch aborts, then threw.
  const slowApiServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    const timer = setTimeout(() => {
      if (!res.writableEnded) {
        res.statusCode = 404;
        res.end("not found");
      }
    }, 15_000);
    req.on("close", () => clearTimeout(timer));
  });
  await new Promise<void>((resolve) => slowApiServer.listen(0, "127.0.0.1", resolve));
  const slowApiBase = `http://127.0.0.1:${(slowApiServer.address() as { port: number }).port}`;
  try {
    const t0 = Date.now();
    const loop = await runScanLoop("testowner", "testrepo", {
      cursor: apiHistoryCursor(),
      apiBase: slowApiBase,
      budgetMs: 2000,
    });
    const elapsed = Date.now() - t0;
    check("slow API history: loop returns partial, never throws", loop.status === "partial" && !!loop.cursor, `status=${loop.status}`);
    check("slow API history: loop returns within budget + small unwind", elapsed < 8000, `${elapsed} ms for a 2000 ms budget`);
    if (loop.status === "partial" && loop.cursor) {
      const decoded = decodeCursor(loop.cursor, "testowner", "testrepo");
      check("slow API history: cursor still at the unscanned commit", decoded.stage === "history" && decoded.histPage === 1 && decoded.histIdx === 0, `stage=${decoded.stage} page=${decoded.histPage} idx=${decoded.histIdx}`);
      check("slow API history: partial carries the 202 shape (progress, no report)", loop.partial != null && loop.progress != null, `partial=${!!loop.partial}`);
    }
  } finally {
    await new Promise<void>((resolve) => slowApiServer.close(() => resolve()));
  }

  // --- 3. API chunk deadline unit. ---
  const slowApiServer2 = createServer((req: IncomingMessage, res: ServerResponse) => {
    const timer = setTimeout(() => {
      if (!res.writableEnded) {
        res.statusCode = 404;
        res.end("not found");
      }
    }, 15_000);
    req.on("close", () => clearTimeout(timer));
  });
  await new Promise<void>((resolve) => slowApiServer2.listen(0, "127.0.0.1", resolve));
  const slowApiBase2 = `http://127.0.0.1:${(slowApiServer2.address() as { port: number }).port}`;
  try {
    const t0 = Date.now();
    const past = await scanHistoryApiChunk("testowner", "testrepo", "main", { page: 1, idx: 0, pageShas: [] }, 10, {
      apiBase: slowApiBase2, expectedHeadSha: SHA, deadlineMs: Date.now() - 1000,
    });
    check("API chunk with a past deadline returns at once, same position, never failed", Date.now() - t0 < 1000 && !past.failed && !past.done && past.nextPage === 1 && past.nextIdx === 0, `${Date.now() - t0} ms failed=${past.failed}`);
    const t1 = Date.now();
    const soon = await scanHistoryApiChunk("testowner", "testrepo", "main", { page: 1, idx: 0, pageShas: [] }, 10, {
      apiBase: slowApiBase2, expectedHeadSha: SHA, deadlineMs: Date.now() + 100,
    });
    check("API chunk with a 100 ms deadline returns promptly, never failed", Date.now() - t1 < 5000 && !soon.failed && !soon.done, `${Date.now() - t1} ms failed=${soon.failed}`);
  } finally {
    await new Promise<void>((resolve) => slowApiServer2.close(() => resolve()));
  }

  // --- 4. Slow git clone: the clone aborts at the loop deadline. ---
  const startGitSmartHttp = (root: string, stallUploadPackMs: number) =>
    createServer((req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const handle = async () => {
        if (req.method === "POST" && url.pathname.endsWith("/git-upload-pack") && stallUploadPackMs > 0) {
          // The slow-pack stall: the clone's upload-pack POST hangs.
          // Abort the stall early if the client goes away (its
          // deadline fired) so the server does not hold the test.
          const stalled = await new Promise<boolean>((resolve) => {
            const t = setTimeout(() => resolve(true), stallUploadPackMs);
            req.on("close", () => {
              clearTimeout(t);
              resolve(false);
            });
          });
          if (!stalled || req.destroyed || res.writableEnded) return;
        }
        const child = spawn("git", ["http-backend"], {
          env: {
            ...process.env,
            GIT_PROJECT_ROOT: root,
            GIT_HTTP_EXPORT_ALL: "1",
            PATH_INFO: url.pathname,
            QUERY_STRING: url.search.slice(1),
            REQUEST_METHOD: req.method ?? "GET",
            CONTENT_TYPE: (req.headers["content-type"] as string) ?? "",
            CONTENT_LENGTH: (req.headers["content-length"] as string) ?? "",
            REMOTE_ADDR: "127.0.0.1",
          },
        });
        let headerDone = false;
        let headerBuf = Buffer.alloc(0);
        child.stdout.on("data", (chunk: Buffer) => {
          if (headerDone) {
            res.write(chunk);
            return;
          }
          headerBuf = Buffer.concat([headerBuf, chunk]);
          const idx = headerBuf.indexOf("\r\n\r\n");
          if (idx >= 0) {
            for (const line of headerBuf.subarray(0, idx).toString("utf8").split("\r\n")) {
              const m = /^([^:]+):\s*(.*)$/.exec(line);
              if (!m) continue;
              if (m[1].toLowerCase() === "status") res.statusCode = parseInt(m[2], 10);
              else res.setHeader(m[1], m[2]);
            }
            headerDone = true;
            res.write(headerBuf.subarray(idx + 4));
          }
        });
        child.stdout.on("end", () => res.end());
        child.stderr.on("data", () => undefined);
        child.on("error", () => {
          if (!res.headersSent) res.statusCode = 500;
          res.end();
        });
        req.pipe(child.stdin);
      };
      void handle();
    });

  const gitRoot = await mkdtemp(join(tmpdir(), "gitsecure-phase16-git-"));
  const gitRepo = join(gitRoot, "repo");
  try {
    await git(gitRoot, ["init", "-b", "main", "repo"]);
    await git(gitRepo, ["config", "user.email", "test@example.com"]);
    await git(gitRepo, ["config", "user.name", "GitSecure Test"]);
    await writeFile(join(gitRepo, "app.js"), "module.exports = {};\n");
    await git(gitRepo, ["add", "."]);
    await git(gitRepo, ["commit", "-m", "first"]);
    await writeFile(join(gitRepo, "notes.txt"), "unrelated change\n");
    await git(gitRepo, ["add", "."]);
    await git(gitRepo, ["commit", "-m", "second"]);
    await writeFile(join(gitRepo, "notes.txt"), "another change\n");
    await git(gitRepo, ["add", "."]);
    await git(gitRepo, ["commit", "-m", "third"]);
    const tipSha = await git(gitRepo, ["rev-parse", "HEAD"]);

    const gitServer = startGitSmartHttp(gitRoot, 30_000);
    await new Promise<void>((resolve) => gitServer.listen(0, "127.0.0.1", resolve));
    const gitBase = `http://127.0.0.1:${(gitServer.address() as { port: number }).port}/repo`;
    // The git path's fallback (clone aborted) is the API chunk — it
    // gets the same sleeping mock, and with no time left it returns
    // its position at once instead of fetching.
    const slowApiServer3 = createServer((req: IncomingMessage, res: ServerResponse) => {
      const timer = setTimeout(() => {
        if (!res.writableEnded) {
          res.statusCode = 404;
          res.end("not found");
        }
      }, 15_000);
      req.on("close", () => clearTimeout(timer));
    });
    await new Promise<void>((resolve) => slowApiServer3.listen(0, "127.0.0.1", resolve));
    const slowApiBase3 = `http://127.0.0.1:${(slowApiServer3.address() as { port: number }).port}`;
    try {
      const t0 = Date.now();
      const loop = await runScanLoop("gitowner", "gitrepo", {
        cursor: gitHistoryCursor(tipSha),
        cloneUrlOverride: gitBase,
        apiBase: slowApiBase3,
        budgetMs: 2000,
      });
      const elapsed = Date.now() - t0;
      check("slow git clone: loop returns partial, never throws", loop.status === "partial" && !!loop.cursor, `status=${loop.status}`);
      check("slow git clone: loop returns within budget + small unwind", elapsed < 10_000, `${elapsed} ms for a 2000 ms budget (30 s stalled clone)`);
      if (loop.status === "partial" && loop.cursor) {
        const decoded = decodeCursor(loop.cursor, "gitowner", "gitrepo");
        check("slow git clone: cursor stays at the history stage", decoded.stage === "history", `stage=${decoded.stage}`);
      }
    } finally {
      await new Promise<void>((resolve) => slowApiServer3.close(() => resolve()));
      await new Promise<void>((resolve) => gitServer.close(() => resolve()));
    }
  } finally {
    await rm(gitRoot, { recursive: true, force: true }).catch(() => undefined);
  }

  // --- 5. Fast path still completes end to end. ---
  // Stubbed fetch serves a 1-file fake tarball and answers the
  // assemble step's HEAD check; the fast mock API serves 1 commit.
  // Zero deps, so no OSV network. The loop must finish (done) —
  // the deadline threading must not break a small repo answering
  // in one call.
  const fastApiServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    if (url.pathname === "/repos/testowner/testrepo/commits") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify([{ sha: SHA }]));
      return;
    }
    const detailM = /^\/repos\/testowner\/testrepo\/commits\/([0-9a-f]+)$/.exec(url.pathname);
    if (detailM) {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ sha: SHA, files: [] }));
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  });
  await new Promise<void>((resolve) => fastApiServer.listen(0, "127.0.0.1", resolve));
  const fastApiBase = `http://127.0.0.1:${(fastApiServer.address() as { port: number }).port}`;
  const realFetch = globalThis.fetch;
  setRemoteHeadResolverForTests(async () => ({ ok: true, branch: "main", headSha: SHA, gitRequests: 0 }));
  const fakeTarball = (): Buffer => {
    const header = Buffer.alloc(512);
    header.write("a.txt", 0, "utf8");
    header.write("00000000005\0", 124, "ascii"); // size 5, octal
    header.write("0", 156, "ascii"); // regular file
    const data = Buffer.alloc(512);
    data.write("hello", 0, "utf8");
    const end = Buffer.alloc(1024); // end-of-archive zero blocks
    return gzipSync(Buffer.concat([header, data, end]));
  };
  const stubFetch = (async (url: unknown, init?: unknown): Promise<Response> => {
    const u = String(url);
    if (u.includes("codeload.github.com")) {
      return new Response(fakeTarball() as unknown as BodyInit, { status: 200, headers: { "Content-Type": "application/gzip" } });
    }
    // The assemble step's HEAD check only. Note the trailing "&":
    // "per_page=1" alone would also match the history list's
    // "per_page=100" and answer it with one sha (the list would
    // then look complete while the detail fetch threw).
    if (u.includes("/repos/testowner/testrepo/commits?per_page=1&")) {
      return new Response(JSON.stringify([{ sha: SHA }]), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    // Everything else (the mock API server, the git clone attempt)
    // goes to the real fetch.
    return realFetch(url as string, init as RequestInit);
  }) as typeof fetch;
  try {
    (globalThis as { fetch: typeof fetch }).fetch = stubFetch;
    const t0 = Date.now();
    const done = await runScanLoop("testowner", "testrepo", { apiBase: fastApiBase, budgetMs: 10_000 });
    const elapsed = Date.now() - t0;
    check("fast path: loop still finishes in one call", done.status === "done" && !!done.report, `status=${done.status}`);
    if (done.status === "done" && done.report) {
      check("fast path: report covers the 1 file + 1 commit", done.report.counts.filesScanned === 1 && done.report.counts.historyCommitsScanned === 1, `files=${done.report.counts.filesScanned} hist=${done.report.counts.historyCommitsScanned}`);
      check("fast path: finishes well inside the budget", elapsed < 10_000, `${elapsed} ms`);
    }
  } finally {
    (globalThis as { fetch: typeof fetch }).fetch = realFetch;
    setRemoteHeadResolverForTests(null);
    await new Promise<void>((resolve) => fastApiServer.close(() => resolve()));
  }

  // --- 7. Assemble is exempt from the start floor. ---
  // Same fast mocks as section 5, but the mock API answers slowly,
  // so the history chunk finishes (and assemble starts) after the
  // loop's 21 s start floor. Without the exemption the loop would
  // answer partial here; with it the scan finishes in one call and
  // the report keeps every finding. Budget is the production 40 s.
  // The delay is split 11 s + 11 s across the list and detail
  // fetches because each API fetch aborts at 12 s
  // (API_FETCH_TIMEOUT_MS) — a single 22 s sleep would abort.
  const delayedApiServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    const sleepAndAnswer = (ms: number, body: string) => {
      const timer = setTimeout(() => {
        if (!res.writableEnded) {
          res.setHeader("Content-Type", "application/json");
          res.end(body);
        }
      }, ms);
      req.on("close", () => clearTimeout(timer));
    };
    if (url.pathname === "/repos/testowner/testrepo/commits") {
      sleepAndAnswer(11_000, JSON.stringify([{ sha: SHA }]));
      return;
    }
    const detailM = /^\/repos\/testowner\/testrepo\/commits\/([0-9a-f]+)$/.exec(url.pathname);
    if (detailM) {
      sleepAndAnswer(11_000, JSON.stringify({ sha: SHA, files: [] }));
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  });
  await new Promise<void>((resolve) => delayedApiServer.listen(0, "127.0.0.1", resolve));
  const delayedApiBase = `http://127.0.0.1:${(delayedApiServer.address() as { port: number }).port}`;
  setRemoteHeadResolverForTests(async () => ({ ok: true, branch: "main", headSha: SHA, gitRequests: 0 }));
  try {
    (globalThis as { fetch: typeof fetch }).fetch = stubFetch;
    const t0 = Date.now();
    const done = await runScanLoop("testowner", "testrepo", { apiBase: delayedApiBase, budgetMs: 40_000 });
    const elapsed = Date.now() - t0;
    check("assemble exemption: loop finishes in one call despite history ending after the 21 s floor", done.status === "done" && !!done.report, `status=${done.status} elapsed=${elapsed} ms`);
    if (done.status === "done" && done.report) {
      check("assemble exemption: report covers the 1 file + 1 commit (no findings lost)", done.report.counts.filesScanned === 1 && done.report.counts.historyCommitsScanned === 1, `files=${done.report.counts.filesScanned} hist=${done.report.counts.historyCommitsScanned}`);
      check("assemble exemption: still well under the 60 s ceiling", elapsed < 55_000, `${elapsed} ms`);
    }
  } finally {
    (globalThis as { fetch: typeof fetch }).fetch = realFetch;
    setRemoteHeadResolverForTests(null);
    await new Promise<void>((resolve) => delayedApiServer.close(() => resolve()));
  }

  // --- 6. Contract / source checks. ---
  const route = src("src/app/api/scan/[owner]/[repo]/route.ts");
  check("API route passes the tightened budget", route.includes("API_FAST_PATH_WAIT_MS") && !route.includes("budgetMs: FAST_PATH_WAIT_MS"));
  check("API route still answers 202 with cursor + running status", route.includes("status: 202") && route.includes('status: "running"') && route.includes("cursor: result.cursor"));
  check("API route still answers 200 with the full report when done", route.includes("NextResponse.json(result.report)"));
  const mcp = src("src/lib/mcp.ts");
  check("MCP passes the tightened budget in both tools", (mcp.match(/budgetMs: API_FAST_PATH_WAIT_MS/g) ?? []).length === 2);
  const page = src("src/app/[owner]/[repo]/page.tsx");
  // Worker A's Phase 16 fix landed in this tree: the page no longer
  // awaits the scan server-side at all (it renders the shell and the
  // browser drives chunks). This test only asserts Worker B did not
  // touch it and it uses none of Worker B's budget.
  check("report page does not await runScanLoop (Worker A's fix)", !page.includes("runScanLoop"));
  check("report page uses none of the tightened budget", !page.includes("API_FAST_PATH_WAIT_MS"));
  const chunks = src("src/lib/chunks.ts");
  check("loop passes its deadline into each chunk", chunks.includes("deadlineMs: deadline"));
  check("loop refuses a new chunk under the start floor", chunks.includes("startFloorMs") && chunks.includes("budgetMs - 21_000"));
  check("assemble stage is exempt from the start floor (Phase 16 fix)", chunks.includes('nextStage !== "assemble"'));

  console.log(failures === 0 ? "\nAll Phase 16 Worker B tests passed." : `\n${failures} test(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("Phase 16 Worker B test crashed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
