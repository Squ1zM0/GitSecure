// Phase 9 cursor test. Run: npm run test:cursor-phase9
//
// Proves, mostly with no network:
//   1. Cursors round-trip (encode → decode identical), and bogus cursors
//      (garbage, wrong version, wrong repo, negative/huge numbers,
//      non-object) are rejected with a plain-English ScanError 400 —
//      never a crash, never a stack trace. advanceScan answers the
//      same 400 for a bogus cursor.
//   2. A scan interrupted mid-history RESUMES and produces the
//      identical final findings to an uninterrupted scan — on both
//      history paths, with all server state dropped between chunks
//      (clearHistoryCache between git chunks; the API chunks are pure
//      functions of the cursor state):
//        (a) API path: mock GitHub API, 3 commits, paginated list,
//            chunk size 1 — findings + commitsScanned match the
//            uninterrupted scanHistoryViaApi exactly.
//        (b) Git path: real smart-HTTP fixture repo, 3 commits, chunk
//            size 1 — findings + commitsScanned match the
//            uninterrupted scanHistoryViaGit exactly.
//   3. API chunking survives a rate limit mid-history (cursor points
//      at the rate-limited commit; a later chunk retries it), skips a
//      commit whose detail fetch fails (skipped: 1, scan moves on),
//      and reports a moved HEAD (headMoved) instead of scanning stale
//      history. Git chunking reports headMoved for a resume point no
//      longer in the log.
//   4. Assemble (synthetic HEAD partial, zero deps so no OSV network):
//      the finished report's counts/score match the inputs exactly,
//      and a stopped-early history is labelled incomplete, never
//      presented as complete.
//   5. A second page-load resumes from saved progress: the
//      sessionStorage helpers round-trip, reject malformed storage,
//      and the resume line names the exact counts so far.
//   6. The provisional HEAD report is labelled provisional, scores
//      HEAD-only, and says history is still scanning (or done).
//   7. buildLimits copy (moved from the Phase 8 jobs test): a complete
//      scan says so once with exact counts and no cap language; a
//      partial scan states exactly what it could not cover.
//   8. Source checks: no jobs imports remain, the "no longer running"
//      dead-end copy is gone, the chunk endpoint exists, and the
//      cursor protocol is documented in README.md.
//   9. Phase 15 (finding 1): a fetch timeout inside the HEAD chunk
//      returns a partial cursor (stage "head") instead of throwing —
//      so ScanProgress mounts and the resume path engages. Mocked at
//      the chunk-driver level: the repo-info and HEAD-sha fetches
//      answer, the tarball body stream aborts mid-download — no live
//      100k-file repo involved. And a timeout before the HEAD meta is
//      known still throws (nothing scanned yet, nothing to resume).
//
// The fake secrets below are assembled from fragments (never a literal
// secret-pattern string in this file), as in test-scanner.ts.

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { execFile, spawn } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { gzipSync } from "node:zlib";
import { decodeCursor, encodeCursor, initialHistoryCursor, type ScanCursorData } from "../src/lib/cursor";
import { advanceScan, runScanLoop } from "../src/lib/chunks";
import { assembleReport, buildLimits } from "../src/lib/scan";
import { scanHistoryViaApi, scanHistoryViaGit, clearHistoryCache, scanHistoryApiChunk, setRemoteHeadResolverForTests } from "../src/lib/history";
import { buildProvisionalReport } from "../src/lib/provisional";
import { loadProgress, loadReport, resumedLine, saveProgress, saveReport, type ProgressStorage } from "../src/lib/resume";
import { ScanError } from "../src/lib/scan";
import { leaksSecret } from "../src/lib/redact";
import { computeScore } from "../src/lib/score";
import type { HeadPartial, SecretFinding } from "../src/lib/types";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

const ROOT = process.cwd();
const src = (p: string) => readFileSync(join(ROOT, p), "utf8");
const FAKE = "FAKE";

function git(cwd: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile("git", args, { cwd }, (err, stdout) => {
      if (err) reject(new Error(`git ${args.join(" ")} failed: ${err.message}`));
      else resolve(stdout.trim());
    });
  });
}

function sortFindings(list: SecretFinding[]): SecretFinding[] {
  return [...list].sort((a, b) =>
    `${a.type}:${a.file}:${a.line}:${a.commit}`.localeCompare(`${b.type}:${b.file}:${b.line}:${b.commit}`),
  );
}

async function main() {
  // --- 1. Cursor round-trip + bogus cursors. ---
  const headSha = "a".repeat(40);
  const cursorData: ScanCursorData = {
    v: 1, owner: "testowner", repo: "testrepo", branch: "main", headSha,
    stage: "history", historyMethod: "api", histScanned: 2,
    histResumeAfter: null, histPage: 1, histIdx: 1,
    histPageShas: ["b".repeat(40)], histDone: false, histStop: null, histNote: null,
  };
  const encoded = encodeCursor(cursorData);
  const decoded = decodeCursor(encoded, "testowner", "testrepo");
  check("cursor round-trips exactly", JSON.stringify(decoded) === JSON.stringify(cursorData));
  check("cursor is base64url (no +/= padding in the middle)", /^[A-Za-z0-9_-]+$/.test(encoded));
  check("initial history cursor starts at stage history, page 1", (() => {
    const c = initialHistoryCursor({ owner: "o", repo: "r", branch: "main", headSha, historyMethod: "git" });
    return c.stage === "history" && c.histPage === 1 && c.histScanned === 0 && c.histDone === false;
  })());

  const bogus: [string, string][] = [
    ["garbage, not base64", "!!!not-a-cursor!!!"],
    ["valid base64, not JSON", Buffer.from("hello world", "utf8").toString("base64url")],
    ["JSON array, not object", Buffer.from("[1,2,3]", "utf8").toString("base64url")],
    ["wrong version", Buffer.from(JSON.stringify({ ...cursorData, v: 2 }), "utf8").toString("base64url")],
    ["wrong owner", Buffer.from(JSON.stringify({ ...cursorData, owner: "someoneelse" }), "utf8").toString("base64url")],
    ["negative page", Buffer.from(JSON.stringify({ ...cursorData, histPage: -1 }), "utf8").toString("base64url")],
    ["huge page", Buffer.from(JSON.stringify({ ...cursorData, histPage: 999999999 }), "utf8").toString("base64url")],
    ["negative scanned count", Buffer.from(JSON.stringify({ ...cursorData, histScanned: -5 }), "utf8").toString("base64url")],
    ["short head sha", Buffer.from(JSON.stringify({ ...cursorData, headSha: "abc" }), "utf8").toString("base64url")],
    ["bad stage", Buffer.from(JSON.stringify({ ...cursorData, stage: "explode" }), "utf8").toString("base64url")],
    ["101 page shas", Buffer.from(JSON.stringify({ ...cursorData, histPageShas: Array.from({ length: 101 }, () => "c".repeat(40)) }), "utf8").toString("base64url")],
    ["empty string", ""],
  ];
  for (const [label, raw] of bogus) {
    let threw: unknown = null;
    try {
      decodeCursor(raw, "testowner", "testrepo");
    } catch (e) {
      threw = e;
    }
    check(
      `bogus cursor (${label}) → plain-English 400, no crash`,
      threw instanceof ScanError && threw.status === 400 && /doesn't look right|fresh scan/i.test(threw.message),
      threw instanceof Error ? threw.message : String(threw),
    );
  }
  // advanceScan answers the same 400 for a bogus cursor (no network).
  let advanceThrew: unknown = null;
  try {
    await advanceScan({ owner: "testowner", repo: "testrepo", cursor: "!!!not-a-cursor!!!" });
  } catch (e) {
    advanceThrew = e;
  }
  check(
    "advanceScan with a bogus cursor → ScanError 400, never a crash",
    advanceThrew instanceof ScanError && advanceThrew.status === 400,
    advanceThrew instanceof Error ? advanceThrew.message : String(advanceThrew),
  );

  // --- 2a. API path: interrupted mid-history resumes identically. ---
  const SHA_OLD = "1111111111111111111111111111111111111111";
  const SHA_MID = "2222222222222222222222222222222222222222";
  const SHA_NEW = "3333333333333333333333333333333333333333";
  // Realistic GitHub pagination at per_page=100: full pages except the
  // last, so page 1 holds 100 SHAs (NEW, MID + 98 fillers) and page 2
  // holds the oldest commit. A short non-last page never happens on
  // the real API, so the chunker's "short page = last page" rule holds.
  const fillSha = (i: number) => "e".repeat(38) + i.toString(16).padStart(2, "0");
  const page1Shas = [SHA_NEW, SHA_MID, ...Array.from({ length: 98 }, (_, i) => fillSha(i))];
  const fakeWebhookApi =
    "https://discord.com/api/webhooks/" + "987654321098765432/" + FAKE.repeat(6) + "123456";
  const apiServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    const base = `http://${req.headers.host}`;
    if (url.pathname === "/repos/testowner/testrepo/commits") {
      const page = url.searchParams.get("page") ?? "1";
      const perPage = url.searchParams.get("per_page") ?? "100";
      if (perPage === "1") {
        // HEAD check: newest commit only.
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify([{ sha: SHA_NEW }]));
        return;
      }
      if (page === "1") {
        res.setHeader("Link", `<${base}/repos/testowner/testrepo/commits?per_page=100&sha=main&page=2>; rel="next"`);
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(page1Shas.map((sha) => ({ sha }))));
      } else {
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify([{ sha: SHA_OLD }]));
      }
      return;
    }
    const detailM = /^\/repos\/testowner\/testrepo\/commits\/([0-9a-f]+)$/.exec(url.pathname);
    if (detailM) {
      const sha = detailM[1];
      let files: { filename: string; patch: string }[] = [];
      if (sha === SHA_OLD) {
        files = [{ filename: "app.js", patch: `@@ -0,0 +1,2 @@\n+const HOOK = "${fakeWebhookApi}";\n+module.exports = { HOOK };\n` }];
      } else if (sha === SHA_MID) {
        files = [{ filename: "notes.txt", patch: "@@ -1,1 +1,2 @@\n context\n+unrelated change\n" }];
      } else if (sha === SHA_NEW) {
        files = [{ filename: "app.js", patch: `@@ -1,2 +1,1 @@\n-const HOOK = "${fakeWebhookApi}";\n-module.exports = { HOOK };\n+module.exports = {};\n` }];
      }
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ sha, files }));
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  });
  await new Promise<void>((resolve) => apiServer.listen(0, "127.0.0.1", resolve));
  const apiBase = `http://127.0.0.1:${(apiServer.address() as { port: number }).port}`;
  try {
    // Uninterrupted whole-API scan (the reference result).
    const whole = await scanHistoryViaApi("testowner", "testrepo", "main", { apiBase });
    check("API reference scan succeeds", whole.ok && whole.commitsScanned === 101, `${whole.commitsScanned} scanned`);

    // Chunked scan, one commit per chunk, no shared state between chunks.
    let state = { page: 1, idx: 0, pageShas: [] as string[] };
    let chunkedFindings: SecretFinding[] = [];
    let chunkedScanned = 0;
    let done = false;
    let chunks = 0;
    while (!done && chunks < 150) {
      chunks++;
      const chunk = await scanHistoryApiChunk("testowner", "testrepo", "main", state, 1, { apiBase, expectedHeadSha: SHA_NEW });
      check(`API chunk ${chunks} does not fail`, !chunk.failed && !chunk.rateLimited && !chunk.headMoved, chunk.note ?? "");
      chunkedFindings = [...chunkedFindings, ...chunk.findings];
      chunkedScanned += chunk.commitsScanned;
      state = { page: chunk.nextPage, idx: chunk.nextIdx, pageShas: chunk.nextPageShas };
      done = chunk.done;
    }
    check("API chunked scan finishes in 101 chunks (100 + 1 across pages)", done && chunks === 101, `${chunks} chunks`);
    check("API chunked scan covers all 101 commits", chunkedScanned === 101, `${chunkedScanned} scanned`);
    check(
      "API chunked findings are IDENTICAL to the uninterrupted scan",
      JSON.stringify(sortFindings(chunkedFindings)) === JSON.stringify(sortFindings(whole.findings)),
      `${chunkedFindings.length} vs ${whole.findings.length} findings`,
    );
    check("no full fake secret in API chunked findings", !leaksSecret(JSON.stringify(chunkedFindings), fakeWebhookApi));

    // Rate limit mid-history: chunk 1 hits the limit on MID, chunk 2
    // (limit lifted) retries MID, chunk 3 scans OLD. The cursor points
    // at the rate-limited commit — nothing is skipped, nothing repeats.
    let midAttempts = 0;
    const rlServer = createServer((req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
      if (url.pathname === "/repos/testowner/testrepo/commits") {
        if (url.searchParams.get("per_page") === "1") {
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify([{ sha: SHA_MID }]));
          return;
        }
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify([{ sha: SHA_MID }, { sha: SHA_OLD }]));
        return;
      }
      const m = /^\/repos\/testowner\/testrepo\/commits\/([0-9a-f]+)$/.exec(url.pathname);
      if (m) {
        if (m[1] === SHA_MID) {
          midAttempts++;
          if (midAttempts === 1) {
            res.statusCode = 403;
            res.setHeader("x-ratelimit-remaining", "0");
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ message: "API rate limit exceeded" }));
            return;
          }
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ sha: SHA_MID, files: [{ filename: "notes.txt", patch: "@@ -1,1 +1,2 @@\n context\n+unrelated change\n" }] }));
          return;
        }
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ sha: SHA_OLD, files: [{ filename: "app.js", patch: `@@ -0,0 +1,1 @@\n+const HOOK = "${fakeWebhookApi}";\n` }] }));
        return;
      }
      res.statusCode = 404;
      res.end("not found");
    });
    await new Promise<void>((resolve) => rlServer.listen(0, "127.0.0.1", resolve));
    const rlBase = `http://127.0.0.1:${(rlServer.address() as { port: number }).port}`;
    try {
      let rlState = { page: 1, idx: 0, pageShas: [] as string[] };
      const rl1 = await scanHistoryApiChunk("testowner", "testrepo", "main", rlState, 1, { apiBase: rlBase, expectedHeadSha: SHA_MID });
      check("rate-limit chunk reports rateLimited, not failed", rl1.rateLimited && !rl1.failed, `rateLimited=${rl1.rateLimited} failed=${rl1.failed}`);
      check("rate-limit chunk's cursor still points at the limited commit", rl1.nextIdx === 0 && rl1.commitsScanned === 0, `nextIdx=${rl1.nextIdx} scanned=${rl1.commitsScanned}`);
      rlState = { page: rl1.nextPage, idx: rl1.nextIdx, pageShas: rl1.nextPageShas };
      const rl2 = await scanHistoryApiChunk("testowner", "testrepo", "main", rlState, 1, { apiBase: rlBase, expectedHeadSha: SHA_MID });
      check("retry chunk after the limit scans the commit", !rl2.rateLimited && rl2.commitsScanned === 1, `scanned=${rl2.commitsScanned}`);
      rlState = { page: rl2.nextPage, idx: rl2.nextIdx, pageShas: rl2.nextPageShas };
      const rl3 = await scanHistoryApiChunk("testowner", "testrepo", "main", rlState, 1, { apiBase: rlBase, expectedHeadSha: SHA_MID });
      check("third chunk finishes the history", rl3.done && rl3.commitsScanned === 1, `done=${rl3.done}`);
      check("rate-limit resume still finds the old-commit webhook once", [...rl2.findings, ...rl3.findings].filter((f) => f.type === "discord-webhook").length === 1);
    } finally {
      await new Promise<void>((resolve) => rlServer.close(() => resolve()));
    }

    // A commit whose detail fetch fails (500) is skipped and counted,
    // and the chunk moves on — no stall, no crash.
    const skipServer = createServer((req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
      if (url.pathname === "/repos/testowner/testrepo/commits") {
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify([{ sha: SHA_MID }, { sha: SHA_OLD }]));
        return;
      }
      const m = /^\/repos\/testowner\/testrepo\/commits\/([0-9a-f]+)$/.exec(url.pathname);
      if (m) {
        if (m[1] === SHA_MID) {
          res.statusCode = 500;
          res.end("boom");
          return;
        }
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ sha: SHA_OLD, files: [{ filename: "app.js", patch: `@@ -0,0 +1,1 @@\n+const HOOK = "${fakeWebhookApi}";\n` }] }));
        return;
      }
      res.statusCode = 404;
      res.end("not found");
    });
    await new Promise<void>((resolve) => skipServer.listen(0, "127.0.0.1", resolve));
    const skipBase = `http://127.0.0.1:${(skipServer.address() as { port: number }).port}`;
    try {
      const s1 = await scanHistoryApiChunk("testowner", "testrepo", "main", { page: 1, idx: 0, pageShas: [] }, 1, { apiBase: skipBase });
      check("failed commit is skipped and counted (skipped 1, scanned 0)", s1.skipped === 1 && s1.commitsScanned === 0, `skipped=${s1.skipped} scanned=${s1.commitsScanned}`);
      check("failed commit does not stall the chunk (cursor advances)", s1.nextIdx === 1, `nextIdx=${s1.nextIdx}`);
      const s2 = await scanHistoryApiChunk("testowner", "testrepo", "main", { page: s1.nextPage, idx: s1.nextIdx, pageShas: s1.nextPageShas }, 1, { apiBase: skipBase });
      check("chunk after the skip still finds the webhook and finishes", s2.done && s2.findings.some((f) => f.type === "discord-webhook"), `done=${s2.done}`);
    } finally {
      await new Promise<void>((resolve) => skipServer.close(() => resolve()));
    }

    // Moved HEAD: the expected sha is not the branch tip.
    const moved = await scanHistoryApiChunk("testowner", "testrepo", "main", { page: 1, idx: 0, pageShas: [] }, 1, { apiBase, expectedHeadSha: "a".repeat(40) });
    check("API chunk with a moved HEAD reports headMoved, not findings", moved.headMoved && moved.findings.length === 0, `headMoved=${moved.headMoved}`);
  } finally {
    await new Promise<void>((resolve) => apiServer.close(() => resolve()));
  }

  // --- 2b. Git path: interrupted mid-history resumes identically. ---
  const startGitSmartHttp = (root: string) =>
    createServer((req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
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
    });

  clearHistoryCache();
  const gitRoot = await mkdtemp(join(tmpdir(), "gitsecure-cursor-git-"));
  const gitRepo = join(gitRoot, "repo");
  try {
    await git(gitRoot, ["init", "-b", "main", "repo"]);
    await git(gitRepo, ["config", "user.email", "test@example.com"]);
    await git(gitRepo, ["config", "user.name", "GitSecure Test"]);
    const fakeWebhookGit =
      "https://discord.com/api/webhooks/" + "555555555555555555/" + FAKE.repeat(6) + "123456";
    await writeFile(join(gitRepo, "app.js"), `const HOOK = "${fakeWebhookGit}";\nmodule.exports = { HOOK };\n`);
    await git(gitRepo, ["add", "."]);
    await git(gitRepo, ["commit", "-m", "add webhook (bad idea)"]);
    const gitOldSha = await git(gitRepo, ["rev-parse", "--short=7", "HEAD"]);
    await writeFile(join(gitRepo, "app.js"), "module.exports = {};\n");
    await git(gitRepo, ["add", "."]);
    await git(gitRepo, ["commit", "-m", "remove webhook"]);
    await writeFile(join(gitRepo, "notes.txt"), "unrelated change\n");
    await git(gitRepo, ["add", "."]);
    await git(gitRepo, ["commit", "-m", "notes"]);

    const gitServer = startGitSmartHttp(gitRoot);
    await new Promise<void>((resolve) => gitServer.listen(0, "127.0.0.1", resolve));
    const gitBase = `http://127.0.0.1:${(gitServer.address() as { port: number }).port}/repo`;
    try {
      // Uninterrupted reference: full git walk.
      clearHistoryCache();
      const whole = await scanHistoryViaGit("gitowner", "gitrepo", "main", { cloneUrlOverride: gitBase });
      check("git reference scan succeeds, all 3 commits", whole.ok && whole.commitsScanned === 3, `${whole.commitsScanned} scanned`);

      // Chunked: one commit per chunk, cache dropped between chunks —
      // the "server restarted" simulation. No chunk may depend on the
      // previous chunk's in-memory state.
      clearHistoryCache();
      let resumeAfter: string | null = null;
      let chunkedFindings: SecretFinding[] = [];
      let chunkedScanned = 0;
      let complete = false;
      let chunks = 0;
      while (!complete && chunks < 10) {
        chunks++;
        clearHistoryCache(); // simulate a fresh serverless instance
        const chunk = await scanHistoryViaGit("gitowner", "gitrepo", "main", {
          cloneUrlOverride: gitBase,
          resumeAfterSha: resumeAfter,
          maxCommits: 1,
        });
        check(`git chunk ${chunks} succeeds`, chunk.ok, chunk.note ?? "");
        chunkedFindings = [...chunkedFindings, ...chunk.findings];
        chunkedScanned += chunk.commitsFetched;
        resumeAfter = chunk.lastScannedSha ?? resumeAfter;
        complete = chunk.complete ?? false;
      }
      check("git chunked scan finishes in 3 chunks", complete && chunks === 3, `${chunks} chunks`);
      check("git chunked scan covers all 3 commits", chunkedScanned === 3, `${chunkedScanned} scanned`);
      check(
        "git chunked findings are IDENTICAL to the uninterrupted scan",
        JSON.stringify(sortFindings(chunkedFindings)) === JSON.stringify(sortFindings(whole.findings)),
        `${chunkedFindings.length} vs ${whole.findings.length} findings`,
      );
      check("git chunked scan finds the old-commit webhook once", chunkedFindings.filter((f) => f.type === "discord-webhook").length === 1);
      check("git chunked finding attributed to the old commit", chunkedFindings.find((f) => f.type === "discord-webhook")?.commit === gitOldSha);
      check("no full fake secret in git chunked findings", !leaksSecret(JSON.stringify(chunkedFindings), fakeWebhookGit));

      // Resume point no longer in the log → headMoved, never a crash.
      clearHistoryCache();
      const moved = await scanHistoryViaGit("gitowner", "gitrepo", "main", {
        cloneUrlOverride: gitBase,
        resumeAfterSha: "f".repeat(40),
        maxCommits: 1,
      });
      check("git chunk with a vanished resume point reports headMoved", !moved.ok && moved.headMoved === true, `ok=${moved.ok} headMoved=${moved.headMoved}`);
    } finally {
      await new Promise<void>((resolve) => gitServer.close(() => resolve()));
    }
  } finally {
    await rm(gitRoot, { recursive: true, force: true }).catch(() => undefined);
  }

  // --- 4. Assemble (synthetic HEAD, zero deps → no OSV network). ---
  const headFinding: SecretFinding = {
    id: "s1", type: "discord-webhook", title: "Discord webhook", severity: "critical",
    confidence: "high", file: "app.js", line: 1, commit: "HEAD",
    fragment: "http…56", fix: "Rotate the webhook.", plainEnglish: "A Discord webhook URL is committed.",
  };
  const historyFinding: SecretFinding = { ...headFinding, id: "s2", commit: "abcdef0" };
  const head: HeadPartial = {
    owner: "testowner", repo: "testrepo", branch: "main", headSha: "a".repeat(40),
    filesScanned: 3, filesTotal: 3, treeTruncated: false, tarballFallback: false,
    secrets: [headFinding], frameworks: [], dependencies: [],
    posture: [{ id: "no-security-md", title: "No SECURITY.md", severity: "low", detail: "No SECURITY.md.", fix: "Add one." }],
    unpinnedCount: 0, historyMethod: "git", retainedIncomplete: false,
  };
  const assembled = await assembleReport(head, { findings: [historyFinding], commitsScanned: 3, ok: true, method: "git", note: null });
  check("assembled report counts both HEAD + history secrets", assembled.counts.secrets === 2, `${assembled.counts.secrets}`);
  check("assembled report counts history commits exactly", assembled.counts.historyCommitsScanned === 3, `${assembled.counts.historyCommitsScanned}`);
  const expectedScore = computeScore({ secrets: [headFinding, historyFinding], vulnerabilities: [], posture: head.posture, unpinnedCount: 0 });
  check("assembled score matches the inputs exactly", assembled.score === expectedScore.score && assembled.grade === expectedScore.grade, `${assembled.score}/${assembled.grade}`);
  check("assembled report is not provisional", assembled.provisional !== true);
  check("assembled limits name the history count", assembled.limits.some((l) => l.includes("History checked: 3 commits")), assembled.limits.join(" | "));
  // Stopped-early history is labelled incomplete, never complete.
  const partialAssembled = await assembleReport(head, {
    findings: [historyFinding], commitsScanned: 2, ok: false, method: "api",
    note: "GitHub API rate limit was hit — scanned 2 commits before stopping. Setting a GITHUB_TOKEN raises the limit.",
  });
  check("partial-history report says history is incomplete", partialAssembled.limits.some((l) => l.includes("History incomplete: 2 newest commits")), partialAssembled.limits.join(" | "));
  check("partial-history report carries the rate-limit note", partialAssembled.limits.some((l) => l.includes("rate limit")), partialAssembled.limits.join(" | "));
  check("partial-history report counts only the commits scanned", partialAssembled.counts.historyCommitsScanned === 2, `${partialAssembled.counts.historyCommitsScanned}`);

  // --- 5. Second page-load resumes from saved progress. ---
  class FakeStorage implements ProgressStorage {
    private map = new Map<string, string>();
    getItem(key: string): string | null { return this.map.get(key) ?? null; }
    setItem(key: string, value: string): void { this.map.set(key, value); }
    removeItem(key: string): void { this.map.delete(key); }
  }
  const storage = new FakeStorage();
  check("no saved progress before saving", loadProgress(storage, "testowner", "testrepo") === null);
  saveProgress(storage, "testowner", "testrepo", {
    cursor: encoded, head, historyFindings: [historyFinding], historyScanned: 2,
  });
  const loaded = loadProgress(storage, "testowner", "testrepo");
  check("saved progress round-trips (cursor + counts)", loaded !== null && loaded.cursor === encoded && loaded.historyScanned === 2 && loaded.historyFindings.length === 1);
  storage.setItem("gitsecure:progress:testowner/testrepo", "{not json");
  check("malformed saved progress loads as nothing, never a crash", loadProgress(storage, "testowner", "testrepo") === null);
  storage.setItem("gitsecure:progress:testowner/testrepo", JSON.stringify({ cursor: 42 }));
  check("wrong-shaped saved progress loads as nothing", loadProgress(storage, "testowner", "testrepo") === null);
  check(
    "resume line names the exact counts (singular)",
    resumedLine(1, 1) === "Resumed — picked up where it left off (1 history commit checked, 1 secret found so far).",
    resumedLine(1, 1),
  );
  check(
    "resume line names the exact counts (plural, thousands)",
    resumedLine(1234, 5) === "Resumed — picked up where it left off (1,234 history commits checked, 5 secrets found so far).",
    resumedLine(1234, 5),
  );
  saveReport(storage, "testowner", "testrepo", assembled, "a".repeat(40));
  const loadedReport = loadReport(storage, "testowner", "testrepo");
  check("saved finished report round-trips with its HEAD sha", loadedReport !== null && loadedReport.headSha === "a".repeat(40));

  // --- 6. Provisional HEAD report. ---
  const provisional = buildProvisionalReport(head, [historyFinding], 2, false);
  check("provisional report is flagged provisional", provisional.provisional === true);
  check("provisional score is HEAD-only (no vulnerabilities yet)", provisional.counts.vulnerabilities === 0 && provisional.counts.secrets === 2);
  check("provisional limits say history is still scanning", provisional.limits.some((l) => l.includes("History still scanning: 2 commits")));
  const provisionalDone = buildProvisionalReport(head, [historyFinding], 3, true);
  check("provisional with complete history says so, no still-scanning line", provisionalDone.limits.some((l) => l.includes("History checked: 3 commits")) && !provisionalDone.limits.some((l) => l.includes("still scanning")));

  // --- 7. buildLimits copy (from the Phase 8 jobs test). ---
  const completeLimits = buildLimits({
    filesScanned: 2802, filesTotal: 2802, historyOk: true, historyMethod: "git",
    historyCommitsScanned: 62, historyMs: 4000, historyNote: null,
    depsChecked: 2, depsQueryable: 2, depsTotal: 2, advisoriesTotal: 4, detailCapped: 0,
    treeTruncated: false, tarballFallback: false,
  });
  check("complete scan says so once with exact counts", completeLimits[0].includes("Scanned all 2802 files") && completeLimits[1].includes("History checked: 62 commits"), completeLimits.join(" | "));
  check("complete scan has no cap language", !/cap|limit|truncat/i.test(completeLimits.slice(0, 2).join(" ")), completeLimits.join(" | "));
  const partialLimits = buildLimits({
    filesScanned: 100, filesTotal: 200, historyOk: true, historyMethod: "api",
    historyCommitsScanned: 48, historyMs: 0, historyNote: "GitHub API rate limit was hit — scanned 48 commits before stopping. Setting a GITHUB_TOKEN raises the limit.",
    depsChecked: 1, depsQueryable: 5, depsTotal: 9, advisoriesTotal: 3, detailCapped: 1,
    treeTruncated: true, tarballFallback: true,
  });
  check("partial scan states the un-fetched files exactly", partialLimits.some((l) => l.includes("Fetched 100 of 200 files") && l.includes("100 could not be fetched")));
  check("partial scan states the uncovered deps exactly", partialLimits.some((l) => l.includes("1 of 5 pinned dependencies were checked")));
  check("partial scan states the ID-only advisories exactly", partialLimits.some((l) => l.includes("2 of 3 listed advisories")));
  check("partial scan carries the history note", partialLimits.some((l) => l.includes("rate limit")));
  check("partial scan states the truncated tree", partialLimits.some((l) => l.includes("truncated file tree")));
  check("partial scan states the tarball fallback", partialLimits.some((l) => l.includes("one by one instead")));

  // --- 8. Source checks: the job store is gone, the dead-end is gone. ---
  const srcFiles: string[] = [];
  const { readdirSync, statSync } = await import("node:fs");
  const collect = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) collect(p);
      else if (/\.(ts|tsx)$/.test(name)) srcFiles.push(p);
    }
  };
  collect(join(ROOT, "src"));
  const allSrc = srcFiles.map((f) => readFileSync(f, "utf8")).join("\n");
  check("no jobs imports remain in src", !/from\s+["'][^"']*lib\/jobs["']/.test(allSrc));
  check("no jobs.ts file remains", !existsSync(join(ROOT, "src/lib/jobs.ts")));
  check("no jobs poll route remains", !existsSync(join(ROOT, "src/app/api/scan/jobs")));
  check("the 'no longer running' dead-end copy is gone from src", !/no longer running/i.test(allSrc));
  check("no job-not-found kind remains in src", !/job-not-found/.test(allSrc));
  check("chunk endpoint exists", existsSync(join(ROOT, "src/app/api/scan/chunk/route.ts")));
  check("cursor module exists", existsSync(join(ROOT, "src/lib/cursor.ts")));
  check("chunks driver exists", existsSync(join(ROOT, "src/lib/chunks.ts")));
  check("ScanProgress saves progress in sessionStorage", src("src/components/ScanProgress.tsx").includes("sessionStorage") && src("src/components/ScanProgress.tsx").includes("Resumed"));
  check("ScanProgress shows the resumed line", src("src/components/ScanProgress.tsx").includes("resumedLine"));
  const readme = src("README.md");
  check("README documents the cursor protocol", readme.includes("Scan cursors") && readme.includes("POST /api/scan/chunk"));
  check("README says the server holds no scan state", /no scan state|holds no state/i.test(readme));

  // --- 9. Phase 15 (finding 1): HEAD-chunk fetch timeout → partial cursor. ---
  const SHA_TIMEOUT = "b".repeat(40);
  const realFetch = globalThis.fetch;
  // Phase 15 (worker D): the HEAD meta (branch + HEAD sha) no longer
  // comes from the REST repo-info call — it comes from one
  // git-protocol info/refs request — so the fetch stub below answers
  // ONLY the tarball. The meta is supplied by the test-only resolver
  // override (the mock-git-server equivalent for the driver test:
  // branch main, HEAD sha SHA_TIMEOUT). Any fetch call to a REST URL
  // would throw "unexpected URL" — proving the meta no longer uses
  // fetch at all. The tarball body delivers one real file, then
  // aborts mid-download (the torvalds/linux slow-download-day
  // failure, at the driver level). The one file proves the partial
  // keeps the live progress reached before the stall — it is not
  // just a zeroed placeholder.
  setRemoteHeadResolverForTests(async () => ({ ok: true, branch: "main", headSha: SHA_TIMEOUT, gitRequests: 0 }));
  const fakeTarball = (): Buffer => {
    const header = Buffer.alloc(512);
    header.write("a.txt", 0, "utf8");
    header.write("00000000005\0", 124, "ascii"); // size 5, octal
    header.write("0", 156, "ascii"); // regular file
    const data = Buffer.alloc(512);
    data.write("hello", 0, "utf8");
    // Deliberately NO end-of-archive zero blocks: the parser is still
    // waiting for the next header when the stream aborts, so the
    // abort — not a clean finish — ends the download.
    return gzipSync(Buffer.concat([header, data]));
  };
  const timeoutFetch = (async (url: unknown): Promise<Response> => {
    const u = String(url);
    if (u.includes("codeload.github.com")) {
      const gz = fakeTarball();
      let pulled = 0;
      const body = new ReadableStream({
        pull(controller) {
          if (pulled++ === 0) {
            controller.enqueue(gz);
          } else {
            // The stall comes AFTER the first chunk was delivered
            // and processed — like a real mid-download stall — so
            // the abort must not fire before the loop consumes it.
            // (An immediate abort destroys gunzip while its
            // decompressed output is still buffered, and the file
            // that already arrived is never counted.)
            setTimeout(() => controller.error(new DOMException("The operation was aborted.", "AbortError")), 50);
          }
        },
      });
      return new Response(body, { status: 200, headers: { "Content-Type": "application/gzip" } });
    }
    throw new Error(`timeoutFetch: unexpected URL ${u}`);
  }) as typeof fetch;
  try {
    (globalThis as { fetch: typeof fetch }).fetch = timeoutFetch;
    // Fresh scan (no cursor): timeout → partial, not a throw.
    const t1 = await advanceScan({ owner: "testowner", repo: "testrepo", cursor: null });
    check(
      "HEAD timeout (fresh scan) returns a partial, never throws",
      t1.status === "partial",
      `status=${t1.status}`,
    );
    if (t1.status === "partial") {
      const decoded = decodeCursor(t1.cursor, "testowner", "testrepo");
      check("HEAD-timeout cursor stays at the head stage", decoded.stage === "head", `stage=${decoded.stage}`);
      check("HEAD-timeout cursor pins the HEAD sha the repo reported", decoded.headSha === SHA_TIMEOUT, decoded.headSha);
      check("HEAD-timeout partial has no HEAD yet (nothing half-reported)", t1.partial.head === null);
      check("HEAD-timeout partial says the download timed out", typeof t1.note === "string" && /timed out/i.test(t1.note), t1.note ?? "");
      // Phase 15 (worker D): the stall aborts the whole-buffer
      // download BEFORE any entry is parsed — the download and the
      // parse are separate phases there, so zero files were scanned
      // yet and the partial honestly keeps 0. (The old test forced
      // the streaming transport with a fake 2 GB repo size, where
      // entries are scanned as they arrive and 1 file was counted;
      // the size gate is gone, so a small tarball takes the
      // whole-buffer path and the count is 0. The invariants that
      // matter — partial not throw, head stage, nothing
      // half-reported, timed-out note — all still hold.)
      check("HEAD-timeout partial keeps live progress (0 files scanned before the stall)", t1.progress.step === "files" && t1.progress.filesScanned === 0, `step=${t1.progress.step} files=${t1.progress.filesScanned}`);
    }
    // Same via an explicit head-stage cursor (a client retrying it).
    const headCursor = encodeCursor({
      v: 1, owner: "testowner", repo: "testrepo", branch: "main", headSha: SHA_TIMEOUT,
      stage: "head", historyMethod: "api", histScanned: 0, histResumeAfter: null,
      histPage: 1, histIdx: 0, histPageShas: [], histDone: false, histStop: null, histNote: null,
    });
    const t2 = await advanceScan({ owner: "testowner", repo: "testrepo", cursor: headCursor });
    check(
      "HEAD timeout (head-stage cursor) returns a partial, never throws",
      t2.status === "partial" && decodeCursor(t2.cursor, "testowner", "testrepo").stage === "head",
      `status=${t2.status}`,
    );
    // runScanLoop drives the same path: partial, not a throw.
    const t3 = await runScanLoop("testowner", "testrepo", { budgetMs: 500 });
    check(
      "runScanLoop on a HEAD timeout returns a partial, never throws",
      t3.status === "partial" && !!t3.cursor && decodeCursor(t3.cursor, "testowner", "testrepo").stage === "head",
      `status=${t3.status}`,
    );
  } finally {
    (globalThis as { fetch: typeof fetch }).fetch = realFetch;
    setRemoteHeadResolverForTests(null);
  }
  // Timeout BEFORE the HEAD meta is known (the git-protocol info/refs
  // request itself stalls): still throws — there is no sha to pin a
  // cursor to and nothing was scanned yet. Phase 15 (worker D): the
  // meta step is a git-protocol request now, not a REST fetch, so the
  // stall is scripted through the resolver override (a "timeout"
  // outcome), not a fetch stub — no fetch call is involved at all.
  setRemoteHeadResolverForTests(async () => ({ ok: false, reason: "timeout", gitRequests: 1 }));
  try {
    let earlyThrew: unknown = null;
    try {
      await advanceScan({ owner: "testowner", repo: "testrepo", cursor: null });
    } catch (e) {
      earlyThrew = e;
    }
    check(
      "HEAD timeout before the repo meta is known still throws (ScanError 504 timeout)",
      earlyThrew instanceof ScanError && earlyThrew.kind === "timeout" && earlyThrew.status === 504,
      earlyThrew instanceof Error ? `${earlyThrew.name}: ${earlyThrew.message}` : String(earlyThrew),
    );
  } finally {
    setRemoteHeadResolverForTests(null);
  }

  // --- 9b. Phase 15 (rate-limit recovery): a 429 carries the reset time. ---
  // ghJson reads GitHub's x-ratelimit-reset / retry-after headers onto
  // the ScanError, so the error page can say honestly how long to
  // wait. Mocked at the fetch level — no quota burned, no live 429.
  // Phase 15 (worker D): the repo-info REST call is gone, so the 429
  // is retargeted at the one REST call the HEAD step still makes on
  // failure — the recursive-tree fetch the per-file fallback needs
  // when the tarball is unavailable. The meta comes from the resolver
  // override; the tarball answers 500 so the scan reaches the tree.
  const resetEpoch = Math.floor(Date.now() / 1000) + 600;
  setRemoteHeadResolverForTests(async () => ({ ok: true, branch: "main", headSha: SHA_TIMEOUT, gitRequests: 0 }));
  const rateLimitFetch = (async (url: unknown): Promise<Response> => {
    const u = String(url);
    if (u.includes("codeload.github.com")) {
      return new Response("tarball unavailable", { status: 500 });
    }
    if (u.includes("/repos/testowner/testrepo/git/trees/")) {
      return new Response(JSON.stringify({ message: "API rate limit exceeded" }), {
        status: 429,
        headers: { "Content-Type": "application/json", "x-ratelimit-reset": String(resetEpoch), "x-ratelimit-remaining": "0" },
      });
    }
    throw new Error(`rateLimitFetch: unexpected URL ${u}`);
  }) as typeof fetch;
  try {
    (globalThis as { fetch: typeof fetch }).fetch = rateLimitFetch;
    let rlThrew: unknown = null;
    try {
      await advanceScan({ owner: "testowner", repo: "testrepo", cursor: null });
    } catch (e) {
      rlThrew = e;
    }
    check(
      "429 with x-ratelimit-reset → ScanError 429 carrying the reset time",
      rlThrew instanceof ScanError && rlThrew.kind === "rate-limit" && rlThrew.status === 429 && rlThrew.resetAtMs === resetEpoch * 1000,
      rlThrew instanceof ScanError ? `kind=${rlThrew.kind} resetAtMs=${rlThrew.resetAtMs}` : String(rlThrew),
    );
  } finally {
    (globalThis as { fetch: typeof fetch }).fetch = realFetch;
    setRemoteHeadResolverForTests(null);
  }
  // 429 with no reset headers: still a rate-limit error, reset unknown.
  setRemoteHeadResolverForTests(async () => ({ ok: true, branch: "main", headSha: SHA_TIMEOUT, gitRequests: 0 }));
  const bareRateLimitFetch = (async (url: unknown): Promise<Response> => {
    const u = String(url);
    if (u.includes("codeload.github.com")) {
      return new Response("tarball unavailable", { status: 500 });
    }
    if (u.includes("/repos/testowner/testrepo/git/trees/")) {
      return new Response(JSON.stringify({ message: "API rate limit exceeded" }), { status: 429, headers: { "Content-Type": "application/json" } });
    }
    throw new Error(`bareRateLimitFetch: unexpected URL ${u}`);
  }) as typeof fetch;
  try {
    (globalThis as { fetch: typeof fetch }).fetch = bareRateLimitFetch;
    let bareThrew: unknown = null;
    try {
      await advanceScan({ owner: "testowner", repo: "testrepo", cursor: null });
    } catch (e) {
      bareThrew = e;
    }
    check(
      "429 with no reset headers → ScanError 429, reset time absent (hourly fallback)",
      bareThrew instanceof ScanError && bareThrew.kind === "rate-limit" && bareThrew.resetAtMs === undefined,
      bareThrew instanceof ScanError ? `kind=${bareThrew.kind} resetAtMs=${bareThrew.resetAtMs}` : String(bareThrew),
    );
  } finally {
    (globalThis as { fetch: typeof fetch }).fetch = realFetch;
    setRemoteHeadResolverForTests(null);
  }

  console.log(failures === 0 ? "\nAll cursor (Phase 9) tests passed." : `\n${failures} test(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("Cursor test crashed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
