// Phase 21 (Workstream C) - resume tests. Run: npm run test:phase21-resume
//
// Covers, against local fixture repos served over smart HTTP (never
// live):
//   A. Multi-chunk resume: a chunked scan (maxCommits 3 per chunk,
//      cache dropped between chunks to simulate a fresh serverless
//      instance) returns findings identical to one uninterrupted
//      scan.
//   B. Resume on a 1005-commit fixture: the resume point after the
//      first chunk continues cleanly instead of reporting headMoved.
//      The git path carries no 1000 cap (Phase 8 removed it, pinned
//      by test-history.ts), so the clone is full, not depth-bounded.
//   C. The no-progress loop case: a chunk that times out inside the
//      clone must advance instead of retrying byte-identical. The
//      loop fix lives in chunks.ts (apiChunkResult advances a failed
//      chunk's cursor to assemble); this section runs the scenario
//      black-box (a stalling git server plus a failing API fallback,
//      driven twice through advanceScan with the same cursor) and
//      asserts the returned cursor advanced to assemble.
//
// The fake secrets below are assembled from fragments (never a
// literal secret-pattern string in this file), as in test-scanner.ts
// and test-history.ts.

import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile, spawn } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { scanHistoryViaGit, clearHistoryCache } from "../src/lib/history";
import { advanceScan } from "../src/lib/chunks";
import { encodeCursor, type ScanCursorData } from "../src/lib/cursor";
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
// Webhook URLs assembled from fragments at runtime. The committed
// fixture source contains these values; this file never holds them whole.
const webhookFor = (id18: string) =>
  "https://discord.com/api/webhooks/" + id18 + "/" + FAKE.repeat(6) + "123456";

function gitCmd(cwd: string, args: string[]): Promise<string> {
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

// Same git http-backend bridge as scripts/test-history.ts:
// isomorphic-git cannot clone from a local filesystem path, so the
// fixture repos are served over HTTP by the system git's own CGI
// backend. No api.github.com traffic is involved at any point.
function startGitSmartHttp(root: string) {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
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
}

async function main() {
  // --- A. Multi-chunk resume on a 7-commit fixture. ---
  // Commit 2 plants webhook A (app.js), commit 3 removes it;
  // commit 5 plants webhook B (config.js), commit 6 removes it.
  clearHistoryCache();
  const root = await mkdtemp(join(tmpdir(), "gitsecure-p21-resume-"));
  try {
    const repo = join(root, "repo");
    await gitCmd(root, ["init", "-b", "main", "repo"]);
    await gitCmd(repo, ["config", "user.email", "test@example.com"]);
    await gitCmd(repo, ["config", "user.name", "GitSecure Test"]);
    const fakeA = webhookFor("555555555555555555");
    const fakeB = webhookFor("666666666666666666");
    await writeFile(join(repo, "notes.txt"), "first\n");
    await gitCmd(repo, ["add", "."]);
    await gitCmd(repo, ["commit", "-m", "first"]);
    await writeFile(join(repo, "app.js"), `const HOOK = "${fakeA}";\nmodule.exports = { HOOK };\n`);
    await gitCmd(repo, ["add", "."]);
    await gitCmd(repo, ["commit", "-m", "plant webhook A"]);
    const shaA = await gitCmd(repo, ["rev-parse", "--short=7", "HEAD"]);
    await writeFile(join(repo, "app.js"), "module.exports = {};\n");
    await gitCmd(repo, ["add", "."]);
    await gitCmd(repo, ["commit", "-m", "remove webhook A"]);
    await writeFile(join(repo, "notes2.txt"), "fourth\n");
    await gitCmd(repo, ["add", "."]);
    await gitCmd(repo, ["commit", "-m", "fourth"]);
    await writeFile(join(repo, "config.js"), `const HOOK2 = "${fakeB}";\nmodule.exports = { HOOK2 };\n`);
    await gitCmd(repo, ["add", "."]);
    await gitCmd(repo, ["commit", "-m", "plant webhook B"]);
    const shaB = await gitCmd(repo, ["rev-parse", "--short=7", "HEAD"]);
    await writeFile(join(repo, "config.js"), "module.exports = {};\n");
    await gitCmd(repo, ["add", "."]);
    await gitCmd(repo, ["commit", "-m", "remove webhook B"]);
    await writeFile(join(repo, "notes3.txt"), "seventh\n");
    await gitCmd(repo, ["add", "."]);
    await gitCmd(repo, ["commit", "-m", "seventh"]);
    const tip = await gitCmd(repo, ["rev-parse", "HEAD"]);
    check("resume fixture really has 7 commits", (await gitCmd(repo, ["rev-list", "--count", "HEAD"])) === "7");

    const server = startGitSmartHttp(root);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const gitBase = `http://127.0.0.1:${(server.address() as { port: number }).port}/repo`;
    try {
      clearHistoryCache();
      const whole = await scanHistoryViaGit("resumeowner", "resumerepo", "main", { cloneUrlOverride: gitBase });
      check("uninterrupted reference scan succeeds, all 7 commits", whole.ok && whole.commitsScanned === 7, `${whole.commitsScanned} scanned`);
      check("reference scan finds both planted webhooks", whole.findings.filter((f) => f.type === "discord-webhook").length === 2, `${whole.findings.length} findings`);

      // Chunked: 3 commits per chunk, cache dropped between chunks.
      clearHistoryCache();
      let resumeAfter: string | null = null;
      let chunkedFindings: SecretFinding[] = [];
      let chunkedScanned = 0;
      let complete = false;
      let chunks = 0;
      while (!complete && chunks < 10) {
        chunks++;
        clearHistoryCache(); // simulate a fresh serverless instance
        const chunk = await scanHistoryViaGit("resumeowner", "resumerepo", "main", {
          cloneUrlOverride: gitBase,
          resumeAfterSha: resumeAfter,
          maxCommits: 3,
        });
        check(`resume chunk ${chunks} succeeds`, chunk.ok, chunk.note ?? "");
        chunkedFindings = [...chunkedFindings, ...chunk.findings];
        chunkedScanned += chunk.commitsFetched;
        resumeAfter = chunk.lastScannedSha ?? resumeAfter;
        complete = chunk.complete ?? false;
      }
      check("chunked resume finishes in 3 chunks (3 + 3 + 1)", complete && chunks === 3, `${chunks} chunks`);
      check("chunked resume covers all 7 commits", chunkedScanned === 7, `${chunkedScanned} scanned`);
      check(
        "chunked resume findings are IDENTICAL to the uninterrupted scan",
        JSON.stringify(sortFindings(chunkedFindings)) === JSON.stringify(sortFindings(whole.findings)),
        `${chunkedFindings.length} vs ${whole.findings.length} findings`,
      );
      check("chunked resume attributes webhook A to its commit", chunkedFindings.some((f) => f.type === "discord-webhook" && f.file === "app.js" && f.commit === shaA));
      check("chunked resume attributes webhook B to its commit", chunkedFindings.some((f) => f.type === "discord-webhook" && f.file === "config.js" && f.commit === shaB));
      check("no full fake secret in chunked resume findings", !leaksSecret(JSON.stringify(chunkedFindings), fakeA) && !leaksSecret(JSON.stringify(chunkedFindings), fakeB));

      // A resume point that is still in the log never reports headMoved.
      clearHistoryCache();
      const mid = await scanHistoryViaGit("resumeowner", "resumerepo", "main", {
        cloneUrlOverride: gitBase,
        resumeAfterSha: whole.lastScannedSha,
        maxCommits: 3,
      });
      check("resume after the last commit is complete, not headMoved", mid.ok && mid.complete === true && mid.headMoved === false, `ok=${mid.ok} complete=${mid.complete} headMoved=${mid.headMoved}`);
      void tip;
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  } finally {
    await rm(root, { recursive: true, force: true }).catch(() => undefined);
  }

  // --- B. Resume on a 1005-commit fixture. ---
  // Root plants webhook A (outside the newest 1000); the newest
  // commit plants webhook B (inside). Chunk 1 takes the newest 3;
  // chunk 2 resumes after chunk 1. The resume point is the 3rd
  // newest commit, so chunk 2 must continue cleanly under the full
  // clone (the git path carries no 1000 cap).
  clearHistoryCache();
  const bigRoot = await mkdtemp(join(tmpdir(), "gitsecure-p21-resume-big-"));
  const bigRepo = join(bigRoot, "repo");
  try {
    await gitCmd(bigRoot, ["init", "-b", "main", "repo"]);
    await gitCmd(bigRepo, ["config", "user.email", "test@example.com"]);
    await gitCmd(bigRepo, ["config", "user.name", "GitSecure Test"]);
    const fakeA = webhookFor("777777777777777777");
    const fakeB = webhookFor("888888888888888888");
    const contentA = `const HOOK = "${fakeA}";\n`;
    const contentB = `const HOOK2 = "${fakeB}";\n`;
    const streamLines: string[] = [
      "blob",
      "mark :100000",
      `data ${Buffer.byteLength(contentA, "utf8")}`,
      contentA,
      "blob",
      "mark :100001",
      `data ${Buffer.byteLength(contentB, "utf8")}`,
      contentB,
      "commit refs/heads/main",
      "mark :1",
      "author GitSecure Test <test@example.com> 1700000000 +0000",
      "committer GitSecure Test <test@example.com> 1700000000 +0000",
      `data ${"plant webhook A in root commit".length}`,
      "plant webhook A in root commit",
      "M 100644 :100000 app.js",
      "",
    ];
    for (let i = 2; i <= 1005; i++) {
      streamLines.push(
        "commit refs/heads/main",
        `mark :${i}`,
        "author GitSecure Test <test@example.com> 1700000000 +0000",
        "committer GitSecure Test <test@example.com> 1700000000 +0000",
        `data ${`empty ${i}`.length}`,
        `empty ${i}`,
        `from :${i - 1}`,
      );
      if (i === 1005) streamLines.push("M 100644 :100001 other.js");
      streamLines.push("");
    }
    await new Promise<void>((resolve, reject) => {
      const child = spawn("git", ["fast-import", "--quiet"], { cwd: bigRepo });
      child.on("error", reject);
      child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`fast-import exited ${code}`))));
      child.stdin.end(streamLines.join("\n"));
    });
    check("depth-boundary resume fixture really has 1005 commits", (await gitCmd(bigRepo, ["rev-list", "--count", "HEAD"])) === "1005");
    const headMinus5 = await gitCmd(bigRepo, ["rev-parse", "HEAD~5"]);
    const rootSha = await gitCmd(bigRepo, ["rev-parse", "--short=7", "HEAD~1004"]);

    const bigServer = startGitSmartHttp(bigRoot);
    await new Promise<void>((resolve) => bigServer.listen(0, "127.0.0.1", resolve));
    const bigBase = `http://127.0.0.1:${(bigServer.address() as { port: number }).port}/repo`;
    try {
      clearHistoryCache();
      const c1 = await scanHistoryViaGit("resumebigowner", "resumebigrepo", "main", { cloneUrlOverride: bigBase, maxCommits: 3 });
      check("boundary chunk 1 succeeds and scans the newest 3", c1.ok && c1.commitsScanned === 3, `${c1.commitsScanned} scanned`);
      check("boundary chunk 1 is not complete (chunk boundary)", c1.complete === false, `complete=${c1.complete}`);
      check("boundary chunk 1 finds webhook B (newest commit)", c1.findings.some((f) => f.type === "discord-webhook" && f.file === "other.js"), `${c1.findings.length} findings`);
      clearHistoryCache();
      const c2 = await scanHistoryViaGit("resumebigowner", "resumebigrepo", "main", {
        cloneUrlOverride: bigBase,
        resumeAfterSha: c1.lastScannedSha,
        maxCommits: 3,
      });
      check("boundary chunk 2 (resumed inside the depth) succeeds", c2.ok, c2.note ?? "");
      check("boundary chunk 2 scans the next 3 commits", c2.commitsScanned === 3, `${c2.commitsScanned} scanned`);
      check("boundary chunk 2 does not report headMoved", c2.headMoved === false, `headMoved=${c2.headMoved}`);
      check("boundary chunk 2 is not complete (more history remains)", c2.complete === false, `complete=${c2.complete}`);
      check("boundary chunk 2 ends at HEAD~5", c2.lastScannedSha === headMinus5, `lastScannedSha=${c2.lastScannedSha?.slice(0, 7) ?? "(null)"} expected ${headMinus5.slice(0, 7)}`);
      check(
        "first 6 commits hold no root webhook (it is outside the depth)",
        ![...c1.findings, ...c2.findings].some((f) => f.type === "discord-webhook" && f.commit === rootSha),
      );
      check("no full fake secret in boundary resume findings", !leaksSecret(JSON.stringify([...c1.findings, ...c2.findings]), fakeA) && !leaksSecret(JSON.stringify([...c1.findings, ...c2.findings]), fakeB));
    } finally {
      await new Promise<void>((resolve) => bigServer.close(() => resolve()));
    }
  } finally {
    await rm(bigRoot, { recursive: true, force: true }).catch(() => undefined);
  }

  // --- C. No-progress loop case: DRAFT HARNESS, pending workstream A. ---
  // Scenario (black-box, no guess at A's internals): a history chunk
  // whose clone times out, while the API fallback is also down, is
  // driven twice through advanceScan with the same cursor. Today the
  // second attempt must not silently return the byte-identical
  // cursor (that is the loop: no progress persisted, same cursor
  // retried forever). Workstream A decides the mechanism (advance
  // the cursor through the API fallback, or surface an honest
  // non-retryable error with the reset time); this section is
  // finalized against that mechanism once it lands.
  //
  // Harness: the git server never answers (the clone aborts at the
  // chunk deadline), and the mock API answers 500 to every list
  // call (the fallback cannot run either). The cursor is built
  // directly so no HEAD scan (and no live network) is involved.
  const stallServer = createServer(() => {
    // Never respond: the clone must abort at deadlineMs, not hang.
  });
  await new Promise<void>((resolve) => stallServer.listen(0, "127.0.0.1", resolve));
  const stallBase = `http://127.0.0.1:${(stallServer.address() as { port: number }).port}/repo`;
  const failApi = createServer((req: IncomingMessage, res: ServerResponse) => {
    void req;
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ message: "boom" }));
  });
  await new Promise<void>((resolve) => failApi.listen(0, "127.0.0.1", resolve));
  const failApiBase = `http://127.0.0.1:${(failApi.address() as { port: number }).port}`;
  try {
    const headSha = "a".repeat(40);
    const cursorData: ScanCursorData = {
      v: 1, owner: "loopowner", repo: "looprepo", branch: "main", headSha,
      stage: "history", historyMethod: "git", histScanned: 0,
      histResumeAfter: null, histPage: 1, histIdx: 0,
      histPageShas: [], histDone: false, histStop: null, histNote: null,
    };
    const cursor = encodeCursor(cursorData);
    const attempt = async (label: string): Promise<{ outcome: string; cursorOut: string | null }> => {
      const deadlineMs = Date.now() + 8000;
      const race = Promise.race([
        advanceScan({ owner: "loopowner", repo: "looprepo", cursor, chunkCommits: 10, apiBase: failApiBase, cloneUrlOverride: stallBase, deadlineMs })
          .then((r) => ({ outcome: r.status === "partial" ? `partial stage=${(r as { partial: { historyComplete: boolean } }).partial ? "history" : "?"}` : "done", cursorOut: r.status === "partial" ? r.cursor : null }))
          .catch((err) => ({ outcome: `threw ${(err as Error).message ?? err}`, cursorOut: null })),
        new Promise<{ outcome: string; cursorOut: string | null }>((resolve) =>
          setTimeout(() => resolve({ outcome: "TIMED OUT after 20s (clone did not abort at the deadline)", cursorOut: null }), 20000),
        ),
      ]);
      const result = await race;
      console.log(`loop harness ${label}: ${result.outcome}${result.cursorOut ? ` cursor=${result.cursorOut.slice(0, 24)}...` : ""}`);
      return result;
    };
    const first = await attempt("attempt 1");
    const second = await attempt("attempt 2");
    // Finalized (Phase 21 integration): the loop fix in chunks.ts
    // (apiChunkResult) advances a failed chunk's cursor to assemble
    // instead of throwing with no cursor, so the driver cannot retry
    // byte-identical. Both attempts start from the same input cursor
    // and deterministically return the same ADVANCED cursor.
    check(
      "loop harness: both attempts were observed (neither hung past the race guard)",
      !first.outcome.startsWith("TIMED OUT") && !second.outcome.startsWith("TIMED OUT"),
      `first=${first.outcome} second=${second.outcome}`,
    );
    const decodeStage = (c: string | null): string => {
      if (!c) return "(none)";
      try {
        return (JSON.parse(Buffer.from(c, "base64url").toString("utf8")) as { stage?: string }).stage ?? "(no stage)";
      } catch {
        return "(undecodable)";
      }
    };
    check(
      "loop harness: a failed chunk advances the cursor to assemble instead of retrying byte-identical",
      first.cursorOut !== null && second.cursorOut !== null && first.cursorOut !== cursor && second.cursorOut !== cursor && decodeStage(first.cursorOut) === "assemble" && decodeStage(second.cursorOut) === "assemble",
      `first stage=${decodeStage(first.cursorOut)} second stage=${decodeStage(second.cursorOut)}`,
    );
  } finally {
    // Destroy the held stall sockets so the process can exit.
    (stallServer as unknown as { closeAllConnections?: () => void }).closeAllConnections?.();
    await new Promise<void>((resolve) => stallServer.close(() => resolve()));
    await new Promise<void>((resolve) => failApi.close(() => resolve()));
  }

  // --- D. This file carries no literal secret-pattern values. ---
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
    console.error("Phase 21 resume test crashed:", err instanceof Error ? err.message : err);
    process.exit(1);
  });
