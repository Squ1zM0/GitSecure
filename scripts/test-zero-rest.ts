// Phase 15 (worker D): prove the happy-path scan makes ZERO
// api.github.com requests. Run: npm run test:zero-rest
//
// The count is taken at the fetch layer: global fetch is wrapped
// before the scan runs, and every URL whose host is api.github.com
// is counted. isomorphic-git does NOT use global fetch (it has its
// own HTTP client over github.com), so the wrapper sees exactly the
// REST calls — nothing else. Three proofs, in increasing realism:
//
//   1. Unit: the bounded git HTTP client (history.ts boundedGitHttp)
//      throws PackTooLargeError past its byte bound, aborts the
//      underlying request, and lets non-pack requests through.
//   2. Fixture: resolveRemoteHead + the git history path against a
//      local mock git server (git http-backend, same setup as
//      test-history.ts) — the same code path as the live scan, with
//      no GitHub traffic at all. (A full scanHead against the
//      fixture is not possible: the tarball URL is hardcoded to
//      codeload for the named repo, so the full-scan proof is live.)
//   3. Live: a full scanRepo("Squ1zM0", "TechDirect") against the
//      real GitHub — branch + HEAD over the git protocol, files from
//      the tarball, history over the git protocol — with 0
//      api.github.com calls, and the report still 83/B with the
//      whole tree scanned. The tree cross-check at the end is a
//      TEST-side REST call made AFTER the counting wrapper is
//      removed, so it is reported separately and never counted as a
//      scan call.

import { spawn } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/lib/scan";
import {
  boundedGitHttp,
  clearHistoryCache,
  PackTooLargeError,
  resolveRemoteHead,
  scanHistoryViaGit,
} from "../src/lib/history";
import { isSkippablePath } from "../src/lib/paths";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

function git(cwd: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("git", args, { cwd });
    let out = "";
    child.stdout.on("data", (d: Buffer) => {
      out += d.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve(out.trim()) : reject(new Error(`git ${args.join(" ")} exited ${code}`))));
  });
}

// Same smart-HTTP bridge as test-history.ts: the fixture repo is
// served by the system git's own CGI backend. No api.github.com
// traffic is involved at any point.
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
  // --- 1. Unit: the bounded git HTTP client. ---
  {
    let capturedSignal: AbortSignal | null = null;
    const chunks = [new Uint8Array(600), new Uint8Array(600)];
    const fakeInner = {
      request: async (args: { url: string; method?: string; signal?: AbortSignal }) => {
        capturedSignal = args.signal ?? null;
        return {
          url: args.url,
          method: args.method ?? "GET",
          headers: {},
          statusCode: 200,
          statusMessage: "OK",
          body: (async function* () {
            for (const c of chunks) yield c;
          })(),
        };
      },
    } as unknown as Parameters<typeof boundedGitHttp>[0];
    const bounded = boundedGitHttp(fakeInner, 1000);
    let threw: unknown = null;
    try {
      const res = await bounded.request({ url: "https://example.com/repo.git/git-upload-pack", method: "POST", headers: {} });
      for await (const _c of res.body as AsyncIterable<Uint8Array>) {
        // consume until the bound trips
      }
    } catch (e) {
      threw = e;
    }
    check("bounded http: pack past the byte bound throws PackTooLargeError", threw instanceof PackTooLargeError, threw instanceof Error ? threw.message : String(threw));
    check("bounded http: error carries the byte count read", threw instanceof PackTooLargeError && threw.bytes === 1200, threw instanceof PackTooLargeError ? `${threw.bytes} bytes` : "(no error)");
    check("bounded http: the underlying request was aborted", capturedSignal?.aborted === true, `aborted=${capturedSignal?.aborted}`);
    // A non-pack request passes through uncounted: same 1200-byte
    // body, GET to info/refs, must yield every chunk.
    let yielded = 0;
    const res2 = await bounded.request({ url: "https://example.com/repo.git/info/refs?service=git-upload-pack", method: "GET", headers: {} });
    for await (const _c of res2.body as AsyncIterable<Uint8Array>) yielded++;
    check("bounded http: non-pack request is not bounded", yielded === 2, `${yielded} chunks`);
  }

  // --- Counting wrapper for everything below. ---
  let apiFetchCalls = 0;
  const hosts = new Map<string, number>();
  const realFetch = globalThis.fetch;
  (globalThis as unknown as { fetch: typeof fetch }).fetch = ((...args: Parameters<typeof fetch>) => {
    const url = String(args[0]);
    try {
      const host = new URL(url).host;
      hosts.set(host, (hosts.get(host) ?? 0) + 1);
      if (host === "api.github.com") apiFetchCalls++;
    } catch {
      // Ignore unparseable URLs in the count.
    }
    return realFetch(...args);
  }) as typeof fetch;

  try {
    // --- 2. Fixture: git-protocol legs against the mock server. ---
    // Timeout race first: a server that accepts but never answers
    // must yield reason "timeout" inside the test-only timeoutMs,
    // not hang the scan (the same 12 s bound ghJson used to give
    // the REST calls, now on the git-protocol request).
    const silent = createServer(() => undefined);
    await new Promise<void>((resolve) => silent.listen(0, "127.0.0.1", resolve));
    const silentBase = `http://127.0.0.1:${(silent.address() as { port: number }).port}/repo`;
    try {
      const timedOut = await resolveRemoteHead("gitowner", "gitrepo", { cloneUrlOverride: silentBase, timeoutMs: 200 });
      check("resolveRemoteHead times out on a silent server (reason timeout)", !timedOut.ok && timedOut.reason === "timeout", timedOut.ok ? "unexpectedly ok" : timedOut.reason);
    } finally {
      (silent as unknown as { closeAllConnections?: () => void }).closeAllConnections?.();
      await new Promise<void>((resolve) => silent.close(() => resolve()));
    }

    clearHistoryCache();
    const gitRoot = await mkdtemp(join(tmpdir(), "gitsecure-zero-rest-"));
    const gitRepo = join(gitRoot, "repo");
    await git(gitRoot, ["init", "-b", "main", "repo"]);
    await git(gitRepo, ["config", "user.email", "test@example.com"]);
    await git(gitRepo, ["config", "user.name", "GitSecure Test"]);
    await writeFile(join(gitRepo, "app.js"), "module.exports = {};\n");
    await git(gitRepo, ["add", "."]);
    await git(gitRepo, ["commit", "-m", "first"]);
    const fixtureHead = await git(gitRepo, ["rev-parse", "HEAD"]);
    const gitServer = startGitSmartHttp(gitRoot);
    await new Promise<void>((resolve) => gitServer.listen(0, "127.0.0.1", resolve));
    const gitBase = `http://127.0.0.1:${(gitServer.address() as { port: number }).port}/repo`;
    try {
      const head = await resolveRemoteHead("gitowner", "gitrepo", { cloneUrlOverride: gitBase });
      check("fixture resolveRemoteHead succeeds over the git protocol", head.ok, head.ok ? "" : (head as { reason: string }).reason);
      if (head.ok) {
        check("fixture resolveRemoteHead reports the default branch", head.branch === "main", head.branch);
        check("fixture resolveRemoteHead reports the HEAD sha", head.headSha === fixtureHead, head.headSha);
      }
      const hist = await scanHistoryViaGit("gitowner", "gitrepo", "main", { cloneUrlOverride: gitBase });
      check("fixture git history succeeds", hist.ok, hist.note ?? "");
      check("fixture git history made zero REST calls", hist.restCalls === 0, `${hist.restCalls} REST calls`);
      check("fixture: no api.github.com fetch during the git-protocol legs", apiFetchCalls === 0, `${apiFetchCalls} calls`);
    } finally {
      await new Promise<void>((resolve) => gitServer.close(() => resolve()));
    }

    // --- Live: resolveRemoteHead against the real GitHub. ---
    const liveHead = await resolveRemoteHead("Squ1zM0", "TechDirect");
    check("live resolveRemoteHead succeeds over the git protocol", liveHead.ok, liveHead.ok ? "" : (liveHead as { reason: string }).reason);
    if (liveHead.ok) {
      check("live resolveRemoteHead reports the default branch (main)", liveHead.branch === "main", liveHead.branch);
      check("live resolveRemoteHead reports a 40-hex HEAD sha", /^[0-9a-f]{40}$/.test(liveHead.headSha), liveHead.headSha);
    }
    const missing = await resolveRemoteHead("Squ1zM0", "does-not-exist-xyz");
    check("live resolveRemoteHead reports a missing repo as not-found", !missing.ok && missing.reason === "not-found", missing.ok ? "unexpectedly ok" : missing.reason);
    check("live resolveRemoteHead: no api.github.com fetch so far", apiFetchCalls === 0, `${apiFetchCalls} calls`);

    // --- 3. Live: full scanRepo("Squ1zM0", "TechDirect"). ---
    const before = apiFetchCalls;
    const started = Date.now();
    const full = await scanRepo("Squ1zM0", "TechDirect");
    const wallMs = Date.now() - started;
    const scanApiCalls = apiFetchCalls - before;
    console.log(`live scan: ${wallMs}ms, score ${full.score}/${full.grade}, files ${full.counts.filesScanned}, history commits ${full.counts.historyCommitsScanned}`);
    console.log(`fetch calls by host during the scan: ${[...hosts.entries()].map(([h, n]) => `${h}=${n}`).join(", ") || "(none)"}`);
    check("live full scan made ZERO api.github.com requests", scanApiCalls === 0, `${scanApiCalls} calls`);
    check("live full scan still scores 83/B", full.score === 83 && full.grade === "B", `${full.score}/${full.grade}`);
    check("live full scan reports the default branch (main)", full.branch === "main", full.branch);
    check("live full scan pinned a 40-hex HEAD sha", /^[0-9a-f]{40}$/.test(full.commit), full.commit);
    if (liveHead.ok) {
      check("live full scan HEAD sha matches resolveRemoteHead", full.commit === liveHead.headSha, `${full.commit} vs ${liveHead.headSha}`);
    }
    check("live full scan covered the whole file list", full.counts.filesScanned > 0, `${full.counts.filesScanned} files`);
    check("live full scan history ran over the git protocol", full.limits.some((l) => l.includes("git protocol")), full.limits.join(" | "));
    check("live full scan history covered commits", full.counts.historyCommitsScanned > 0, `${full.counts.historyCommitsScanned} commits`);
    check("live full scan: no api.github.com fetch in total", apiFetchCalls === 0, `${apiFetchCalls} calls`);

    // Save the report for inspection (outside the counting window
    // the wrapper is still installed, but nothing below scans).
    const { writeFileSync, mkdirSync } = await import("node:fs");
    mkdirSync(join(process.cwd(), "test-results"), { recursive: true });
    writeFileSync(join(process.cwd(), "test-results/zero-rest-techdirect.json"), JSON.stringify(full, null, 2));
    // Keep the report's file count for the tree cross-check below.
    (globalThis as unknown as { __zeroRestFilesScanned?: number }).__zeroRestFilesScanned = full.counts.filesScanned;
    (globalThis as unknown as { __zeroRestBranch?: string }).__zeroRestBranch = full.branch;
  } finally {
    (globalThis as unknown as { fetch: typeof fetch }).fetch = realFetch;
  }

  // --- Tree cross-check (TEST-side REST call, outside the window). ---
  // The scan made 0 REST calls; this one call is the test verifying
  // the tarball-derived file list against GitHub's own tree count.
  const branch = (globalThis as unknown as { __zeroRestBranch?: string }).__zeroRestBranch ?? "main";
  const scanned = (globalThis as unknown as { __zeroRestFilesScanned?: number }).__zeroRestFilesScanned ?? 0;
  const treeRes = await fetch(
    `https://api.github.com/repos/Squ1zM0/TechDirect/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    { headers: { Accept: "application/vnd.github+json", "User-Agent": "GitSecure-test-zero-rest" } },
  );
  if (!treeRes.ok) throw new Error(`tree cross-check fetch failed: ${treeRes.status}`);
  const treeData = (await treeRes.json()) as { tree?: { path: string; type: string }[]; truncated?: boolean };
  if (treeData.truncated) throw new Error("tree was truncated by GitHub — cannot prove the count");
  const expected = (treeData.tree ?? []).filter((t) => t.type === "blob" && !isSkippablePath(t.path)).length;
  console.log(`tree cross-check (test-side call, not counted as a scan call): ${expected} scannable files in the tree, filesScanned=${scanned}`);
  check("tree cross-check: tarball-derived file list matches the tree count", scanned === expected, `scanned=${scanned} tree=${expected}`);

  if (failures > 0) {
    console.error(`\n${failures} test(s) FAILED.`);
    process.exit(1);
  }
  console.log("\nZero-REST proof passed: full happy-path scan, 0 api.github.com requests.");
}

main().catch((err) => {
  console.error("Zero-REST test crashed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
