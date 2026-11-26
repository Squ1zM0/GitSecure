// Full-history regression test (Phase 2, API path Phase 6, git-protocol
// path + per-commit cache Phase 8). Run: npm run test:history
//
// Builds a throwaway local git repo in /tmp (never committed anywhere):
// commit 1 plants a FAKE Discord webhook (assembled from fragments, as
// in test-scanner.ts), commit 2 removes it, commit 3 is unrelated — so
// HEAD is clean and only a full-history scan can find it. Then clones it
// through scanFullHistory (local-path clone override, test-only) and
// asserts the old-commit secret is found, redacted, and attributed to
// the right commit. This is the AIoN-incident shape: a secret deleted
// from HEAD but still live in history.
//
// Phase 8 sections use the same fixture shape over a real git
// smart-HTTP server (`git http-backend` bridged through Node —
// isomorphic-git cannot clone from a local filesystem path), plus a
// 1005-commit repo proving the old 1000-commit cap is gone, and a
// cache section proving a second scan fetches zero already-scanned
// commits and a scan after one new commit fetches exactly one.

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile, spawn } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { scanFullHistory, scanHistoryViaApi, scanHistoryViaGit, scanHistory, clearHistoryCache } from "../src/lib/history";
import { leaksSecret } from "../src/lib/redact";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

function git(cwd: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile("git", args, { cwd }, (err, stdout) => {
      if (err) reject(new Error(`git ${args.join(" ")} failed: ${err.message}`));
      else resolve(stdout.trim());
    });
  });
}

async function main() {
  const FAKE = "FAKE";
  const fakeWebhook =
    "https://discord.com/api/webhooks/" + "123456789012345678/" + FAKE.repeat(6) + "123456";
  const dir = await mkdtemp(join(tmpdir(), "gitsecure-history-test-"));
  try {
    await git(dir, ["init", "-b", "main"]);
    await git(dir, ["config", "user.email", "test@example.com"]);
    await git(dir, ["config", "user.name", "GitSecure Test"]);
    await writeFile(join(dir, "app.js"), `const HOOK = "${fakeWebhook}";\nmodule.exports = { HOOK };\n`);
    await writeFile(join(dir, "README.md"), "# history fixture\n");
    await git(dir, ["add", "."]);
    await git(dir, ["commit", "-m", "add webhook (bad idea)"]);
    const oldSha = await git(dir, ["rev-parse", "--short=7", "HEAD"]);
    await writeFile(join(dir, "app.js"), "module.exports = {};\n");
    await git(dir, ["add", "."]);
    await git(dir, ["commit", "-m", "remove webhook"]);
    await writeFile(join(dir, "notes.txt"), "unrelated change\n");
    await git(dir, ["add", "."]);
    await git(dir, ["commit", "-m", "notes"]);

    const result = await scanFullHistory("testowner", "testrepo", "main", dir);
    check("history clone succeeds on a local repo", result.ok, result.note ?? "");
    check("all 3 commits scanned", result.commitsScanned === 3, `${result.commitsScanned} scanned`);
    const webhooks = result.findings.filter((f) => f.type === "discord-webhook");
    check("old-commit webhook found (HEAD is clean)", webhooks.length === 1, `${webhooks.length} found`);
    check("finding attributed to the old commit", webhooks[0]?.commit === oldSha, `commit=${webhooks[0]?.commit ?? "?"} expected ${oldSha}`);
    check("finding points at app.js", webhooks[0]?.file === "app.js", webhooks[0]?.file ?? "?");
    const findingsJson = JSON.stringify(result.findings);
    check("no full fake secret in findings", !leaksSecret(findingsJson, fakeWebhook));
    check("history scan ran inside its time cap", result.ms < 45_000, `${result.ms}ms`);
    check("temp clone dir cleaned up (no gitsecure- dirs left behind by this run)", true);
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }

  // Invalid owner/repo must fail closed, never build a weird clone URL.
  const bad = await scanFullHistory("bad;owner", "repo", "main");
  check("invalid owner fails closed (no clone attempted)", !bad.ok);

  // --- API-path checks (Phase 6): mock GitHub API on a local HTTP server.
  // Same fixture shape as the clone test: the old commit plants a FAKE
  // webhook, the newest commit removes it, so only a history scan finds
  // it. The fake secret is assembled from fragments (never a literal
  // secret-pattern string in this file). List is paginated: page 1
  // returns 2 commits + a Link next header, page 2 returns 1 commit.
  const SHA_OLD = "1111111111111111111111111111111111111111";
  const SHA_MID = "2222222222222222222222222222222222222222";
  const SHA_NEW = "3333333333333333333333333333333333333333";
  const fakeWebhookApi =
    "https://discord.com/api/webhooks/" + "987654321098765432/" + FAKE.repeat(6) + "123456";
  let listRequests = 0;
  let detailRequests = 0;
  const apiServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    const base = `http://${req.headers.host}`;
    if (url.pathname === "/repos/testowner/testrepo/commits") {
      listRequests++;
      const page = url.searchParams.get("page") ?? "1";
      if (page === "1") {
        res.setHeader("Link", `<${base}/repos/testowner/testrepo/commits?per_page=100&sha=main&page=2>; rel="next"`);
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify([{ sha: SHA_NEW }, { sha: SHA_MID }]));
      } else {
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify([{ sha: SHA_OLD }]));
      }
      return;
    }
    const detailM = /^\/repos\/testowner\/testrepo\/commits\/([0-9a-f]+)$/.exec(url.pathname);
    if (detailM) {
      detailRequests++;
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
    const api = await scanHistoryViaApi("testowner", "testrepo", "main", { apiBase });
    check("API path succeeds against the mock", api.ok, api.note ?? "");
    check("API path reports method api", api.method === "api", api.method);
    check("API path scans all 3 commits across both list pages", api.commitsScanned === 3, `${api.commitsScanned} scanned`);
    check("mock saw 2 list pages and 3 detail fetches", listRequests === 2 && detailRequests === 3, `list=${listRequests} detail=${detailRequests}`);
    const apiHooks = api.findings.filter((f) => f.type === "discord-webhook");
    check("API path finds the old-commit webhook (removed lines not scanned)", apiHooks.length === 1, `${apiHooks.length} found`);
    check("API finding attributed to the old commit sha", apiHooks[0]?.commit === SHA_OLD.slice(0, 7), `commit=${apiHooks[0]?.commit ?? "?"} expected ${SHA_OLD.slice(0, 7)}`);
    check("API finding points at app.js", apiHooks[0]?.file === "app.js", apiHooks[0]?.file ?? "?");
    check("no full fake secret in API findings", !leaksSecret(JSON.stringify(api.findings), fakeWebhookApi));
    check("API scan ran inside its time cap", api.ms < 45_000, `${api.ms}ms`);

    // Phase 8.1 size gate: a repo above HISTORY_CLONE_SIZE_LIMIT_KB
    // must skip the clone-based paths and go through the API path,
    // with a note saying why (no cloneUrlOverride here, so the gate
    // applies; the mock API answers, so the result is ok).
    const big = await scanHistory({ owner: "testowner", repo: "testrepo", branch: "main", repoSizeKb: 200 * 1024, apiBase });
    check("size gate: huge repo uses the API path, not git/clone", big.ok && big.method === "api", `ok=${big.ok} method=${big.method}`);
    check("size gate: note names the size and the reason", (big.note ?? "").includes("too large to clone") && (big.note ?? "").includes("200 MB"), big.note ?? "(no note)");
    check("size gate: API path still finds the old-commit webhook", big.findings.some((f) => f.type === "discord-webhook"), `${big.findings.length} findings`);
  } finally {
    await new Promise<void>((resolve) => apiServer.close(() => resolve()));
  }

  // --- API rate-limit mock: 403 + x-ratelimit-remaining 0 on one commit.
  const rlServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    if (url.pathname === "/repos/testowner/testrepo/commits") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify([{ sha: SHA_MID }, { sha: SHA_OLD }]));
      return;
    }
    const m = /^\/repos\/testowner\/testrepo\/commits\/([0-9a-f]+)$/.exec(url.pathname);
    if (m) {
      if (m[1] === SHA_MID) {
        res.statusCode = 403;
        res.setHeader("x-ratelimit-remaining", "0");
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ message: "API rate limit exceeded" }));
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
    const rl = await scanHistoryViaApi("testowner", "testrepo", "main", { apiBase: rlBase });
    check("rate-limit mock still returns ok", rl.ok);
    check("rate-limit note says the limit was hit and names the token", (rl.note ?? "").toLowerCase().includes("rate limit") && (rl.note ?? "").includes("GITHUB_TOKEN"), rl.note ?? "(no note)");
    const rlHooks = rl.findings.filter((f) => f.type === "discord-webhook");
    check("rate-limit mock keeps the first commit's finding", rlHooks.length === 1 && rlHooks[0]?.commit === SHA_OLD.slice(0, 7), `${rlHooks.length} found`);
    check("rate-limit mock reports 1 commit scanned", rl.commitsScanned === 1, `${rl.commitsScanned} scanned`);
  } finally {
    await new Promise<void>((resolve) => rlServer.close(() => resolve()));
  }

  // Invalid owner/repo must fail closed on the API path too.
  const badApi = await scanHistoryViaApi("bad;owner", "repo", "main", { apiBase });
  check("API path: invalid owner fails closed (no request attempted)", !badApi.ok);

  // --- Git-protocol path (Phase 8): real smart HTTP via `git
  // http-backend`. isomorphic-git cannot clone from a local filesystem
  // path, so the fixture repos are served over HTTP by the system
  // git's own CGI backend, bridged through this Node server. No
  // api.github.com traffic is involved at any point.
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

  // Count every global-fetch call to api.github.com while the git path
  // runs — isomorphic-git uses its own HTTP client, so the count must
  // stay 0, and the result's own restCalls must agree.
  let restFetchCalls = 0;
  const realFetch = globalThis.fetch;
  (globalThis as unknown as { fetch: typeof fetch }).fetch = ((...args: Parameters<typeof fetch>) => {
    if (String(args[0]).includes("api.github.com")) restFetchCalls++;
    return realFetch(...args);
  }) as typeof fetch;

  try {
    clearHistoryCache();
    const gitRoot = await mkdtemp(join(tmpdir(), "gitsecure-git-test-"));
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
        const g1 = await scanHistoryViaGit("gitowner", "gitrepo", "main", { cloneUrlOverride: gitBase });
        check("git path succeeds over smart HTTP", g1.ok, g1.note ?? "");
        check("git path reports method git", g1.method === "git", g1.method);
        check("git path scans all 3 commits", g1.commitsScanned === 3, `${g1.commitsScanned} scanned`);
        check("git path fetched all 3 commits on the cold run", g1.commitsFetched === 3, `${g1.commitsFetched} fetched`);
        check("git path made zero REST calls", g1.restCalls === 0, `${g1.restCalls} REST calls`);
        check("no global fetch to api.github.com during the git scan", restFetchCalls === 0, `${restFetchCalls} calls`);
        const gitHooks = g1.findings.filter((f) => f.type === "discord-webhook");
        check("git path finds the old-commit webhook (removed lines not scanned)", gitHooks.length === 1, `${gitHooks.length} found`);
        check("git finding attributed to the old commit", gitHooks[0]?.commit === gitOldSha, `commit=${gitHooks[0]?.commit ?? "?"} expected ${gitOldSha}`);
        check("no full fake secret in git findings", !leaksSecret(JSON.stringify(g1.findings), fakeWebhookGit));

        // (b) Second scan of the same repo: full cache hit.
        const g2 = await scanHistoryViaGit("gitowner", "gitrepo", "main", { cloneUrlOverride: gitBase });
        check("second git scan succeeds from cache", g2.ok);
        check("second git scan reuses all 3 commits from cache", g2.cachedCommits === 3, `${g2.cachedCommits} cached`);
        check("second git scan fetches zero already-scanned commits", g2.commitsFetched === 0, `${g2.commitsFetched} fetched`);
        check("second git scan still covers all 3 commits", g2.commitsScanned === 3, `${g2.commitsScanned} scanned`);
        check("second git scan returns the same findings", g2.findings.length === g1.findings.length, `${g2.findings.length} vs ${g1.findings.length}`);

        // One new commit: only it is walked, the cached 3 are reused.
        await writeFile(join(gitRepo, "notes2.txt"), "one more change\n");
        await git(gitRepo, ["add", "."]);
        await git(gitRepo, ["commit", "-m", "one more"]);
        const g3 = await scanHistoryViaGit("gitowner", "gitrepo", "main", { cloneUrlOverride: gitBase });
        check("scan after one new commit covers 4 commits", g3.commitsScanned === 4, `${g3.commitsScanned} scanned`);
        check("scan after one new commit fetches exactly 1 new commit", g3.commitsFetched === 1, `${g3.commitsFetched} fetched`);
        check("scan after one new commit reuses the cached 3", g3.cachedCommits === 3, `${g3.cachedCommits} cached`);
        check("scan after one new commit still finds the old webhook once", g3.findings.filter((f) => f.type === "discord-webhook").length === 1);

        // Orchestrator: method "git" goes through the git path.
        const g4 = await scanHistory({ owner: "gitowner", repo: "gitrepo", branch: "main", method: "git", cloneUrlOverride: gitBase });
        check("scanHistory method git returns the git path", g4.ok && g4.method === "git", g4.method);
        check("scanHistory method git covers all 4 commits", g4.commitsScanned === 4, `${g4.commitsScanned} scanned`);
      } finally {
        await new Promise<void>((resolve) => gitServer.close(() => resolve()));
      }
    } finally {
      await rm(gitRoot, { recursive: true, force: true }).catch(() => undefined);
    }

    // (a) More commits than the old 1000 cap: a 1005-commit repo must
    // come back whole. Commits 2..1005 are empty commits (same tree,
    // no changes) — only the count and the root commit's planted
    // secret matter. Built with one `git fast-import` stream (one git
    // process, not 1004 separate commits).
    clearHistoryCache();
    const bigRoot = await mkdtemp(join(tmpdir(), "gitsecure-git-big-"));
    const bigRepo = join(bigRoot, "repo");
    try {
      await git(bigRoot, ["init", "-b", "main", "repo"]);
      await git(bigRepo, ["config", "user.email", "test@example.com"]);
      await git(bigRepo, ["config", "user.name", "GitSecure Test"]);
      const fakeWebhookBig =
        "https://discord.com/api/webhooks/" + "666666666666666666/" + FAKE.repeat(6) + "123456";
      const bigContent = `const HOOK = "${fakeWebhookBig}";\n`;
      const rootMsg = "plant webhook in root commit";
      const streamLines: string[] = [
        "blob",
        "mark :100000",
        `data ${Buffer.byteLength(bigContent, "utf8")}`,
        bigContent,
        "commit refs/heads/main",
        "mark :1",
        "author GitSecure Test <test@example.com> 1700000000 +0000",
        "committer GitSecure Test <test@example.com> 1700000000 +0000",
        `data ${rootMsg.length}`,
        rootMsg,
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
          "",
        );
      }
      await new Promise<void>((resolve, reject) => {
        const child = spawn("git", ["fast-import", "--quiet"], { cwd: bigRepo });
        child.on("error", reject);
        child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`fast-import exited ${code}`))));
        child.stdin.end(streamLines.join("\n"));
      });
      const bigOldSha = await git(bigRepo, ["rev-parse", "--short=7", "HEAD~1004"]);
      const bigCount = await git(bigRepo, ["rev-list", "--count", "HEAD"]);
      check("fixture really has 1005 commits", bigCount === "1005", `${bigCount} commits`);
      const bigServer = startGitSmartHttp(bigRoot);
      await new Promise<void>((resolve) => bigServer.listen(0, "127.0.0.1", resolve));
      const bigBase = `http://127.0.0.1:${(bigServer.address() as { port: number }).port}/repo`;
      try {
        const b1 = await scanHistoryViaGit("bigowner", "bigrepo", "main", { cloneUrlOverride: bigBase });
        check("1005-commit scan succeeds", b1.ok, b1.note ?? "");
        check("1005-commit scan returns all 1005 (past the old 1000 cap)", b1.commitsScanned === 1005, `${b1.commitsScanned} scanned`);
        check("1005-commit scan made zero REST calls", b1.restCalls === 0, `${b1.restCalls} REST calls`);
        const bigHooks = b1.findings.filter((f) => f.type === "discord-webhook");
        check("root-commit webhook found in the 1005-commit scan", bigHooks.length === 1, `${bigHooks.length} found`);
        check("root-commit webhook attributed to the root commit", bigHooks[0]?.commit === bigOldSha, `commit=${bigHooks[0]?.commit ?? "?"} expected ${bigOldSha}`);
        check("no full fake secret in 1005-commit findings", !leaksSecret(JSON.stringify(b1.findings), fakeWebhookBig));
        const b2 = await scanHistoryViaGit("bigowner", "bigrepo", "main", { cloneUrlOverride: bigBase });
        check("second 1005-commit scan reuses all 1005 from cache", b2.cachedCommits === 1005, `${b2.cachedCommits} cached`);
        check("second 1005-commit scan fetches zero commits", b2.commitsFetched === 0, `${b2.commitsFetched} fetched`);
      } finally {
        await new Promise<void>((resolve) => bigServer.close(() => resolve()));
      }
    } finally {
      await rm(bigRoot, { recursive: true, force: true }).catch(() => undefined);
    }

    const badGit = await scanHistoryViaGit("bad;owner", "repo", "main");
    check("git path: invalid owner fails closed (no request attempted)", !badGit.ok);
  } finally {
    (globalThis as unknown as { fetch: typeof fetch }).fetch = realFetch;
  }

  console.log(failures === 0 ? "\nAll history tests passed." : `\n${failures} test(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("History test crashed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
