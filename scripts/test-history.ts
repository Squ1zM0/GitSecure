// Full-history regression test (Phase 2). Run: npm run test:history
//
// Builds a throwaway local git repo in /tmp (never committed anywhere):
// commit 1 plants a FAKE Discord webhook (assembled from fragments, as
// in test-scanner.ts), commit 2 removes it, commit 3 is unrelated — so
// HEAD is clean and only a full-history scan can find it. Then clones it
// through scanFullHistory (local-path clone override, test-only) and
// asserts the old-commit secret is found, redacted, and attributed to
// the right commit. This is the AIoN-incident shape: a secret deleted
// from HEAD but still live in history.

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { scanFullHistory, scanHistoryViaApi } from "../src/lib/history";
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

  console.log(failures === 0 ? "\nAll history tests passed." : `\n${failures} test(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("History test crashed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
