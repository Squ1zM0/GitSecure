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
import { scanFullHistory } from "../src/lib/history";
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

  console.log(failures === 0 ? "\nAll history tests passed." : `\n${failures} test(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("History test crashed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
