// Phase 21 Workstream A measurement driver.
// Calls the REAL scanHistoryViaGit code path (bounded HTTP client,
// pack bound, clone abort) and reports wall-clock time plus the pack
// bytes that landed on disk. The clone dir is deleted by
// scanHistoryViaGit itself in its finally block; this script only
// polls tmpdir() for the .pack file while the clone runs, so the
// numbers come from the real path, not a hand-rolled clone.
// Usage: npx tsx drive-history.mts <owner> <repo> <branch> [maxCommits]
// maxCommits defaults to 1 so the walk is negligible and the reported
// ms is dominated by resolve-tip + clone + log parse.
import { scanHistoryViaGit } from "../../../src/lib/history";
import { tmpdir } from "node:os";
import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";

const [owner, repo, branch, maxCommitsArg] = process.argv.slice(2);
if (!owner || !repo || !branch) {
  console.error("usage: drive-history.mts <owner> <repo> <branch> [maxCommits]");
  process.exit(2);
}
const maxCommits = maxCommitsArg ? Number(maxCommitsArg) : 1;

let maxPack = 0;
let stop = false;
async function pollPack(): Promise<void> {
  while (!stop) {
    try {
      for (const e of await readdir(tmpdir())) {
        if (!e.startsWith("gitsecure-git-")) continue;
        const packDir = join(tmpdir(), e, ".git", "objects", "pack");
        try {
          for (const f of await readdir(packDir)) {
            if (!f.endsWith(".pack")) continue;
            const s = await stat(join(packDir, f));
            if (s.size > maxPack) maxPack = s.size;
          }
        } catch {
          // pack dir not written yet (or already removed)
        }
      }
    } catch {
      // tmpdir unreadable; ignore
    }
    await new Promise((r) => setTimeout(r, 50));
  }
}

const poller = pollPack();
const t0 = Date.now();
const result = await scanHistoryViaGit(owner, repo, branch, {
  maxCommits,
  budgetMs: 300_000,
});
const wallMs = Date.now() - t0;
stop = true;
await poller;
console.log(
  JSON.stringify(
    {
      owner,
      repo,
      branch,
      maxCommits,
      ok: result.ok,
      note: result.note,
      packTooLarge: result.packTooLarge,
      timedOut: result.timedOut,
      truncated: result.truncated,
      complete: result.complete,
      commitsScanned: result.commitsScanned,
      commitsFetched: result.commitsFetched,
      cachedCommits: result.cachedCommits,
      patchBytes: result.patchBytes,
      gitRequests: result.gitRequests,
      resultMs: result.ms,
      wallMs,
      maxPackBytesOnDisk: maxPack,
    },
    null,
    2,
  ),
);
