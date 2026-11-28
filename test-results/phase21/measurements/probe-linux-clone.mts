// Phase 21 Workstream A probe: clone a repo with the same
// bounded HTTP client scanHistoryViaGit uses, but surface the raw
// error instead of swallowing it, so failure modes are known.
// Usage: npx tsx probe-linux-clone.mts <owner> <repo> <branch> [depth]
import git from "isomorphic-git";
import http from "isomorphic-git/http/node";
import fs from "node:fs";
import { mkdtemp, rm, readdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { boundedGitHttp } from "../../../src/lib/history";

const [owner, repo, branch, depthArg] = process.argv.slice(2);
const depth = depthArg ? Number(depthArg) : undefined;
const dir = await mkdtemp(join(tmpdir(), "gitsecure-probe-"));
let maxPack = 0;
let stop = false;
async function pollPack(): Promise<void> {
  while (!stop) {
    try {
      const packDir = join(dir, ".git", "objects", "pack");
      for (const f of await readdir(packDir)) {
        if (!f.endsWith(".pack")) continue;
        const s = await stat(join(packDir, f));
        if (s.size > maxPack) maxPack = s.size;
      }
    } catch {
      // not written yet
    }
    await new Promise((r) => setTimeout(r, 50));
  }
}
const poller = pollPack();
const t0 = Date.now();
try {
  await git.clone({
    fs,
    http: boundedGitHttp(http),
    dir,
    url: `https://github.com/${owner}/${repo}.git`,
    ref: branch,
    singleBranch: true,
    noCheckout: true,
    ...(depth !== undefined ? { depth } : {}),
  });
  console.log(JSON.stringify({ ok: true, ms: Date.now() - t0, maxPackBytesOnDisk: maxPack, depth: depth ?? null }));
} catch (e) {
  const err = e as Error & { code?: string; data?: unknown; bytes?: number };
  console.log(
    JSON.stringify({
      ok: false,
      ms: Date.now() - t0,
      name: err.name,
      code: err.code,
      message: err.message,
      bytes: err.bytes ?? null,
      data: err.data !== undefined ? String(err.data).slice(0, 500) : null,
      maxPackBytesOnDisk: maxPack,
      depth: depth ?? null,
      repo: `${owner}/${repo}`,
    }),
  );
} finally {
  stop = true;
  await poller;
  await rm(dir, { recursive: true, force: true }).catch(() => undefined);
}
