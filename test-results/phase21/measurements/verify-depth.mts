// Phase 21 Workstream A verification: isomorphic-git `clone` accepts
// `depth` together with `singleBranch`, and the depth is actually
// respected (shallow boundary at exactly N commits).
// Clones DefinitelyTyped (92k commits) at depth 1000, counts the log,
// and checks the shallow boundary + single-branch refs.
// Usage: npx tsx verify-depth.mts
import git from "isomorphic-git";
import http from "isomorphic-git/http/node";
import fs from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = await mkdtemp(join(tmpdir(), "gitsecure-verify-"));
try {
  const t0 = Date.now();
  await git.clone({
    fs,
    http,
    dir,
    url: "https://github.com/DefinitelyTyped/DefinitelyTyped.git",
    ref: "master",
    singleBranch: true,
    noCheckout: true,
    depth: 1000,
  });
  const cloneMs = Date.now() - t0;
  const commits = await git.log({ fs, dir, ref: "master" });
  const branches = await git.listBranches({ fs, dir });
  const remotes = await git.listBranches({ fs, dir, remote: "origin" });
  const oldest = commits[commits.length - 1];
  const shallowExists = fs.existsSync(join(dir, ".git", "shallow"));
  console.log(
    JSON.stringify(
      {
        depthRequested: 1000,
        logEntries: commits.length,
        depthRespected: commits.length === 1000,
        oldestCommitParents: oldest?.commit?.parent?.length ?? null,
        shallowFilePresent: shallowExists,
        localBranches: branches,
        remoteBranches: remotes,
        singleBranchRespected: branches.length === 1 && remotes.length === 1,
        cloneMs,
      },
      null,
      2,
    ),
  );
} finally {
  await rm(dir, { recursive: true, force: true }).catch(() => undefined);
}
