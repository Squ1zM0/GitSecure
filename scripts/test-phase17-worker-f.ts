// Phase 17 (Worker F) — history-walk budget fix test.
// Run: npm run test:phase17-worker-f
//
// Proves the two halves of the fix in src/lib/history.ts:
//
//   1. Equivalence: addedLinesFast (the O(n) multiset-difference path
//      for large files) returns IDENTICAL added lines to jsdiff on a
//      battery of normal diffs (pure adds, pure deletes, modifications,
//      mixed, empty sides, no-trailing-newline, CRLF, unique lines).
//      The two DOCUMENTED divergences are asserted as such, not
//      hidden: (a) when an added line's text repeats elsewhere in the
//      file, the reported LINE NUMBER can differ (jsdiff pins it to
//      its minimal-edit position, the fast path to the first unmatched
//      occurrence in new-file order) — the added TEXT multiset is
//      still identical; (b) a line moved within the file (deleted and
//      re-added at equal count) is reported as added by jsdiff and
//      invisible to the multiset — safe for secret detection because
//      the line's first introduction in history always raises its
//      count and is reported there.
//   2. Big lockfile: a synthetic ~10k-line lockfile diff completes in
//      seconds through the dispatcher (fast path) and yields the same
//      findings as the slow jsdiff path; a ~5k-line lockfile is
//      diffed both ways and the findings compared directly.
//   3. Chunk budget: a chunk over a lockfile-heavy fixture finishes
//      within its budget and returns partial with findings kept —
//      never a hang. Deterministic half: a budget already spent
//      before the walk (budgetMs=1) stops at the first file, where
//      the old code scanned 16 commits before its first check.
//      Timing half: a budget set just past clone+log stops the walk
//      mid-history; the resumed chunk finishes, and the combined
//      findings equal one unbounded run.
//
// Fixture discipline: everything is generated in memory or in temp
// dirs (never committed). Fake secrets are assembled from fragments
// at runtime, never written as literal secret-pattern strings —
// same convention as test-scanner.ts. No live GitHub calls: the
// fixture repo is served over smart HTTP by the system git's own
// `git http-backend`, bridged through Node (copied from
// test-history.ts — isomorphic-git cannot clone from a local path).

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile, spawn } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { diffLines } from "diff";
import {
  addedLines,
  addedLinesFast,
  ADDED_LINES_JSDIFF_MAX_LINES,
  scanHistoryViaGit,
  clearHistoryCache,
} from "../src/lib/history";
import { scanLinesForSecrets } from "../src/lib/secrets";
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

/** Test-local jsdiff oracle: the old addedLines body, verbatim. */
function jsdiffOracle(oldText: string, newText: string): { line: number; text: string }[] {
  const out: { line: number; text: string }[] = [];
  let newLine = 1;
  for (const part of diffLines(oldText, newText)) {
    const count = part.count ?? 0;
    if (part.added) {
      const lines = part.value.split("\n");
      for (let i = 0; i < count; i++) out.push({ line: newLine + i, text: lines[i] ?? "" });
    }
    if (!part.removed) newLine += count;
  }
  return out;
}

const samePairs = (a: { line: number; text: string }[], b: { line: number; text: string }[]) =>
  JSON.stringify(a) === JSON.stringify(b);
const sameTexts = (a: { text: string }[], b: { text: string }[]) =>
  JSON.stringify(a.map((x) => x.text).sort()) === JSON.stringify(b.map((x) => x.text).sort());

// Fake secret assembled from fragments at runtime — no literal
// secret-pattern string in this file.
const FAKE = "FAKE";
const fakeTokenLine = (name: string) =>
  `const ${name} = "` + "ghp_" + FAKE.repeat(8) + "1234\";";

/** Lockfile-like text: `blocks` 5-line package blocks. `churn` is the
 *  fraction of version lines bumped. Deterministic (seeded). */
function lockfile(blocks: number, churn: number, seed: number): string {
  const lines: string[] = [];
  let s = seed;
  const rnd = () => ((s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  for (let i = 0; i < blocks; i++) {
    const pkg = `pkg-${i % 500}`;
    const ver = `1.${Math.floor(rnd() * 9)}.${Math.floor(rnd() * 20)}`;
    lines.push(
      `      "${pkg}": {`,
      `        "version": "${ver}",`,
      `        "resolved": "https://registry.npmjs.org/${pkg}/-/${pkg}-${ver}.tgz",`,
      `        "integrity": "sha512-${"x".repeat(20)}${i}"`,
      `      },`,
    );
  }
  return lines.join("\n") + "\n";
}

function lockfileChurned(blocks: number, churn: number, seed: number, extraLines: string[] = []): string {
  const base = lockfile(blocks, 0, seed).split("\n");
  let s = seed + 999;
  const rnd = () => ((s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const out = base.map((l) =>
    l.includes('"version"') && rnd() < churn ? l.replace(/1\.\d+\.\d+/, "2.0.0") : l,
  );
  if (extraLines.length > 0) out.splice(Math.floor(out.length / 2), 0, ...extraLines);
  return out.join("\n");
}

async function main() {
  // --- 1. Equivalence battery: fast path vs jsdiff oracle. ---
  const cases: { name: string; oldText: string; newText: string }[] = [
    { name: "pure adds (append)", oldText: "a\nb\nc\n", newText: "a\nb\nc\nd\ne\n" },
    { name: "pure adds (insert middle)", oldText: "a\nb\nc\n", newText: "a\nX\nY\nb\nc\n" },
    { name: "pure deletes", oldText: "a\nb\nc\nd\n", newText: "a\nd\n" },
    { name: "modifications (unique lines)", oldText: "alpha\nbravo\ncharlie\ndelta\n", newText: "alpha\nBRAVO2\ncharlie\nDELTA2\n" },
    {
      name: "mixed add/delete/modify",
      oldText: "one\ntwo\nthree\nfour\nfive\n",
      newText: "one\nTWO\nthree\nsix\nfive\nseven\n",
    },
    { name: "new file (empty old)", oldText: "", newText: "first\nsecond\n" },
    { name: "deleted file (empty new)", oldText: "first\nsecond\n", newText: "" },
    { name: "both empty", oldText: "", newText: "" },
    { name: "no trailing newline", oldText: "a\nb", newText: "a\nb\nc" },
    { name: "CRLF lines", oldText: "a\r\nb\r\n", newText: "a\r\nB\r\nc\r\n" },
    { name: "single line changed", oldText: "only\n", newText: "ONLY\n" },
    {
      name: "lockfile version bump (small)",
      oldText: ['  "a": {', '    "version": "1.0.0",', "  },", '  "b": {', '    "version": "1.0.0",', "  },"].join("\n") + "\n",
      newText: ['  "a": {', '    "version": "2.0.0",', "  },", '  "b": {', '    "version": "1.0.0",', "  },"].join("\n") + "\n",
    },
    {
      name: "identical files",
      oldText: "same\nlines\nhere\n",
      newText: "same\nlines\nhere\n",
    },
  ];
  let equivPairs = 0;
  for (const c of cases) {
    const fast = addedLinesFast(c.oldText, c.newText);
    const js = jsdiffOracle(c.oldText, c.newText);
    const ok = samePairs(fast, js);
    if (ok) equivPairs++;
    check(`equivalence (identical pairs): ${c.name}`, ok, `fast=${fast.length} js=${js.length}`);
  }
  check("equivalence battery: all normal diffs identical", equivPairs === cases.length, `${equivPairs}/${cases.length}`);

  // Documented divergence (a): duplicate line text — inserted block
  // whose closing lines already occur in the file. Added TEXTS are
  // identical; the reported line numbers differ (jsdiff pins the
  // inserted `},` lines to the edit position, the fast path to the
  // first unmatched occurrence in new-file order).
  {
    const oldText = lockfile(100, 0, 42);
    const newText = lockfileChurned(100, 0.05, 42, [
      `      "added-pkg-0": {`,
      `        "version": "9.9.9",`,
      `      },`,
    ]);
    const fast = addedLinesFast(oldText, newText);
    const js = jsdiffOracle(oldText, newText);
    check(
      "divergence (a) duplicate lines: added TEXT multiset identical",
      sameTexts(fast, js),
      `fast=${fast.length} js=${js.length}`,
    );
    check(
      "divergence (a) duplicate lines: line numbers may differ (documented, not hidden)",
      !samePairs(fast, js),
      "pairs differ only in attribution, see addedLinesFast comment",
    );
  }

  // Documented divergence (b): a line moved within the file.
  {
    const oldText = "x\ndup\ny\ndup\nz\n";
    const newText = "dup\nx\ndup\ny\nz\n";
    const fast = addedLinesFast(oldText, newText);
    const js = jsdiffOracle(oldText, newText);
    check("divergence (b) moved line: jsdiff reports it as added", js.length === 1 && js[0]?.text === "dup", JSON.stringify(js));
    check("divergence (b) moved line: fast path sees balanced counts", fast.length === 0, JSON.stringify(fast));
  }

  // --- 2. Threshold / routing. ---
  check("jsdiff threshold is 1000 lines", ADDED_LINES_JSDIFF_MAX_LINES === 1000, `${ADDED_LINES_JSDIFF_MAX_LINES}`);
  {
    const smallOld = Array.from({ length: 1000 }, (_, i) => `line ${i}`).join("\n") + "\n";
    const smallNew = smallOld + "line 1000\n";
    check(
      "routing: exactly 1000 lines still takes the jsdiff path",
      samePairs(addedLines(smallOld, smallNew), jsdiffOracle(smallOld, smallNew)),
    );
    const bigOld = Array.from({ length: 1001 }, (_, i) => `line ${i}`).join("\n") + "\n";
    const bigNew = bigOld + "line 1001\n";
    check(
      "routing: 1001 lines takes the fast path",
      samePairs(addedLines(bigOld, bigNew), addedLinesFast(bigOld, bigNew)),
    );
  }

  // --- 3. Big lockfile: fast path in seconds, same findings as slow. ---
  {
    const oldLock = lockfile(1000, 0, 7); // ~5,000 lines
    const token = fakeTokenLine("LEAKED_TOKEN");
    const newLock = lockfileChurned(1000, 0.3, 7, [token]);
    const t0 = Date.now();
    const fastAdded = addedLines(oldLock, newLock);
    const fastMs = Date.now() - t0;
    check("big lockfile (~5k lines): dispatcher diff completes in seconds", fastMs < 5000, `${fastMs}ms`);
    const fastFindings = scanLinesForSecrets({ path: "package-lock.json" }, fastAdded, "abc1234");
    check("big lockfile: fast path finds the planted token", fastFindings.some((f) => f.type === "github-token"), fastFindings.map((f) => f.type).join(","));
    check("big lockfile: planted token found at its line", fastFindings.some((f) => f.type === "github-token" && newLock.split("\n")[f.line - 1]?.includes("LEAKED_TOKEN")), fastFindings.map((f) => `${f.type}:${f.line}`).join(","));
    check("big lockfile: no full fake secret in findings", !leaksSecret(JSON.stringify(fastFindings), token));
    // The slow path on this size is affordable (~1 s at 30% churn):
    // compare findings directly, same file/line/type/fragment.
    const t1 = Date.now();
    const slowAdded = jsdiffOracle(oldLock, newLock);
    const slowMs = Date.now() - t1;
    const slowFindings = scanLinesForSecrets({ path: "package-lock.json" }, slowAdded, "abc1234");
    const key = (f: { type: string; file: string; line: number; fragment: string }) =>
      `${f.type}:${f.file}:${f.line}:${f.fragment}`;
    check(
      "big lockfile: fast findings identical to slow-path findings",
      JSON.stringify(fastFindings.map(key).sort()) === JSON.stringify(slowFindings.map(key).sort()),
      `fast=${fastFindings.length} slow=${slowFindings.length}`,
    );
    console.log(`  (big-lockfile timings: fast ${fastMs}ms, jsdiff ${slowMs}ms)`);
  }
  {
    // ~10k lines, 50% churn: the shape that cost 43.8 s via jsdiff
    // in the profile (75 added lines). Fast path only — jsdiff here
    // is the pre-fix cost and is not re-paid in the test suite.
    const oldLock = lockfile(2000, 0, 11); // ~10,000 lines
    const token = fakeTokenLine("LEAKED_TOKEN2");
    const newLock = lockfileChurned(2000, 0.5, 11, [token]);
    const t0 = Date.now();
    const fastAdded = addedLines(oldLock, newLock);
    const fastMs = Date.now() - t0;
    check("huge lockfile (~10k lines, 50% churn): diff completes in seconds", fastMs < 5000, `${fastMs}ms`);
    const findings = scanLinesForSecrets({ path: "frontend/package-lock.json" }, fastAdded, "abc1234");
    check("huge lockfile: planted token found", findings.some((f) => f.type === "github-token"), findings.map((f) => f.type).join(","));
    check("huge lockfile: no full fake secret in findings", !leaksSecret(JSON.stringify(findings), token));
  }

  // --- 4. Chunk budget over a lockfile-heavy fixture (mock git server). ---
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

  const gitRoot = await mkdtemp(join(tmpdir(), "gitsecure-workerf-test-"));
  const gitServer = startGitSmartHttp(gitRoot);
  await new Promise<void>((resolve) => gitServer.listen(0, "127.0.0.1", resolve));
  const gitBase = `http://127.0.0.1:${(gitServer.address() as { port: number }).port}/budgetrepo`;
  try {
    const repo = join(gitRoot, "budgetrepo");
    await git(gitRoot, ["init", "-b", "main", "budgetrepo"]);
    await git(repo, ["config", "user.email", "test@example.com"]);
    await git(repo, ["config", "user.name", "GitSecure Test"]);
    // Commit 1 (oldest): a planted token in a small file, removed in
    // commit 2 — only a full-history walk finds it.
    const oldToken = fakeTokenLine("OLD_TOKEN");
    await writeFile(join(repo, "config.js"), `${oldToken}\nmodule.exports = {};\n`);
    await git(repo, ["add", "."]);
    await git(repo, ["commit", "-m", "commit 1: plant token"]);
    const oldSha = await git(repo, ["rev-parse", "--short=7", "HEAD"]);
    await writeFile(join(repo, "config.js"), "module.exports = {};\n");
    await git(repo, ["add", "."]);
    await git(repo, ["commit", "-m", "commit 2: remove token"]);
    // Commits 3..N: each rewrites three ~10k-line lockfiles with
    // churn, newest-first walk order means the newest commits are
    // scanned first. The newest commit also plants a second token
    // in a small file, so chunk 1 must keep a finding.
    const N = 40;
    const newToken = fakeTokenLine("NEW_TOKEN");
    for (const name of ["a", "b", "c"]) await mkdir(join(repo, name), { recursive: true });
    for (let i = 3; i <= N; i++) {
      for (const name of ["a/package-lock.json", "b/package-lock.json", "c/package-lock.json"]) {
        const full = join(repo, name);
        await writeFile(full, lockfileChurned(2000, 0.5, i * 13 + name.length));
      }
      if (i === N) await writeFile(join(repo, "app.js"), `${newToken}\nmodule.exports = {};\n`);
      await git(repo, ["add", "."]);
      await git(repo, ["commit", "-m", `commit ${i}: lockfile churn`]);
    }
    const total = parseInt(await git(repo, ["rev-list", "--count", "HEAD"]), 10);
    check("budget fixture really has 40 commits", total === N, `${total} commits`);

    // (a) Deterministic: a budget already spent before the walk
    // (budgetMs=1 — clone+log alone take longer) must stop at the
    // first file. The old code's first budget check was at 16
    // commits, so it scanned 16 commits before stopping.
    clearHistoryCache();
    const tA = Date.now();
    const spent = await scanHistoryViaGit("budgetowner", "budgetrepo", "main", {
      cloneUrlOverride: gitBase,
      budgetMs: 1,
    });
    const spentMs = Date.now() - tA;
    check("spent budget: chunk returns ok (partial, not failed)", spent.ok, spent.note ?? "");
    check("spent budget: zero commits scanned (stops at first file)", spent.commitsScanned === 0, `${spent.commitsScanned} scanned`);
    check("spent budget: not complete", spent.complete === false, `complete=${spent.complete}`);
    check("spent budget: cursor at the resume point (no commit scanned)", spent.lastScannedSha === null, spent.lastScannedSha ?? "(null)");
    check("spent budget: returns promptly, never hangs", spentMs < 30_000, `${spentMs}ms`);

    // (b) Timing: a budget set just past clone+log stops the walk
    // mid-history. The spent run's `ms` measures clone+log on this
    // machine; give the walk 300 ms past it.
    clearHistoryCache();
    const walkBudget = spent.ms + 300;
    const tB = Date.now();
    const chunk1 = await scanHistoryViaGit("budgetowner", "budgetrepo", "main", {
      cloneUrlOverride: gitBase,
      budgetMs: walkBudget,
    });
    const chunk1Ms = Date.now() - tB;
    check("mid-walk budget: chunk returns ok", chunk1.ok, chunk1.note ?? "");
    check("mid-walk budget: not complete (stopped mid-history)", chunk1.complete === false, `complete=${chunk1.complete}`);
    check(
      "mid-walk budget: scanned some commits but not all",
      chunk1.commitsScanned > 0 && chunk1.commitsScanned < total,
      `${chunk1.commitsScanned}/${total} scanned`,
    );
    check(
      "mid-walk budget: cursor at the last fully scanned commit",
      typeof chunk1.lastScannedSha === "string" && chunk1.lastScannedSha.length === 40,
      chunk1.lastScannedSha ?? "(null)",
    );
    check(
      "mid-walk budget: finishes within its budget + slack, never hangs",
      chunk1Ms < walkBudget + 15_000,
      `${chunk1Ms}ms vs budget ${walkBudget}ms`,
    );
    const newHooks = chunk1.findings.filter((f) => f.type === "github-token");
    check("mid-walk budget: findings kept (newest commit's token)", newHooks.length === 1, `${newHooks.length} found`);
    check("mid-walk budget: no full fake secret in chunk findings", !leaksSecret(JSON.stringify(chunk1.findings), newToken));

    // (c) Resume from the chunk-1 cursor with a generous budget:
    // the walk finishes, and chunk1 + chunk2 findings equal one
    // unbounded run exactly (same type/file/line/fragment/commit).
    const chunk2 = await scanHistoryViaGit("budgetowner", "budgetrepo", "main", {
      cloneUrlOverride: gitBase,
      resumeAfterSha: chunk1.lastScannedSha,
    });
    check("resume: second chunk finishes the walk", chunk2.ok && chunk2.complete === true, `complete=${chunk2.complete}`);
    check(
      "resume: chunks together cover all commits",
      chunk1.commitsScanned + chunk2.commitsScanned === total,
      `${chunk1.commitsScanned}+${chunk2.commitsScanned}=${chunk1.commitsScanned + chunk2.commitsScanned} vs ${total}`,
    );
    clearHistoryCache();
    const whole = await scanHistoryViaGit("budgetowner", "budgetrepo", "main", { cloneUrlOverride: gitBase });
    check("resume: unbounded run covers all commits", whole.ok && whole.commitsScanned === total, `${whole.commitsScanned} scanned`);
    const key = (f: { type: string; file: string; line: number; fragment: string; commit: string | null }) =>
      `${f.type}:${f.file}:${f.line}:${f.fragment}:${f.commit}`;
    const combined = [...chunk1.findings, ...chunk2.findings].map(key).sort();
    const wholeKeys = whole.findings.map(key).sort();
    check(
      "resume: chunked findings equal the unbounded run",
      JSON.stringify(combined) === JSON.stringify(wholeKeys),
      `chunked=${combined.length} whole=${wholeKeys.length}`,
    );
    const oldHooks = whole.findings.filter((f) => f.type === "github-token");
    check("resume: oldest commit's token found exactly once", oldHooks.length === 2, `${oldHooks.length} found`);
    check(
      "resume: old token attributed to the oldest commit",
      oldHooks.some((f) => f.commit === oldSha),
      oldHooks.map((f) => `${f.file}:${f.commit}`).join(","),
    );
  } finally {
    await new Promise<void>((resolve) => gitServer.close(() => resolve()));
    await rm(gitRoot, { recursive: true, force: true }).catch(() => undefined);
  }

  console.log(failures === 0 ? "\nAll Phase 17 Worker F tests passed." : `\n${failures} test(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("Phase 17 Worker F test crashed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
