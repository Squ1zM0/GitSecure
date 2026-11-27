# Resume-proof harness — GitSecure Phase 17, Part 1

Proves the Phase 9 accumulation hole with real numbers, and re-runs
after the fix to prove it closed. See `run-resume-proof.mjs` header
for the mechanism.

## Run (local, pre-fix evidence)

```sh
cd ~/workspace/gitsecure
npm run build
npm run start -- -p 3100        # or: npx next start -p 3100
node test-results/phase17/resume-proof/run-resume-proof.mjs \
  --base http://localhost:3100 --repo vinta/awesome-python
echo "exit=$?"   # 1 = sets differ (hole demonstrated), 0 = sets match
```

Run against the live site instead (no GitHub REST quota burned on
the happy path — history runs over the git protocol):

```sh
node test-results/phase17/resume-proof/run-resume-proof.mjs \
  --base https://git-secure.com --repo vinta/awesome-python
```

Single path, or a probe (first N history chunks only, no final
report — cheap way to check whether a candidate repo has any history
findings at all):

```sh
node test-results/phase17/resume-proof/run-resume-proof.mjs \
  --base http://localhost:3100 --repo axios/axios \
  --mode chunk --max-history-chunks 2
# probe mode exits 2 without a diff (no final report) — that is
# expected: a probe is a check, not a comparison.
```

## What the pre-fix evidence shows (2026-11-26, local build)

- **docker/awesome-compose — HOLE DEMONSTRATED (exit 1).**
  Chunk path: 24 secrets (14 HEAD + 10 history). GET path: 14 secrets
  (14 HEAD + 0 history). The GET path lost ALL 10 history findings:
  4 by finding identity (`file + line + type + fragment`), 10
  commit-qualified — the identity count undercounts because 6 of the
  lost history instances share an identity with a HEAD finding (same
  secret line still present at HEAD). Score/grade are 0/F on BOTH
  paths: the loss is invisible in the headline numbers, only in the
  finding list. GET call #1 ran 184.7s (head + the single 64-commit
  history chunk, overrunning the 40s budget) and answered 202 with
  the cursor at `assemble`; call #2 assembled with no history
  findings. See `awesome-compose/diff.json` and `evidence.md`.
- **vinta/awesome-python — VACUOUS match (exit 0).** Both paths
  report 0 secrets (91/A, 126 files, 3,350 commits). There is nothing
  to lose, so the match proves nothing about the hole. The task's
  named repo cannot demonstrate it; awesome-compose is the
  demonstrator. First GET run on the same server right after the
  chunk path was also CONTAMINATED by the cache effect below
  (1 call, 1.7s, 150 commits); the clean cold-cache re-run is in
  `awesome-python/` (chunk report from the first run, GET re-run
  cold).
- **Cache poisoning (second defect, found by this harness).** A
  chunked scan's final history chunk walks only the tail commits yet
  can cache them as the repo's "complete" history
  (`src/lib/history.ts`: `complete = !truncated && !chunkStopped`
  does not account for the resume skip), so a later scan on the same
  server instance reports only that tail. Observed: after the
  awesome-python chunk path (3,350 commits), a GET scan on the same
  server answered in 1.7s claiming 150 history commits. Preserved
  raw artifacts: `awesome-python/cache-poisoning/`. The harness now
  diffs `historyCommitsScanned` too and exits 1 on a mismatch.
  ALWAYS restart the server between the two paths (cold cache each)
  — see below.

- Path A starts with `POST /api/scan/start`, NOT with a `GET`:
  the `GET` 202 body carries no `historyFindings`, so starting path A
  from a `GET` cursor would lose the first invocation's history chunks
  on the accumulating path too. Start + chunk mirrors the browser
  driver exactly (`src/lib/resume.ts`, `src/app/[owner]/[repo]/page.tsx`).
- Finding identity is `file + line + type + redacted fragment`
  (never a full secret). `diff.json` also reports the
  commit-qualified count, since the server dedupes on
  `type:file:line:fragment:commit`.
- Exit 0 with zero history findings on both sides is a VACUOUS
  match: it proves nothing about the hole. The evidence file says
  which runs were vacuous and which demonstrated loss.
- Cold cache matters: the server keeps a module-level in-memory
  history cache (`historyCache` in `src/lib/history.ts`) shared by
  both paths. A warm cache lets the second path finish in far fewer
  invocations and can mask the hole. For a clean comparison, restart
  the server between the two paths and run each path separately into
  the same `--out` dir — the harness loads the other path's report
  from disk for the diff:

```sh
node test-results/phase17/resume-proof/run-resume-proof.mjs \
  --base http://localhost:3100 --repo vinta/awesome-python --mode chunk
# restart the server (cold cache), then:
node test-results/phase17/resume-proof/run-resume-proof.mjs \
  --base http://localhost:3100 --repo vinta/awesome-python --mode get
```
- Slow and network-dependent by design; kept out of the main test
  suite (nothing under `test-results/` is imported by `scripts/` or
  `tests/`).

## Evidence

`evidence.md` in this directory — numbers, lost-finding lists,
timings, and what could not be measured locally.

## Live proof after provisioning (2026-11-27, post-deploy 57323998)

Run against https://git-secure.com after the store went live:

```sh
node test-results/phase17/resume-proof/run-resume-proof.mjs \
  --base https://git-secure.com --repo docker/awesome-compose \
  --out test-results/phase17/resume-proof/awesome-compose-live3
```

- **GET spanned two invocations** (call 1: HTTP 202 after 40.3 s,
  261/274 commits; call 2 resumed with `?cursor=` and finished 200
  after 24.5 s). The cursor carries no findings and the GET caller
  passes none, so the early-chunk findings in the finished report
  could only have come back from the store.
- **MATCH, exit 0:** chunk 30 secrets (14 HEAD + 16 history) vs GET
  30 (14 + 16), 0 lost, 0 gained, depth 274 = 274. Pre-fix this same
  repo's GET lost all 10 history findings.
- This closes design §4.6 step 9. The DefinitelyTyped-scale
  multi-invocation run was not needed: awesome-compose crossed a real
  invocation boundary live with history findings on both sides of it.
