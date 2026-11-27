# Phase 17, Part 1 — resume-proof evidence (pre-fix)

Worker D (proof harness). Local production build, `npm run build` +
`next start -p 3100`, repo at remote head `2707ff21` (working tree has
no `.git`; head taken from the task brief). All runs local; nothing
was run against the live site and nothing was pushed. No `src/` file
was modified. All finding data below is file + line + type +
server-redacted fragment only — no full secret value appears in any
file in this directory (fragments come from server responses, which
redact by construction).

Harness: `run-resume-proof.mjs` (+ `README.md`). Re-run instructions
at the bottom.

## 0. Headline

The Phase 9 accumulation hole is **demonstrated with real numbers**
on `docker/awesome-compose`: the GET resume path lost **all 10 of
the scan's history findings** (4 by finding identity, 10
commit-qualified). Harness exit **1**.

The task's named repo, `vinta/awesome-python`, **cannot** demonstrate
the hole: both paths report **0 secrets** over the full 3,350-commit
history, so its match (exit 0) is vacuous. It is kept as the control
run. See §4 for the candidate hunt that led to awesome-compose.

A **second defect** fell out of the harness: a chunked scan's final
history chunk can poison the server's in-memory history cache so a
later scan on the same instance reports only the tail of the history
(§3). The harness now diffs history depth too.

## 1. Demonstration: docker/awesome-compose (exit 1)

Head SHA on both paths: `503c0dcef31b07fb77b2d4c5556bfafdf86f4f1a`
(match). 64 history commits, 429 files, both reports.

| | Path A — chunk accumulation (POST /api/scan/start + POST /api/scan/chunk) | Path B — GET resume (GET /api/scan/[owner]/[repo], fresh each call) |
|---|---|---|
| HTTP calls | 3 (start 5.0s, 1 history chunk 146.8s, assemble 20.5s) | 2 (202 in 184.7s, 200 in 17.5s) |
| Wall time | 172.4s | 202.3s |
| History chunks / invocations | 1 history chunk | 2 GET invocations |
| History commits scanned | 64 | 64 (depth matches) |
| Score / grade | 0 / F | 0 / F (identical — the loss is invisible in headline numbers) |
| Secrets total | **24** (14 HEAD + 10 history) | **14** (14 HEAD + 0 history) |
| History secrets | 10 | **0** |

GET call #1 ran head + the single 64-commit history chunk (146.8s of
chunk work, overrunning the 40s loop budget) and answered **202**
with the cursor at stage `assemble`. Call #2 assembled with no
`historyFindings` — exactly the hole: `runScanLoop()` starts each
invocation with an empty accumulation, and the 202 body does not even
carry the findings for a caller to carry (`bodyHasHistoryFindings:
false` on every 202 observed in this project).

### Exactly which findings were lost

Identity = `type | file | line | redacted fragment`. By identity,
**4 lost, 0 gained**. Commit-qualified (identity + commit), **10
lost, 0 gained** — the identity count undercounts because 6 of the
lost history instances share an identity with a HEAD finding (the
same secret line is still present in the current files, so the
identity survives as a HEAD finding while its history instance is
lost). The true loss is 10/10 history findings.

Lost by identity (all `database-url`, all at commit `e6b1d27`,
all history-only):

| type | file | line | fragment |
|---|---|---|---|
| database-url | wasmedge-kafka-mysql/.docker/docker-compose.yml | 27 | mysq…ql |
| database-url | wasmedge-kafka-mysql/README.md | 63 | mysq…ql |
| database-url | wasmedge-mysql-nginx/.docker/docker-compose.yml | 17 | mysq…ql |
| database-url | wasmedge-mysql-nginx/README.md | 55 | mysq…ql |

Lost commit-qualified (the 4 above plus 6 more whose identity also
exists at HEAD):

- `database-url | wasmedge-kafka-mysql/compose.yml | 27 | mysq…ql | e6b1d27`
- `database-url | wasmedge-mysql-nginx/compose.yml | 17 | mysq…ql | e6b1d27`
- `database-url | wasmedge-mysql-nginx/backend/src/main.rs | 23 | mysq…ql | e6b1d27`
- `hardcoded-password | nginx-golang-mysql/compose.yaml | 20 | pass…)" | f329300`
- `hardcoded-password | nginx-flask-mysql/compose.yaml | 10 | pass…)" | 111c55d`
- `hardcoded-password | nginx-aspnet-mysql/compose.yaml | 22 | pass…)" | 9f4f9d8`

Raw artifacts: `awesome-compose/diff.json`,
`awesome-compose/chunk-report.json`, `awesome-compose/get-report.json`,
`awesome-compose/{chunk,get}-calls.jsonl`,
`awesome-compose/{chunk,get}-findings.json`, `awesome-compose/summary.json`.

## 2. Control: vinta/awesome-python (exit 0, vacuous)

Head SHA on both paths: `4c3cb15dc695e95ae64add86b9994add8277f323`
(match). 126 files, 3,350 history commits, score 91/A on both.

| | Path A (chunk) | Path B (GET, cold cache) |
|---|---|---|
| HTTP calls | 19 (start + 17 history chunks + assemble) | 16 GET invocations (15× 202, 1× 200) |
| Wall time | 360.2s | 448.5s |
| Per-chunk / per-invocation | 17 history chunks, ~19–23s each, 200 commits each | mostly 1 chunk per ~21s invocation; four invocations did 2 chunks (~38–44s) |
| History commits scanned | 3,350 | 3,350 (depth matches) |
| Secrets | 0 (0 HEAD + 0 history) | 0 (0 HEAD + 0 history) |

Lost by identity: 0. Lost commit-qualified: 0. There are no history
findings to lose, so this match proves nothing about the hole — it
only proves the harness and both paths agree on a clean repo, and
re-confirms the Phase 16 result (0 secrets across all 3,350 commits)
through the chunk path with per-chunk finding counts (0 on every one
of the 17 chunks).

Raw artifacts: `awesome-python/` (same file set as above) and the
run logs `awesome-python.log`, `awesome-python-get-cold.log`.

## 3. Second defect found by the harness: history-cache poisoning

When the awesome-python GET path was first run on the **same server
instance immediately after the chunk path**, it answered in **1.7s
with a finished report claiming 150 history commits** — not 3,350.
Score/grade were still 91/A (0 secrets either way), so the
short-history report looked identical except for the depth number.

Mechanism (code-read, `src/lib/history.ts`): `scanHistoryViaGit`
caches a walk as the repo's complete history when
`complete = !truncated && !chunkStopped`. A chunked scan's final
chunk walks only the tail commits (here 3,200 → 3,350, 150 commits),
reaches the oldest commit, so `complete` is true — but the walk
skipped every commit newer than its resume point, so the cached
"complete" order holds only the tail. The next scan on that instance
takes the full cache hit and reports the tail as the whole history.

Preserved raw artifacts of the poisoned run:
`awesome-python/cache-poisoning/` (`get-report.json`,
`get-calls.jsonl`, `summary.json`, `diff.json` — depth 150 vs 3,350).

Consequences for this harness: the two paths **must run on separate
server processes (cold cache each)** for a clean comparison — a warm
cache lets the second path finish in far fewer invocations and can
mask the hole (and, as here, corrupt its depth). The harness now
diffs `historyCommitsScanned` and exits 1 on a mismatch; `--mode
diff` exists to compare reports produced in separate invocations.
The cold-cache re-run (§2, Path B) is the clean GET measurement.

Note for the fix worker: the accumulation fix and this cache fix are
different bugs. Caching a resumed (non-initial) walk as complete is
only safe if the walk started at the tip; a resumed walk has no
stored prefix to merge with, so it should not write the cache.

## 4. Candidate hunt (why awesome-compose is the demonstrator)

Probes ran Path A only, first 2 history chunks, newest history
first (`--mode chunk --max-history-chunks 2`). Finding counts are
history findings in the probed newest commits only.

| Repo | Total commits | Newest history probed | History findings in probe | Commits / chunk | Verdict |
|---|---|---|---|---|---|
| vinta/awesome-python | 3,350 | all (full runs, §2) | 0 | 200 (~21s) | control; vacuous |
| Squ1zM0/TechDirect (smoke) | 62 | all (full runs) | 0 | 62 in 1 chunk | smoke test only; 0/0, exit 0 |
| docker/awesome-compose | 64 | all (full runs, §1) | 10 (1 chunk) | 64 in 1 chunk (~147s) | **demonstrator** |
| OWASP/wrongsecrets | 8,154 | newest 20 | 4 (1 identity × 4 commits) | 10 (API fallback) | near-miss: full comparison infeasible — 816 chunks + REST quota (see below) |
| OWASP/NodeGoat | 461 | newest 32 | 0 | 16 (~40–80s) | not run fully; ~29 chunks ≈ 30 min/path, findings unknown deeper |
| axios/axios | 2,291 | newest 16 | 0 | 16 (46s) | too slow, no findings in probe |
| gitleaks/gitleaks | ~1,500+ | newest 32 | 0 | 16 (~50s) | too slow, no findings in probe |
| sindresorhus/awesome | 1,209 | newest 400 | 0 | 200 (~7s) | fast but clean |
| Snailclimb/JavaGuide | ? | newest 20 | 0 | 10 (API fallback) | no findings in probe |
| CyC2018/CS-Notes | ? | newest 20 | 0 | 10 (API fallback) | no findings in probe |
| EbookFoundation/free-programming-books | ? | newest 32 | 0 | 16 (81–109s) | far too slow, no findings |
| trufflesecurity/trufflehog | ? | newest 0 | — (first history chunk >180s, timed out) | — | too slow |
| OWASP/railsgoat | ? | newest 0 | — (first history chunk >180s, timed out) | — | too slow |
| docker/awesome-compose (first probe) | 64 | newest 0 | — (first history chunk >180s, timed out — server was backlogged with abandoned walks, §5) | — | re-probed clean after server restart |

Why wrongsecrets is infeasible for a full comparison: its history
chunks cover 10 commits each (the git path fails per chunk and the
driver falls back to the API path, `API_HISTORY_CHUNK_COMMITS =
10`), so a full scan is ~816 chunks, and the API path needs ~1 REST
call per commit — far past the 60/hr unauthenticated quota, so the
scan would stop early with `histStop: "rate-limit"`. Its 4 probe
findings (all `hardcoded-password | js/index.js | 3 | pass…="` at
commits `692b475`, `4ab1fbc`, `a11398a`, `990e12b`) show the pattern
but cannot be turned into a full-scan diff locally.

Per-chunk throughput varies enormously by repo on this VM
(1.5 shared CPUs): md-only repos do 200 commits in ~7–21s per
chunk; code repos with big diffs do 10–16 commits in ~40–110s per
chunk. That variance, not the harness, is what bounds which repos
can serve as demonstrators.

## 5. Incidents and method notes (all reflected in the harness)

- **Path A must start with POST /api/scan/start, not GET.** The
  GET 202 body carries no `historyFindings`, so starting Path A
  from a GET cursor would lose the first invocation's history chunks
  on the accumulating path too. Start + chunk mirrors the browser
  driver exactly (`src/lib/resume.ts`,
  `src/app/[owner]/[repo]/page.tsx`).
- **Cold cache between paths.** See §3. Restart the server between
  the two paths; `--mode diff` compares reports from separate
  invocations. Kill the `next-server` child PID (from `ss -ltnp`),
  not the `npx` wrapper PID in `server.pid` — killing the wrapper
  leaves the server listening and the next start fails with
  EADDRINUSE (observed once; recovered, no data lost).
- **No retry on client timeout.** Aborting the client does NOT stop
  the server-side chunk: after several timed-out probes the server
  sat at ~111% CPU with 33 CPU-minutes of abandoned walks still
  grinding, and later probes timed out against that backlog. The
  harness now retries only on HTTP 502/503/504, never on a
  transport error or timeout.
- **Build collision with a sibling worker's file.** The first
  `npm run build` failed type-checking on a sibling Phase 17
  worker's in-progress `test-results/phase17/loss-repro/loss-repro.ts`
  (TS2345 at line 178). I moved it aside with its sha256 recorded,
  built (exit 0, BUILD_ID `qsfb0m6p04XyywQQnawCn`), and found the
  sibling had recreated the file mid-build with new content — so I
  left their version in place and discarded my hold copy. No
  sibling data was lost or overwritten. `build.log` is in this
  directory.
- **Runtime restart mid-probes.** One background probe session was
  lost to a runtime restart (axios probe, first history chunk). The
  server was down afterwards; state was recovered from the probe
  logs and the server restarted. No evidence was fabricated: the
  axios probe's recorded numbers are the start call (3.3s) and
  chunk #2 (46.3s, 16 commits, 0 findings) from its log.
- **Harness bug found and fixed during the work.** The first
  `--mode diff` run crashed (`TypeError` reading `diff.chunkReport`)
  because the history-depth check referenced the diff object before
  it was assigned — the cold awesome-python GET run (16 calls,
  448.5s) finished fine but its summary was never written. The bug
  is fixed (depth computed from the report counts before the diff
  literal is built); the run's numbers were restored into
  `summary.json` from `awesome-python-get-cold.log` (noted in the
  summary's `notes` field) and the diff was regenerated with
  `--mode diff`. A stray output directory created by one invocation
  run from the wrong working directory was removed.
- **Smoke test.** `Squ1zM0/TechDirect`, both paths, before the long
  runs: chunk 3 calls / 15.7s / 0 secrets; GET 1 call / 3.3s /
  0 secrets; exit 0. (`smoke-techdirect/`.)
- **Local server left running.** `next start -p 3100`, PID 17000
  at time of writing, serving the production build
  (`BUILD_ID qsfb0m6p04XyywQQnawCn`). Stop with
  `kill <next-server pid from ss -ltnp 'sport = :3100'>`.
  `/tmp` clone leftovers (`gitsecure-git-*`) were cleaned; the
  512M tmpfs sat at 16% worst-case during the runs.

## 6. What could not be measured locally

- **Live site.** Not run (task: run locally; the harness takes
  `--base https://git-secure.com` for a live check). The live
  Vercel 60s ceiling would change chunk/invocation shapes but not
  the mechanism.
- **MCP `resume_scan`.** Not driven separately. It calls the same
  `runScanLoop(owner, repo, { cursor, budgetMs })` with no
  `historyFindings` as the GET route (`src/lib/mcp.ts`), so the
  same loss applies by construction; the GET-path numbers are the
  evidence for both. A dedicated MCP-driver run is still open if
  the coordinator wants it.
- **Full wrongsecrets / NodeGoat comparisons.** See §4 — infeasible
  (wrongsecrets) or not attempted (NodeGoat: ~30 min/path, findings
  deeper than the newest 32 commits unknown).
- **Post-fix verification.** Not run — there is no fix yet. See §7.

## 7. Re-run after the fix (post-fix verification)

From `~/workspace/gitsecure`, with a fresh production build:

```sh
# Path A (chunk accumulation) — restart the server first (cold cache)
node test-results/phase17/resume-proof/run-resume-proof.mjs \
  --base http://localhost:3100 --repo docker/awesome-compose \
  --call-timeout-ms 300000 --mode chunk \
  --out test-results/phase17/resume-proof/awesome-compose
# Restart the server again (cold cache), then Path B:
node test-results/phase17/resume-proof/run-resume-proof.mjs \
  --base http://localhost:3100 --repo docker/awesome-compose \
  --call-timeout-ms 300000 --mode get \
  --out test-results/phase17/resume-proof/awesome-compose
# Or: --mode diff --out <same dir> to compare without re-running.
echo "exit=$?"   # expect 0: 24 vs 24 secrets, 10 vs 10 history, depth 64 vs 64
```

Expected post-fix: exit **0** on awesome-compose (24 vs 24 secrets,
10 vs 10 history findings, depth 64 vs 64). The same commands on
`vinta/awesome-python` should stay exit 0 with depth 3,350 vs 3,350
(and will still be vacuous on findings). Any exit 1 means the sets
still differ — `diff.json` names the lost findings. A depth mismatch
(exit 1 via `historyDepthMatch: false`) means the §3 cache issue is
still present even if the finding sets match.

Note: `--call-timeout-ms 300000` is needed for awesome-compose
because its single history chunk takes ~147–185s locally.
