# Phase 16 — Worker A: report page fast shell + visible resume state

## Decision: zero server await

The page no longer awaits any scan server-side. A single HEAD chunk
cannot be proven to stay under ~5 s: measured locally, the HEAD chunk
alone took 4.17 s (vinta/awesome-python, 126 files) and 6.56 s
(Squ1zM0/GitSecure, 120 files) — before any cold start. The tarball
download inside it carries a 30 s abort timer (Phase 15 finding 1),
so any short server budget could still blow past 5 s on a huge repo.
Zero await is the only budget that holds for every repo.

## What changed

- `src/app/[owner]/[repo]/page.tsx` — renders `<ScanProgress
  cursor={null} …>` immediately. No `runScanLoop`, no
  `FAST_PATH_WAIT_MS`, no chunk-driver import. Only a malformed
  owner/repo name keeps a server-side error page (same words as
  before, via the shared module). `export const dynamic` was NOT
  added: it is incompatible with `cacheComponents` (build error) and
  awaiting `params` already makes the page render on demand. (The old
  `export const instant = false` was dead — `instant` is not a route
  segment config.)
- `src/components/ScanProgress.tsx` — the driver now starts the scan
  itself: first chunk via `POST /api/scan/start` (HEAD chunk), then
  `POST /api/scan/chunk` per chunk. Resume: saved progress from
  sessionStorage wins whenever it exists (the old "further ahead than
  the server's fresh partial" comparison is gone with the server
  wait); on resume it sets the resume line, the provisional report,
  AND the progress counts at once (new `progressFromSaved`), and
  re-bases worker C's history pace (`baseCommitsRef.current =
  scanned`) so the measured rate covers only this session's driving.
  Fixed a latent bug the old code had: its else branch saved the
  empty initial state over real saved progress whenever the saved scan
  had 0 history commits (HEAD done, history not started) — nothing is
  saved until the first chunk answers now. A terminal failure before
  any progress (not-found / private / rate-limit / timeout /
  bad-format / head-moved) renders the full error page with the exact
  Phase 15 words instead of the retry card; failures after progress
  keep the Phase 15 retry card. Worker C's history-pace wiring,
  provisional/ paused rendering, and all Phase 15 behaviour are
  intact.
- `src/lib/scan-error-copy.ts` (new, client-safe) — the error-copy
  mapping moved here from page.tsx so the page and the driver share
  one source of truth; strings are byte-identical to the old page
  copy.
- `src/app/api/scan/start/route.ts` (new) — `POST {owner, repo}` runs
  exactly one fresh chunk (`advanceScan` with a null cursor) and
  returns the same partial shape as the chunk route. Backward-
  compatible addition; the chunk route is untouched.
- `src/app/api/scan/[owner]/[repo]/tip/route.ts` (new) — `GET` answers
  `{branch, headSha}` from one git-protocol info/refs round trip
  (`resolveRemoteHead`). Lets a finished report saved in
  sessionStorage render immediately on reload only if its HEAD still
  matches the live tip; a failed tip check never blocks the scan.
- `src/lib/chunks.ts`, `FAST_PATH_WAIT_MS`, the chunk route, the scan
  API route, and MCP are NOT touched by this change. (Note: Worker B
  landed the API budget split concurrently — `API_FAST_PATH_WAIT_MS =
  40_000`, now used by the scan API route and MCP; `FAST_PATH_WAIT_MS`
  is still 50_000. See "Concurrent work" below.)
- `scripts/test-resilience-phase15.ts` — three checks repointed from
  page.tsx source strings to their new homes (shared error-copy
  module + ScanProgress terminal render). Wording asserted is
  unchanged.
- `scripts/test-phase16-worker-a.ts` (new) + `test:phase16-a` script
  in package.json — 56 checks.
- `loading.tsx` and the home scan-status line were NOT touched (worker
  C's honest-timing copy already lives there and its test asserts it).

## Measured numbers (local production server, `npm run start`)

### Shell document time (the hard requirement: < ~5 s)

Pre-fix (live, from `test-results/phase16/repro.md`):
`https://git-secure.com/vinta/awesome-python` — TTFB 0.5–0.8 s,
total document 52.8–63.6 s; slow runs returned only the loading shell
(stream cut at Vercel's 60 s ceiling).

Post-fix, local `next start` (build 2, current tree):

| URL | run 1 | run 2 | run 3 |
|---|---|---|---|
| /vinta/awesome-python | 0.234 s (cold) | 0.029 s | 0.042 s |
| /vinta/awesome-python (rebuild) | 0.534 s (cold) | 0.082 s | 0.156 s |
| /Squ1zM0/GitSecure | 0.030 s | 0.029 s | 0.031 s |
| /Squ1zM0/GitSecure (rebuild) | 0.084 s | — | — |
| / (home, control) | 0.057 s | — | 0.021 s |
| /nope-not-real-xyz/nope-not-real-xyz | 0.024 s | — | — |
| /bad%20owner/repo (bad-format) | 0.055 s | — | — |

TTFB 0.007–0.22 s. Shell HTML (22,080 bytes) contains the honest
zero-state progress card: "Scanning vinta/awesome-python", "0 files
scanned so far", "History not checked yet", "No leaked secrets found
so far", "Dependencies not checked yet". The bad-format URL streams
loading.tsx first, then swaps in the error page ("That doesn't look
like a valid repo" + "Retry this scan" + "Scan another repo").

### New endpoints, live

- `GET /api/scan/Squ1zM0/GitSecure/tip` → 200, 1.20 s,
  `{"branch":"main","headSha":"2f6f9303774a50fedaa04b45a62572a09c779cd2"}`
  (matches remote head 2f6f9303).
- `GET /api/scan/vinta/awesome-python/tip` → 200, 0.55 s,
  `{"branch":"master","headSha":"4c3cb15dc695e95ae64add86b9994add8277f323"}`
  (matches the repro's live commit 4c3cb15).
- `GET tip` nonexistent repo → 404 `{"kind":"not-found"}`; bad-format
  owner → 400 `{"kind":"bad-format"}`.
- `POST /api/scan/start {}` → 400 `{"kind":"bad-format"}`.
- `POST /api/scan/start` nonexistent repo → 404 `{"kind":"not-found"}`
  in 0.21 s (the client driver shows the full error page for this).

### Full client-driven scans (curl loop mimicking the browser driver)

- Squ1zM0/GitSecure: start (HEAD chunk) 6.56 s, 120 files →
  chunk 1: 37.61 s, 16 commits → chunk 2: 18.70 s, 34 commits →
  chunk 3 (assemble): 2.97 s → DONE, score 100/A, 37 secrets
  (all test keys, as the MCP test expects), 0 vulns. Total 65.8 s
  wall, shell rendered in 0.03 s.
- vinta/awesome-python (first 2 history chunks only): start 4.17 s,
  126 files → chunk 1: 24.94 s, 200 commits → chunk 2: 25.75 s,
  400 commits. ~470 commits/min — consistent with the iPhone's
  observed ~400/min. (Full scan not driven: ~16 min, same as before;
  scan behaviour unchanged.)

## Resume state (what a reload shows)

- Reload mid-scan (same tab): the driver loads sessionStorage before
  any fetch and immediately sets — the resume line
  (`resumedLine`, e.g. "Resumed — picked up where it left off (1,016
  history commits checked, 0 secrets found so far)."), the
  provisional report, and the progress counts + current stage via
  `progressFromSaved`. No bare spinner: the card shows the retained
  files/commits/secrets counts under the resume line.
- Reload after completion: the saved report renders immediately if
  the tip check confirms its HEAD sha is still current; otherwise a
  fresh scan starts.
- Reload during the HEAD chunk (nothing saved yet): fresh start — correct,
  nothing had been done.
- Limitation, stated plainly: the resume UI path is verified at the
  unit level (`resume.ts` exact-string tests, source assertions, live
  endpoints) and by the curl-driven chunk loop — NOT visually in a
  real browser. This subagent cannot operate a live browser; the
  iPhone visual check belongs to the parent's device-browser task.
  Also: sessionStorage is per-tab, so a reload that opens a NEW tab
  (or a tab that was discarded) has no saved progress to resume from
  — that is the pre-existing sessionStorage design, unchanged here.
  The first paint after a reload is the SSR shell (honest zero state)
  until hydration runs the restore effect; the resumed state appears
  on mount, before the first chunk fetch.

## Tests

- `npm run build` — exit 0 (output:
  `test-results/phase16/worker-a-build2.log`). Both new routes listed
  as dynamic; report page is Partial Prerender (static shell +
  streamed dynamic content).
- Full battery, all exit 0 (log:
  `test-results/phase16/worker-a-tests-final.log`):

| Suite | PASS | FAIL |
|---|---|---|
| test:phase16-a (new) | 56 | 0 |
| test:ui-phase16c (worker C) | 45 | 0 |
| test:resilience-phase15 | 47 | 0 |
| test:ui-phase7 | 155 | 0 |
| test:ui-phase15c | 36 | 0 |
| test:cursor-phase9 | 192 | 0 |
| test:public-full | 56 | 0 |
| test:fixtures-phase14 | 42 | 0 |
| test:scanner | 73 | 0 |
| test:score-phase12 | 40 | 0 |
| test:report-markdown | 30 | 0 |
| test:triage-phase10 | 63 | 0 |
| test:usage-phase11 | 91 | 0 |
| test:tier3 | 40 | 0 |
| test:history | 70 | 0 |

- Baseline before changes (same suites minus phase16-a):
  ui-phase16c 45, resilience-phase15 45, ui-phase7 155, ui-phase15c
  36, cursor-phase9 192 — all passed. (resilience-phase15 grew
  45 → 47: two checks added when repointing the error-copy checks.)
- `test:mcp`: first run failed environmentally — it needs a running
  server, and when run against the server its `scan_repo` call hit
  GitHub's unauthenticated quota (core remaining 0, reset 20:11:17
  UTC; my live scan driving had consumed the shared 60/hr quota).
  The failure message is the rate-limit error, not a code failure —
  and the curl-driven scan minutes earlier returned exactly the
  report the MCP test expects (100/A, 37 secrets). Rerun after the
  quota reset (log: `test-results/phase16/worker-a-mcp-rerun.log`):
  **49 PASS, 13 FAIL — all 13 are `scan_repo TechDirect` checks
  downstream of a single GitHub 429** ("GitHub's request limit was
  hit"). Every GitSecure `scan_repo` check passes on the rerun; the
  TechDirect scan hit the quota again because the fresh 60/hr window
  was shared with sibling workers' live testing (core remaining 8 at
  20:15 UTC, next reset 20:44:40 UTC). No third run: the cause is
  purely the shared quota, and the scan path itself is proven by the
  curl-driven full scans above plus the passing GitSecure MCP checks.
  MCP code (`mcp.ts`, `runScanLoop`, budgets) was not touched by this
  change.
- `test:deps-phase13` / `test:zero-rest` / `test:history-git` /
  `test:techdirect`: live-network suites, not run in this pass
  (quota exhausted at the time; they do not touch the changed code
  paths — zero-rest covers the REST-call count of the happy-path scan,
  which this change does not alter: the page makes no scan calls at
  all now).
- Secret grep over all changed files: clean (no matches for
  `sk_live|ghp_|AKIA|discord.com/api/webhooks/\d+/`).

## Concurrent work (not mine — flagging for the parent)

- Worker C's Phase 16 changes (honest timing, history pace,
  provisional vuln wording, typo fix) were already in the tree; I
  preserved them and re-based the history pace on resume.
- Worker B's API budget audit landed in `src/lib/chunks.ts`,
  `src/app/api/scan/[owner]/[repo]/route.ts`, and `src/lib/mcp.ts`
  while I worked (new `API_FAST_PATH_WAIT_MS = 40_000`, start-floor
  logic, `deadlineMs`). I touched none of those files. At one point
  mid-edit `tsc` transiently reported `Cannot find name
  'LOOP_CHUNK_MIN_REMAINING_MS'` in chunks.ts; a re-run after their
  edit settled is clean, and the final build passes.
- No git repo exists in `~/workspace/gitsecure` (plain working copy);
  nothing was pushed, per instructions.

## Files changed (exact)

- `src/app/[owner]/[repo]/page.tsx` (rewritten)
- `src/components/ScanProgress.tsx` (driver rework; worker C blocks kept)
- `src/lib/scan-error-copy.ts` (new)
- `src/app/api/scan/start/route.ts` (new)
- `src/app/api/scan/[owner]/[repo]/tip/route.ts` (new)
- `scripts/test-phase16-worker-a.ts` (new)
- `scripts/test-resilience-phase15.ts` (3 checks repointed)
- `package.json` (added `test:phase16-a` script)
- `test-results/phase16/worker-a-*.log` + this file (measurements)

## MCP rerun (after GitHub quota reset)

See the `test:mcp` bullet under Tests: 49 PASS, 13 FAIL, all 13
downstream of one GitHub 429 on `scan_repo TechDirect`. Log:
`test-results/phase16/worker-a-mcp-rerun.log`.
