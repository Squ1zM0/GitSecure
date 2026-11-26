# Phase 16 — Worker D: full-suite regression + local headless verification

Date: 2026-11-26. Surface for every number below: **local production server**
(`next start`, port 3000, build current — no source file newer than
`.next/BUILD_ID`) + headless Chromium (Playwright-core driving the
`~/.cache/ms-playwright/chromium-1255` binary). No real-iPhone result is
claimed anywhere here; that check is not available to this worker.
No application source was changed. No push. The repo has no `.git` dir in
this working tree, so the remote head (2f6f9303) could not be diffed
locally; "changed files" for the secret grep is the Worker A+B+C union
listed in §4.

## 1. Full test suites (`npm run test:*`, run 20:18–20:20 UTC)

Every suite in `package.json`, run once in order, logs in
`test-results/phase16/worker-d-<suite>.log`.

| Suite | Result |
|---|---|
| scanner | **73 PASS, 0 FAIL**, exit 0, 2 s |
| tier3 | **40 PASS, 0 FAIL**, exit 0, 1 s |
| history | **70 PASS, 0 FAIL**, exit 0, 7 s |
| history-git (live) | **exit 0** — no PASS lines in this script; substance: `ok: true`, method `git`, 62/62 commits, 0 REST calls, second scan 62/62 from cache in 1,111 ms |
| public-full | **56 PASS, 0 FAIL**, exit 0, 1 s |
| score-phase12 | **40 PASS, 0 FAIL**, exit 0, 1 s |
| report-markdown | **30 PASS, 0 FAIL**, exit 0, 1 s |
| deps-phase13 | **22 PASS, 0 FAIL**, exit 0, 7 s |
| triage-phase10 | **63 PASS, 0 FAIL**, exit 0, 3 s |
| usage-phase11 | **91 PASS, 0 FAIL**, exit 0, 2 s |
| mcp | **exit 1 on first run — server not running** (the script requires `npm start` on port 3000; it failed at "server reachable"). See re-run below. |
| cursor-phase9 | **192 PASS, 0 FAIL**, exit 0, 4 s |
| phase16-worker-b | **25 PASS, 0 FAIL**, exit 0, 6 s |
| resilience-phase15 | **47 PASS, 0 FAIL**, exit 0, 2 s |
| fixtures-phase14 | **42 PASS, 0 FAIL**, exit 0, 6 s |
| zero-rest | **25 PASS, then crash, exit 1** — the scan portion passed (`live full scan: no api.github.com fetch — 0 calls`); the test-side tree cross-check failed `403 API rate limit exceeded for 104.29.196.211` (shared-IP unauthenticated quota exhausted at the time). See re-run below. |
| ui-phase7 | **155 PASS, 0 FAIL**, exit 0, 2 s |
| ui-phase15c | **36 PASS, 0 FAIL**, exit 0, 1 s |
| ui-phase16c | **45 PASS, 0 FAIL**, exit 0, 1 s |
| phase16-a | **56 PASS, 0 FAIL**, exit 0, 2 s |
| techdirect (live scan script) | **exit 1 — scan itself succeeded**: 83/B, 0 secrets, 4 vulns, 3 posture, 2,802 files, 62 history commits, 17.8 s; the post-scan tree cross-check then failed `tree fetch failed: 403` (same exhausted quota). See re-run below. |

Offline-suite total (PASS-line suites, first run): **1,101 PASS, 0 FAIL**.

### Live-suite re-runs after the quota window rolled over

Unauthenticated `api.github.com` core quota was **0 remaining** at 20:19
UTC (reset quoted 20:45 UTC at first check). It rolled to **59 remaining**
by 20:22 UTC. Re-runs (20:22–20:24 UTC, logs
`worker-d-<suite>-rerun.log`):

- **zero-rest re-run: 26 PASS, 0 FAIL, exit 0.** "Zero-REST proof passed:
  full happy-path scan, 0 api.github.com requests." Tree cross-check:
  scanned=2,802 = tree=2,802. **PASS.**
- **techdirect re-run: exit 0.** "UNLIMITED scan proven:
  filesScanned matches the full scannable tree." **PASS.**
- **mcp re-run: 50 checks passed, 12 FAILED, exit 1** — run while the
  headless browser scan of awesome-python was running concurrently and
  burning the shared quota (see §2). Failures:
  - `scan_repo Squ1zM0/GitSecure` (11 fails): the tool returned a
    still-running cursor as prose instead of report JSON — "The scan of
    Squ1zM0/GitSecure is still running (cursor …). So far: 120 of 120
    files scanned, 0 history commits checked." Reproduced by direct
    `curl` to the local `/mcp` at 20:25 UTC (HTTP 200, 675 bytes): the
    self-scan did not finish inside the 40 s `API_FAST_PATH_WAIT_MS`
    budget under concurrent load. `scan_repo TechDirect` in the same run
    passed fully (83/B, 0 secrets, 4 vulns, js-yaml named, >250 files).
  - `get_report TechDirect` (1 fail): "GitHub's request limit was hit"
    — the shared quota was being drained by the concurrent browser
    scan at that moment.
  - This is **not yet a clean verdict**: a lone re-run of `test:mcp`
    with no concurrent load, after the quota reset, is still owed —
    see §5.

## 2. Local headless verification (Playwright, port 3000)

Script: `/tmp/worker-d-pw/verify.mjs` (kept out of the repo tree; it is a
verification harness, not app code). Log: `worker-d-headless.log`.
Machine JSON: `worker-d-headless.json`.

### 2a. `/vinta/awesome-python` at 1280×900

- Shell: **navigation 2,445 ms; responseStart 380 ms;
  DOMContentLoaded 1,089 ms; load 1,346 ms.** Shell renders in seconds,
  not ~50 s: "Scanning vinta/awesome-python… / Checking the current
  files for leaked secrets… / 0 files scanned so far / History not
  checked yet". Screenshot: `phase16-awesome-python-1280-shell.png`.
- Scan progress (measured, not assumed): at **304 s** wall time the
  report was still provisional — **91, Grade A, 0 secrets found so far,
  3 posture issues, 126 files, 1,872 of ~3,350 history commits** —
  and the 300 s wait timed out before the finished dial appeared
  ("Security score … out of 100" never rendered in that window).
  Screenshot of the provisional state:
  `phase16-awesome-python-1280.png`.
- **The finished browser report (91/A, 0 secrets, 0 vulns, 3 posture,
  126 files, 3,350 history commits) was NOT reached in this run.**
  Cause, measured: history for this repo runs over the **REST API
  fallback** (`historyMethod: "api"` in the MCP cursor; pack path trips
  its byte bound on a 3,350-commit history), paginating
  `api.github.com` — the unauthenticated 60/hr quota went
  59 → 17 → 0 remaining between 20:22 and 20:28 UTC while the browser
  scan, the MCP test, and the suite re-runs ran concurrently. The
  scan was still advancing honestly when the wait expired (1,872
  commits at 304 s, ≈ 6 commits/s); it was not stuck. A clean
  single-scan completion run after the quota reset is still owed —
  see §5.
- "Roll all into report": **present** in the finished-provisional
  report DOM (`rollAllPresent: true` in the page-text read at both
  1280 and in the resume step).

### 2b. Reload mid-scan (360×800)

- Pre-reload: scan showed **16 history commits** scanned at 46 s.
- After reload: the page re-rendered the provisional report (91 /
  Grade A, branch master, commit `4c3cb15`) — **never a bare spinner**.
  Screenshot: `phase16-resume-360.png`.
- **Caveat — resume line not yet proven:** my first check sliced only
  the first 900 chars of `innerText` and the resume line renders in
  the status card *below* the provisional report, so
  `hasResumeLine: false` from that slice is a measurement artifact,
  not evidence the line is absent. The screenshot's viewport also
  cuts off before the status card. A focused re-check against the
  FULL page text after a mid-scan reload is still owed — see §5.

### 2c. `/vinta/awesome-python` at 360×800

- Shell screenshot: `phase16-awesome-python-360-shell.png` (run as the
  third step of the same script; finished-report screenshot
  `phase16-awesome-python-360.png` captured the provisional state
  because the 300 s wait expired before completion — same quota cause
  as §2a).

## 3. Local API checks (curl, port 3000)

- Home page: **200 in 0.109 s**.
- TechDirect via MCP `scan_repo` (local server): **83/B, 0 secrets,
  4 vulns** — full detail, js-yaml named. (Local API-route curl for
  TechDirect/GitSecure self-scan still owed after the quota reset —
  see §5; the MCP GitSecure call returned a still-running cursor, §1.)
- MCP `initialize` handshake: **PASS** in `test:mcp` ("PASS initialize
  handshake", "PASS tools/list returns scan_repo, get_report,
  resume_scan, list_checks") against the local server's canonical
  `/mcp` endpoint (`/api/mcp` is an alias serving the same handler;
  both are Streamable HTTP, stateless). A direct `curl` POST
  `tools/call scan_repo` to `http://localhost:3000/mcp` also returned
  HTTP 200 with a valid JSON-RPC envelope.

## 4. Secret-pattern grep over the changed files

Phase 16 changed-file union (Worker A: `src/app/[owner]/[repo]/page.tsx`,
`src/components/ScanProgress.tsx`, `src/lib/scan-error-copy.ts` (new),
`src/app/api/scan/start/route.ts` (new),
`src/app/api/scan/[owner]/[repo]/tip/route.ts` (new); Worker B:
`src/lib/chunks.ts`, `src/app/api/scan/[owner]/[repo]/route.ts`,
`src/lib/mcp.ts`; Worker C: `src/lib/score.ts`,
`src/components/ScoreDial.tsx`, `src/app/page.tsx`,
`src/app/[owner]/[repo]/loading.tsx`, `src/lib/progress.ts`,
`src/components/ReportView.tsx`, `src/lib/report-markdown.ts`):

- Full-length secret-value patterns (`ghp_`/`gho_` 36-char,
  `github_pat_`, `AKIA…`, `sk_live_…`, `xox…`, `-----BEGIN … PRIVATE
  KEY`, Slack/Discord webhook URLs): **zero matches**.
- The same precise grep over all of `src/` + `scripts/` (excluding the
  detector `src/lib/secrets.ts` and test/fixture files, which carry
  only regexes and `__SECRET_n__` placeholders): **zero matches**.
  Fixtures use `__SECRET_n__` placeholders; fake secrets are assembled
  in memory only (`scripts/test-scanner.ts`). **Clean.**

## 5. Gaps — work still owed (not hidden, not passed)

1. **`test:mcp` clean re-run, alone.** 50 pass / 12 fail under
   concurrent load + quota exhaustion. Re-run solo after the quota
   reset (core reset 21:04:53 UTC, 0 remaining at ~20:28 UTC) and
   record the true count. The 12 fails split as: 11× `scan_repo
   GitSecure` returning a still-running cursor inside the 40 s budget
   (needs a lone-run check — if it still returns a cursor alone, that
   is a real Phase 16 behaviour question for Workers A/B, since the
   test expects report JSON), 1× `get_report TechDirect` rate-limit
   (environmental).
2. **Browser scan to completion (1280px, then 360px).** One full
   awesome-python scan needs ~35 REST calls for history pagination;
   run it alone after the reset with a 900 s wait and record the
   finished 91/A numbers (expected: 0 secrets, 0 vulns, 3 posture,
   126 files, 3,350 commits) + wall time + finished screenshots.
3. **Resume-line proof.** Reload mid-scan and search the FULL page
   text (and the status card, scrolled into view) for
   "Resumed — picked up where it left off (… history commits checked,
   … secrets found so far)."
4. **Local API-route curls** for TechDirect (expect 83/B) and
   Squ1zM0/GitSecure (expect 100/A) via `GET /api/scan/[owner]/[repo]`
   (+ resume loop if it 202s), recording scores, counts, history depth.
5. **Stop the server cleanly by PID when done** (PID 30967, `next start`
   on port 3000; log `worker-d-server.log`).

## 6. Notes for the parent

- The 300 s per-step wait in the first headless script was too short
  for awesome-python's history over the REST fallback (~9 min at the
  measured ~6 commits/s). That is a measurement-budget miss, not a
  scan failure.
- Concurrent live scans share one unauthenticated 60/hr quota and one
  small VM; the MCP failures in §1 correlate exactly with that
  contention (Worker B's report records the same failure mode clearing
  on a lone re-run: 62/62). Nothing in the failures points at a code
  regression so far — but the lone re-run is the proof, and it is not
  done yet.
- Worker C's copy is visible live in the served page: "Grade A —
  excellent" (correct article), provisional wording "the current files
  are scanned, but history and dependency checks are still running"
  with no premature "0 vulnerabilities" claim.
