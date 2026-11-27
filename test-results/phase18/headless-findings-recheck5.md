# Phase 18 headless verification — RECHECK-5 findings (Worker C)

Date: 2026-11-27 (early morning UTC; ~23:00–23:30 MST Nov 26). Server: own
`next start` on :3100 (killed after the run; port 3000 untouched — still 200
after my kill). Browser: `playwright-core@1.57.0` (in `/tmp/p18`) driving the
cached `~/.cache/ms-playwright/chromium-1255/chrome-linux64/chrome`. No source
files edited. Full assertion log: `headless-run-recheck5.log` (two 600s
settle attempts + appended diagnostics). Scripts: `/tmp/p18/recheck5-final.cjs`,
`/tmp/p18/diag-recheck5.cjs`, `/tmp/p18/diag2-recheck5.cjs`,
`/tmp/p18/diag3-recheck5.cjs`.

Self-scan used: Squ1zM0/GitSecure. **The FINAL report never settled, so no
recheck item could be verified in the browser. No screenshots were taken —
there was no final report to screenshot, and none are fabricated here.**

## Headline

**BLOCKED — the scan never reaches the final report, so neither round-4 fix
could be verified.** Two full 600 s settle attempts (strict settle test from
round 4: 37 secrets AND progress card gone AND final report saved in
sessionStorage) both failed the same way: the HEAD chunk finishes in ~25 s
(provisional report: 18 secrets, 100/A), but the HISTORY stage then makes
**zero progress forever** — every history chunk (~32 s each, HTTP 200
`partial`) returns the byte-identical cursor (`stage: "history"`,
`historyMethod: "git"`, `histScanned: 0`, `histPage: 1`, `histIdx: 0`,
`histDone: false`) across 4+ chunks in a 150 s probe and ~18 chunks across
each 600 s attempt. Per the task instructions, I stopped here and asserted
nothing on the provisional report.

## Verdicts

| # | Check | Result |
|---|-------|--------|
| 1 | Zoomed label overlap at k≈1.8–1.9 (was 6 pairs, worst 1001.6 px²) | **NOT VERIFIED — blocked, no final report** |
| 2a/b/c | Selected-track labels incl. "used in tests ×N" vs S8 node circle | **NOT VERIFIED — blocked, no final report** |
| 3 | No regressions (click/drag/reset/gating/edge-click/redaction/overflow) | **NOT VERIFIED — blocked, no final report** |
| 4 | Screenshots (360 selected / 360 light / 1280 zoomed) | **NONE TAKEN — no final report to screenshot** |

## Why the scan stalls (evidence, not speculation)

1. **HEAD is fine.** `/api/scan/start` responds at ~24.8 s with `status:
   "partial"`, cursor already at `stage: "history"`. The provisional report
   renders: 18 secrets, 100/A, "Provisional score — the current files are
   scanned, but history and dependency checks are still running."
2. **History makes zero progress.** Chunk responses at 58.4 s, 90.3 s,
   122.6 s (and on through the 600 s attempts) all return the identical
   cursor: `histScanned: 0`, `histPage: 1`, `histIdx: 0`,
   `histResumeAfter: null`, `histDone: false`. No `histNote`, no error, no
   rate-limit text, no failed requests, no console errors.
3. **Not rate-limiting.** `curl https://api.github.com/rate_limit`:
   core 52/60 remaining. Not the quota.
4. **Not the tarball.** `curl` of the 74.8 MB HEAD tarball via codeload:
   HTTP 200 in 20.4 s.
5. **The clone is the bottleneck.** `git clone --bare
   https://github.com/Squ1zM0/GitSecure.git` from this VM takes **102.9 s**
   (71 MB pack, 42 commits). The history path is `scanHistoryViaGit`
   (isomorphic-git over smart-HTTP, ephemeral clone dir deleted in
   `finally`), and one history chunk's budget is
   `GIT_HISTORY_CHUNK_BUDGET_MS = 30_000` (`src/lib/chunks.ts:82`). The
   clone alone takes ~3× the chunk budget, so each chunk aborts inside the
   clone with 0 commits walked and persists no progress; the next chunk
   re-clones from scratch. That is the no-progress loop, measured end to
   end.
6. **Local server runs unauthenticated.** There is no `.env.local` in
   `~/workspace/gitsecure` — no `GITHUB_TOKEN`, no Upstash creds (those live
   only in Vercel env). The git-protocol path needs no token, but there is
   also no server-side resume cache to skip the clone.
7. **Why recheck-4 settled and this one does not.** Recheck-4's loads
   settled the final 37-secret report in ~14–28 s. The only variable that
   explains the difference is the git-protocol fetch speed from this VM
   tonight (~103 s for the clone vs a ~30 s chunk budget). This is an
   environment/pipeline interaction, not a map defect — but it is a real
   fragility: a history chunk that times out inside the clone records no
   progress and no fallback (the API fallback only fires when the git path
   fails outright, and the cursor still says `historyMethod: "git"`).

## What was confirmed without a browser (code read only, no edits)

- `edgeLabelThresholdWorld` in `src/lib/map-view.ts` implements the design
  exactly: longest label text per kind present, width = `text.length * 4 +
  8`, max over kinds, empty input → 70. No division by k anywhere in the
  label path.
- The push-out math is present in the `labelClusters` memo in
  `src/components/ReportLists.tsx` (exact quadratic solve along the edge
  direction, applied for both endpoints, radius + 14).
- The cluster label `<text>` elements render LAST in the SVG — after the
  centre, file, and finding node groups (comment at ~line 1359, markup at
  ~line 1364).
- Code matching the fix description is **not** browser verification. The
  two fixes remain unverified in the browser.

## What the provisional report shows (observed, NOT asserted on)

The provisional report (18 HEAD secrets, 100/A) does render a UsageMap —
but per the task instructions I did not open it, click anything in it, or
measure it: it is not the final settled report (37 secrets), its finding
set differs, and a provisional remount would wipe Map state. Nothing in
this file is a claim about the map on the provisional report.

## Method notes / honest gaps

- Two independent 600 s settle attempts, same outcome; three diagnostic
  probes (60 s page-state, 90 s request log, 150 s chunk-response capture)
  all agree. The stall reproduces deterministically tonight.
- The `filesSoFar=null` in the wait logs (vs `"0"` in the 1280 px probe) is
  a logging quirk: at 360 px the progress text does not contain the
  `"N files scanned so far"` phrase the regex looks for. The substantive
  signal in both viewports is identical: `has37=false`, progress card
  present, no saved report, for the full 600 s.
- No real-iPhone tap test (per design).
- The recheck-5 harness itself (`/tmp/p18/recheck5-final.cjs`, 25239 bytes)
  is ready to run unchanged the moment a final report can settle: it
  implements all four recheck items with the exact assertions from the
  task (zoom k 1.8–1.9 overlap count, label-vs-visible-circle intersection
  area for the S8 track, all regressions, three `-recheck5` screenshots).

## Recommended next step (for the parent)

Re-run this recheck when the git-protocol fetch is fast again (or from a
machine where `git clone --bare Squ1zM0/GitSecure` completes well inside
30 s) — the harness is ready and the server build is already in place. If
the stall persists, the scan pipeline itself needs attention first: a
history chunk that times out inside the clone should persist partial
progress (or fall back to the API path) instead of looping forever with an
unchanged cursor — that is a separate defect from the two map fixes, and it
currently makes the self-scan unverifiable headlessly.
