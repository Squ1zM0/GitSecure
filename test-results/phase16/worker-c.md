# Phase 16 — Worker C test results (2026-11-26)

Scope: honest timing copy, footer contradiction, typo. Copy/UI state only —
no scan behaviour, caps, scoring, redaction, or API/MCP changes. Nothing pushed.

## Fix 1 — Honest timing copy
- `src/app/page.tsx:80` — home scan-status line now reads "Small repos usually
  take 15–30 seconds; a large repo with a long history takes several minutes."
  (was the unscoped "This usually takes 15–30 seconds.")
- `src/app/[owner]/[repo]/loading.tsx:25` — "A small repo usually takes 15–30
  seconds. A large repo with a long history takes several minutes." (was
  "A full scan usually takes 15–30 seconds.")
- `src/lib/progress.ts:50` — new pure helper `historyRatePerMin(commitsDelta,
  elapsedSec)`: commits/minute from measured numbers only; null when under
  100 commits or under 20 s (early chunks include HEAD setup time, so an
  early rate would overstate the pace). No total commit count exists before
  the scan finishes, so there is no ETA — only the observed rate.
- `src/components/ScanProgress.tsx:419-422, 437-444` — during the history step
  the progress card shows a live line: with a measurable rate, "History is
  the slow part on a big repo: N commits checked so far, about M a minute —
  a repo with thousands of commits takes several minutes."; otherwise the
  same sentence with no number. The rate is the DELTA of commits checked
  since this browser session started driving chunks over the seconds spent
  driving (refs at mount), never the server's pre-mount work divided by the
  client-side clock.

## Fix 2 — Footer contradiction
Diagnosis: while a scan is still running, ScanProgress renders the provisional
ReportView above the progress card. The provisional report showed
"Dependency vulnerabilities (0)" + "No known vulnerabilities were found in
the dependencies checked" while the card below said "Dependencies not checked
yet" — but the OSV check only runs at assemble time, so the 0 was a count
for a check that had not run. Fix follows the actual state machine: the
count must not render before the check completes.
- `src/components/ReportView.tsx:68` — provisional stat tile shows "—" with
  "dependency vulnerabilities — not checked yet" instead of "0".
- `src/components/ReportView.tsx:136,145` — provisional vulnerabilities
  section heading is "Dependency vulnerabilities (not checked yet)" with
  "Dependencies haven't been checked for known flaws yet — this section
  fills in when the scan finishes." Finished reports are unchanged
  ("(0)" + "No known vulnerabilities were found in the dependencies checked.").
- `src/lib/report-markdown.ts:128,164` — same agreement in the downloadable
  Markdown: provisional summary bullet and section heading say "not checked
  yet" instead of 0; finished reports unchanged. (The Markdown body already
  said "Dependency checks are still running — no vulnerabilities listed yet.")
- Verified by rendering both states locally (renderToString in the new test):
  provisional ReportView, finished ReportView, and the combined ScanProgress
  view (provisional report + progress card) — section and footer now agree.

## Fix 3 — Typo
- `src/lib/score.ts:141` — new shared helper `gradeWordWithArticle(grade)`:
  "an excellent" for A, "a good"/"a fair"/"a poor"/"a needs urgent attention"
  otherwise. Used by both templates that hard-coded "a":
  `src/lib/score.ts:119` (`explainScore`) and `src/components/ScoreDial.tsx:167`
  (`adjustedExplainScore`). The 91/A line now reads "91 out of 100 (grade A)
  is an excellent score". No other "a excellent" pattern exists in the
  codebase (the two templates were the only sites; `report-markdown.ts`
  uses `gradeWord` without an article and is unaffected).

## Tests
- `npm run build` — exit 0 (output in /tmp/build-phase16-worker-c.log).
- New `scripts/test-ui-phase16-worker-c.ts` (`npm run test:ui-phase16c`,
  `package.json:36`): **45 PASS, 0 FAIL**. Covers the typo for every grade,
  the scoped timing copy, `historyRatePerMin` boundaries, and the
  provisional/finished render agreement (page + Markdown). Live-case
  fixture reproduces the iPhone report (vinta/awesome-python, 91/A,
  0 secrets, 0 vulns, 3 posture issues, 126 files, 3,350 commits).
- Updated `scripts/test-ui-phase15-worker-c.ts` finding-11 checks to the new
  scoped copy: `npm run test:ui-phase15c` — **36 PASS, 0 FAIL**.
- `npm run test:ui-phase7` — **155 PASS, 0 FAIL**.
- `npm run test:score-phase12` — **40 PASS, 0 FAIL**.
- `npm run test:report-markdown` — **30 PASS, 0 FAIL**.
- Also passing (summary lines only, counts not captured): test:public-full,
  test:fixtures-phase14, test:resilience-phase15, test:triage-phase10,
  test:usage-phase11, test:cursor-phase9, test:tier3, test:scanner,
  test:history, test:zero-rest, test:deps-phase13.
- `npm run test:mcp` — **36 pass, 26 fail, all 26 environmental**: every
  failure is a live-scan call failing with "GitHub's request limit was
  hit". Verified at `https://api.github.com/rate_limit`: unauthenticated
  core quota 0/60 remaining at check time. No MCP/scan/API code was touched
  by this worker, so this is not a regression from these changes; the MCP
  checks that do not need a live scan all pass. (Needs a re-run once GitHub
  quota resets; nothing in this worker's scope can fix it.)

## Notes / open points
- The F-grade wording is still "is a needs urgent attention score" — the
  article is now correct ("a" before a consonant), but the phrasing is
  awkward. Left as-is: out of scope for the reported typo, and changing it
  would alter score copy beyond the fix.
- `GITSECURE.md:1649` still records the Phase 15 wording ("loading copy
  says 'usually takes 15–30 seconds'") as history; left untouched as a
  changelog entry, not user-facing copy.
- No `.git` directory exists in `~/workspace/gitsecure`, so no commit/push
  was possible or attempted; working tree contains only the files below.
  (Remote head per task brief: 2f6f9303, unverified locally.)

## Files changed
- `src/lib/score.ts`
- `src/components/ScoreDial.tsx`
- `src/app/page.tsx`
- `src/app/[owner]/[repo]/loading.tsx`
- `src/lib/progress.ts`
- `src/components/ScanProgress.tsx`
- `src/components/ReportView.tsx`
- `src/lib/report-markdown.ts`
- `scripts/test-ui-phase15-worker-c.ts` (finding-11 checks updated)
- `scripts/test-ui-phase16-worker-c.ts` (new)
- `package.json` (new `test:ui-phase16c` script)
- `test-results/phase16/worker-c.md` (this note)
