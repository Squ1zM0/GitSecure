# Phase 16 — headless final verification notes

## v1 run: DISCARDED (wrong "finished" signal)

`headless-final-v1.log` / `headless-final-v1.json` / `phase16-awesome-python-1280-final.png`
(v1) / `phase16-awesome-python-360-final.png` (v1).

v1 detected "finished" with the regex `/(\d+)\s+out of 100 \(grade (\w)\)/`.
That text comes from `<ScoreDial>`, and `ReportView` renders ScoreDial for
BOTH the provisional and the finished report — so v1 "finished" at 28 s on
the provisional report (91/A, roll-all present) without the scan ever
completing. Its resume proof was also weak: it reloaded at ~12 s, before
history started, so the resume line read 0 history commits / 0 secrets.

What v1 still proves (valid measurements): shell responseStart 175 ms;
resume line renders; 360 px scrollWidth 360, no overflow.

## v2 run: the real verification (2026-11-26, ~21:01–21:06 MST)

Script `/tmp/p16-pw/verify.mjs`. Correct finished signal: the summary line
is "Scan complete. ..." only on a finished report; provisional says
"So far: ...". Results in `headless-final.json` / `headless-final.log`:

- Shell: responseStart **81 ms** (target: shell complete in under ~5 s).
- Poll +10 s: 0 history commits (HEAD done, history not started).
- Poll +20 s: 200 history commits — reloaded at 21.6 s.
- Resume line (FULL page text): "Resumed — picked up where it left off
  (**200 history commits checked, 0 secrets found so far**)" — real
  retained progress, no bare spinner.
- Finished at 264.8 s wall (4m25s): **91/A, 0 secrets, 0 vulns,
  3 posture issues, 126 files**, branch master, commit 4c3cb15 —
  identical to Freddy's device-browser result. "Scan complete. No leaked
  secrets were found in the files scanned; 3 security hygiene issues to
  fix; 1 framework fingerprinted."
- "91 out of 100 (grade A) is **an excellent** score." — typo fix renders.
- 360 px: scrollWidth 360, no overflowing elements.
- Roll all into report present on the finished report.

Known script wart: `historyCommits: null` in the JSON. The finished text
reads "History checked: 3350 commits, newest first." — the script's
regexes (`N history commits`, `N of ~M history`, `N commits checked`)
do not match that wording. The true count **3,350** is confirmed from
the finished screenshot (`phase16-awesome-python-1280-final.png`):
"Scanned 11/26/2026, 9:05:59 PM · History checked: 3350 commits, newest
first." and "History checked: 3350 commits, newest first (git protocol —
no git binary, no REST quota)."

Server: local prod build (`npm run build` + `npm start`, port 3000),
GITHUB_TOKEN unset (unauthenticated, the harder case). GitHub core quota
was 53/60 at run start.
