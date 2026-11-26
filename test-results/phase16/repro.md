# Phase 16 — pre-fix reproduction (live, 2026-11-26 ~12:44 MST)

## curl timing, https://git-secure.com/vinta/awesome-python
- Run 1 (this session): TTFB 0.82s, total 52.80s, HTTP 200, 33,976 bytes
- Parent's earlier measurements, same URL: TTFB 0.5s, totals 56.3s (finished report, 34KB) and 63.6s (loading shell only, 19KB — stream cut)
- Home page for comparison: TTFB ~0.9s, total ~0.9s, 200

## Device-browser evidence (user's iPhone, in-app browser)
- Scan DID complete: 91/A, 0 secrets, 0 vulns, 3 posture issues (no SECURITY.md, no Dependabot, .gitignore gaps), 126 files, 3,350 history commits, branch master, commit 4c3cb15.
- Failure reproduced FOUR times: page failed after ~60s with "This page couldn't load" + Reload only; one tab disappeared entirely during a 60s wait.
- Reloads returned to bare "Checking files…" with NO resume indicator, progress count, or retry control — impossible to tell if progress was retained.
- Provisional report only appeared after re-entering via the homepage scan form.
- History advanced ~400 commits/min (216 → 616 → 1016 → 1616 → 2016 → 2416 → 2816 → 3350). Total time 16 minutes vs page's stated "usually takes 15–30 seconds".

## Diagnosis (confirmed)
- `src/app/[owner]/[repo]/page.tsx` awaits `runScanLoop(..., { budgetMs: FAST_PATH_WAIT_MS })`, FAST_PATH_WAIT_MS = 50_000 in `src/lib/chunks.ts`, before rendering. 50s budget + chunk overhead lands on Vercel's 60s function ceiling; slow runs get their stream cut and Safari/WebKit reports "This page couldn't load".
- Scope of Phase 16: fast shell (<~5s), visible resume state, honest timing copy, footer contradiction, "a excellent" typo. Out of scope: home-page Safari failure (stale DNS on user's phone), scan behaviour/caps/scoring/redaction, API/MCP contracts.
