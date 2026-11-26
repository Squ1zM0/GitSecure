# GitSecure Phase 15 — UX audit (step 1)

Local production build only. `npm run build` exit 0 (see `test-results/phase15/build.log`),
then `npm start` on port 3000. Playwright 1.63.0 + cached Chromium headless shell
(revision 1255), real rendered pages — every screenshot below was looked at, not just asserted.
No app code was changed. Audit run 2026-11-26, ~17:29–17:50 MST.

## Measured timings

| Journey | Measured |
|---|---|
| Home hero (first paint of `h1`) | 325 ms; home TTFB 0.049 s (curl) |
| TechDirect `/Squ1zM0/TechDirect` | loading screen at 195 ms; finished report at **27.1 s** (83/B, 2,802 files, 62/62 history) |
| GitSecure self-scan `/Squ1zM0/GitSecure` | finished report at **11.0 s** (100/A, 37 secrets — all 37 likely test keys, 0 vulns, 0 posture, 86 files, 33 history commits) |
| DefinitelyTyped `/DefinitelyTyped/DefinitelyTyped` | provisional report at **53.6 s** (0/F, 403 secrets, 136 test keys, 9,406 deps, 61,814 files); **still provisional at 360 s**, then chunk error (finding 3) |
| torvalds/linux `/torvalds/linux` | no report; timeout error page (finding 1) |

## Verified good (no action)

- **First visit explains the tool in seconds.** "Is this repo safe?" + lede + struck-through
  `github.com/Squ1zM0/GitSecure → git-secure.com/Squ1zM0/GitSecure` strip + prefilled
  `Squ1zM0/GitSecure` input. `home-desktop-light.png`.
- **Input validation is plain English and correct.** Empty → "Enter a repo to scan, like
  Squ1zM0/GitSecure."; `not a repo!!!`, bare `Squ1zM0`, and `Squ1zM0/TechDirect/extra/segments`
  → "Enter owner/repo — for example Squ1zM0/GitSecure."; pasted full URLs with `/tree/main`,
  trailing slash, and `.git` all navigate to `/Squ1zM0/TechDirect` with the button reading
  "Scanning…".
- **No horizontal overflow** on home, TechDirect report, or GitSecure report at 1280 px and
  360 px, light and dark (`scrollWidth == innerWidth` on all six renders).
- **Contrast passes AA everywhere sampled**, light and dark: body 16.10 / 16.02, muted 6.83 /
  7.83, links 7.40 / 10.52, primary button 6.25 / 6.70, grade chip 5.40 / 5.80, severity pills
  6.85 / 7.83 (lowest pair is the light-mode grade chip at 5.40 — still above 4.5).
- **Keyboard:** Tab order is logical (skip link → brand → input → Scan button → MCP copies →
  Try-it link); every stop shows a solid 3 px focus-visible ring; the skip link slides into
  view on focus (`top: 12`, focused, `home-skip-link-focused.png`).
- **Score dial:** `role="img"` on the dial itself with
  `aria-label="Security score 83 out of 100, grade B, good"` (verified in the DOM; my first
  probe used a wrong descendant selector and briefly reported null — the label is present).
- **Filter counts are `aria-live="polite"`** and read true counts ("Showing 37 of 37 secrets ·
  7 files. Of the 37 secrets, 37 look like test keys…").
- **Copy link works end to end:** clicking "Copy link" flips to "Copied" and the clipboard
  holds `http://localhost:3000/Squ1zM0/GitSecure#secret-0`. MCP copy buttons also flip to
  "Copied".
- **Verdict sections work:** on the self-scan only the "Likely test keys (37 findings)"
  section exists, collapsed by default, expanding on click; genuine/uncertain sections are
  absent when empty rather than shown empty.
- **Usage map click-to-track works:** clicking finding node S8 dims everything else, shows
  the focus ring, and renders the track detail panel with references and a "Show this finding
  in the list" button (`report-gitsecure-map-track2.png`).
- **Error copy is plain English** with a clear next action on the 404 and bad-format pages
  (`error-404.png`, `error-badformat.png`).
- **"Scan another repo" is discoverable:** back-link at the top of every report and a
  prominent button at the bottom.

---

## Findings (ranked by impact)

### 1. HIGH — torvalds/linux fails outright: minutes of static waiting, then a dead-end error page, no resume, no retry

- **Where:** `/torvalds/linux` (report page, local production server).
- **Evidence:** `linux-progress.png` — after the loading screen, the page renders
  "GitHub took too long to answer / A request to GitHub timed out, so this scan couldn't run
  right now. The scan itself has no time limit — try again in a bit." The only action is
  "Scan another repo". The `ScanProgress` component (live chunk progress, provisional report,
  sessionStorage resume) never mounted in the clean 180 s attempt, so the resume path was
  never engaged. (An earlier reload test was inconclusive — it reloaded ~2.5 s in, before any
  chunk could complete and save progress.) `server.log` shows repeated
  `uncaughtException: Error [AbortError]` lines around the attempts.
- **Why it matters:** this is the exact case Phase 9 was built for ("That scan is no longer
  running"). The page comment promises "No scan is ever killed for taking too long", and the
  spec says a slow HEAD chunk "stops cleanly at 50 s and retries from its cursor — nothing
  lost, no dead-end". What actually happened: a fetch-level timeout inside the HEAD chunk
  throws instead of returning a partial cursor, so the user gets a terminal error page after
  minutes of a static screen that promises "usually takes about 15 seconds". The error text
  itself is false in the user's experience ("The scan itself has no time limit") and its
  advice ("try again in a bit") restarts from scratch with no resume.
- **Suggested fix:** make the HEAD chunk return a partial cursor on a fetch timeout instead
  of throwing (catch the timeout in `runScanLoop` / the chunk driver and return partial), so
  `ScanProgress` mounts and the resume path engages; and add a "Retry this scan" button to
  the page-level error states, matching the one the chunk-error state already has.

### 2. HIGH — DefinitelyTyped report overflows horizontally at 360 px

- **Where:** `/DefinitelyTyped/DefinitelyTyped` report, 360 px viewport.
- **Evidence:** `scrollWidth 426` vs `innerWidth 360`. The overflowing elements are the
  finding-row GitHub links: `A.github-link`, rect left 43 / right **426** / width 383, text
  "View on GitHub — types/nginstack__datasource/lib/DataSourceDataType.d.ts, line 1"
  (a second one reaches right 369). TechDirect and GitSecure reports are clean at 360 px —
  their file paths are short, so this only bites on reports with long paths, i.e. exactly the
  big-repo reports a phone user is most likely to open.
- **Suggested fix:** let the link wrap — `overflow-wrap: anywhere` on `.github-link`, or
  shorten the visible label to "View on GitHub" and put the long path in a wrapping `<code>`
  element. Re-check at 360 px against the DT report, not just TechDirect.

### 3. HIGH — DefinitelyTyped never finishes locally: 6 minutes of chunking ends in a generic error

- **Where:** `/DefinitelyTyped/DefinitelyTyped`, chunked scan (`ScanProgress`).
- **Evidence:** provisional report at 53.6 s; still provisional at 360 s;
  `report-dt-still-provisional.png` then shows the chunk-error state: "Couldn't scan
  DefinitelyTyped/DefinitelyTyped / GitHub didn't answer as expected. Try again in a bit —
  the scan picks up from the last finished chunk." with a "Retry from where it left off"
  button. The finished report (history + OSV) was never observed in this audit. The cause
  is **not established** from the evidence: the unauthenticated GitHub quota read 55/60
  remaining afterwards, and `server.log` carries no chunk-error line, so I cannot attribute
  it to rate-limit vs. a chunk failure — the UI does not say either.
- **Why it matters:** the huge-repo journey ends in a retry loop with no information: no
  reason for the failure, no "history X of ~92,000 commits checked" progress, and no sense
  of whether retrying will help. Worse, the provisional report below the error card still
  carries the banner "history and dependency checks are still running" — stale copy once the
  driver has errored, directly contradicting the error card above it.
- **Suggested fix:** (a) surface the failure reason in the chunk-error card (rate limit with
  "wait until …" / network / chunk error) and the progress reached; (b) when the chunk driver
  errors, replace the provisional banner's "still running" wording with "paused — history and
  dependency checks stopped here"; (c) consider an honest per-session bound on the history
  walk for DT-scale repos with a note, rather than an unbounded walk that can only end in
  error/retry.

### 4. MEDIUM — the usage map is cluttered at 12 findings / 8 files: truncated labels, overlapping counts

- **Where:** GitSecure self-scan report, secrets Map view.
- **Evidence:** `report-gitsecure-map-full.png`. File labels are clipped mid-word with no
  ellipsis — "test-history.t", "test-usage-pha", "test-scanner.t", "test-triage-ph",
  "phase14-self-s", "test-public-fu" — so two files sharing a prefix are indistinguishable.
  Count labels collide with edges and each other ("35 uses" struck through by dashed edges,
  "12" overlapping the test-usage-phase11 node, a bare "0" sitting on the test-history.ts
  node edge). The S8/S33/S16 cluster in the centre is a knot of crossing dashed edges.
  The track-selection dimming itself works well (`report-gitsecure-map-track2.png`).
- **Suggested fix:** shorten file labels to basename + an ellipsis (or wrap to two lines),
  offset count labels off the edges, and spread the inner ring (or cap rendered findings
  lower) so labels stop colliding at this density.

### 5. MEDIUM — a provisional report says "Scan complete." — contradicting its own banner

- **Where:** any provisional report (observed on DefinitelyTyped).
- **Evidence:** `report-dt-desktop-light.png`: the banner at the top says "Provisional score
  — the current files are scanned, but history and dependency checks are still running",
  and directly below it the summary reads "Scan complete. 4 possible leaked secrets found —
  rotate and remove these first; 136 look like test keys…". Source: `plainSummary()` in
  `src/lib/score.ts` always prefixes "Scan complete. ".
- **Suggested fix:** give the provisional report its own summary prefix ("So far: …" /
  "Current files scanned. …"), or suppress the summary line until the report is finished.

### 6. MEDIUM — a bare owner URL lands on the stock Next.js 404 with no way forward

- **Where:** `/Squ1zM0` (single path segment), and by extension any mistyped mirror URL.
- **Evidence:** `error-single-segment.png` — the unbranded Next.js "404 / This page could not
  be found" page (HTTP 404), no GitSecure header context beyond the topbar, no "Scan another
  repo" link, no hint that the URL shape is `git-secure.com/owner/repo`. The home form would
  have caught this input with a helpful message; a direct URL visit does not.
- **Suggested fix:** add a branded `not-found.tsx` (or a catch-all route) that explains the
  expected `owner/repo` shape and links home. This is a plausible first-time-user typo —
  pasting `git-secure.com/Squ1zM0` from a mirror-URL habit.

### 7. LOW — report summary reads "Scan complete. no leaked secrets…" (lowercase after the period)

- **Where:** TechDirect report hero (any zero-secret report).
- **Evidence:** `report-techdirect-desktop-light.png`, and `src/lib/score.ts:92` pushes the
  lowercase part `"no leaked secrets were found in the files scanned"` which line 96 joins
  after `"Scan complete. "`. Invisible when secrets > 0 (the first part then starts with a
  number).
- **Suggested fix:** capitalise the part to "No leaked secrets were found in the files
  scanned".

### 8. LOW — score-0 dial renders a stray red dot at the top of the ring

- **Where:** DefinitelyTyped provisional report dial (score 0, grade F).
- **Evidence:** `report-dt-desktop-light.png` — a red dot sits at 12 o'clock on the dial ring.
  Cause: the arc uses `strokeLinecap="round"` on a zero-length dash, so the cap draws a dot.
- **Suggested fix:** use `strokeLinecap="butt"` when the fraction is 0 (or skip rendering the
  arc at 0).

### 9. LOW — track detail prints an empty "Used by: ;" when there are no non-test references

- **Where:** GitSecure self-scan, usage map, click finding S8.
- **Evidence:** DOM text of `.map-track-detail`: "Secret 8 — Hardcoded password / secret
  assignment · scripts/test-scanner.ts:106 · **Used by: ;** in tests:
  scripts/test-history.ts:343, … (+25 more)". The non-test list is empty, so the label
  renders with nothing after it.
- **Suggested fix:** omit the "Used by:" segment when the non-test list is empty (or render
  "Used by: nothing in non-test code").

### 10. LOW — the MCP section is the longest thing on the home page and assumes the reader knows what MCP is

- **Where:** home page, "Use with your AI assistant (MCP)" card.
- **Evidence:** `home-desktop-light.png` — the section is ~60% of the page height (four large
  JSON blocks); the "Try it: scan Squ1zM0/GitSecure" link sits below all of it. The copy
  says "Point your AI assistant at GitSecure" and "Paste one of these into your assistant's
  MCP config" without one line saying what MCP is or where that config lives for a
  non-technical user. Separately, every snippet points at `https://gitsecure.vercel.app/mcp`
  while the site now lives at `git-secure.com` — the URL works, but it is not the domain the
  page itself is selling. On mobile the JSON lines are cut off mid-URL with horizontal scroll
  and no scroll affordance (`mcp-home-360.png`).
- **Suggested fix:** one plain line ("MCP lets an AI assistant like Claude call GitSecure for
  you — no account needed"), collapse the four snippets behind client tabs or a
  `<details>`, point the URL at the canonical domain, and add a fade/scroll hint on mobile
  code blocks.

### 11. LOW — the loading screen promises "about 15 seconds"; the baseline repo took 27 s

- **Where:** `loading.tsx`, TechDirect scan.
- **Evidence:** TechDirect finished at 27.1 s this run (earlier phases measured 8–19 s, so
  this varies with network). The loading screen says "A full scan usually takes about 15
  seconds."
- **Suggested fix:** soften to "usually takes 15–30 seconds" or drop the number; the screen
  is otherwise honest and the "nothing to click" line is good.

### 12. LOW — sub-44 px tap targets: the project's own ≥44 px rule has exceptions

- **Where:** everywhere (measured lists in the run logs).
- **Evidence:** `button.copy-btn` and `button.file-chip` are 36 px by design in
  `globals.css` (`min-height: 36px`), overriding the base 44 px rule; inline links measure
  18–22 px tall ("← Scan another repo" 20 px, "View advisory on OSV.dev" / "Link to this
  finding" 21 px, "full JSON report for this repo" 18 px, brand link 32 px). Nothing
  measured as unusable, and the links are ordinary inline text.
- **Suggested fix:** either raise `.copy-btn` / `.file-chip` to 44 px, or restate the rule as
  "controls ≥44 px; inline text links exempt" so the claim matches the CSS.

### 13. LOW — the one-line score explanation names only the top driver and never mentions the rest

- **Where:** TechDirect report hero.
- **Evidence:** `report-techdirect-desktop-light.png` — "83 out of 100 (grade B) is a good
  score. The points lost come from 3 small security-hygiene issues — fixing those would
  raise the score." The report also has 4 dependency vulnerabilities, which the sentence
  never mentions; a reader could conclude the vulns don't matter. (The "How this score
  works" paragraph gives the full split, but only for secrets.)
- **Suggested fix:** append the runner-up ("plus 4 known flaws in dependencies") or show the
  per-component deduction split in the explanation.

### 14. LOW — the scan input has no visible label, only a placeholder

- **Where:** home page scan form.
- **Evidence:** the input carries `aria-label="owner/repo"` and placeholder "owner/repo", but
  no visible `<label>`; once the user starts typing (or the prefilled value is cleared) the
  only cue is gone. The prefilled `Squ1zM0/GitSecure` value mitigates it.
- **Suggested fix:** add a small visible label above the input ("GitHub repo to scan").

### 15. LOW — four different "upgrade to" versions for the same package on one report

- **Where:** TechDirect report, js-yaml 4.1.1 vulnerabilities.
- **Evidence:** `report-techdirect-desktop-light.png` — four LOW findings each say a different
  fix: "Upgrade js-yaml to 4.3.2 or later", "to 3.15.0 or later", "to 4.3.1 or later",
  "to 4.2.0 or later". This is per-advisory OSV data, not a rendering bug, but a user acting
  on the first fix line would pick the wrong target for the others.
- **Suggested fix:** reconcile to a single recommended version per package (the max of the
  advisory fixed versions, or the newest) and say so in the Fix line.

### 16. LOW (known caveat, recorded) — failed scans answer HTTP 200

- **Where:** report page for a missing repo.
- **Evidence:** `GET /thisownerdoesnotexist12345/thisrepodoesnotexist99` returned HTTP 200
  with the "Couldn't find …" page. This is the documented Phase 3 limitation (App Router
  pages cannot set a status; only the API carries the honest status). It matters for
  shared/bookmarked error links and for crawlers, not for the human reading the page.
- **Suggested fix:** none short of a route-handler redirect; keep as a known limitation.

---

## Not checked / could not verify

- **429 (GitHub rate limit) path:** not triggerable safely without burning the shared
  unauthenticated quota; code-reviewed only, as in Phase 3.
- **"Retry from where it left off" button:** offered by the DT chunk-error state, not clicked
  — verifying it needs another multi-minute chunked run.
- **Keyboard Enter on map nodes:** mouse click verified (finding: track works); the legend
  promises Tab + Enter, and nodes are `role="button"` with `tabindex="0"`, but Enter
  activation was not pressed in this audit.
- **Finished DefinitelyTyped report:** never arrived locally in 6 minutes (finding 3).
- **Finished torvalds/linux report:** never arrived locally (finding 1).
- **Reduced motion:** `prefers-reduced-motion` rules exist in CSS; not exercised in the
  browser.
- **Real screen reader:** `aria-live` counts and the dial's `role="img"` label were verified
  in the DOM only, not listened to with a screen reader.
- **429 / timeout via the scan API:** not probed separately from the page flows above.

## Prioritised fix list (for the implementation workers)

1. **Linux dead-end (finding 1):** HEAD-chunk fetch timeouts must return a partial cursor,
   not throw — so `ScanProgress` + resume engage; add "Retry this scan" to page-level error
   states.
2. **DT mobile overflow (finding 2):** make `.github-link` wrap at 360 px; re-verify against
   the DT report.
3. **DT never finishes (finding 3):** surface the chunk-failure reason + progress reached,
   and fix the stale "still running" provisional banner when the driver errors.
4. **Usage map legibility (finding 4):** un-truncate file labels, move count labels off the
   edges, de-clutter the inner ring.
5. **Provisional "Scan complete." (finding 5):** provisional reports need their own summary
   wording.
6. **Branded 404 (finding 6):** `not-found.tsx` for bare-owner / mistyped mirror URLs.
7. **Small copy fixes (findings 7, 8, 9):** "No leaked secrets…" capitalisation, score-0 dial
   dot, empty "Used by: ;".
8. **MCP onboarding (finding 10):** one plain-English line on what MCP is, collapsed snippets,
   canonical-domain URL.

## Files

- Audit: `test-results/phase15-ux-audit.md` (this file)
- Build log: `test-results/phase15/build.log` (exit 0); server log: `test-results/phase15/server.log`
- Screenshots (`test-results/phase15/`): `home-desktop-light.png`, `home-desktop-dark.png`,
  `home-360-light.png`, `home-360-dark.png`, `home-skip-link-focused.png`,
  `loading-desktop.png`, `loading-linux.png`, `linux-progress.png`,
  `report-techdirect-desktop-light.png`, `report-techdirect-desktop-dark.png`,
  `report-techdirect-360.png`, `report-gitsecure-desktop-light.png`,
  `report-gitsecure-desktop-dark.png`, `report-gitsecure-360.png`,
  `report-gitsecure-secrets-open.png`, `report-gitsecure-map.png`,
  `report-gitsecure-map-full.png`, `report-gitsecure-map-track.png`,
  `report-gitsecure-map-track2.png`, `mcp-home.png`, `mcp-home-360.png`,
  `error-404.png`, `error-badformat.png`, `error-single-segment.png`,
  `report-dt-desktop-light.png`, `report-dt-360.png`, `report-dt-360-overflow.png`,
  `report-dt-still-provisional.png`
- Local production server left running on port 3000 for follow-up workers.
