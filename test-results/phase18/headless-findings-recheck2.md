# Phase 18 headless verification — RECHECK-2 findings (Worker C)

Date: 2026-11-27. Server: own `next start` on :3100 (killed after the run;
port 3000 untouched — see §6). Browser: `playwright-core@1.57.0` (installed
in `/tmp/p18`, NOT in the repo) driving the cached
`~/.cache/ms-playwright/chromium-1255/chrome-linux64/chrome`. No source
files edited. Full assertion log: `headless-run-recheck2.log` (runs
recheck2, recheck3/supplemental, recheck4/final, recheck5/tail, plus the
TechDirect proper-control addendum).

Self-scan used: Squ1zM0/GitSecure. Final report — 37 secrets, 12 findings +
8 files drawn, 92 edges. Fit view: `translate(194.4 8.0) scale(1.058)`.
360px fit: `translate(8.0 52.2) scale(0.720)`.

## Verdicts

| # | Check | Result |
|---|-------|--------|
| 1 | Mouse/tap click finding node S1 → detail + recentre/zoom (was FAIL 3a) | **PASS** — detail "Secret 1", selected `finding:0`, `translate(194.4 8.0) scale(1.058)` → `translate(-124.6 -235.3) scale(1.851)` |
| 1b | Click edge midpoint (mouse) → edge detail (was FAIL 3f) | **PASS on re-probe** — "Secret Hardcoded password / secret assignment lives in scripts/test-scanner.ts:95 — this is the file the secret itself sits in." + `scripts/test-scanner.ts:95 · lives in` + "Show Secret 6". See §1 for why run 1 said FAIL |
| 2 | Drag background → pan (was FAIL 3b) | **PASS** — delta exactly (120.0, 60.0) for a (120, 60) drag; k unchanged |
| 3 | Pin, then pan → pinned node world pos stable (was vacuous) | **PASS, now non-vacuous** — aria-pressed=true, pin mark present before+after pan, cx/cy `286.6025403784439`/`240` IDENTICAL while the view panned `translate(-124.6 -235.3)` → `translate(-4.6 -175.3)` at k=1.851 |
| 4a | Label gating at fit, nothing selected | **PASS** — 0 `map-edge-label` elements in the DOM at k=1.058 |
| 4b | Selected track's labels visible below k=1.5 | **PASS (clean, final report)** — at 360px, k=1.260 after selecting Secret 8: exactly 11 labels = the 11 edges of Secret 8's track, of 92 total |
| 4c | Zoom past k=1.5 → non-selected edge labels appear | **PASS** — k 1.058 → 1.322 → 1.653, labels 0 → 0 → 52 (all edges) |
| 5 | Responsive zoom target @360px | **PASS** — k=1.260 (< 2); selected node + repo centre both inside the 306×380 plane. Note: design doc's "~1.5" is approximate — the formula gives fitK 0.720 × 1.75 = 1.26 for the 306px-wide plane |
| 6a | Wheel zoom (`page.mouse.wheel`) | **PASS** — k 1.058 → 2.602 |
| 6b | Toolbar Zoom in / Reset view | **PASS** — zoom-in k 2.602 → 3.253; Reset returned exactly to fit `translate(194.4 8.0) scale(1.058)` |
| 6c | Traverse Next + Go to | **PASS (corrected assertion)** — crumbs 2 → 3 `["This repo","Secret 1","test-pub…ll.ts"]`, detail switched to the traversed file node |
| 6d | Redaction | **PASS** — no `sk-ant-`, no `-----BEGIN` in map plane/detail/breadcrumb, nor anywhere on the page |
| 6e | 360px overflow | **PASS** — `documentElement.scrollWidth` = 360: self-scan light, self-scan dark, TechDirect |
| 6f | Reduced motion | **PASS with caveat** — world `<g>` class `""` on open and after select-attempt, no `map-animated`. Caveat: the selection itself did not stick in the reduce context (see §4) |
| — | TechDirect no-usage fallback (FileMap) | **NOT VERIFIABLE as specified** (same as round 1, see §5) |

## §1 — The run-1 edge-click FAIL was a scan-chunk race, not a product defect

The first recheck2 run recorded 1b as FAIL: a mouse click on an edge
midpoint left the detail panel on its empty state. The instrumented
re-probe (recheck3) clicked the identical point (698.6, 712.2) and it
worked. The instrumentation proves the fixed pointer path:

- `pointerdown target=line, edge=own-5` — the hit line receives the press.
- `pointerup target=svg`, `click target=svg` — capture retargets both to
  the svg, exactly as the fix round describes, and selection happens on
  pointerup from the gesture record anyway.
- The clicked edge was `own-5` (Secret 6), not the computed target
  `own-15`: parallel overlapping edges share the midpoint, and the click
  correctly selected the topmost one.

Why run 1 failed: both early runs were on the PROVISIONAL report (18
secrets, scan still chunking). When a scan chunk lands, the findings
array is replaced and the component's `useEffect([findings])` clears the
selection by design. A chunk landing inside the 600ms click→read window
erases a just-made selection. The same race produced the run-1 4b FAIL
(selection read as null after Reset view) and is the likely cause of the
unsticky selection in the reduced-motion context (§4). The decisive
re-probes ran on the settled final report (recheck4: scan quiet, progress
gone, 37 secrets / 92 edges) and passed first try.

## §2 — The three other run-1 FAIL lines are harness artifacts, corrected

- **4c (run 1):** the script selected a node first, which already pushed
  k to 1.851 (> 1.5), so all 52 labels were visible before the toolbar
  zoom-ins — there was no increase left to measure. The isolated re-probe
  (zoom only, nothing selected) shows the gate cleanly: 0 labels at
  k=1.058 and k=1.322, all 52 at k=1.653.
- **6c (run 1):** the script asserted selection via `g.map-node-selected`,
  a class file nodes never get — the same harness error round 1 already
  corrected for 3e. Breadcrumb growth (2 → 3) + detail switch is the real
  check, and it passes.
- **4b (recheck3):** the selection was cleared by a scan chunk before the
  read (see §1). The clean proof is recheck4 §4b above.

## §3 — Visual defects (from the `-recheck2` screenshots, final report)

1. **FIXED: the fit-view hairball is gone** — 1280px and 360px, light and
   dark. Zero edge labels at fit zoom; the spider reads as dashed/solid
   edges with node captions. The fix round's label gating does what it
   claims.
2. **REMAINING (moderate): selected-track label pile-up.** When a finding
   has many parallel edges to the same file, the labels sit at
   near-coincident midpoints and stack unreadably — see
   `selfscan-360-selected-recheck2.png`: Secret 8's 11 labels
   ("used in tests" ×~6 plus "lives in") overlap into one pile under S8,
   with the "70 uses" caption overlapping the stack too. The ±6-world-unit
   perpendicular offset separates the LINES but not the ~70px-wide
   identical label texts. The edge DETAIL on click still works as the
   fallback, and the fit view stays clean — but the zoomed selected track
   is exactly where the user reads "what each connection is", so for
   high-fan-out findings the labels defeat their purpose. Suggested
   direction (not implemented): stagger parallel-edge labels along the
   edge, or collapse same-file+kind parallel edges to one label with a
   count.
3. **REMAINING (minor): "N uses" caption collisions in the centre cluster
   at fit zoom.** S8 "70 uses" overlaps S16/S33 "62 uses" captions (1280
   light+dark; worse at 360 dark). The Phase 15 caption staggering (±14px)
   does not separate adjacent high-ref findings. Counts stay legible, but
   text overlaps text.
4. **REMAINING (minor): outer file labels touch the plane edge at 360px
   fit.** "test-sca…er.ts" (right) and "config.js" (left) sit right at the
   plane border, borderline clipped. The label x-clamp (42..358 world)
   does not account for text width at small k.
5. Cosmetic only: the `:focus-visible` outline around a clicked node
   renders as a large heavy black rounded rect (S8 in the 360-selected
   shot). Prominent, but correct as a focus indicator.

Otherwise clean: dark mode readable throughout, toolbar wraps 2×2 at
360px, no horizontal overflow anywhere, dim-others-on-select works (the
360-selected shot shows the selected track at full strength, rest dimmed),
detail panel and breadcrumb legible at both widths.

## §4 — Reduced-motion caveat

World `<g>` class is `""` (no `map-animated`) on open in the
`reducedMotion: 'reduce'` context, and still `""` after the select
attempt — the class criterion passes. But the selection itself did not
stick in that context: both a real mouse click and a DOM-focus+Enter
fallback read back `selected=null`. Most plausible cause is the §1
scan-chunk race (that context's scan was still streaming provisional
chunks). Round 1 verified class `""` after a *successful* keyboard
select, so the combined evidence is solid; the "after select" sample in
this round is the weaker half.

## §5 — TechDirect control

Settled page (completion marker "No leaked secrets were found" reached in
2.8s on a resumed scan; provisional score 91/A at that point): the page
renders `H2: Leaked secrets (0)` but `SecretsList` never mounts — no
`.view-toggle`, no `.map-plane`, no `.map-toolbar`. The FileMap fallback
(`ReportLists.tsx`, `if (!hasUsage) return <FileMap …/>`) only renders
when a report HAS secrets but NONE have usage data, and TechDirect has 0
secrets, so the fallback is still **not verifiable** via TechDirect — same
finding as round 1. (I did not re-verify the final 83/B TechDirect score
in this round; the 2.8s run saw the provisional 91/A.) 360px overflow on
the settled TechDirect page: scrollWidth = 360, PASS.

## §6 — Method notes / honest gaps

- **Provisional vs final report.** The first two runs ran on the
  PROVISIONAL self-scan (18 secrets, 52 edges) because the scan stalled
  with the progress card still present after 120s / 300s waits — the
  chunk driver appears to pause on the unauthenticated GitHub quota
  (the local `next start` has no `GITHUB_TOKEN`; the shared 60/hr core
  quota showed 53 remaining at one check). The final run (recheck4)
  reached the FINAL report (37 secrets, 92 edges, progress gone) and
  the decisive re-probes (4b, 5, 6e-dark, screenshots) were done there.
  Items 1/1b/2/3/6a/6b/6c/6d were verified on the provisional report
  only — the code paths are identical, but the counts differ (52 vs 92
  edges). The 1b instrumented re-probe was also provisional; its
  mechanism (pointerup selection) is count-independent.
- **Runtime restart mid-task.** The VM runtime restarted during the
  final pass: `/tmp` was wiped (scripts + the playwright-core install)
  and both servers died — :3100 (mine) and :3000 (another job's).
  I rebuilt `/tmp/p18`, reinstalled `playwright-core@1.57.0`, restarted
  ONLY my :3100 server from the existing `.next` build (same BUILD_ID
  `_x2qJZ97jeumzDn3UyNxu`), and re-ran the final pass verbatim. I did
  not touch :3000; it was still down after the restart (not restarted
  by me). The pre-restart final-pass screenshots (04:42) survived in the
  workspace and were retaken identically by the re-run.
- **Item 5 method.** The 360px zoom-target check ran on the same settled
  page via viewport resize + Reset view (avoids a second full scan);
  Reset view recomputes fit from the live container size, so the
  measurement is equivalent to a fresh 360 load.
- **Dark screenshots** via `page.emulateMedia({colorScheme: 'dark'})` —
  the theme is `prefers-color-scheme` driven, same page, no re-scan.
- **Log note.** The tail section was appended twice by a script bug (the
  second copy adds only the "done" line); the saved
  `headless-run-recheck2.log` has been deduped, and the TechDirect
  proper-control results appended as an addendum.
- **Pinch zoom was NOT tested** (no touch emulation in this run) — same
  gap as round 1; the design already records it as
  headless-emulation-only.
- **No real-iPhone tap test** (per design, say so, don't claim one).
