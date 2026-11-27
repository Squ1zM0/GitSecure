# Phase 18 headless verification — findings (Worker C)

Date: 2026-11-27. Server: own `next start` on :3100 (killed after the run;
port 3000 untouched). Browser: `playwright-core@1.57.0` (installed in
`/tmp/p18`, NOT in the repo) driving the cached
`~/.cache/ms-playwright/chromium-1255/chrome-linux64/chrome`. No source
files edited. Full assertion log: `headless-run.log` (+ `headless-recheck.log`
for the three re-checked items).

Self-scan used: Squ1zM0/GitSecure, final report — 37 secrets, 12 findings +
8 files drawn, 92 edges, 92 edge labels. Fit view:
`translate(194.4 8.0) scale(1.058)`.

## Verdicts

| # | Check | Result |
|---|-------|--------|
| 3a | Click finding node (mouse) → detail + recentre/zoom | **FAIL** — real defect (see §1) |
| 3a-ctrl | Same via keyboard Enter | PASS — "Secret 1", k 1.058 → 2.000 |
| 3b | Drag background → pan | **FAIL** — real defect (see §2) |
| 3c | Wheel zoom (`page.mouse.wheel`) | PASS — k 2.000 → 4.000 (MAX); no dispatchEvent fallback needed |
| 3d | Pin → aria-pressed + pin mark; world pos stable across camera move | PASS — aria-pressed=true, `.map-pinned-mark` present before/after wheel zoom, cx/cy `113.397…/240.0` identical. Caveat: the prescribed background-drag half is vacuous while 3b is broken (the drag moves nothing), so pin stability was verified across a real camera move (wheel) instead. |
| 3e | Traverse Next + Go to → breadcrumb grows, selection changes | PASS (corrected — see note) — crumbs 2 → 3 `["This repo","Secret 1","test-pub…ll.ts"]`, detail panel switched to the file node. Note: "Next neighbour" alone only moves the pointer (crumbs unchanged); the crumb grows on "Go to", per the markup. Separator is `›`, not `>`. |
| 3f | Click edge midpoint (mouse) → edge detail | **FAIL** — real defect (see §1), confirmed with an on-screen target (674.5, 648.2) |
| 3f-ctrl | Same via keyboard Enter on the edge | PASS — "Secret Hardcoded password … lives in scripts/test-scanner.ts:106 and is read by scripts/test-history.ts:431 in a test …" + `scripts/test-history.ts:431 · used in tests` |
| 3g | Toolbar Zoom in / Reset view | PASS — zoom-in k 2.000 → 2.500; Reset returned exactly to fit `translate(194.4 8.0) scale(1.058)` |
| 3h | Edge labels visible | PASS — 92/92 visible; "used in tests" + "lives in" present ("used in code" absent in this dataset — 0 code-kind edges drawn) |
| 3i | Reduced motion → no `map-animated` | PASS — world `<g>` class `""` on open and after select |
| 4 | Redaction spot check | PASS — no `sk-ant-`, no `-----BEGIN` in map plane/detail/breadcrumb, nor anywhere on the page |
| — | 360px overflow, self-scan light + dark | PASS — `documentElement.scrollWidth` = 360 both |
| — | 360px overflow, TechDirect | PASS — scrollWidth = 360 |
| — | TechDirect no-usage fallback (FileMap) | **NOT VERIFIABLE as specified** (see §3) |

## §1 — Mouse/tap selection of nodes and edges is broken (3a, 3f)

A real mouse click on a finding node (on-screen point 548.4, 743.4) leaves
the detail panel on its empty state and the transform untouched. Keyboard
Enter on the same node selects + zooms correctly, so `selectNode`/
`selectEdge` themselves work — only the pointer path is broken.

Root cause, proven by event instrumentation (probe 1): `onPointerDown`
calls `e.currentTarget.setPointerCapture(e.pointerId)` on the svg. Pointer
capture retargets the subsequent `pointerup` AND the `click` to the svg, so
React's `onClick` on the node/edge `<g>` never fires (observed:
`pointerdown target=text`, `pointerup target=svg`, `click target=svg`).
The design doc assumes "the click event fires after pointerup" on the node —
capture breaks that assumption, for mouse and touch alike. Fix direction
(for Worker B, not done here): select on `pointerup` when `isTap()` using
the gesture's node/edge id, instead of relying on `onClick`.

## §2 — Background drag does not pan (3b)

Real-mouse background drags (viewport coords, confirmed background target)
produce zero `transform` mutations (MutationObserver) at fit zoom and at
k=2. The pan math is fine — `panBy`/`setView` work (wheel zoom and toolbar
zoom both move the view) and **node dragging works through the same
`onPointerMove`** (probe 3: finding:0 cx 113.4 → 170.1, cy 240 → 268.4).

Root cause, proven by arithmetic on a synthetic dispatch (probe 5): the pan
branch computes the delta *inside* the `setView` updater —
`setView((v) => panBy(v, pt.x - g.last.x, pt.y - g.last.y, w, h))` — but
assigns `g.last = pt` synchronously right after the `setView` call, before
React invokes the updater. The updater therefore always reads
`g.last === pt` and computes dx=dy=0. When six moves were dispatched
synchronously in one task, the batched updaters summed
Σ(pt_i − pt_final) = (−300, −150) — exactly the observed jump, confirming
the mechanism. The node branch is immune because it computes `pos`
eagerly as numbers before `setOverrides`. Fix direction: hoist the deltas
into locals before `setView` (`const dx = pt.x - g.last.x; …; g.last = pt;
setView((v) => panBy(v, dx, dy, w, h))`). Disabling `setPointerCapture`
(probe 6) did NOT fix pan, so capture is not the pan culprit.

## §3 — TechDirect fallback premise does not hold

TechDirect's completed report is 83/B with "No leaked secrets were found"
— and `ReportView` only mounts `SecretsList` when `report.secrets.length >
0`, so there is no secrets section and no map of any kind. The FileMap
fallback (`ReportLists.tsx:687`, `if (!hasUsage) return <FileMap …/>`)
only renders when a report HAS secrets but NONE have usage data. No such
report was available in this run, so the fallback was **not verified**.
The `techdirect-*.png` shots show the completed 83/B report top (no map),
not a fallback map.

## Visual defects (from the screenshots)

1. **Default fit view is a hairball.** 12 findings + 8 files + 92 edges with
   a label on every edge, in a 400×380 world: at fit zoom the centre is an
   unreadable stack of overlapping "used in tests" / "used in code" /
   "lives in" labels and "N uses" captions (light and dark, 1280 and 360).
   The design's claim that labels stay readable at default zoom does not
   hold at this density. The map only becomes readable after zooming to a
   node — which mouse users currently cannot do (§1).
2. **360px after interaction: map slides mostly off-screen.** Fresh load at
   360px fits correctly (dark shot). But after any interaction
   (`interactedRef=true`) a resize does NOT refit by design, so the
   1280-fit transform persists in a 304px-wide plane: the light 360 shot
   shows an almost-empty box with nodes cut off at the right edge. Only
   "Reset view" recovers it. By-design tradeoff, but the visual result is
   poor; worth a call on whether resize-after-interaction should re-fit
   when the world no longer fits.
3. Otherwise clean: dark mode readable throughout, toolbar wraps 2×2 at
   360px, no horizontal overflow anywhere, detail panel and breadcrumb
   legible at both widths.

## Method notes / honest gaps

- The report page remounts when the scan's final chunk lands
  (`setFinalReport` → fresh `ReportView` → view state resets to List).
  All interaction runs waited for the FINAL report (progress card gone)
  before opening the map; earlier runs that opened the map on the
  provisional report saw the map unmount mid-test.
- Pinch zoom was NOT tested (no touch emulation in this run) — the design
  already records it as headless-emulation-only; same gap stands.
- No real-iPhone tap test (per design, say so, don't claim one).
- Node drag (move a node) works via real mouse — verified in probe 3.
