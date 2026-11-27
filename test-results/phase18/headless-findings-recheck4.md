# Phase 18 headless verification — RECHECK-4 findings (Worker C)

Date: 2026-11-27 (early morning MST, ~05:00–05:40). Server: own `next start`
on :3100 (killed after the run; port 3000 untouched — still 200 after my
kill). Browser: `playwright-core@1.57.0` (in `/tmp/p18`) driving the cached
`~/.cache/ms-playwright/chromium-1255/chrome-linux64/chrome`. No source
files edited. Full assertion log: `headless-run-recheck4.log` (main run +
appended supplement); supplement log also kept separately as
`headless-run-recheck4-supplement.log`. Scripts: `/tmp/p18/recheck4-final.cjs`,
`/tmp/p18/recheck4-supplement.cjs`, `/tmp/p18/probe-s8.cjs` (diagnostic).

Self-scan used: Squ1zM0/GitSecure. FINAL report in every asserted run —
37 secrets, 12 findings + 8 files drawn, 92 edges. Fit view: 1280px
`translate(219.7 32.0) scale(0.932)`; 360px `translate(32.0 75.0)
scale(0.600)` (identical to recheck3).

## Headline

**The clustering fix HOLDS on the case it was built for, but does NOT
fully hold at zoom.** The recheck-3 FAIL is fixed on the selected track:
S8's 11 labels collapse to exactly 2 — `"lives in"` + `"used in tests
×10"` — with **0 overlapping label bboxes** (was 11 labels, 16
overlapping pairs, max 5 on one). But zoomed past k=1.5 with all 92
edges labelled, **6 overlapping pairs remain** (worst 1001.6 px²),
reproduced identically in two independent runs. The threshold (~70
screen px) is smaller than the rendered counted labels (up to 130 px
wide), so clusters whose centroids clear the threshold still overlap.
Plus two small visual defects on the selected track itself (§1c).

## Verdicts

| # | Check | Result |
|---|-------|--------|
| 1a | Cluster labels on S8 selected track (was: 11 labels in one blob) | **PASS** — 2 labels: `"lives in"`, `"used in tests ×10"` |
| 1b | Zero overlapping label bboxes on S8 track | **PASS** — 0 pairs (was 16) |
| 1c | Selected track readable one label at a time (screenshot) | **PASS with 2 caveats** (see §1) |
| 2 | Counted cluster labels at zoom (k > 1.5) | **PASS** — 18 labels, 13 counted (`×2`–`×18`) |
| 2b | Zero overlapping label bboxes at zoom | **FAIL — 6 overlapping pairs, worst 1001.6 px²** (see §2) |
| 3 | Edge click through a cluster label selects the edge | **PASS (corrected)** — see §3; the main-run FAIL line was a harness bug |
| 4a | Click finding selects + zooms + detail | **PASS** — S8: k 0.600 → 1.260; S1: k 0.932 → 1.851 |
| 4b | Background drag pans | **PASS** — delta exactly (+120.0, +60.0), k unchanged |
| 4c | Reset view returns to fit | **PASS** — exact, both viewports |
| 4d | Label gating (0 labels at fit, nothing selected) | **PASS** — 0 at 360 and 1280 |
| 4e | Redaction | **PASS** — no `sk-ant-`, no `-----BEGIN` in text or HTML |
| 4f | 360px overflow | **PASS** — scrollWidth = 360 (1280px: 1280) |

## §1 — The clustering fix holds on the selected track

360px, Secret 8 selected (richest track, 11 edges), k=1.260:

- 2 visible `map-edge-label` texts: `"lives in"` at (223.6, 542.4),
  36.3×15px, and `"used in tests ×10"` at (164.6, 485.3), 89.4×15px.
  Exactly the design prediction (10 test + 1 own, own never merges
  with test). Both `pointer-events: none`.
- **0 overlapping pairs** between the two labels (was 16 pairs in
  recheck3).
- `selfscan-360-selected-recheck4.png`: the blob is gone. The track
  reads one label at a time. Two caveats, both visible in the shot
  and measured:
  1. The `"used in tests ×10"` label is centred so close to the S8
     node that its left ~46 px sits **behind the node circle**
     (finding nodes paint after the labels, so the node covers the
     label). It reads as `"tests ×10"` — the `"used in "` prefix is
     occluded. Measured against the node's r=24 hit circle:
     45.7×15.0 px overlap.
  2. The `"lives in"` label overlaps the `"70 uses"` caption box by
     3.9×7.8 px (~30 px²). Small; in the screenshot the two sit
     tight together and the label reads as `"…es in"` next to the
     caption. Not text-on-text at glyph level, but they touch.

## §2 — At zoom, 6 overlapping pairs remain (FAIL)

Nothing selected, 5 toolbar Zoom-in clicks, k=1.831 (threshold
70/k = 38.2 world units). 18 labels rendered, all 18 in viewport,
13 of them counted: `"used in tests ×18"`, `"×16"`, `"×10"`, `"×9"`,
`"×8"` (×2), `"×4"`, `"×2"` (×2), `"lives in ×3"` (×2), `"lives in
×2"` (×2). Overlapping pairs (identical coordinates in both runs):

| Pair | Overlap area |
|---|---|
| `"lives in ×3"` vs `"used in tests ×9"` | **1001.6 px²** (51.1×19.6) |
| `"used in tests ×8"` vs `"used in tests"` | 699.1 px² (34.1×20.5) |
| `"lives in ×3"` vs `"used in tests ×2"` | 427.1 px² (33.9×12.6) |
| `"lives in ×3"` vs `"used in tests"` | 365.3 px² (28.1×13.0) |
| `"used in tests ×9"` vs `"used in tests"` | 54.1 px² (3.3×16.4) |
| `"used in tests ×8"` vs `"lives in"` | 22.4 px² (18.7×1.2) |

`selfscan-360-zoomed-recheck4.png` (supplement) shows it: `"70
uses"` captions stacked over `"used in tests ×9"`, `"used in tests
×8"` crossing `"lives in"`, counted labels colliding mid-map, and
several labels half-hidden behind the centre "This repo" node
(labels paint before nodes).

Why it still overlaps (arithmetic, not speculation): the threshold
is ~70 screen px — one *uncounted* label width. Counted labels are
much wider: `"used in tests ×18"` is 130 px, `"used in tests ×9"`
120.6 px, plain `"used in tests"` 97.5 px. Two cluster centroids
can clear the 70 px threshold and still have their 120–130 px
labels overlap by 30–50 px. Same-kind pairs overlap too
(`"×8"` vs plain `"used in tests"`, 699 px²), so it is not only the
by-kind split: the threshold is simply smaller than the labels it
separates. A fix would need a threshold derived from the rendered
label width (or a second-pass collision pass), not a fixed 70 px.

## §3 — Edge click through a cluster label: PASS (main-run FAIL was mine)

`elementFromPoint` at the centre of `"used in tests ×10"` returns
the edge hit line (`line -> test-19-scripts/test-history.ts-449`),
proving `pointer-events: none` lets the tap fall through. Clicking
there shows the edge detail: *"Secret Hardcoded password / secret
assignment lives in test-results/phase14-self-scan-inventory.md:314
and is read by scripts/test-history.ts:449 in a test — it proves the
value is exercised, not that production uses it."* Correct file:line,
correct kind.

The main-run log line says FAIL only because my assertion required
the literal text `"Secret 8"` in the panel — but `edgeDetailText`
names the finding by *title*, never `"Secret N"`, so that string
cannot appear. Harness bug, corrected in the supplement run (PASS),
and the correction is appended to `headless-run-recheck4.log`.

## §4 — No regressions

- 4a: S8 click at 360px selects on first attempt (detail "Secret 8 —
  Hardcoded password / secret assignment · scripts/test-scanner.ts:106"),
  k 0.600 → 1.260. S1 click at 1280px, k 0.932 → 1.851.
- 4b: drag from a verified background point (elementFromPoint =
  `svg`) (+120,+60) → translate delta exactly (+120.0, +60.0), k
  unchanged.
- 4c: Reset view returns to the exact fit transform at both
  viewports; after Escape+Reset the detail panel is back to the
  empty hint.
- 4d/4e/4f: as table above.

## §5 — Screenshots (all looked at)

- `selfscan-360-selected-recheck4.png` — S8 track readable, blob
  gone; caveats §1c (label behind node, label touching caption).
- `selfscan-360-light-recheck4.png` — fit, nothing selected: clean,
  no labels, file labels inside the plane, no collisions.
- `selfscan-1280-light-recheck4.png` — fit, nothing selected: clean,
  all 12 findings + 8 files legible, no label collisions.
- `selfscan-360-zoomed-recheck4.png` (supplement) — k=1.831: counted
  labels present but colliding (§2); several labels half-hidden
  behind nodes.
- `probe-s8-recheck4.png` (diagnostic only) — the list view the page
  falls back to when the provisional report is replaced; see §6.

## §6 — Method notes / honest gaps

- **The scan stall, and the provisional-report trap.** The first
  run never settled in 180s and a diagnostic tab sat at "0 files
  scanned so far" for 300s: the HEAD chunk downloads a 74.8 MB
  tarball (~11.5 s from this VM) and must fit download + extract +
  scan in the ~30 s chunk budget, so attempts time out and the
  page's driver retries them. I extended the wait to 600 s; the
  browser's own driver then settled the FINAL report in 14.2 s /
  28.3 s / 13.2 s across the three loads. (A curl-driven chunk
  chain of mine produced an 18-secret "done" report — discarded:
  bare-cursor resumes drop history findings by design; only the
  browser-driven report counts.)
- **Run 2 died on the provisional report.** "37 secrets" with no
  "Scanning" text fires while the scan is still running: the page
  renders a *provisional* report plus the progress card, and when
  the real report lands the provisional `ReportView` unmounts and a
  fresh one mounts, wiping Map state (the map vanished ~2 s after
  I opened it, and the S8 node sat below the fold at viewport
  y=1049, so the click hit nothing). The corrected settle test —
  37 secrets AND the progress card gone AND the final report saved
  in sessionStorage (`gitsecure:report:Squ1zM0/GitSecure`) — is what
  the good runs used. The probe that found this is
  `/tmp/p18/probe-s8.cjs`.
- **Clicking below the fold.** At 360px the S8 node sits below the
  viewport after opening the map; the scripts scroll the target
  into view and re-measure before clicking (and log
  `elementFromPoint` first). Any future headless run must do the
  same — a raw click at the pre-scroll coordinates hits thin air.
- **No real-iPhone tap test** (per design).
- The 360px selected screenshot shows Reset view focused (my
  toolbar click); cosmetic only.
