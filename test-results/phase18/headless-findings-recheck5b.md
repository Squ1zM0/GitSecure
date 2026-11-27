# Phase 18 headless verification — RECHECK-5b findings (Worker C)

Date: 2026-11-27 (early morning MST, ~06:00–06:10). Server: own `next start`
on :3100 (killed after the run; port 3000 untouched — still 200 after my
kill). Browser: `playwright-core@1.57.0` (in `/tmp/p18`) driving the cached
`~/.cache/ms-playwright/chromium-1255/chrome-linux64/chrome`. No source
files edited. Full assertion log: `headless-run-recheck5b.log` (main run +
supplement + probe-2 merged; the supplement and probe-2 logs are also kept
separately as `headless-run-recheck5b-supplement.log` and
`headless-run-recheck5b-probe2.log`). Scripts: `/tmp/p18/recheck5b-final.cjs`
(main, adapted from recheck5-final by changing only the repo to
docker/awesome-compose, the settle expectation to 30 secrets, the
sessionStorage key, the 300 s settle cap, and the `-recheck5b` output
names), `/tmp/p18/recheck5b-supplement.cjs`, `/tmp/p18/recheck5b-probe2.cjs`.

Repo used: docker/awesome-compose. FINAL report in every asserted load —
**30 secrets** (14 HEAD + 16 history, as expected), 12 findings + 24 files
drawn (nodes=37), **80 edges** (the task brief's "92 edges" was the
self-scan count; awesome-compose draws 80). Fit view: 1280px
`translate(219.7 32.0) scale(0.932)`; 360px `translate(32.0 75.0)
scale(0.600)` (identical fit transforms to the self-scan runs).

## Headline

**Both round-4 fixes HOLD on the exact metrics they were built for, on this
repo — but the same class of defect survives one step outward.** The zoomed
label overlap is gone (0 pairs at k=1.819, was 6 pairs / worst 1001.6 px²),
and the selected-track cluster label no longer hides behind its own finding
node (0 px² vs the S6 visible circle, was ~46 px behind S8). What remains:
the round-4 push-out clears a label only from its OWN edge endpoints, so
cluster labels now land on NEIGHBOURING nodes and captions instead — on the
richest track both cluster labels sit on finding:8's circle (worst
529.5 px²), at zoom a label collides with the "10 uses" caption (382.7 px²,
visibly reading "10 uslives in ×2"), and tapping a cluster label selects
the node beneath it instead of the edge. The labels themselves stay readable
(paint-last works: text renders on top of the circles, never behind them),
so this is a collision/pointer defect, not a hidden-text defect.

## Scan settle — the recheck-5 stall was repo-specific, as diagnosed

The awesome-compose scan settled cleanly on the strict settle test (30
secrets AND progress card gone AND final report saved in sessionStorage) in
**42.3 s, 43.3 s, 42.4 s, 50.4 s, 44.5 s, 42.3 s** across the six page loads
(main ×2, supplement ×2, probe-2 ×2). The self-scan never settled in 600 s
in recheck-5. The stall was the slow `git clone --bare` of the big GitSecure
pack against the history chunk's 30 s budget, not the code. Confirmed.

## Verdicts

| # | Check | Result |
|---|-------|--------|
| 1 | Zoomed label overlap at k≈1.8–1.9 (was 6 pairs, worst 1001.6 px²) | **PASS** — 0 overlapping pairs |
| 2a | Cluster labels on richest track (was: 11 labels in one blob) | **PASS (corrected)** — 2 labels: `"lives in"`, `"used in code ×10"` |
| 2b | Counted label vs its OWN finding node circle | **PASS (corrected)** — intersection 0 px² |
| 2b-extra | Selected-track labels vs ANY node circle | **FAIL — 3 intersections, worst 529.5 px²** (see §2) |
| 2b-caption | `"lives in"` vs `"10 uses"` caption (was 30 px² graze) | **PASS** — 0 px² |
| 3 | Edge click through a cluster label selects the edge | **FAIL — tap selects finding:8 (Secret 9) instead** (see §3) |
| 3-edge | Direct edge-line click selects the edge | **PASS** — correct file:line detail |
| 3a | Click finding selects + zooms + detail | **PASS (corrected)** — 360: S6 k 0.600 → 1.260; 1280: S11 k 0.932 → 1.851 |
| 3b | Background drag pans | **PASS** — delta exactly (+120.0, +60.0), k unchanged |
| 3c | Reset view returns to fit | **PASS** — exact, both viewports |
| 3d | Label gating (0 labels at fit, nothing selected) | **PASS** — 0 at 360 and 1280 |
| 3e/redaction | Redaction | **PASS** — no `sk-ant-`, no `-----BEGIN` in text or HTML |
| 3f | 360px overflow | **PASS** — scrollWidth = 360 (1280px: 1280) |
| 4 | Screenshots (360 selected / 360 light / 1280 zoomed) | **Looked at** — see §4 |

Combined tally across the three logs: 17 PASS, 7 FAIL. Of the 7 FAIL lines,
3 were harness artifacts corrected to PASS in the supplement (2a, 2b,
3a@1280 — all three hard-coded self-scan specifics: "used in tests",
`finding:0`); the other 4 FAIL lines cover the 2 real defects above
(§2, §3).

## §1 — Zoomed overlap: the threshold fix holds

Nothing selected, 3 toolbar Zoom-in clicks, k=1.819: 10 labels rendered,
3 in viewport (`"lives in ×2"`, `"used in code ×13"`, `"used in code ×9"`),
9 counted overall (incl. `"used in code ×29"`, `"lives in ×4"`,
`"used in code ×14"`). **0 overlapping label bbox pairs** among the
in-viewport labels (recheck-4: 6 pairs, worst 1001.6 px²). The
scale-invariant `edgeLabelThresholdWorld` fix holds on this repo.

Caveat, measured not asserted: the same zoomed view has **12 label vs
visible-node-circle intersections** (worst 2006.2 px², `"used in code ×3"`
vs the repo centre node; others: `"used in code ×13"` vs finding:7 484.8 /
vs finding:5 709.7, `"used in code ×9"` vs finding:8 903.0, `"lives in ×4"`
vs finding:17 1120.8, `"lives in ×2"` vs repo 946.3). Labels paint last,
so the text is on top and legible — but the labels sit on top of node
circles all over the zoomed plane (see §4).

## §2 — Selected track: own-node clear, neighbours not

360px, Secret 6 selected — the richest track on this repo, 11 edges
(**10 "used in code" + 1 "lives in"**; there is no "used in tests" edge on
this track, which is why the main run's 2a/2b FAILs were harness artifacts:
it hard-coded the self-scan S8 kind). Secret 6 is "Committed .env file",
`pihole-cloudflared-DoH/.env:1`, "Likely genuine leak". k=1.260 after
selection, same as S8's 1.260 in recheck-4.

- Exactly 2 visible `map-edge-label` texts: `"lives in"` at (193.3, 560.2),
  36.3×15px, and `"used in code ×10"` at (189.1, 529.1), 89.6×15px. Both
  `pointer-events: none`. **0 overlapping pairs** between them.
- `"used in code ×10"` vs the S6 **visible** node circle (r=15):
  **intersection 0 px²**; vs the invisible hit circle (r=24): also 0 px².
  The recheck-4 defect (left ~46 px behind the node circle) is gone on
  this repo.
- `"lives in"` vs the `"10 uses"` caption: **0 px²** (recheck-4 graze was
  30 px²). `"used in code ×10"` vs the caption: also 0 px².
- **But** — labels vs ANY visible node circle: **3 intersections**:
  `"used in code ×10"` vs finding:8 (Secret 9) **529.5 px²**,
  `"used in code ×10"` vs file `postgresql-pgadmin/.env` 105.8 px²,
  `"lives in"` vs finding:8 46.4 px². The push-out moves the anchor away
  from its own two endpoints only; the cluster centroid then lands on the
  neighbouring finding node that sits right next to S6 in the ring. The
  label text still renders on top (paint-last) and reads fully in the
  screenshot — but the label's box is mostly over another node's circle,
  which is what breaks the tap-through (§3).

## §3 — Edge click: the line works, the label tap does not

- **Through a cluster label: FAIL.** Both selected-track label centres sit
  over finding:8's circle: `"lives in"` centre (211.4, 567.7) →
  `circle -> finding:8`; `"used in code ×10"` centre (233.9, 536.6) →
  `circle -> finding:8`. Clicking either centre selects Secret 9's finding
  detail, not an edge detail. No counted label centre on this track sits
  over an edge hit line at all, so the recheck-4 behaviour ("tap on a label
  falls through to the edge hit line beneath it") does not hold here — the
  thing beneath is a node, and the tap selects that node. In recheck-4 the
  same check passed only because S8's label centre happened to sit over an
  edge.
- **Direct edge-line click: PASS.** Sampling points along edge lines
  (probe-2): clicking `code-5-pihole-cloudflared-DoH/compose.yaml-28` at
  f=0.2 shows the edge detail: *"Secret Committed .env file lives in
  pihole-cloudflared-DoH/.env:1 and is read by
  pihole-cloudflared-DoH/compose.yaml:30. Rotating it means updating that
  file too."* Correct file:line, correct kind. Edge selection itself is
  intact; only the through-label path is hijacked. (Side observation from
  the sampling: at this zoom most sampled edge points are covered by node
  circles — the map is dense, edges are thin targets where exposed.)

## §4 — Screenshots (all looked at)

- `awesome-360-selected-recheck5b.png` — S6 track: both cluster labels
  fully readable, neither hidden behind a node; `"10 uses"` caption and
  `"used in code ×10"` label sit stacked but not overlapping. The map
  region is cramped at 360px (side file labels clip at the plane edge —
  pre-existing fit behaviour, not an edge-label issue). Readable.
- `awesome-360-light-recheck5b.png` — fit, nothing selected: clean, no
  edge labels, all 12 findings + 24 files legible, no collisions.
- `awesome-1280-zoomed-recheck5b.png` — k=1.819: no label is half-hidden
  behind a node (paint-last works), but the plane is cluttered where
  labels sit on nodes/captions: `"used in code ×13"` crosses the S6 node
  circle, `"used in code ×9"` crosses the S9 node and a `compose.yaml`
  file label, and `"lives in ×2"` overlaps the `"10 uses"` caption so the
  two read as one string, **"10 uslives in ×2"**. Measured: that
  label-vs-caption pair intersects by **382.7 px²** (probe-2; the only
  in-viewport label/caption intersection at this zoom). The text stays
  legible because labels paint on top, but the collision is real and
  visible, not a bbox technicality.

## §5 — Harness corrections (why 3 main-run FAILs are not code defects)

- **2a/2b main-run FAILs:** the harness asserted a `"used in tests ×N"`
  label. Secret 6's 11 edges are 10 code + 1 own; no test edges exist on
  this track. The supplement re-measured with the actual counted kind
  (`"used in code ×10"`): labels present, 0 overlaps, 0 px² vs own node.
- **3a@1280 main-run FAIL:** the harness clicked `finding:0` ("node not
  found in DOM"). The 12 drawn findings on this repo are
  `finding:5, 7, 8, 9, 10, 12, 13, 14, 15, 17, 18, 24` — finding:0 is not
  drawn (the drawn set is the findings with usage, not the first 12 by
  index). The supplement clicked the first drawn node, finding:10
  (Secret 11): selected first attempt, k 0.932 → 1.851, detail correct.

## §6 — Remaining defects (for the next fix round)

1. **Cluster labels are pushed clear of their own endpoints but not of
   neighbouring nodes/captions.** Evidence: §2 (3 intersections on the
   selected track, worst 529.5 px² vs finding:8) and §1/§4 (12 intersections
   at zoom, worst 2006.2 px²; 1 caption collision, 382.7 px², visibly
   "10 uslives in ×2"). A fix would need the push-out / placement to
   consider all nearby nodes and captions, not just the edge's endpoints —
   or a second-pass collision pass over labels vs node circles/captions.
2. **Tapping a cluster label can select a neighbouring node instead of the
   edge.** Consequence of (1): on S6's track both label centres sit over
   finding:8, so the tap selects Secret 9. The `pointer-events: none`
   fall-through only reaches the edge when the edge is actually beneath
   the tap point.

## §7 — Method notes / honest gaps

- The strict settle test from round 4 was used for every load (30 secrets
  AND progress card gone AND final report saved in sessionStorage
  `gitsecure:report:docker/awesome-compose`); no assertions were made on a
  provisional report.
- The zoomed label-vs-node-circle and label-vs-caption numbers are
  bounding-box intersections, not glyph-level collisions; the screenshots
  are the visual cross-check and agree with the numbers.
- No real-iPhone tap test (per design).
- The 360px selected screenshot shows Reset view focused (toolbar click
  from the earlier run); cosmetic only.
