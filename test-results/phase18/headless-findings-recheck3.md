# Phase 18 headless verification — RECHECK-3 findings (Worker C)

Date: 2026-11-27. Server: own `next start` on :3100 (killed after the run;
port 3000 untouched — still 200 after my kill). Browser:
`playwright-core@1.57.0` (in `/tmp/p18`) driving the cached
`~/.cache/ms-playwright/chromium-1255/chrome-linux64/chrome`. No source
files edited. Full assertion log: `headless-run-recheck3.log` (main run
plus the drag re-probe supplement). Script: `recheck3.cjs`.

Self-scan used: Squ1zM0/GitSecure. FINAL report both times — 37 secrets,
12 findings + 8 files drawn, 92 edges. Settled fast this round (14.1s on
first load, 2.0s on the fresh 360px load and the touch context — resumed
scan state, no quota stall). Fit view: 1280px
`translate(219.7 32.0) scale(0.932)`; 360px `translate(32.0 75.0)
scale(0.600)`. The padding-32 fit shrank k ~12% at 1280px (1.058 →
0.932) and ~17% at 360px (0.720 → 0.600) vs recheck2, as designed.

## Verdicts

| # | Check | Result |
|---|-------|--------|
| 1 | Selected-track label stagger (was: 11 labels in one blob over S8) | **FAIL — fix does NOT hold** (see §1) |
| 2 | File labels inside the plane at 360px fit (was: butting/clipped at border) | **PASS** — all 8 inside, light + dark |
| 3 | "N uses" captions separated at 1280px fit (was: "70 uses"/"62 uses" overlap) | **PASS with a hairline caveat** (see §3) |
| 4a | Click finding selects + zooms + detail | **PASS** — finding:0, k 0.932 → 1.851, detail "Secret 1" |
| 4b | Background drag pans | **PASS on re-probe** — delta exactly (+120.0, +60.0), k unchanged (see §4) |
| 4c | Reset view returns to fit | **PASS** — back to `translate(219.7 32.0) scale(0.932)` exactly |
| 4d | Edge labels gated | **PASS** — 0 at fit/nothing selected; 11 selected-track labels at k=1.260; 92/92 past k=1.5 (k=1.819 after 3 toolbar zoom-ins) |
| 4e | Redaction | **PASS** — no `sk-ant-`, no `-----BEGIN` in page text or HTML |
| 4f | 360px overflow | **PASS** — scrollWidth = 360 light and dark |
| 5 | Pinch zoom (first time tested) | **PASS** — CDP two-finger pinch-out, k 0.932 → 4.000 (MAX_ZOOM clamp) |

## §1 — Fix 1 FAILS: the stagger does not separate the S8 fan

Measured on the final report at 360px, Secret 8 selected (richest track,
11 edges, k=1.260, exactly 11 labels visible — the selected track only):

- 11 visible `map-edge-label` texts, 10 of them "used in tests" + 1 "lives in".
- **16 overlapping bbox pairs; max 5 labels overlap any one label's box.**
  The leftmost label at (131.4, 367.1) overlaps five others. Overlap
  areas up to 665 px² (two 67×15px labels almost fully on top of each other).
- Label positions (screen px): x from 131.4 to 227.6, y from 359.6 to 408.1 —
  the whole set sits in a ~96×48px patch. Neighbouring label centres are
  ~8px apart horizontally while each label is 67px wide.
- `selfscan-360-selected-recheck3.png`: visually unchanged from recheck2 —
  the "used in tests" texts still stack into one unreadable blob over S8,
  and the "70 uses" caption is buried in it too. The stagger is visible
  only as a slight diagonal smear of the pile, not as separated labels.

Why the fix is too weak (arithmetic, not speculation): S8 sits on the
inner ring (r=100) and its files on the outer ring (r=140), so its edges
are ~40–90 world units long. Cycling t through [0.35, 0.5, 0.65] moves a
label by 0.15 × edge length ≈ 6–14 world units ≈ 8–17 screen px at
k=1.26 — against a 67px-wide label. Neighbouring labels in the fan still
overlap by ~30–50px. The t-stagger would need to be several times larger
(e.g. spread t across most of the edge, or offset labels perpendicular
to the edge, or collapse same-file+kind parallel edges to one label with
a count — the direction recheck2 already suggested). As implemented, the
selected track of a high-fan-out finding is still unreadable at the exact
zoom where the user reads "what each connection is". Edge detail on click
remains the working fallback.

## §2 — Fix 2 PASSES: file labels inside the plane at 360px

Fresh 360px load, fit view, nothing selected. All 8 file-node labels
measured against the `.map-plane` container box (x=27.0, w=306.0,
y=865.8, h=380.0):

- test-his…ry.ts, test-usa…11.ts, test-sca…er.ts, phase14-…ry.md,
  test-pub…ll.ts, test-tri…10.ts, config.js, README.md — every label's
  box strictly inside the container on all four sides.
- `selfscan-360-light-recheck3.png` and `selfscan-360-dark-recheck3.png`:
  no label touches or crosses the border; side labels (config.js left,
  test-sca…er.ts right) now have clear breathing room. Dark mode readable
  throughout. (The dark shot was taken with the S8 selection still active
  — Reset view is camera-only, so the selected-track label pile from §1
  is visible at the top of the dark shot too.)

## §3 — Fix 3 PASSES, with a hairline caveat

At 1280px fit, all 12 finding-node "N uses" captions measured pairwise:
**0 overlapping pairs** (overlap = >1px intersection in both axes).
Closest pair gap = 0.0px — the two "70 uses" captions (S8/S33 area) touch:
their boxes intersect by a 24.2 × 0.5px sliver, i.e. the box edges just
kiss; the glyphs do not collide. In `selfscan-1280-light-recheck3.png`
the captions read one by one ("70 uses", "62 uses", "50 uses", "0 uses"
all legible, no text-on-text). Verdict is PASS; the 0.5px box touch is
disclosed, not hidden, and is not a visual defect at this size.

## §4 — The main-run drag FAIL is a harness artifact; the re-probe passes

The main run's drag test started the drag at the exact centre of the SVG
— which is the repo node ("This repo", world centre 200,190). A
pointerdown on a node starts a node drag, not a pan, so the view
translate correctly did not move (delta 0,0); the gesture moved the node
instead. Re-probe from a verified background point (elementFromPoint =
`svg`, no node/edge): drag (+120,+60) → translate delta exactly
(+120.0, +60.0), k unchanged at 0.932, and the repo node's screen centre
moved with the pan (640.0,916.5 → 760.0,976.5), confirming a true pan.
The main-run FAIL line is superseded by the re-probe PASS (both lines
are in the log; the supplement is appended after the main run).

## §5 — Pinch zoom (previously untested, now tested)

Touch context (`hasTouch: true, isMobile: true`), final report settled.
Two-finger pinch-out via CDP `Input.dispatchTouchEvent` (touchStart with
two points 40px apart at the map centre, 10 touchMove steps spreading to
280px apart, touchEnd): **k 0.932 → 4.000**, i.e. zoomed all the way to
the MAX_ZOOM clamp. First headless pinch evidence for Phase 18; no
real-iPhone tap test (per design, say so, don't claim one).

## §6 — Method notes / honest gaps

- **Final-report discipline held.** Every assertion in the main run was
  on the settled final report (progress gone + "37 secrets" present;
  14.1s / 2.0s / 2.0s waits). No provisional-report races this round;
  the S8 selection stuck on the first attempt at 360px.
- **Caption measurement threshold.** Overlap counted only when boxes
  intersect by >1px in both axes (SVG text bboxes have sub-pixel
  rounding); the single 0.5px vertical touch in §3 is below that bar
  and is reported explicitly rather than rounded away.
- **Drag re-probe note.** The re-probe's first `elementFromPoint` call
  at the SVG centre returned `null` because the page had not been
  scrolled and the point (y=917) was below the 900px viewport — that
  call only confirmed the probe's geometry, not the product; the
  background-point check (`svg`, no node/edge) is the operative one.
- **Not re-verified this round:** pin-then-pan stability, neighbour
  traverse, reduced motion, TechDirect fallback (unchanged code paths,
  covered in recheck2; this round's scope was the three fixes +
  spot-check regressions + pinch).
- **No real-iPhone tap test** (per design).
