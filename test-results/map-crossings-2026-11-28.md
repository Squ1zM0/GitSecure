# Map edge crossings - measurement and fix (2026-11-28)

Freddy, from his screenshot of the swapped self-scan map: "we need to
have the connected on the same side so that line don't intersect".
And: "it's gonna be free to expand out just pass those circles
outward".

## What was measured

Tool: /tmp/measure-crossings.mjs (replicates ReportLists.tsx
basePositions + edges exactly) on the live self-scan report
(GET /api/scan/Squ1zM0/GitSecure, 39 secrets, 24 drawn, 10 files,
0 posture). Edges counted once per unique (from, to) pair;
crossings exclude shared endpoints.

Baseline (first-claim rule, drawn order): **202 crossings**
- own+own 33, own+test 101, test+test 68. 54 unique edges.
- Max edge span 180 degrees, mean 71 degrees.

Root cause: the four shared test files were all claimed by S8 (the
first drawn finding), so they all sat in S8's sector at 276-315
degrees. Fourteen own edges from findings on the other side of the
map (S2-S7 at 71-135 degrees own test-scanner.ts; S10-S14 at
161-212 degrees and S15/S23 own test-usage-phase11.ts) crossed the
whole map to reach them. At fit zoom only own edges are visible
(test edges hide below k=1.5), so the 33 own+own crossings are
exactly what Freddy saw.

## Variants tried (tool: /tmp/ab-crossings.mjs)

| Variant | Total | own+own | own+test | test+test | max span |
|---|---|---|---|---|---|
| A current (drawn order, first-claim) | 202 | 33 | 101 | 68 | 180 deg |
| B greedy order + median claim | 155 | 4 | 60 | 91 | 173 deg |
| C greedy order + first-claim | 200 | 31 | 101 | 68 | 180 deg |
| D drawn order + median claim | 153 | 5 | 60 | 88 | 173 deg |
| E weighted greedy + median claim | 129 | 0 | 27 | 102 | 160 deg |
| F E + first referencer for unowned files | 141 | 0 | 20 | 121 | 180 deg |
| G E + last referencer for unowned files | 140 | 0 | 28 | 112 | 180 deg |

The median claim is what matters (C shows ordering alone does
nothing; D shows claiming alone gets most of it). The weighted
greedy (a shared own file counts 10, a shared reference 1) gets
own+own to 0. Variant E was shipped: greedy order
S8 S35 S2 S3 S4 S5 S6 S7 S17 S18 S21 S22 S15 S23 S10 S11 S12 S13
S14 S1 S9 S16 S20 S19, median claim (A to S3, B to S11, C to S18,
D/E to S18, H to S16).

## The test-edge trade-off, stated honestly

Test+test crossings rise 68 -> 102 in variant E. That is the
structural floor for this data, not a regression to fix by
tweaking: two findings sharing two test files cannot be drawn
without a crossing on straight edges, and the eight heavy findings
all share the same four test files. The test edges hide at fit
zoom, so the default view (what Freddy looks at) is clean: 0
own-edge crossings. The test edges reappear on zoom or when a
track is selected, and there they still cross. Fixing those would
need curved/bundled edges, a different feature, not a layout
tweak.

## Expansion (same push)

World 480x440 -> 480x480, centre (240,240). Rings pushed outward:
files 125 -> 140, posture 165 -> 185, findings 205 -> 225. The
map plane grows: .map-plane height 420px -> 540px on desktop,
420px at 480px wide and under, 380px at 360px and under. On
Freddy's phone (390px wide) the map is width-limited, so the rings
still render about 10% bigger on screen.

## Verification

- New suite scripts/test-map-ordering.ts: 19/19. It rebuilds the
  live self-scan's connection structure as a fixture and asserts
  the order, the median claims, and own crossings = 0.
- Full offline suite: 28 PASS / 0 FAIL (test:mcp excluded by the
  runner; run separately against the live site).
- tsc exit 0, build exit 0.
- Screenshots: test-results/map-grouped-2026-11-28-phone.png and
  -desktop.png (local production server, live self-scan map).
