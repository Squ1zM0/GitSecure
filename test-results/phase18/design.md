# Phase 18 design — dynamic spider-web plane

Trigger: Freddy — "it needs to be a dynamic visual plane that the user
can pin Zoom click Zoom move around traverse know what each connection
is." The static SVG from Phase 11 is hard for humans to read in
reverse. This phase rebuilds `UsageMap` (and only it) as a pannable,
zoomable surface. `FileMap` stays static as the no-usage fallback.

## What stays (do not regress)

- Ring layout as the STARTING arrangement: world 400×380, centre
  (200,190), findings inner ring r=100, files outer ring r=140,
  same angle math (`-PI/2` start). Node sizes, dead-end greying,
  shortLabel middle-truncation, labels with halos, counts inside node
  circles, centre painted after edges, dim-others-on-select.
- Rendering caps: MAP_FINDINGS=12, MAP_NODES=24 — rendering caps,
  labelled as such. Every finding stays in the list below.
- Redaction: fragment-only everywhere, including tooltips, edge
  labels, edge details, detail panel. No full secret ever renders.
- Dark mode via existing CSS custom properties; existing classes
  (`.map-edge`, `.map-node`, `.map-label`, `.map-dim`, …) keep their
  meaning; new classes are additive.
- `onSelectFile` (filter list to a file) and `onShowFinding` (jump to
  a finding in the list) still exist — but they move behind detail
  panel buttons (see below). A file-node click no longer navigates
  away immediately: it selects + zooms + shows detail first.

## New model — `src/lib/map-view.ts` (pure, no React, no DOM)

World coordinates are the existing 400×380 ring space. The screen is
one SVG `<g transform={translate(x,y) scale(k)}>` wrapping everything
— cheap, no re-layout per frame.

```ts
export interface ViewTransform { x: number; y: number; k: number }
export const MIN_ZOOM = 0.5;
export const MAX_ZOOM = 4;
export const WORLD_W = 400;
export const WORLD_H = 380;
export function fitView(containerW: number, containerH: number, padding?: number): ViewTransform
export function zoomAt(view: ViewTransform, px: number, py: number, factor: number,
  containerW: number, containerH: number): ViewTransform
  // Zoom centred on screen point (px,py): the world point under the
  // cursor stays under the cursor. Clamps k to [MIN_ZOOM, MAX_ZOOM]
  // and the translate so the world cannot be panned out of view.
export function zoomByFactor(view: ViewTransform, factor: number,
  containerW: number, containerH: number): ViewTransform
  // Zoom centred on the container centre (toolbar +/- buttons).
export function panBy(view: ViewTransform, dx: number, dy: number,
  containerW: number, containerH: number): ViewTransform
export function zoomToNode(view: ViewTransform, node: { x: number; y: number },
  containerW: number, containerH: number, targetK?: number): ViewTransform
  // Centres the node, target k = 2 (default) clamped to [fitK,
  // MAX_ZOOM]. Fix round 2026-11-27: the target is an optional fifth
  // parameter — the component passes min(2, fitK * 1.75) so a 360px
  // viewport zooms to ~1.5 instead of 2, which left most of the
  // 400-wide world off-screen.
export function clampView(view: ViewTransform, containerW: number, containerH: number): ViewTransform
export function worldToScreen(p: { x: number; y: number }, view: ViewTransform): { x: number; y: number }
export function screenToWorld(p: { x: number; y: number }, view: ViewTransform): { x: number; y: number }
export function viewTransformString(view: ViewTransform): string // `translate(x y) scale(k)`
```

Node ids: `repo` | `finding:${idx}` | `file:${path}`.

```ts
export function ringLayout(n: number, cx: number, cy: number, radius: number): { x: number; y: number }[]
  // Same angle math as today.
export function resolveNodePositions(
  base: Map<string, { x: number; y: number }>,
  overrides: Map<string, { x: number; y: number }>,
): Map<string, { x: number; y: number }>  // overrides win
export function togglePin(pins: ReadonlySet<string>, id: string): Set<string> // immutable
```

Pin semantics (testable distinction): dragging a node sets a position
override but does NOT pin it. A pinned node keeps its world position
when the findings change (unpinned nodes re-ring); a dragged-but-
unpinned node re-rings with the rest. Pin survives pan/zoom and
reset-view (reset-view resets the CAMERA only, never node positions).
Pins reset when the findings list is replaced, like `selected` today.
Pin state is per-view session state in the component — never sent to
the server, never persisted.

Edges: group by (fromId, toId); parallel edges (same finding → same
file, different lines/kinds) get a perpendicular offset of
`(index - (n-1)/2) * 6` world units so each is separately visible and
clickable, and its label sits at the adjusted segment's midpoint.

```ts
export type EdgeKind = "code" | "test" | "own";
export function edgeLabelText(kind: EdgeKind): string
  // code -> "used in code", test -> "used in tests", own -> "lives in"
export function edgeDetailText(args: {
  findingTitle: string; findingFile: string; findingLine: number;
  refFile: string; refLine: number; kind: EdgeKind;
}): string
  // Plain English, built ONLY from those args (never a fragment):
  // code: "Secret <title> lives in <findingFile>:<findingLine> and is
  //   read by <refFile>:<refLine>. Rotating it means updating that
  //   file too."
  // test: same shape, "…is read by <refFile>:<refLine> in a test — it
  //   proves the value is exercised, not that production uses it."
  // own: "Secret <title> lives in <refFile>:<refLine> — this is the
  //   file the secret itself sits in."
export function neighboursOf(nodeId: string, edges: { fromId: string; toId: string; kind: EdgeKind }[]): { id: string; kind: EdgeKind }[]
  // Adjacency both directions; `repo` has no neighbours.
export function traverseStep(path: string[], nextId: string): string[] // append, no immediate backtrack duplicate
export function traverseBack(path: string[]): string[] // pop; never pops the last element
```

## Component — `UsageMap` in `src/components/ReportLists.tsx`

State (all `useState`, session-only): `view: ViewTransform`,
`selected: { type: "node" | "edge"; id: string } | null`,
`pins: Set<string>`, `overrides: Map<string, {x,y}>`,
`path: string[]` (breadcrumb, starts `["repo"]` on select),
`neighbourIdx: number` (which neighbour the prev/next stepper
points at).

- Toolbar (real buttons, ≥44px, above the map): Zoom in, Zoom out,
  Reset view, plus a "Reset layout" button that clears overrides +
  pins (camera untouched). Buttons have `aria-label`s.
- Container: fixed height (420px desktop, 380px at ≤360px via CSS),
  `touch-action: none` on the `<svg>` so the browser never hijacks
  gestures inside the box. Initial view = `fitView` measured on
  mount (ResizeObserver + window resize); server render uses the
  640×420 default so render-to-string still works, client corrects
  in `useEffect` (no hydration error: view is state, not markup).
- Pointer handling (Pointer Events, one code path for mouse/touch/
  pen): a pointer cache (`Map<pointerId, {x,y}>`). One pointer down
  on background → pan; on a node → start a possible node drag.
  Two pointers → pinch (zoom around the midpoint, pan follows the
  midpoint). A pointer-up with <5px movement and <500ms counts as a
  tap/click: node → select + `zoomToNode` + detail; edge → select
  edge + detail; background → deselect (camera stays). Dragging a
  node updates its override live (edges follow — they read positions
  from the same resolved map every render).
- Wheel zoom: React's `onWheel` is passive in some setups and cannot
  `preventDefault`, so attach the wheel handler NATIVELY via a ref +
  `addEventListener("wheel", handler, { passive: false })` in
  `useEffect`. Wheel over the map zooms the map (cursor-centred);
  page scroll works everywhere outside the map box.
- Reduced motion: `matchMedia("(prefers-reduced-motion: reduce)")`
  once on mount; when set, the world `<g>` gets NO transition
  (jump cuts). Otherwise `transition: transform 150ms ease` on the
  `<g>` (new class `map-animated`).
- Edge labels: `<text class="map-label map-edge-label">` at each
  adjusted edge midpoint, halo class reused. Label density by zoom
  (fix round 2026-11-27 — deliberate deviation from the original
  "labels at every zoom" rule): the selected track's labels always
  render; all other edges' labels render only when `view.k >= 1.5`
  (`EDGE_LABEL_MIN_ZOOM`). The headless evidence proved the old rule
  unreadable at this density: 92 edge labels stacked into a hairball
  at the centre at fit zoom (1280px and 360px, light and dark). The
  legend + edge styles (solid/dashed/thin) still distinguish every
  edge at fit zoom, and any edge's meaning is one click away (edge
  detail) or one zoom-in away (all labels appear). Non-selected
  edges dim with their lines (existing `map-edge-dim`); labels dim
  with them. The hint line under the map says labels appear on zoom.
- Edge hit targets: each edge renders a second invisible line
  (`stroke: transparent; stroke-width: 12; pointer-events: stroke`)
  for pointer clicks, and the visible line's parent `<g>` is
  focusable (`tabIndex={0}`, `role="button"`, `aria-label`:
  "Connection: Secret N used in code in <file> line <line>" —
  file:line only, never a fragment).
- Detail panel (replaces the old `.map-track-detail` content when
  something is selected; the old track hint stays as the empty
  state): for a finding node — title, file:line, triage verdict,
  dead-end vs in-use, reference counts, the plain-English
  "why this matters" line (in-use: "This file reads this secret, so
  rotating it means updating this file too." naming up to 3
  referencing files; dead-end: the existing dead-end sentence),
  buttons: Pin/Unpin, Show this finding in the list, and neighbour
  stepper (Previous / Next neighbour + "Go to" for the current
  neighbour). For a file node — path, finding count, button "Filter
  list to this file". For an edge — the `edgeDetailText` sentence +
  file:line + kind, and a button to select the finding at its far
  end. All in plain HTML below the map (touch users never need a
  hover tooltip). `aria-live="polite"` on the panel.
- Breadcrumb: `This repo > Secret N > file.ts` as buttons; clicking
  an earlier crumb jumps back (pops the path, selects that node,
  recentres). The "This repo" crumb resets to the full view.
- Neighbour highlight: neighbours of the selected node get a
  `map-neighbour` class (accent ring); everything else dims (keep
  the existing dim behaviour — selected track full-strength, rest
  dimmed).
- FileMap: untouched.

## Gesture split (desktop vs touch) — documented here and in code

- Desktop: wheel = zoom at cursor; drag background = pan; drag node
  = move node; click node = select + zoom-to-node; click edge =
  select edge; click background = deselect; buttons = zoom/reset.
- Touch: the map is a fixed-height region that owns ALL gestures
  inside its box (`touch-action: none`): one finger drag = pan,
  one finger drag starting on a node = move that node, pinch =
  zoom, tap node/edge = select (+ zoom-to-node for nodes), tap
  background = deselect. The page scrolls from anywhere OUTSIDE the
  map box. The toolbar buttons are the no-gesture fallback for
  zoom/reset on both.
- Keyboard: Tab reaches every node and edge; Enter/Space selects;
  with a node selected, `[` / `]` (and the on-screen Previous/Next
  buttons) step neighbours; `Escape` deselects; `0` resets the view.
  Focus ring is the existing `:focus-visible` stroke; edges get the
  same treatment via a new `.map-edge-focus` rule.

## Accessibility

- Every node AND edge keyboard reachable with a visible focus ring.
- Zoom/pan/reset/pin/traverse controls are real `<button>`s with
  labels; touch targets ≥44px (existing file-chip rule, extended
  to the toolbar).
- Screen-reader summary of the selected node's connections in the
  detail panel (`aria-live="polite"`), plus a visually-hidden text
  summary of the whole map (counts by kind) for the SVG group.
- `prefers-reduced-motion`: jump cuts, no animated zoom (above).

## Performance + scale

- Caps unchanged (12 findings / 24 files, labelled rendering caps).
- One `<g transform>` — no per-node layout on pan/zoom; pointer
  moves update one state object (view or one override) per frame.
- No new dependencies. Hand-rolled transform state.

## Files to change / not change

- NEW: `src/lib/map-view.ts`, `scripts/test-map-phase18.ts`
  (new suite; add a `test:map-phase18` script to package.json).
- CHANGE: `src/components/ReportLists.tsx` (UsageMap only +
  toolbar/detail panel; FileMap untouched), `src/app/globals.css`
  (additive map classes only), `scripts/test-ui-phase7.ts` (extend
  render checks where the map's output intentionally changes —
  hint text, toolbar, edge labels; say so in the phase note),
  `GITSECURE.md` (Phase 18 section), `README.md` only where the
  map is described.
- DO NOT TOUCH: scan pipeline, triage, scoring, detectors, caps,
  redaction, Upstash store code, MCP tools, the rest of the report
  page.

## Tests

- `test:map-phase18` (new): transform math — zoomAt keeps the world
  point under the cursor fixed; zoom clamps to [0.5, 4]; pan clamps
  so the world cannot leave the viewport; fitView fits 400×380 into
  the container; zoomToNode centres the node. Edge labels —
  `edgeLabelText` for all three kinds; `edgeDetailText` names the
  finding, both files, both lines, and never contains a fragment
  (assert against a known fake value). Pins — togglePin adds/removes
  immutably; overrides win in resolveNodePositions; pinned nodes
  survive a base re-layout, unpinned do not (test via the resolve
  helper). Traversal — neighboursOf both directions; traverseStep
  appends, traverseBack pops, breadcrumb never empties.
- Render-to-string (in `test-ui-phase7.ts` extensions): the map
  renders with toolbar buttons (Zoom in/out, Reset view), edge
  labels ("used in code" / "used in tests" / "lives in"), legend,
  detail-panel region, and keyboard-reachable edges
  (`role="button"` on edge groups). No full secret in the rendered
  output (assert the fixture's full fake value is absent while its
  redacted fragment is present).
- Existing suites must pass unmodified in behaviour.

## Verification

- `npm run build` exit 0 (captured to a file, code checked).
- Full suite green; secret-pattern grep clean before push.
- Playwright + headless Chromium (cached chromium-1255 in
  ~/.cache/ms-playwright; the playwright npm package is NOT in
  devDependencies — install/run via npx, or drive the cached binary
  with playwright-core + executablePath): screenshots at 1280px and
  360px, light + dark, of a report WITH usage data (GitSecure
  self-scan — it has usage) and TechDirect as the no-usage fallback.
  Exercise the interactions headlessly, don't just screenshot:
  click a finding node and assert the plane recentres + detail panel
  appears; drag the background and assert the view translate
  changes; wheel/pinch-zoom and assert scale changes; pin a node,
  pan, assert the node keeps its world position; step to a neighbour
  and assert the breadcrumb grows; click an edge and assert its
  detail appears. Save screenshots + a run log to
  test-results/phase18/.
- Live verification after push: home 200, TechDirect 83/B,
  self-scan 100/A, and the served report page containing the new
  toolbar/edge-label markup.
- Honest gaps to record: no real-iPhone tap test (say so, don't
  claim one); pinch zoom verified in headless emulation only.

## Fix round (2026-11-27) — Worker C headless findings

Worker C's headless run (playwright-core + cached Chromium, own
`next start`, self-scan report) found two real pointer defects and
two visual defects in the UsageMap rebuild. All four fixed here;
nothing else touched.

1. **Mouse/tap selection broken.** Root cause, proven by event
   instrumentation: `onPointerDown` calls `setPointerCapture` on
   the svg, which retargets `pointerup` AND `click` to the svg, so
   React's `onClick` on a node/edge `<g>` never fired (observed
   `pointerdown target=text`, `click target=svg`). Keyboard Enter
   on the same node worked, so `selectNode`/`selectEdge` were fine
   — only the pointer path was broken. Fix: select on `pointerup`
   when the gesture is a tap (<5px, <500ms), using the node/edge id
   recorded in the gesture ref at `pointerdown` time (capture
   retargets the pointerup target too, so the id can never come
   from the pointerup event). Node tap → select + zoomToNode +
   detail + path; edge tap → select + detail; background tap →
   deselect. The now-dead `onClick` handlers on all four `<g>`
   groups were removed. `onPointerCancel` is now a separate
   handler that only cleans up (a cancelled gesture never
   selects), and a right-click never starts a gesture.
   Keyboard Enter/Space selection is a separate path
   (`onNodeKeyDown` / `onEdgeKeyDown`) and is untouched.
2. **Background drag did not pan.** Root cause, proven by
   arithmetic on a synthetic dispatch: the pan branch computed
   `pt.x - g.last.x` INSIDE the `setView` updater, but `g.last =
   pt` was assigned synchronously before React invoked the
   updater — dx=dy=0 always (six batched moves summed to exactly
   the observed jump). Fix: deltas hoisted into locals before
   `setView` (`const dx = pt.x - g.last.x; …; g.last = pt;
   setView(v => panBy(v, dx, dy, …))`). Audit of every other
   delta-inside-updater site: the pinch midpoint pan read a
   captured `prev` object (not itself broken) but was hoisted the
   same way to remove the hazard; the node-drag branch computes
   its position eagerly before `setOverrides` (immune); wheel and
   toolbar handlers use event values/constants only.
3. **Default fit view was a hairball.** 92 edge labels collided
   into an unreadable stack at the centre at fit zoom (1280px and
   360px, light and dark). Fix: label density by zoom — selected
   track labels always visible, all other edge labels only when
   `view.k >= 1.5` (`EDGE_LABEL_MIN_ZOOM` in the component). This
   deliberately deviates from "labels at every zoom" above; the
   legend + edge styles still distinguish every edge at fit zoom.
4. **360px map slid mostly off-screen after interaction.**
   Zoom-to-node always targeted k=2, which on a 360px viewport
   leaves most of the 400-wide world off-screen; only Reset view
   recovered. Fix: `zoomToNode` takes an optional fifth parameter
   `targetK = 2` (default keeps current behaviour), and the
   component passes `Math.min(2, fitView(w, h).k * 1.75)` — ~1.5
   on a 360px plane. New `test:map-phase18` checks cover explicit
   `targetK` centring, clamping to fitK, the unchanged default of
   2, and the 360px responsive target.

Redaction re-checked in this round: the detail panel and edge
labels never render a fragment at all, let alone a full secret
(edge labels are fixed kind strings; edge detail is built only
from file:line; the detail panel shows title/file:line/triage).

## Fix round 2 (2026-11-27) — Worker C recheck screenshots

Worker C's recheck proved all four round-1 fixes hold in the
browser, but the screenshots showed two remaining layout defects
(plus one minor caption overlap in the same frames). All three
fixed here, in `src/components/ReportLists.tsx` (UsageMap) only;
`map-view.ts` untouched, no new unit tests (the stagger lives in
the component, covered by the headless recheck).

1. **Selected-track label pile-up.** Evidence:
   `selfscan-360-selected-recheck2.png` — finding S8 has 11 "used
   in tests" edges fanning to nearby files; all 11 labels sat at
   near-coincident midpoints and stacked into a single unreadable
   blob directly on top of the S8 node (the "70 uses" caption was
   buried in it too). The ±6-unit perpendicular offset separates
   the LINES, not the ~70px-wide identical label TEXTS. Fix:
   stagger edge labels ALONG their edge. For the edges of one
   finding (in draw order), the label fraction t cycles through
   [0.35, 0.5, 0.65] (t = point at fraction t along the adjusted
   segment, `from + (to - from) * t`), so neighbouring edges in a
   fan carry their labels on different arcs. Parallel edges to the
   same file already have the ±6 offset; the t-stagger separates
   their labels as well. A finding with a single edge keeps the
   midpoint (t=0.5). Stored as `labelT` on the component's
   `MapEdge` (assigned in the `edges` memo, after the parallel
   offset grouping); halo class and label-gating rule unchanged.
2. **File labels clipped/touching the plane edge at fit zoom
   (360px).** Evidence: `selfscan-360-light-recheck2.png` — side
   file labels ("ME.md" left, "test-usa…11.ts" right,
   "test-sca…er.ts" right, "test-his…ry.ts" top) butt hard against
   the plane border and read as clipped. Cause: `fitView` fits the
   400×380 WORLD, but file labels sit radially OUTWARD from the
   outer ring (up to ~r+14 world units beyond it), i.e. outside
   the fitted rect. Fix: the initial fit and Reset view (same code
   path) call `fitView(containerW, containerH, 32)` instead of
   the default padding (8) — 32 screen px of breathing room on
   every side; the map gets slightly smaller (fit k drops ~16%
   at 360px), labels fit inside. `fitView`'s default stays 8;
   the existing `lx` clamp is unchanged; the round-1 responsive
   zoom target (`zoomTargetK`) is unchanged.
3. **Neighbouring "N uses" captions overlap.** Evidence: "70
   uses" / "62 uses" captions of adjacent finding nodes overlap
   in the centre cluster at fit zoom (same screenshots). Fix:
   the alternating caption sideways step grows from ±14 to ±20
   world units, and the caption line moves from `fr + 12` to
   `fr + 14` below the node. Small, low-risk; the caption layout
   is otherwise unchanged.

## Fix round 3 (2026-11-27) — Worker C recheck-3: the stagger does NOT work

Recheck-3 proved the round-2 label stagger fails on the exact case
it was built for. Secret 8 selected at 360px, k=1.260: its 11
selected-track labels (10 "used in tests" + 1 "lives in") still pile
into one blob — **16 overlapping bbox pairs, max 5 labels on any
one label**, the whole set sitting in a ~96×48px patch with
neighbouring label centres ~8px apart against 67px-wide labels
(`headless-findings-recheck3.md` §1, `selfscan-360-selected-
recheck3.png` visually unchanged from recheck2).

Root-cause arithmetic, from the headless log: S8 sits on the inner
ring (r=100) and its files on the outer ring (r=140), so its edges
are only ~40–90 world units long. Cycling t through [0.35, 0.5,
0.65] moves a label by 0.15 × edge length ≈ 6–14 world units ≈
8–17 screen px at k=1.26 — against a 67px-wide label. Neighbouring
labels in the fan still overlap by ~30–50px. Staggering along short
edges cannot separate 67px-wide identical labels, so no bigger
stagger was attempted — the fix is clustering instead.

**The clustering rule.** `clusterEdgeLabels(items, thresholdWorld)`
is a new pure function in `src/lib/map-view.ts` (unit-tested in
`scripts/test-map-phase18.ts`):

- Group by kind first — a "used in code" label never merges with a
  "used in tests" label.
- Within a kind, greedy clustering in draw order: for each item,
  find the first existing cluster of the same kind whose centroid
  is within `thresholdWorld` (Euclidean distance); if found, add
  the item and update the centroid to the mean of its items; else
  start a new cluster. The centroid is the running mean, so it
  drifts toward each new item and a chain can merge even when its
  endpoints are farther apart than the threshold — chaining is the
  specified behaviour and is asserted in the tests (A=(0,0),
  B=(40,0), C=(80,0) at threshold 60 merge into one cluster with
  centroid (40,0), even though A–C is 80).
- Cluster label position = centroid of its items. Clusters return
  in first-seen order.

**Component** (`src/components/ReportLists.tsx`, label placement
only): the per-edge `<text>` is gone. For the currently VISIBLE
label set — selected-track edges, or all edges when k >= 1.5, the
same gating as before — the component computes one anchor per
visible edge from the label position it already computed (the
adjusted segment point at `labelT`), then calls
`clusterEdgeLabels(anchors, 70 / view.k)`. The threshold is
zoom-aware: ~70 screen px is one label width, so at k=1.26 the
threshold is ~55 world units and at k=1.819 it is ~38. Label text
is `edgeLabelText(kind)` when count is 1 and
`edgeLabelText(kind) + " ×" + count` when count > 1 (e.g. "used in
tests ×11"). Cluster labels get `pointer-events: none` (attribute
on the `<text>`), so a tap on a label falls through to the edge hit
line beneath it — the edges themselves stay individually clickable
with their own detail. The halo class, the gating rule, the ±6
parallel offset, and the t-stagger all stay in place (the stagger
is harmless now; it positions each edge's anchor).

S8's 11 selected-track labels at k=1.26 should now render as one
"used in tests ×10" label plus the separate "lives in" label (the
"own" kind never merges with "test"), instead of 11 stacked texts.
Headless recheck to confirm the counted form and the bbox count.

## Fix round 4 (2026-11-27) — Worker B: recheck-4 FAILs (zoom overlap + paint order)

Recheck-4 proved the round-3 clustering HOLDS on the selected track
(S8: exactly 2 labels, "lives in" + "used in tests ×10", 0
overlapping pairs) but NOT at zoom, plus one paint-order defect on
the track itself. Both fixed here, in `src/lib/map-view.ts` (one new
pure helper), `src/components/ReportLists.tsx` (UsageMap label
placement + paint order only), and the unit tests. `clusterEdgeLabels`
itself is unchanged; the label gating (k >= 1.5 / selected track
always), the t-stagger, the ±6 offset, and the responsive zoom target
all stay as they are.

1. **Cluster labels still overlap at zoom.** Evidence:
   `headless-findings-recheck4.md` §2 — nothing selected, 5 toolbar
   Zoom-in clicks, k=1.831: 18 labels, 13 counted, **6 overlapping
   pairs, worst 1001.6 px²** ("lives in ×3" vs "used in tests ×9"),
   reproduced identically in two runs. Root cause: the threshold
   was wrong, and wrong in a specific direction. The component
   passed `70 / view.k` as the world-unit threshold — backwards.
   Label text lives INSIDE the transformed `<g>`, so both a label's
   width and the distance between two label anchors scale with k:
   the overlap condition is scale-invariant, and the correct
   world-unit threshold is simply the label width IN WORLD UNITS,
   independent of k. At k=1.831 the code passed 38 world units
   while the widest counted label ("used in tests ×18", measured
   130 screen px = 71 world units) needs ~71; at k=1.26 the code
   passed 55, close to the ~64 needed for "×10", which is why the
   selected track passed and the zoomed view failed. Fix: new pure
   helper `edgeLabelThresholdWorld(visibleKindCounts)` in
   `src/lib/map-view.ts` — for each kind present, the longest label
   text is `edgeLabelText(kind)` when count is 1, else
   `edgeLabelText(kind) + " ×" + count`; estimated width in world
   units = text.length * 4 + 8 (font-size 9 world units, ~4 units
   per char + padding); return the MAX over the kinds present, or
   70 for empty input (the uncounted-label default). The component
   replaces `70 / view.k` with
   `edgeLabelThresholdWorld(perKindCounts)`, where perKindCounts is
   counted from the currently visible label set (same gating as
   before) — a constant for a given visible set, NOT divided by k.
   Worked values: 18 "used in tests" edges → 76 ("used in tests
   ×18" is 17 chars, 17×4+8; the brief's "80" miscounts the text
   as 18 chars — 76 still exceeds the measured 71, so the safe
   margin holds); one "used in code" edge → 56; empty → 70;
   mixed kinds → the max of the two. Unit-tested in
   `scripts/test-map-phase18.ts` (§19).
2. **Cluster label painted OVER by its own finding node.**
   Evidence: recheck-4 §1c — ~46px of "used in tests ×10" hidden
   behind the S8 node circle (it read as "tests ×10"), and "lives
   in" grazing the "70 uses" caption by 3.9×7.8px. Root causes: (i)
   labels rendered BEFORE the node groups, so nodes painted over
   them; (ii) short edges put the label anchor within the finding
   node's radius. Fix: (a) PAINT ORDER — the cluster label `<text>`
   elements now render AFTER the node groups in the SVG (labels
   last, after centre, file, and finding nodes), so no node can
   cover a label; the centre keeps its existing rule (painted after
   the edges); the halo class is unchanged. (b) PUSH-OUT — after
   computing each label anchor and BEFORE clustering, if the anchor
   lies within (endpoint node radius + 14) world units of either
   endpoint node's centre, it is pushed outward along the edge
   direction (away from that endpoint) to exactly that distance,
   applied for both endpoints (finding node radius = the node's
   `fr`, file node radius = its `r`, same formulas as the node
   rendering). The push solves |anchor + s·d − centre| = radius+14
   exactly for the step s along the unit edge direction d (a plain
   shift of minDist − dist would only be exact if the anchor lay on
   the line through the centre; the ±6 parallel offset means it
   generally does not). This keeps labels out from under nodes and
   away from the finding captions that sit just below the node.

## Convergence (2026-11-27, parent decision — no further recheck rounds)

Freddy: the phase is taking insanely long. Parent: converge now. Recheck-5b is
the last headless round. Two items decided, not re-tested:

**1. The 3e through-cluster-label click FAIL is a test-geometry artifact, not a
product bug.** Probe evidence (recheck-5b supplement + probe-2, awesome-compose,
Secret 6 track): both counted label centres sit over a NODE, not over an edge
hit line — "lives in" centre (211.4, 567.7) → `circle -> finding:8`;
"used in code ×10" centre (233.9, 536.6) → `circle -> finding:8`. No counted
label centre on the track sits over an edge hit line at all. Cluster labels
are `pointer-events: none`, so the tap falls through to the topmost element
beneath the tap point — here a node circle, which correctly selects that node
(Secret 9). The edge itself remains clickable along its exposed length:
probe-2 direct edge-line click PASSes with the correct edge detail
("Secret Committed .env file lives in pihole-cloudflared-DoH/.env:1 and is
read by pihole-cloudflared-DoH/compose.yaml:30. Rotating it means updating
that file too."). In recheck-4 the same check passed only because S8's label
centre happened to sit over an edge. Recorded as artifact; no further round.

**2. The recheck-5 BLOCKED item (local self-scan history stall) is
local-server-only.** Evidence: the LIVE self-scan works — parent verified it
19:04 and 19:40 MST 2026-11-26 (100/A, 37 secrets); awesome-compose settled
on the same local server in ~42–50 s across six loads. Root cause (measured):
`git clone --bare Squ1zM0/GitSecure` from this VM takes 102.9 s vs the history
chunk's 30 s budget (`GIT_HISTORY_CHUNK_BUDGET_MS`) — each chunk burns its
whole budget inside the isomorphic-git clone, persists no progress (ephemeral
clone deleted), and the next chunk re-clones from scratch, returning the
byte-identical cursor (`stage: "history"`, `histScanned: 0`, `histPage: 1`,
`histIdx: 0`) forever. Recorded as an open local-test / scan-pipeline
robustness issue: a history chunk timing out inside the clone should persist
partial progress or fall back to the API path instead of looping with an
unchanged cursor. Out of scope for Phase 18; does not block the phase.

**Known cosmetic limitation carried forward (not fixed in this phase, per
convergence):** the round-4 push-out clears a cluster label only from its OWN
edge endpoints, so labels can land on NEIGHBOURING nodes/captions. Measured on
awesome-compose: 3 intersections on the selected track (worst 529.5 px²,
"used in code ×10" vs finding:8/Secret 9), 12 intersections at zoom
k=1.819 (worst 2006.2 px², "used in code ×3" vs the repo centre node), 1
caption collision (382.7 px², "lives in ×2" over the "10 uses" caption,
visibly reading "10 uslives in ×2"). Labels paint last with a halo, so the
text stays readable — this is a collision/pointer defect, not hidden text.
A fix would need placement to consider all nearby nodes and captions (a
second-pass collision pass), not just the edge's endpoints. Candidate for a
future phase if Freddy wants it.

**Harness artifacts corrected in the supplement (not code defects):** main-run
2a/2b hard-coded a "used in tests ×N" label — Secret 6's track is 10 code + 1
own, no test edges exist on this repo; supplement re-measured with the actual
counted kind ("used in code ×10"): PASS. Main-run 3a@1280 clicked finding:0,
which is not among the 12 drawn findings on this repo
(5, 7, 8, 9, 10, 12, 13, 14, 15, 17, 18, 24 — drawn set is the findings with
usage, not the first 12 by index); supplement clicked the first drawn node,
finding:10 (Secret 11): PASS, k 0.932 → 1.851.

**Recheck-5b combined tally:** 17 PASS, 7 FAIL across main + supplement +
probe-2 logs; 3 FAILs were the harness artifacts above (corrected to PASS);
the other 4 FAIL lines cover the two items above (neighbour overlap,
label-centre tap). Round-4 fixes HOLD on their asserted metrics: 0
overlapping label pairs at k=1.819 (recheck-4: 6 pairs, worst 1001.6 px²);
counted label vs its own finding node 0 px² (was ~46 px² behind S8);
"lives in" vs "10 uses" caption 0 px² (was a 30 px² graze); click finding
selects + zooms (360: k 0.600 → 1.260; 1280: k 0.932 → 1.851); background drag
pans exactly (+120.0, +60.0), k unchanged; reset returns to exact fit, both
viewports; label gating 0 at fit; redaction clean; 360 px scrollWidth = 360.
