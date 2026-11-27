// Phase 18 (Worker A, 2026-11-26): pure view-transform / traversal model
// for the dynamic spider-web map.
//
// Pure functions only — no React, no DOM — so the zoom/pan math,
// node layout, pinning, edge copy and traversal can be unit-tested
// without a browser. The component (Worker B) owns rendering and
// event wiring and calls into this module.
//
// World: the map lays nodes out in a fixed 400 x 380 world rect
// (WORLD_W x WORLD_H). A ViewTransform maps world -> screen:
//   screen = world * k + (x, y).
// Clamp rule (pinned by the Phase 18 contract): after any zoom/pan
// the world must stay at least partly visible — the scaled world
// rect must overlap the container by at least 40 screen px on every
// side, i.e. x in [40 - WORLD_W*k, containerW - 40] and
// y in [40 - WORLD_H*k, containerH - 40]. Clamping only bounds the
// translate; it never force-centres.

export interface ViewTransform {
  x: number;
  y: number;
  k: number;
}

export const MIN_ZOOM = 0.5;
export const MAX_ZOOM = 4;
export const WORLD_W = 400;
export const WORLD_H = 380;

/** Pixels of the world that must stay visible on every side. */
const OVERLAP_PX = 40;

function clampNumber(v: number, lo: number, hi: number): number {
  return Math.min(Math.max(v, lo), hi);
}

/**
 * Fit the 400x380 world into the container, default padding 8.
 * Scale = min((cw - 2p) / 400, (ch - 2p) / 380), centred.
 * Zero/negative container sizes (or a container too small for the
 * padding, which would give a non-positive scale) return the
 * identity view { x: 0, y: 0, k: 1 }.
 */
export function fitView(containerW: number, containerH: number, padding = 8): ViewTransform {
  if (!(containerW > 0) || !(containerH > 0)) return { x: 0, y: 0, k: 1 };
  const k = Math.min((containerW - 2 * padding) / WORLD_W, (containerH - 2 * padding) / WORLD_H);
  if (!(k > 0) || !Number.isFinite(k)) return { x: 0, y: 0, k: 1 };
  return {
    x: (containerW - WORLD_W * k) / 2,
    y: (containerH - WORLD_H * k) / 2,
    k,
  };
}

/**
 * Clamp a view: k into [MIN_ZOOM, MAX_ZOOM], then the translate so
 * the scaled world rect overlaps the container by at least 40 px on
 * every side. Never force-centres — it only bounds the translate.
 */
export function clampView(view: ViewTransform, containerW: number, containerH: number): ViewTransform {
  const k = clampNumber(view.k, MIN_ZOOM, MAX_ZOOM);
  return {
    x: clampNumber(view.x, OVERLAP_PX - WORLD_W * k, containerW - OVERLAP_PX),
    y: clampNumber(view.y, OVERLAP_PX - WORLD_H * k, containerH - OVERLAP_PX),
    k,
  };
}

/**
 * Zoom centred on screen point (px, py): the world point under the
 * cursor stays under the cursor after the zoom. k is clamped to
 * [MIN_ZOOM, MAX_ZOOM], then the translate is clamped so the world
 * cannot be panned out of view. A non-positive / non-finite factor
 * is a no-op (the view is returned unchanged).
 */
export function zoomAt(
  view: ViewTransform,
  px: number,
  py: number,
  factor: number,
  containerW: number,
  containerH: number,
): ViewTransform {
  if (!(factor > 0) || !Number.isFinite(factor)) return view;
  const wx = (px - view.x) / view.k;
  const wy = (py - view.y) / view.k;
  const k = clampNumber(view.k * factor, MIN_ZOOM, MAX_ZOOM);
  return clampView({ x: px - wx * k, y: py - wy * k, k }, containerW, containerH);
}

/** Same as zoomAt centred on the container centre. */
export function zoomByFactor(
  view: ViewTransform,
  factor: number,
  containerW: number,
  containerH: number,
): ViewTransform {
  return zoomAt(view, containerW / 2, containerH / 2, factor, containerW, containerH);
}

/** Translate by (dx, dy), then clamp so the world stays in view. */
export function panBy(
  view: ViewTransform,
  dx: number,
  dy: number,
  containerW: number,
  containerH: number,
): ViewTransform {
  return clampView({ x: view.x + dx, y: view.y + dy, k: view.k }, containerW, containerH);
}

/**
 * Centre the node in the container; target k defaults to 2,
 * clamped to [fitK, MAX_ZOOM] where fitK is the fit scale for this
 * container. (When the container is large, fitK can exceed the
 * target, so the node is shown at the fit scale rather than zoomed
 * in past it.)
 *
 * Fix round 2026-11-27 (defect 4): the target is an OPTIONAL fifth
 * parameter because k=2 on a 360px viewport leaves most of the
 * 400-wide world off-screen. Narrow containers pass a smaller
 * target (the component passes min(2, fitK * 1.75)); the default
 * keeps the previous behaviour exactly.
 */
export function zoomToNode(
  view: ViewTransform,
  node: { x: number; y: number },
  containerW: number,
  containerH: number,
  targetK = 2,
): ViewTransform {
  void view;
  const fitK = fitView(containerW, containerH).k;
  const k = clampNumber(targetK, fitK, MAX_ZOOM);
  return clampView(
    { x: containerW / 2 - node.x * k, y: containerH / 2 - node.y * k, k },
    containerW,
    containerH,
  );
}

export function worldToScreen(p: { x: number; y: number }, view: ViewTransform): { x: number; y: number } {
  return { x: p.x * view.k + view.x, y: p.y * view.k + view.y };
}

export function screenToWorld(p: { x: number; y: number }, view: ViewTransform): { x: number; y: number } {
  return { x: (p.x - view.x) / view.k, y: (p.y - view.y) / view.k };
}

/** Exactly `translate(<x> <y>) scale(<k>)` — the SVG transform string. */
export function viewTransformString(view: ViewTransform): string {
  return `translate(${view.x} ${view.y}) scale(${view.k})`;
}

/**
 * Ring layout, same angle math as the current map:
 * angle = 2*PI*i/n - PI/2 (i = 0 starts at the top).
 * n <= 0 yields an empty array.
 */
export function ringLayout(n: number, cx: number, cy: number, radius: number): { x: number; y: number }[] {
  if (!(n > 0)) return [];
  const pts: { x: number; y: number }[] = [];
  for (let i = 0; i < n; i++) {
    const angle = (2 * Math.PI * i) / n - Math.PI / 2;
    pts.push({ x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) });
  }
  return pts;
}

/**
 * Overrides win; returns a NEW map, inputs untouched.
 */
export function resolveNodePositions(
  base: Map<string, { x: number; y: number }>,
  overrides: Map<string, { x: number; y: number }>,
): Map<string, { x: number; y: number }> {
  const out = new Map(base);
  for (const [id, pos] of overrides) out.set(id, pos);
  return out;
}

/** Immutable pin toggle: returns a new Set, the input is untouched. */
export function togglePin(pins: ReadonlySet<string>, id: string): Set<string> {
  const next = new Set(pins);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  return next;
}

export type EdgeKind = "code" | "test" | "own";

export function edgeLabelText(kind: EdgeKind): string {
  if (kind === "code") return "used in code";
  if (kind === "test") return "used in tests";
  return "lives in";
}

/**
 * Fix round 4 (2026-11-27): the world-unit threshold for
 * clusterEdgeLabels, derived from the rendered label width — NOT
 * from the zoom. Recheck-4 proved `70 / view.k` is backwards: at
 * k=1.831 it passed 38 world units while the widest counted label
 * ("used in tests ×18", measured 130 screen px = 71 world units)
 * needs ~71, so 6 overlapping pairs remained at zoom even though
 * the selected track passed at k=1.26 (where 70/k ≈ 55 was close
 * to the ~64 needed for "×10").
 *
 * Scale invariance: a cluster label's <text> lives INSIDE the
 * transformed <g>, so both the label's width and the distance
 * between two label anchors scale with k — the overlap condition
 * is scale-invariant, and the correct world-unit threshold is
 * simply the label width IN WORLD UNITS, independent of k.
 *
 * For each kind present, the longest label text is
 * edgeLabelText(kind) when count is 1, else
 * edgeLabelText(kind) + " ×" + count. Estimated width in world
 * units = text.length * 4 + 8 (font-size 9 world units, ~4 units
 * per char + padding). The measured "used in tests ×18" is 71
 * world units; this formula gives 76 (17 chars × 4 + 8), a small
 * safe margin. Return the MAX over the kinds present. Empty input
 * returns 70 (the uncounted-label default).
 */
export function edgeLabelThresholdWorld(visibleKindCounts: { kind: EdgeKind; count: number }[]): number {
  if (visibleKindCounts.length === 0) return 70;
  let max = 0;
  for (const { kind, count } of visibleKindCounts) {
    const text = count === 1 ? edgeLabelText(kind) : `${edgeLabelText(kind)} ×${count}`;
    max = Math.max(max, text.length * 4 + 8);
  }
  return max;
}

/**
 * Fix round 3 (2026-11-27): collapse coincident identical edge
 * labels into one counted label. Recheck-3 proved the round-2
 * t-stagger cannot work: S8's edges are only ~40-90 world units
 * long, so cycling t through [0.35, 0.5, 0.65] moves a label only
 * ~8-17 screen px at k=1.26 against a 67px-wide label — 11
 * "used in tests" labels still piled into one blob (16 overlapping
 * bbox pairs, max 5 on one label). Staggering along short edges
 * cannot separate 67px-wide identical labels, so identical labels
 * that land on top of each other merge into one label carrying a
 * count ("used in tests ×11"). The edges themselves stay
 * individually clickable with their own detail.
 *
 * Greedy clustering in draw order, grouped by kind first (a "used
 * in code" label never merges with a "used in tests" label). For
 * each item, find the first existing cluster of the same kind whose
 * centroid is within `thresholdWorld` (Euclidean distance); if
 * found, add the item and update the centroid to the mean of its
 * items; else start a new cluster. Because the centroid moves as
 * items join, a chain can merge even when its endpoints are
 * farther apart than the threshold (chaining is the specified
 * behaviour). Clusters are returned in first-seen order.
 */
export interface EdgeLabelAnchor {
  x: number;
  y: number;
  kind: EdgeKind;
  edgeId: string;
}

export interface EdgeLabelCluster {
  x: number;
  y: number;
  kind: EdgeKind;
  count: number;
  edgeIds: string[];
}

export function clusterEdgeLabels(items: EdgeLabelAnchor[], thresholdWorld: number): EdgeLabelCluster[] {
  const clusters: { x: number; y: number; kind: EdgeKind; edgeIds: string[] }[] = [];
  for (const item of items) {
    const cluster = clusters.find(
      (c) => c.kind === item.kind && Math.hypot(item.x - c.x, item.y - c.y) <= thresholdWorld,
    );
    if (cluster) {
      // Running mean: the centroid stays the mean of all items in
      // the cluster, so it drifts toward each new item and a chain
      // can merge (see the unit tests).
      const n = cluster.edgeIds.length + 1;
      cluster.x = (cluster.x * (n - 1) + item.x) / n;
      cluster.y = (cluster.y * (n - 1) + item.y) / n;
      cluster.edgeIds.push(item.edgeId);
    } else {
      clusters.push({ x: item.x, y: item.y, kind: item.kind, edgeIds: [item.edgeId] });
    }
  }
  return clusters.map((c) => ({ x: c.x, y: c.y, kind: c.kind, count: c.edgeIds.length, edgeIds: [...c.edgeIds] }));
}

/**
 * Second-pass collision pass (Phase 18 fix, 2026-11-27 — Freddy:
 * labels landing on neighbouring nodes/captions, worst 2006px²,
 * "lives in ×2" reading as "10 uslives in ×2").
 *
 * The round-4 push-out only clears a label from its OWN edge
 * endpoints. It never looks at neighbouring nodes, other labels,
 * or node captions ("N uses", file basenames) — so a cluster label
 * could still land on the repo centre or across a caption. This
 * pass runs AFTER clustering, on the final label positions, and
 * checks every label against every blocker (node circles as rects,
 * caption/label rects) and every already-placed label.
 *
 * Label bbox: width = text.length * 4 + 8 (the same convention as
 * edgeLabelThresholdWorld — font-size 9 world units, ~4 per char +
 * padding), height 16, centred on the anchor, with a 2-unit margin
 * on every side. Nudge candidates, in order, for the cluster's
 * first edge direction (ux, uy) and its normal (-uy, ux): ±12/±24/
 * ±36 along the normal, ±12/±24 along the edge, ±12/±24 in x, ±12/
 * ±24 in y. First candidate with zero overlap wins; if none is
 * clear, the candidate with the smallest total overlap area wins
 * (a small graze beats a full cover). Candidates are clamped to
 * the world (400×380) so a nudge can never push a label off-plane.
 * Deterministic, bounded, pure — no DOM measurement.
 */
export interface LabelBlocker {
  x: number;
  y: number;
  w: number;
  h: number;
}

export function clusterLabelText(kind: EdgeKind, count: number): string {
  return count === 1 ? edgeLabelText(kind) : `${edgeLabelText(kind)} ×${count}`;
}

export function resolveLabelCollisions(
  clusters: EdgeLabelCluster[],
  blockers: LabelBlocker[],
  edgeDirs: Map<string, { x: number; y: number }>,
): EdgeLabelCluster[] {
  const MARGIN = 2;
  const LABEL_H = 16;
  const boxOf = (x: number, y: number, text: string) => {
    const w = text.length * 4 + 8;
    return { x0: x - w / 2 - MARGIN, y0: y - LABEL_H / 2 - MARGIN, x1: x + w / 2 + MARGIN, y1: y + LABEL_H / 2 + MARGIN };
  };
  const blockerBox = (b: LabelBlocker) => ({ x0: b.x - b.w / 2, y0: b.y - b.h / 2, x1: b.x + b.w / 2, y1: b.y + b.h / 2 });
  const overlapArea = (a: { x0: number; y0: number; x1: number; y1: number }, b: { x0: number; y0: number; x1: number; y1: number }) => {
    const w = Math.min(a.x1, b.x1) - Math.max(a.x0, b.x0);
    const h = Math.min(a.y1, b.y1) - Math.max(a.y0, b.y0);
    return w > 0 && h > 0 ? w * h : 0;
  };
  const blockerBoxes = blockers.map(blockerBox);
  const placed: { x0: number; y0: number; x1: number; y1: number }[] = [];
  const out: EdgeLabelCluster[] = [];
  for (const c of clusters) {
    const text = clusterLabelText(c.kind, c.count);
    const w = text.length * 4 + 8;
    const dir = edgeDirs.get(c.edgeIds[0]) ?? { x: 1, y: 0 };
    const len = Math.hypot(dir.x, dir.y) || 1;
    const ux = dir.x / len;
    const uy = dir.y / len;
    const nx = -uy;
    const ny = ux;
    const candidates: { x: number; y: number }[] = [{ x: c.x, y: c.y }];
    for (const d of [12, 24, 36, 48]) {
      candidates.push({ x: c.x + nx * d, y: c.y + ny * d });
      candidates.push({ x: c.x - nx * d, y: c.y - ny * d });
    }
    for (const d of [12, 24, 36]) {
      candidates.push({ x: c.x + ux * d, y: c.y + uy * d });
      candidates.push({ x: c.x - ux * d, y: c.y - uy * d });
      candidates.push({ x: c.x + d, y: c.y });
      candidates.push({ x: c.x - d, y: c.y });
      candidates.push({ x: c.x, y: c.y + d });
      candidates.push({ x: c.x, y: c.y - d });
    }
    let best = candidates[0];
    let bestArea = Infinity;
    for (const cand of candidates) {
      const cx = Math.max(w / 2 + MARGIN, Math.min(WORLD_W - w / 2 - MARGIN, cand.x));
      const cy = Math.max(LABEL_H / 2 + MARGIN, Math.min(WORLD_H - LABEL_H / 2 - MARGIN, cand.y));
      const box = boxOf(cx, cy, text);
      let area = 0;
      for (const b of blockerBoxes) area += overlapArea(box, b);
      for (const p of placed) area += overlapArea(box, p);
      if (area === 0) {
        best = { x: cx, y: cy };
        bestArea = 0;
        break;
      }
      if (area < bestArea) {
        best = { x: cx, y: cy };
        bestArea = area;
      }
    }
    placed.push(boxOf(best.x, best.y, text));
    out.push({ ...c, x: best.x, y: best.y });
  }
  return out;
}

/**
 * Plain-English edge detail, built ONLY from the named args — never
 * from a secret fragment (this module never sees one). The "own"
 * case uses refFile/refLine: that is the file the finding lives in.
 */
export function edgeDetailText(args: {
  findingTitle: string;
  findingFile: string;
  findingLine: number;
  refFile: string;
  refLine: number;
  kind: EdgeKind;
}): string {
  const { findingTitle, findingFile, findingLine, refFile, refLine, kind } = args;
  if (kind === "code") {
    return `Secret ${findingTitle} lives in ${findingFile}:${findingLine} and is read by ${refFile}:${refLine}. Rotating it means updating that file too.`;
  }
  if (kind === "test") {
    return `Secret ${findingTitle} lives in ${findingFile}:${findingLine} and is read by ${refFile}:${refLine} in a test — it proves the value is exercised, not that production uses it.`;
  }
  return `Secret ${findingTitle} lives in ${refFile}:${refLine} — this is the file the secret itself sits in.`;
}

/**
 * Adjacency in BOTH directions; deduped by neighbour id (first kind
 * wins). "repo" has no neighbours. Self-loops are not neighbours.
 */
export function neighboursOf(
  nodeId: string,
  edges: { fromId: string; toId: string; kind: EdgeKind }[],
): { id: string; kind: EdgeKind }[] {
  if (nodeId === "repo") return [];
  const seen = new Set<string>();
  const out: { id: string; kind: EdgeKind }[] = [];
  for (const e of edges) {
    let neighbour: string | null = null;
    if (e.fromId === nodeId) neighbour = e.toId;
    else if (e.toId === nodeId) neighbour = e.fromId;
    if (neighbour === null || neighbour === nodeId || seen.has(neighbour)) continue;
    seen.add(neighbour);
    out.push({ id: neighbour, kind: e.kind });
  }
  return out;
}

/**
 * Append nextId to the traversal path — unless it equals the last
 * element (an immediate backtrack), in which case the path is
 * returned unchanged.
 */
export function traverseStep(path: string[], nextId: string): string[] {
  if (path.length > 0 && path[path.length - 1] === nextId) return path;
  return [...path, nextId];
}

/** Pop the last element; never pops the last element of a 1-element path. */
export function traverseBack(path: string[]): string[] {
  if (path.length <= 1) return path;
  return path.slice(0, -1);
}
