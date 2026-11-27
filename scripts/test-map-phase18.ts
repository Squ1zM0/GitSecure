// Phase 18 map-view test — pure view-transform / traversal model.
// Run: npm run test:map-phase18
//
// Covers src/lib/map-view.ts: fitView, zoomAt / zoomByFactor,
// panBy, zoomToNode, clampView, world<->screen round-trip,
// viewTransformString, ringLayout, resolveNodePositions, togglePin,
// edgeLabelText / edgeDetailText, neighboursOf, traverseStep /
// traverseBack. No secret-pattern values anywhere in this file:
// the edge-detail absence check uses the obviously fake string
// "FAKE-SECRET-VALUE-1234", which is not a credential format.

import {
  MIN_ZOOM,
  MAX_ZOOM,
  WORLD_W,
  WORLD_H,
  fitView,
  zoomAt,
  zoomByFactor,
  panBy,
  zoomToNode,
  clampView,
  worldToScreen,
  screenToWorld,
  viewTransformString,
  ringLayout,
  resolveNodePositions,
  togglePin,
  edgeLabelText,
  edgeLabelThresholdWorld,
  edgeDetailText,
  neighboursOf,
  traverseStep,
  traverseBack,
  clusterEdgeLabels,
} from "../src/lib/map-view";
import type { ViewTransform, EdgeKind, EdgeLabelAnchor } from "../src/lib/map-view";

let failures = 0;
let total = 0;
function check(name: string, ok: boolean, extra = "") {
  total++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

const approx = (a: number, b: number, eps = 1e-6) => Math.abs(a - b) <= eps;
const ptApprox = (a: { x: number; y: number }, b: { x: number; y: number }, eps = 1e-6) =>
  approx(a.x, b.x, eps) && approx(a.y, b.y, eps);

const CW = 640;
const CH = 420;

// --- 0. Constants ---
check("Constants: MIN_ZOOM 0.5, MAX_ZOOM 4, WORLD 400x380", MIN_ZOOM === 0.5 && MAX_ZOOM === 4 && WORLD_W === 400 && WORLD_H === 380);

// --- 1. fitView ---
const fit = fitView(CW, CH);
const fitK = Math.min((CW - 16) / 400, (CH - 16) / 380);
check("fitView: k = min((640-16)/400, (420-16)/380)", approx(fit.k, fitK), `k=${fit.k} expected=${fitK}`);
check("fitView: centres the world (x)", approx(fit.x, (CW - WORLD_W * fit.k) / 2), `x=${fit.x}`);
check("fitView: centres the world (y = 8, since 380*k = 404)", approx(fit.y, 8), `y=${fit.y}`);
check("fitView: custom padding 0 gives k = min(640/400, 420/380)", approx(fitView(CW, CH, 0).k, Math.min(640 / 400, 420 / 380)), `k=${fitView(CW, CH, 0).k}`);
check("fitView: zero container returns identity (k=1, x=y=0)", JSON.stringify(fitView(0, CH)) === JSON.stringify({ x: 0, y: 0, k: 1 }), JSON.stringify(fitView(0, CH)));
check("fitView: negative container returns identity", JSON.stringify(fitView(-5, -5)) === JSON.stringify({ x: 0, y: 0, k: 1 }));

// --- 2. zoomAt keeps the world point under the cursor fixed ---
const cursor = { x: 320, y: 210 };
const before = screenToWorld(cursor, fit);
const zoomed = zoomAt(fit, cursor.x, cursor.y, 2, CW, CH);
check("zoomAt: world point under cursor is unchanged", ptApprox(screenToWorld(cursor, zoomed), before), `before=${JSON.stringify(before)} after=${JSON.stringify(screenToWorld(cursor, zoomed))}`);
check("zoomAt: factor 2 doubles k", approx(zoomed.k, fit.k * 2), `k=${zoomed.k} expected=${fit.k * 2}`);
const zoomedOffCentre = zoomAt(fit, 100, 50, 1.5, CW, CH);
check("zoomAt: off-centre cursor point also stays fixed", ptApprox(screenToWorld({ x: 100, y: 50 }, zoomedOffCentre), screenToWorld({ x: 100, y: 50 }, fit)));

// --- 3. Zoom clamps to [0.5, 4] ---
check("zoomAt: huge factor up clamps k to 4", zoomAt(fit, 320, 210, 100, CW, CH).k === 4, `k=${zoomAt(fit, 320, 210, 100, CW, CH).k}`);
check("zoomAt: huge factor down clamps k to 0.5", zoomAt(fit, 320, 210, 0.0001, CW, CH).k === 0.5, `k=${zoomAt(fit, 320, 210, 0.0001, CW, CH).k}`);
check("zoomByFactor: huge factor clamps k to 4", zoomByFactor(fit, 100, CW, CH).k === 4);

// --- 4. zoomByFactor is centred on the container centre ---
const centreBefore = screenToWorld({ x: CW / 2, y: CH / 2 }, fit);
const zoomedCentre = zoomByFactor(fit, 2, CW, CH);
check("zoomByFactor: world point at container centre stays fixed", ptApprox(screenToWorld({ x: CW / 2, y: CH / 2 }, zoomedCentre), centreBefore));

// --- 5. panBy clamps so the world cannot leave the viewport ---
// fit.k ≈ 1.0632: x in [40 - 400k, 600] ≈ [-385.26, 600], y in [40 - 380k, 380] = [-364, 380].
const panRight = panBy(fit, 10000, 0, CW, CH);
check("panBy: far-right pan clamps x to containerW - 40", approx(panRight.x, CW - 40), `x=${panRight.x}`);
const panLeft = panBy(fit, -10000, 0, CW, CH);
check("panBy: far-left pan clamps x to 40 - WORLD_W*k", approx(panLeft.x, 40 - WORLD_W * fit.k), `x=${panLeft.x}`);
const panDown = panBy(fit, 0, 10000, CW, CH);
check("panBy: far-down pan clamps y to containerH - 40", approx(panDown.y, CH - 40), `y=${panDown.y}`);
const panUp = panBy(fit, 0, -10000, CW, CH);
check("panBy: far-up pan clamps y to 40 - WORLD_H*k", approx(panUp.y, 40 - WORLD_H * fit.k), `y=${panUp.y}`);
const panSmall: ViewTransform = panBy(fit, 10, -5, CW, CH);
check("panBy: small in-bounds pan moves exactly by (dx, dy)", approx(panSmall.x, fit.x + 10) && approx(panSmall.y, fit.y - 5) && panSmall.k === fit.k, `x=${panSmall.x} y=${panSmall.y}`);

// --- 6. clampView direct ---
const clamped = clampView({ x: 9999, y: -9999, k: 1 }, CW, CH);
check("clampView: clamps x/y to the overlap bounds at k=1", clamped.x === CW - 40 && clamped.y === 40 - WORLD_H, `x=${clamped.x} y=${clamped.y}`);
check("clampView: clamps an out-of-range k into [0.5, 4]", clampView({ x: 0, y: 0, k: 99 }, CW, CH).k === 4 && clampView({ x: 0, y: 0, k: 0.01 }, CW, CH).k === 0.5);
check("clampView: does not force-centre an in-bounds view", JSON.stringify(clampView(fit, CW, CH)) === JSON.stringify(fit), JSON.stringify(clampView(fit, CW, CH)));

// --- 7. zoomToNode ---
const node = { x: 200, y: 190 };
const toNode = zoomToNode(fit, node, CW, CH);
check("zoomToNode: node lands on the container centre", ptApprox(worldToScreen(node, toNode), { x: CW / 2, y: CH / 2 }), JSON.stringify(worldToScreen(node, toNode)));
check("zoomToNode: k is 2 (within [fitK, 4])", toNode.k === 2, `k=${toNode.k}`);
check("zoomToNode: k within [fitK, 4]", toNode.k >= fitK - 1e-9 && toNode.k <= 4);
const toNodeBig = zoomToNode(fit, node, 2000, 1900);
const fitKBig = fitView(2000, 1900).k;
check("zoomToNode: large container uses fitK when fitK > 2", approx(toNodeBig.k, Math.min(fitKBig, 4)) && toNodeBig.k === 4, `k=${toNodeBig.k} fitK=${fitKBig}`);
check("zoomToNode: large container still centres the node", ptApprox(worldToScreen(node, toNodeBig), { x: 1000, y: 950 }), JSON.stringify(worldToScreen(node, toNodeBig)));

// --- 7b. zoomToNode with an explicit targetK (fix round 2026-11-27,
// defect 4): a narrow container zooms less than k=2 so the world
// stays on-screen. ---
const toNodeK15 = zoomToNode(fit, node, CW, CH, 1.5);
check("zoomToNode: explicit targetK 1.5 centres the node at k=1.5", toNodeK15.k === 1.5 && ptApprox(worldToScreen(node, toNodeK15), { x: CW / 2, y: CH / 2 }), `k=${toNodeK15.k} at=${JSON.stringify(worldToScreen(node, toNodeK15))}`);
const toNodeK3 = zoomToNode(fit, node, CW, CH, 3);
check("zoomToNode: explicit targetK 3 centres the node at k=3", toNodeK3.k === 3 && ptApprox(worldToScreen(node, toNodeK3), { x: CW / 2, y: CH / 2 }), `k=${toNodeK3.k}`);
const toNodeSmall = zoomToNode(fit, node, CW, CH, 0.5);
check("zoomToNode: explicit targetK below fitK clamps up to fitK", approx(toNodeSmall.k, fitK) && ptApprox(worldToScreen(node, toNodeSmall), { x: CW / 2, y: CH / 2 }), `k=${toNodeSmall.k} fitK=${fitK}`);
check("zoomToNode: default targetK is still 2", zoomToNode(fit, node, CW, CH).k === 2, `k=${zoomToNode(fit, node, CW, CH).k}`);
// The component's responsive target on a 360px-wide plane:
// min(2, fitK * 1.75) with fitK = min((360-16)/400, (380-16)/380).
const fit360 = fitView(360, 380);
const target360 = Math.min(2, fit360.k * 1.75);
const toNode360 = zoomToNode(fit360, node, 360, 380, target360);
check("zoomToNode: 360px responsive target centres the node below k=2", target360 < 2 && approx(toNode360.k, target360) && ptApprox(worldToScreen(node, toNode360), { x: 180, y: 190 }), `targetK=${target360} k=${toNode360.k}`);

// --- 8. worldToScreen / screenToWorld round-trip ---
const v: ViewTransform = { x: 30, y: -20, k: 2.5 };
const p = { x: 123, y: 45 };
check("worldToScreen: applies scale then translate", ptApprox(worldToScreen(p, v), { x: 123 * 2.5 + 30, y: 45 * 2.5 - 20 }));
check("screenToWorld: inverts worldToScreen", ptApprox(screenToWorld(worldToScreen(p, v), v), p));
check("round-trip: screen -> world -> screen", ptApprox(worldToScreen(screenToWorld({ x: 400, y: 300 }, v), v), { x: 400, y: 300 }));

// --- 9. viewTransformString ---
check("viewTransformString: exact format", viewTransformString({ x: 10, y: 20, k: 2 }) === "translate(10 20) scale(2)", viewTransformString({ x: 10, y: 20, k: 2 }));

// --- 10. ringLayout ---
const ring = ringLayout(4, 200, 190, 100);
check("ringLayout: n=4 gives 4 points", ring.length === 4);
check("ringLayout: first point is the top (angle -PI/2)", ptApprox(ring[0], { x: 200, y: 90 }, 1e-9), JSON.stringify(ring[0]));
check("ringLayout: second point is the right", ptApprox(ring[1], { x: 300, y: 190 }, 1e-9), JSON.stringify(ring[1]));
check("ringLayout: third point is the bottom", ptApprox(ring[2], { x: 200, y: 290 }, 1e-9), JSON.stringify(ring[2]));
check("ringLayout: fourth point is the left", ptApprox(ring[3], { x: 100, y: 190 }, 1e-9), JSON.stringify(ring[3]));
check("ringLayout: n=0 gives []", ringLayout(0, 0, 0, 10).length === 0);
check("ringLayout: n=1 gives the top point", ptApprox(ringLayout(1, 5, 6, 10)[0], { x: 5, y: -4 }, 1e-9));

// --- 11. resolveNodePositions ---
const base = new Map<string, { x: number; y: number }>([
  ["a", { x: 1, y: 2 }],
  ["b", { x: 3, y: 4 }],
]);
const overrides = new Map<string, { x: number; y: number }>([
  ["b", { x: 30, y: 40 }],
  ["c", { x: 5, y: 6 }],
]);
const resolved = resolveNodePositions(base, overrides);
check("resolveNodePositions: override wins", JSON.stringify(resolved.get("b")) === JSON.stringify({ x: 30, y: 40 }), JSON.stringify(resolved.get("b")));
check("resolveNodePositions: untouched base keys preserved", JSON.stringify(resolved.get("a")) === JSON.stringify({ x: 1, y: 2 }) && JSON.stringify(resolved.get("c")) === JSON.stringify({ x: 5, y: 6 }));
check("resolveNodePositions: base map untouched", JSON.stringify(base.get("b")) === JSON.stringify({ x: 3, y: 4 }) && !base.has("c"));
check("resolveNodePositions: overrides map untouched", overrides.size === 2);
check("resolveNodePositions: returns a new map", resolved !== base && resolved !== overrides);

// --- 12. togglePin (immutable) ---
const pins = new Set<string>(["a"]);
const added = togglePin(pins, "b");
check("togglePin: adds a missing id", added.has("a") && added.has("b") && added.size === 2);
check("togglePin: original set unchanged after add", pins.size === 1 && !pins.has("b"));
const removed = togglePin(added, "a");
check("togglePin: removes a present id", !removed.has("a") && removed.has("b") && removed.size === 1);
check("togglePin: original set unchanged after remove", added.size === 2 && added.has("a"));
check("togglePin: returns a new Set", added !== pins && removed !== added);

// --- 13. edgeLabelText ---
check("edgeLabelText: code -> 'used in code'", edgeLabelText("code") === "used in code");
check("edgeLabelText: test -> 'used in tests'", edgeLabelText("test") === "used in tests");
check("edgeLabelText: own -> 'lives in'", edgeLabelText("own") === "lives in");

// --- 14. edgeDetailText ---
const detailArgs = {
  findingTitle: "Test API key",
  findingFile: "src/config.ts",
  findingLine: 12,
  refFile: "src/service.ts",
  refLine: 34,
};
const fakeSecret = "FAKE-SECRET-VALUE-1234";
const codeDetail = edgeDetailText({ ...detailArgs, kind: "code" });
check(
  "edgeDetailText code: exact wording",
  codeDetail === "Secret Test API key lives in src/config.ts:12 and is read by src/service.ts:34. Rotating it means updating that file too.",
  codeDetail,
);
const testDetail = edgeDetailText({ ...detailArgs, kind: "test" });
check(
  "edgeDetailText test: exact wording",
  testDetail === "Secret Test API key lives in src/config.ts:12 and is read by src/service.ts:34 in a test — it proves the value is exercised, not that production uses it.",
  testDetail,
);
const ownDetail = edgeDetailText({ ...detailArgs, kind: "own" });
check(
  "edgeDetailText own: exact wording, uses refFile/refLine",
  ownDetail === "Secret Test API key lives in src/service.ts:34 — this is the file the secret itself sits in.",
  ownDetail,
);
check("edgeDetailText own: does not mention the finding file", !ownDetail.includes(detailArgs.findingFile));
for (const [kind, text] of [["code", codeDetail], ["test", testDetail], ["own", ownDetail]] as [EdgeKind, string][]) {
  check(`edgeDetailText ${kind}: contains title, both files, both lines`, text.includes("Test API key") && text.includes("src/config.ts") === (kind !== "own") && text.includes("src/service.ts") && (kind === "own" || text.includes(":12")) && text.includes(":34"));
  check(`edgeDetailText ${kind}: never contains a secret value`, !text.includes(fakeSecret));
}

// --- 15. neighboursOf ---
const edges = [
  { fromId: "repo", toId: "a", kind: "own" as EdgeKind },
  { fromId: "a", toId: "b", kind: "code" as EdgeKind },
  { fromId: "c", toId: "a", kind: "test" as EdgeKind },
  { fromId: "a", toId: "b", kind: "test" as EdgeKind }, // duplicate neighbour, second kind
  { fromId: "b", toId: "d", kind: "code" as EdgeKind },
];
const nbA = neighboursOf("a", edges);
check("neighboursOf: both directions (outgoing b, incoming c)", nbA.some((n) => n.id === "b") && nbA.some((n) => n.id === "c"));
check("neighboursOf: dedupes by id, keeps first kind (b is code)", nbA.filter((n) => n.id === "b").length === 1 && nbA.find((n) => n.id === "b")?.kind === "code", JSON.stringify(nbA));
check("neighboursOf: repo edge counts as a neighbour of a (repo is a node here)", nbA.some((n) => n.id === "repo"));
check("neighboursOf: 'repo' has no neighbours", neighboursOf("repo", edges).length === 0);
check("neighboursOf: unknown node has no neighbours", neighboursOf("zzz", edges).length === 0);
check("neighboursOf: leaf node sees its incoming neighbour", JSON.stringify(neighboursOf("d", edges)) === JSON.stringify([{ id: "b", kind: "code" }]), JSON.stringify(neighboursOf("d", edges)));

// --- 16. traverseStep / traverseBack ---
const path = ["repo", "a"];
const stepped = traverseStep(path, "b");
check("traverseStep: appends", JSON.stringify(stepped) === JSON.stringify(["repo", "a", "b"]));
check("traverseStep: does not mutate the input path", JSON.stringify(path) === JSON.stringify(["repo", "a"]));
const backtrack = traverseStep(path, "a");
check("traverseStep: immediate backtrack duplicate returns path unchanged", backtrack === path && backtrack.length === 2);
check("traverseBack: pops the last element", JSON.stringify(traverseBack(["repo", "a", "b"])) === JSON.stringify(["repo", "a"]));
const single = ["repo"];
check("traverseBack: never empties a 1-element path", traverseBack(single) === single && traverseBack(single).length === 1);
check("traverseBack: empty path returns unchanged", traverseBack([]).length === 0);

// --- 18. clusterEdgeLabels (fix round 3, 2026-11-27) ---
// Recheck-3 proved the round-2 t-stagger cannot separate 67px-wide
// identical labels on ~40-90-unit edges, so coincident same-kind
// labels collapse into one counted label. Greedy in draw order,
// grouped by kind, centroid = running mean of the cluster's items.
// Chaining is the specified behaviour: the centroid moves as items
// join, so a chain can merge even when its endpoints are farther
// apart than the threshold. A=(0,0), B=(40,0), C=(80,0) at
// threshold 60: B joins (40 from centroid 0), centroid moves to
// 20; C is 60 from centroid 20, so it joins too — even though A-C
// is 80, beyond the threshold.
const anchor = (x: number, y: number, kind: EdgeKind, edgeId: string): EdgeLabelAnchor => ({ x, y, kind, edgeId });
const coincident = clusterEdgeLabels([anchor(0, 0, "test", "a"), anchor(10, 0, "test", "b")], 60);
check("clusterEdgeLabels: two coincident same-kind anchors (distance 10, threshold 60) -> one cluster, count 2", coincident.length === 1 && coincident[0].count === 2, JSON.stringify(coincident));
check("clusterEdgeLabels: coincident cluster centroid is the midpoint (5, 0)", coincident.length === 1 && approx(coincident[0].x, 5) && approx(coincident[0].y, 0), JSON.stringify(coincident[0]));
check("clusterEdgeLabels: coincident cluster keeps both edge ids in draw order", coincident.length === 1 && JSON.stringify(coincident[0].edgeIds) === JSON.stringify(["a", "b"]), JSON.stringify(coincident[0].edgeIds));
const farApart = clusterEdgeLabels([anchor(0, 0, "test", "a"), anchor(200, 0, "test", "b")], 60);
check("clusterEdgeLabels: two far-apart same-kind anchors (distance 200) -> two clusters, count 1 each", farApart.length === 2 && farApart[0].count === 1 && farApart[1].count === 1, JSON.stringify(farApart));
check("clusterEdgeLabels: far-apart clusters stay in first-seen order", farApart.length === 2 && farApart[0].edgeIds[0] === "a" && farApart[1].edgeIds[0] === "b", JSON.stringify(farApart));
const diffKind = clusterEdgeLabels([anchor(0, 0, "test", "a"), anchor(0, 0, "code", "b")], 60);
check("clusterEdgeLabels: same position but different kinds -> two clusters (kinds never merge)", diffKind.length === 2 && diffKind[0].kind === "test" && diffKind[1].kind === "code", JSON.stringify(diffKind));
const singleCluster = clusterEdgeLabels([anchor(7, 3, "own", "only")], 60);
check("clusterEdgeLabels: single item -> one cluster, count 1, at the item position", singleCluster.length === 1 && singleCluster[0].count === 1 && singleCluster[0].x === 7 && singleCluster[0].y === 3 && singleCluster[0].kind === "own", JSON.stringify(singleCluster));
const chained = clusterEdgeLabels([anchor(0, 0, "test", "a"), anchor(40, 0, "test", "b"), anchor(80, 0, "test", "c")], 60);
check("clusterEdgeLabels: chained A-B-C (A-B 40, B-C 40, A-C 80 > 60) -> ONE cluster via the moving centroid", chained.length === 1 && chained[0].count === 3, JSON.stringify(chained));
check("clusterEdgeLabels: chained cluster centroid is the mean of all three (40, 0)", chained.length === 1 && approx(chained[0].x, 40) && approx(chained[0].y, 0), JSON.stringify(chained[0]));
check("clusterEdgeLabels: empty input -> no clusters", clusterEdgeLabels([], 60).length === 0);

// --- 19. edgeLabelThresholdWorld (fix round 4, 2026-11-27) ---
// Recheck-4 proved `70 / view.k` is backwards: at k=1.831 it passed
// 38 world units while "used in tests ×18" needs ~71, so 6 pairs
// still overlapped at zoom. Labels live inside the transformed <g>,
// so label width and anchor distance both scale with k — the
// threshold is scale-invariant, simply the widest visible label in
// world units: text.length * 4 + 8 per kind, max over kinds present,
// 70 when no kinds are present.
// NOTE on the worked example: the brief states 80 for 18 "used in
// tests" edges, but the formula as specified gives 76 — the text
// "used in tests ×18" is 17 chars (13 + 4), not 18, so 17*4+8=76.
// 76 still exceeds the measured 71 world units, so the safe margin
// holds; the test asserts the formula's true value, not the brief's
// miscount.
check("edgeLabelThresholdWorld: 18 'used in tests' edges -> 76 (17 chars * 4 + 8)", edgeLabelThresholdWorld([{ kind: "test", count: 18 }]) === 76, `got=${edgeLabelThresholdWorld([{ kind: "test", count: 18 }])}`);
check("edgeLabelThresholdWorld: one 'used in code' edge -> 56 (12 chars * 4 + 8)", edgeLabelThresholdWorld([{ kind: "code", count: 1 }]) === 56, `got=${edgeLabelThresholdWorld([{ kind: "code", count: 1 }])}`);
check("edgeLabelThresholdWorld: single 'used in tests' edge -> 60 (13 chars * 4 + 8)", edgeLabelThresholdWorld([{ kind: "test", count: 1 }]) === 60, `got=${edgeLabelThresholdWorld([{ kind: "test", count: 1 }])}`);
check("edgeLabelThresholdWorld: empty input -> 70 (uncounted-label default)", edgeLabelThresholdWorld([]) === 70, `got=${edgeLabelThresholdWorld([])}`);
check("edgeLabelThresholdWorld: mixed kinds -> max of the two (test x2 = 72, code x1 = 56)", edgeLabelThresholdWorld([{ kind: "test", count: 2 }, { kind: "code", count: 1 }]) === 72, `got=${edgeLabelThresholdWorld([{ kind: "test", count: 2 }, { kind: "code", count: 1 }])}`);
check("edgeLabelThresholdWorld: 'lives in x3' alone -> 52 (11 chars * 4 + 8), below the empty default", edgeLabelThresholdWorld([{ kind: "own", count: 3 }]) === 52, `got=${edgeLabelThresholdWorld([{ kind: "own", count: 3 }])}`);

// --- 20. No literal secret-pattern values in this file ---
import { readFileSync } from "node:fs";
const self = readFileSync(new URL(import.meta.url).pathname, "utf8");
const leaked = ["AKIA" + "IOSFODNN7EXAMPLE", "ghp_" + "FAKE".repeat(8) + "1234", "sk_test_" + "FAKE".repeat(6) + "12"].some((s) => self.includes(s));
check("No literal secret-pattern values in this file", !leaked);

console.log(failures === 0 ? `\nPASS ${total}/${total}` : `\n${failures} test(s) FAILED out of ${total}.`);
process.exit(failures === 0 ? 0 : 1);
