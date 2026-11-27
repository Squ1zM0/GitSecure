// Phase 19 map test — category nodes, "found in" edges, category
// filter, raised caps, and the label-collision helpers.
// Run: npm run test:map-phase19
//
// Covers src/lib/map-view.ts (new "found" edge kind, posture
// categories, polygon shapes, category filter, cap helpers) plus
// render-to-string checks that the legend, filter toggles, cap line,
// and posture nodes render through UsageMap / SecretsList /
// ReportView. No secret-pattern values anywhere in this file: the
// fixtures use obviously fake fragments like "abcd…yz".

import { readFileSync } from "node:fs";
import { renderToString } from "react-dom/server";
import React from "react";
import {
  MAP_CATEGORY_META,
  MAP_CATEGORY_ORDER,
  MAP_MAX_FILE_NODES,
  MAP_MAX_POSTURE_NODES,
  MAP_MAX_SECRET_NODES,
  capNote,
  cappedSlice,
  categoryLabel,
  categoryPolygonPoints,
  clusterEdgeLabels,
  clusterLabelText,
  edgeDetailText,
  edgeLabelText,
  edgeLabelThresholdWorld,
  filterByCategory,
  postureCategoryOf,
  resolveLabelCollisions,
  type EdgeKind,
  type EdgeLabelAnchor,
  type EdgeLabelCluster,
  type MapCategory,
  type PostureCategory,
} from "../src/lib/map-view";
import { UsageMap, SecretsList } from "../src/components/ReportLists";
import ReportView from "../src/components/ReportView";
import type { PostureIssue, SecretFinding } from "../src/lib/types";

let failures = 0;
let total = 0;
function check(name: string, ok: boolean, extra = "") {
  total++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

const stripComments = (html: string) => html.replace(/<!-- -->/g, "");

// --- 1. New edge kind "found" ---------------------------------------
check("edgeLabelText: found -> 'found in'", edgeLabelText("found") === "found in");
check("edgeLabelText: code/test/own unchanged", edgeLabelText("code") === "used in code" && edgeLabelText("test") === "used in tests" && edgeLabelText("own") === "lives in");
const foundDetail = edgeDetailText({
  findingTitle: "SQL injection in login",
  findingFile: "src/auth.ts",
  findingLine: 42,
  refFile: "src/auth.ts",
  refLine: 42,
  kind: "found",
});
check(
  "edgeDetailText found: exact wording with line",
  foundDetail === "Finding SQL injection in login was found in src/auth.ts:42.",
  foundDetail,
);
const foundNoLine = edgeDetailText({
  findingTitle: "Container runs as root",
  findingFile: "Dockerfile",
  findingLine: 0,
  refFile: "Dockerfile",
  refLine: 0,
  kind: "found",
});
check(
  "edgeDetailText found: line 0 omits the line number",
  foundNoLine === "Finding Container runs as root was found in Dockerfile.",
  foundNoLine,
);
check(
  "edgeDetailText found: never says 'Secret'",
  !foundDetail.includes("Secret") && !foundNoLine.includes("Secret"),
);

// --- 2. Posture categories ------------------------------------------
const allCats: PostureCategory[] = ["code-risk", "actions", "container", "exposed-file", "install-script", "web-config", "hygiene"];
for (const c of allCats) {
  check(`postureCategoryOf: '${c}' maps to itself`, postureCategoryOf({ category: c }) === c);
}
check("postureCategoryOf: missing category counts as hygiene", postureCategoryOf({}) === "hygiene");
check("postureCategoryOf: unknown category counts as hygiene", postureCategoryOf({ category: "bogus" }) === "hygiene");
check("postureCategoryOf: empty category counts as hygiene", postureCategoryOf({ category: "" }) === "hygiene");

const expectedLabels: Record<MapCategory, string> = {
  secrets: "Secrets",
  "code-risk": "Code risks",
  actions: "Actions hardening",
  container: "Container hardening",
  "exposed-file": "Exposed files",
  "install-script": "Install scripts",
  "web-config": "Web config",
  hygiene: "Hygiene",
};
for (const [cat, label] of Object.entries(expectedLabels) as [MapCategory, string][]) {
  check(`categoryLabel: '${cat}' -> '${label}'`, categoryLabel(cat) === label);
}
check(
  "MAP_CATEGORY_ORDER: secrets first, hygiene last, all 12 present",
  MAP_CATEGORY_ORDER.length === 12 && MAP_CATEGORY_ORDER[0] === "secrets" && MAP_CATEGORY_ORDER[11] === "hygiene" && new Set(MAP_CATEGORY_ORDER).size === 12,
);
// Every category has a distinct node shape (sides + rotation), so
// the category never rides on colour alone. Secrets are the circle
// (sides 0); the two triangles point opposite ways.
const shapeKeys = (Object.entries(MAP_CATEGORY_META) as [MapCategory, { sides: number; rotation: number }][]).map(
  ([, m]) => `${m.sides}/${m.rotation}`,
);
check("MAP_CATEGORY_META: all 12 shapes distinct by sides/rotation", new Set(shapeKeys).size === 12, shapeKeys.join(", "));
check("MAP_CATEGORY_META: secrets is the circle (sides 0)", MAP_CATEGORY_META.secrets.sides === 0);
check("MAP_CATEGORY_META: Phase 20 categories present with their own shapes", MAP_CATEGORY_META.ci.sides === 7 && MAP_CATEGORY_META.tls.sides === 9 && MAP_CATEGORY_META.xss.sides === 5 && MAP_CATEGORY_META.logging.sides === 6);
check("MAP_CATEGORY_META: code-risk is the diamond (4 sides, rotation 0)", MAP_CATEGORY_META["code-risk"].sides === 4 && MAP_CATEGORY_META["code-risk"].rotation === 0);
check("MAP_CATEGORY_META: actions is the square (4 sides, rotation 45)", MAP_CATEGORY_META.actions.sides === 4 && MAP_CATEGORY_META.actions.rotation === 45);
check("MAP_CATEGORY_META: hygiene triangle points down (3 sides, rotation 180)", MAP_CATEGORY_META.hygiene.sides === 3 && MAP_CATEGORY_META.hygiene.rotation === 180);
check("MAP_CATEGORY_META: exposed-file triangle points up (3 sides, rotation 0)", MAP_CATEGORY_META["exposed-file"].sides === 3 && MAP_CATEGORY_META["exposed-file"].rotation === 0);

// --- 3. Polygon points ----------------------------------------------
const pts = (s: string) => s.split(" ").map((p) => p.split(",").map(Number) as [number, number]);
const dist = ([x, y]: [number, number], [cx, cy]: [number, number]) => Math.hypot(x - cx, y - cy);
const diamond = categoryPolygonPoints(4, 0, 200, 190, 12);
check("categoryPolygonPoints: diamond has 4 points", pts(diamond).length === 4, diamond);
check(
  "categoryPolygonPoints: diamond first point is the top (200, 178)",
  pts(diamond)[0][0] === 200 && pts(diamond)[0][1] === 178,
  JSON.stringify(pts(diamond)[0]),
);
const square = categoryPolygonPoints(4, 45, 200, 190, 12);
check("categoryPolygonPoints: square has 4 points", pts(square).length === 4);
check(
  "categoryPolygonPoints: square first point is upper-right, not the top",
  Math.abs(pts(square)[0][0] - (200 + 12 * Math.cos((-45 * Math.PI) / 180))) < 0.06 && pts(square)[0][1] < 190,
  JSON.stringify(pts(square)[0]),
);
check("categoryPolygonPoints: hexagon has 6 points", pts(categoryPolygonPoints(6, 0, 0, 0, 10)).length === 6);
check("categoryPolygonPoints: pentagon has 5 points", pts(categoryPolygonPoints(5, 0, 0, 0, 10)).length === 5);
check("categoryPolygonPoints: octagon has 8 points", pts(categoryPolygonPoints(8, 22.5, 0, 0, 10)).length === 8);
check(
  "categoryPolygonPoints: every vertex sits on the radius",
  pts(categoryPolygonPoints(6, 0, 50, 60, 10)).every((p) => Math.abs(dist(p, [50, 60]) - 10) < 0.06),
);
check("categoryPolygonPoints: sides < 3 returns empty (circle instead)", categoryPolygonPoints(2, 0, 0, 0, 10) === "" && categoryPolygonPoints(0, 0, 0, 0, 10) === "");
check("categoryPolygonPoints: radius 0 returns empty", categoryPolygonPoints(4, 0, 0, 0, 0) === "");

// --- 4. Category filter helper --------------------------------------
type CatItem = { id: string; category: MapCategory };
const catItems: CatItem[] = [
  { id: "a", category: "secrets" },
  { id: "b", category: "code-risk" },
  { id: "c", category: "actions" },
  { id: "d", category: "code-risk" },
];
const noneHidden = filterByCategory(catItems, new Set());
check("filterByCategory: empty hidden set keeps all, as a copy", noneHidden.length === 4 && noneHidden !== catItems);
const oneHidden = filterByCategory(catItems, new Set<MapCategory>(["code-risk"]));
check("filterByCategory: hides only that category", oneHidden.length === 2 && oneHidden.every((i) => i.category !== "code-risk"), JSON.stringify(oneHidden.map((i) => i.id)));
check("filterByCategory: input untouched", catItems.length === 4);
check("filterByCategory: hiding everything returns []", filterByCategory(catItems, new Set<MapCategory>(["secrets", "code-risk", "actions"])).length === 0);

// --- 5. Cap helpers --------------------------------------------------
check("MAP_MAX_SECRET_NODES is 24 (raised from 12)", MAP_MAX_SECRET_NODES === 24);
check("MAP_MAX_POSTURE_NODES is 24", MAP_MAX_POSTURE_NODES === 24);
check("MAP_MAX_FILE_NODES is 32 (raised from 24)", MAP_MAX_FILE_NODES === 32);
const under = cappedSlice([1, 2, 3], 24);
check("cappedSlice: under the cap shows all, hides none", under.shown.length === 3 && under.hidden === 0);
const over = cappedSlice([1, 2, 3, 4, 5], 3);
check("cappedSlice: over the cap shows the first N and counts the rest", JSON.stringify(over.shown) === "[1,2,3]" && over.hidden === 2, JSON.stringify(over));
const exact = cappedSlice([1, 2], 2);
check("cappedSlice: exactly at the cap hides none", exact.hidden === 0 && exact.shown.length === 2);
const zero = cappedSlice([1, 2], 0);
check("cappedSlice: cap 0 shows none, hides all", zero.shown.length === 0 && zero.hidden === 2);
check("cappedSlice: empty input hides none", cappedSlice([], 24).hidden === 0);
check("capNote: nothing capped returns null", capNote(3, 3, "secrets") === null && capNote(2, 1, "secrets") === null);
check(
  "capNote: capped case names shown, total, and noun",
  capNote(24, 30, "secrets") === "Showing first 24 of 30 secrets on the map; the full list is below.",
  String(capNote(24, 30, "secrets")),
);

// --- 6. "found" kind in the label machinery -------------------------
const anchor = (x: number, y: number, kind: EdgeKind, edgeId: string): EdgeLabelAnchor => ({ x, y, kind, edgeId });
const foundMerged = clusterEdgeLabels([anchor(0, 0, "found", "a"), anchor(10, 0, "found", "b")], 60);
check("clusterEdgeLabels: two coincident 'found in' anchors merge, count 2", foundMerged.length === 1 && foundMerged[0].count === 2 && foundMerged[0].kind === "found");
const foundVsCode = clusterEdgeLabels([anchor(0, 0, "found", "a"), anchor(0, 0, "code", "b")], 60);
check("clusterEdgeLabels: 'found in' never merges with 'used in code'", foundVsCode.length === 2);
check("clusterLabelText: found count 3 -> 'found in ×3'", clusterLabelText("found", 3) === "found in ×3");
check("edgeLabelThresholdWorld: single 'found in' edge -> 40 (8 chars * 4 + 8)", edgeLabelThresholdWorld([{ kind: "found", count: 1 }]) === 40);
check("edgeLabelThresholdWorld: 'found in ×12' -> 56 (12 chars * 4 + 8)", edgeLabelThresholdWorld([{ kind: "found", count: 12 }]) === 56);
check(
  "edgeLabelThresholdWorld: mixed kinds take the max (found x12 = 60, test x1 = 60)",
  edgeLabelThresholdWorld([{ kind: "found", count: 12 }, { kind: "test", count: 1 }]) === 60,
);
const cluster = (x: number, y: number, kind: EdgeKind, count: number, edgeId: string): EdgeLabelCluster => ({ x, y, kind, count, edgeIds: [edgeId] });
const blocker = (x: number, y: number, w: number, h: number) => ({ x, y, w, h });
const rectOverlap = (a: { x0: number; y0: number; x1: number; y1: number }, b: { x0: number; y0: number; x1: number; y1: number }) => {
  const w = Math.min(a.x1, b.x1) - Math.max(a.x0, b.x0);
  const h = Math.min(a.y1, b.y1) - Math.max(a.y0, b.y0);
  return w > 0 && h > 0 ? w * h : 0;
};
const labelBox = (c: EdgeLabelCluster) => {
  const t = clusterLabelText(c.kind, c.count);
  const w = t.length * 4 + 8;
  return { x0: c.x - w / 2, y0: c.y - 8, x1: c.x + w / 2, y1: c.y + 8 };
};
const blockerBox = (b: { x: number; y: number; w: number; h: number }) => ({ x0: b.x - b.w / 2, y0: b.y - b.h / 2, x1: b.x + b.w / 2, y1: b.y + b.h / 2 });
const foundOnNode = resolveLabelCollisions([cluster(200, 190, "found", 1, "e1")], [blocker(200, 190, 60, 60)], new Map([["e1", { x: 1, y: 0 }]]));
check(
  "resolveLabelCollisions: 'found in' label centred on a node moves to zero overlap",
  rectOverlap(labelBox(foundOnNode[0]), blockerBox(blocker(200, 190, 60, 60))) === 0,
  `moved to (${foundOnNode[0].x}, ${foundOnNode[0].y})`,
);

// --- 7. Fixtures for the render checks ------------------------------
// Posture fixtures carry the Phase 19 fields (category, file, line).
// Built through `as unknown as` so this file also runs before the
// parallel types.ts change lands; the field names are the specified
// ones. One issue per category, plus one with no category (hygiene
// fallback) and one with no file (node with no edge).
const postureFixture = (p: Record<string, unknown>): PostureIssue => p as unknown as PostureIssue;
const posture: PostureIssue[] = [
  postureFixture({ id: "p-cr1", title: "SQL injection in login", severity: "high", detail: "Login query built from user input.", fix: "Use a parameterised query.", category: "code-risk", file: "src/auth.ts", line: 42 }),
  postureFixture({ id: "p-ac1", title: "Third-party action not pinned to a SHA", severity: "high", detail: "Action pinned to a major version only.", fix: "Pin the full commit SHA.", category: "actions", file: ".github/workflows/ci.yml", line: 12 }),
  postureFixture({ id: "p-cn1", title: "Container runs as root", severity: "medium", detail: "No USER instruction in the Dockerfile.", fix: "Add a USER instruction.", category: "container", file: "Dockerfile", line: 1 }),
  postureFixture({ id: "p-ef1", title: "Committed database dump", severity: "high", detail: "A .sql dump is committed.", fix: "Remove it and rotate any credentials in it.", category: "exposed-file", file: "db/backup.sql", line: 0 }),
  postureFixture({ id: "p-is1", title: "postinstall script runs on install", severity: "medium", detail: "A postinstall script runs arbitrary code.", fix: "Remove the script or move it to a manual step.", category: "install-script", file: "package.json", line: 8 }),
  postureFixture({ id: "p-wc1", title: "JWT none algorithm accepted", severity: "high", detail: "Tokens with alg none are accepted.", fix: "Reject alg none.", category: "web-config", file: "src/auth.ts", line: 77 }),
  postureFixture({ id: "p-hy1", title: "No SECURITY.md", severity: "low", detail: "No SECURITY.md in the repo.", fix: "Add one.", category: "hygiene" }),
  postureFixture({ id: "p-unc", title: "No .gitignore", severity: "medium", detail: "No .gitignore in the repo.", fix: "Add one." }),
];
const secretWithUsage: SecretFinding = {
  id: "s1",
  type: "api-key",
  title: "API key",
  severity: "high",
  confidence: "high",
  file: "src/config.ts",
  line: 5,
  commit: "HEAD",
  fragment: "abcd…yz",
  fix: "Rotate it.",
  plainEnglish: "An API key sits in the config.",
  usage: {
    referencedBy: [{ file: "src/app.ts", line: 10 }],
    referencedByTotal: 1,
    referencedByTests: [{ file: "tests/app.test.ts", line: 5 }],
    referencedByTestsTotal: 1,
    deadEnd: false,
  },
};
const byFile = [
  { file: "src/config.ts", count: 1 },
  { file: "src/app.ts", count: 0 },
  { file: "tests/app.test.ts", count: 0 },
];

const mapHtml = stripComments(
  renderToString(
    React.createElement(UsageMap, { findings: [{ item: secretWithUsage, idx: 0 }], posture, byFile, onSelectFile: () => {} }),
  ),
);

// --- 8. Legend --------------------------------------------------------
for (const [cat, label] of Object.entries(expectedLabels) as [MapCategory, string][]) {
  check(`legend: '${label}' renders`, mapHtml.includes(label));
}
check("legend: 'found in' edge explained", mapHtml.includes("Found in - posture issue in that file"));
check("legend: category counts render (Hygiene 2, Secrets 1)", mapHtml.includes("Hygiene (2)") && mapHtml.includes("Secrets (1)"));
check("legend: category shapes render as inline SVG polygons", (mapHtml.match(/<polygon points="/g) ?? []).length >= 7, `polygons=${(mapHtml.match(/<polygon points="/g) ?? []).length}`);

// --- 9. Filter toggles ------------------------------------------------
check("filter: toggle group renders when 2+ categories present", mapHtml.includes('aria-label="Map category filters"'));
check(
  "filter: one toggle per category, all pressed (visible) by default",
  (mapHtml.match(/aria-pressed="true"/g) ?? []).length === 8,
  `pressed=${(mapHtml.match(/aria-pressed="true"/g) ?? []).length}`,
);
check("filter: toggle labels carry counts", mapHtml.includes("Code risks (1)") && mapHtml.includes("Hygiene (2)"));
check("filter: hint states the plane-only rule", mapHtml.includes("Category buttons above the plane show or hide each category; the lists below never change."));
const secretsOnlyHtml = stripComments(
  renderToString(
    React.createElement(UsageMap, { findings: [{ item: secretWithUsage, idx: 0 }], byFile, onSelectFile: () => {} }),
  ),
);
check("filter: no toggle row with a single category (button count stays 4)", !secretsOnlyHtml.includes('aria-label="Map category filters"') && (secretsOnlyHtml.match(/<button/g) ?? []).length === 4);

// --- 10. Posture nodes and "found in" edges --------------------------
check("map: 8 posture nodes render (one per issue)", (mapHtml.match(/map-posture-node/g) ?? []).length === 8, `nodes=${(mapHtml.match(/map-posture-node/g) ?? []).length}`);
check("map: posture nodes carry their category codes (CR1, HY1, HY2)", mapHtml.includes(">CR1<") && mapHtml.includes(">HY1<") && mapHtml.includes(">HY2<"));
check("map: uncategorised issue falls back to hygiene (HY2 exists)", mapHtml.includes(">HY2<"));
check("map: 6 'found in' edges (two file-less issues have none)", (mapHtml.match(/map-edge-found/g) ?? []).length === 6, `found=${(mapHtml.match(/map-edge-found/g) ?? []).length}`);
check(
  "map: 'found in' edge aria-label names the issue and file:line",
  mapHtml.includes('aria-label="Connection: SQL injection in login found in src/auth.ts line 42"'),
);
check(
  "map: 'found in' edge without a line omits it in the aria-label",
  mapHtml.includes('aria-label="Connection: Committed database dump found in db/backup.sql"'),
);
check("map: edge kind labels stay gated at fit zoom (no visible 'found in' text)", !mapHtml.includes(">found in<"));
check("map: secret edges unchanged (code + test + own still render)", mapHtml.includes("map-edge-code") && mapHtml.includes("map-edge-test") && mapHtml.includes("map-edge-own"));
check(
  "map: screen-reader summary names secrets, posture issues, and found-in links",
  mapHtml.includes("Usage map: 1 secrets and 8 posture issues drawn across 8 files. 1 code references, 1 test references, 1 own-file links, 6 found-in links."),
);
check("map: intro states the shown/total counts per kind", mapHtml.includes("Showing 1 of 1 secrets and 8 of 8 posture issues across 8 files."));
check("map: no cap line when nothing is capped", !mapHtml.includes("Map caps:"));

// --- 11. Legacy wording holds with no posture ------------------------
check(
  "legacy: screen-reader summary keeps the exact old wording with no posture",
  secretsOnlyHtml.includes("Usage map: 1 findings and 3 files drawn. 1 code references, 1 test references, 1 own-file links."),
);
check(
  "legacy: intro keeps the old wording with no posture",
  secretsOnlyHtml.includes("Usage map - follow a secret through the repo. Showing 1 of 1 findings and 3 files."),
);
check("legacy: no posture nodes and no 'found in' edges with no posture", !secretsOnlyHtml.includes("map-posture-node") && !secretsOnlyHtml.includes("map-edge-found"));

// --- 12. Caps ---------------------------------------------------------
const manySecrets: SecretFinding[] = Array.from({ length: 30 }, (_, i) => ({
  id: `s${i}`,
  type: "api-key",
  title: `API key ${i + 1}`,
  severity: "medium",
  confidence: "high",
  file: `src/secret${i}.ts`,
  line: 1,
  commit: "HEAD",
  fragment: "abcd…yz",
  fix: "Rotate it.",
  plainEnglish: "An API key sits in a file.",
}));
const manyPosture: PostureIssue[] = Array.from({ length: 30 }, (_, i) =>
  postureFixture({
    id: `p${i}`,
    title: `Code risk ${i + 1}`,
    severity: "medium",
    detail: "A risky pattern.",
    fix: "Fix it.",
    category: "code-risk",
    file: `src/risk${i}.ts`,
    line: 1,
  }),
);
const manyByFile = manySecrets.map((s) => ({ file: s.file, count: 1 }));
const cappedHtml = stripComments(
  renderToString(
    React.createElement(UsageMap, { findings: manySecrets.map((item, idx) => ({ item, idx })), posture: manyPosture, byFile: manyByFile, onSelectFile: () => {} }),
  ),
);
check("caps: cap line states the maxima", cappedHtml.includes("Map caps: 24 secrets, 24 posture issues, 32 files."));
check("caps: secret cap note names 24 of 30", cappedHtml.includes("Showing first 24 of 30 secrets on the map; the full list is below."));
check("caps: posture cap note names 24 of 30", cappedHtml.includes("Showing first 24 of 30 posture issues on the map; the full list is below."));
check("caps: file cap note names 32 of 60", cappedHtml.includes("Showing first 32 of 60 files on the map; the full list is below."));
check("caps: only 24 secret nodes render", (cappedHtml.match(/map-finding-node/g) ?? []).length === 24, `secret nodes=${(cappedHtml.match(/map-finding-node/g) ?? []).length}`);
check("caps: only 24 posture nodes render", (cappedHtml.match(/map-posture-node/g) ?? []).length === 24, `posture nodes=${(cappedHtml.match(/map-posture-node/g) ?? []).length}`);

// --- 13. Zero findings ----------------------------------------------
const emptyHtml = stripComments(
  renderToString(React.createElement(UsageMap, { findings: [], posture: [], byFile: [], onSelectFile: () => {} })),
);
check(
  "empty: repo node plus the empty-state note, no posture nodes",
  emptyHtml.includes("map-plane") && emptyHtml.includes("This repo") && emptyHtml.includes("No secrets in this report") && !emptyHtml.includes("map-posture-node"),
);
check("empty: no filter row with zero categories", !emptyHtml.includes('aria-label="Map category filters"'));

// --- 14. Threading: SecretsList and ReportView ----------------------
const listHtml = stripComments(
  renderToString(
    React.createElement(SecretsList, { secrets: [], posture, owner: "Squ1zM0", repo: "TechDirect", branch: "main" }),
  ),
);
check(
  "threading: SecretsList with no secrets opens on the map with posture nodes",
  listHtml.includes("map-plane") && (listHtml.match(/map-posture-node/g) ?? []).length === 8,
);
check("threading: SecretsList map shows the posture legend", listHtml.includes("Code risks (1)") && listHtml.includes("Hygiene (2)"));
check("threading: list counts never mention posture (secrets count stays honest)", listHtml.includes("Showing 0 of 0 secrets"));

const report = {
  kind: "full",
  repo: "TechDirect",
  owner: "Squ1zM0",
  branch: "main",
  commit: "abc1234",
  score: 50,
  grade: "C",
  scoreDetail: {
    score: 50,
    grade: "C",
    secretsDeduction: 0,
    secretsFullWeight: 0,
    secretsHalfWeight: 0,
    secretsExcluded: 0,
    wouldBeScore: 50,
    vulnDeduction: 0,
    postureDeduction: 10,
    unpinnedDeduction: 0,
  },
  counts: { secrets: 0, testKeySecrets: 0, vulnerabilities: 0, frameworks: 0, dependencies: 0, postureIssues: 8, filesScanned: 10, historyCommitsScanned: 1 },
  summary: "No secrets and eight posture issues.",
  scannedAt: new Date("2026-11-27T07:00:00Z").toISOString(),
  historyDepth: "1 commit",
  limits: ["History checked: 1 commit."],
  // No secrets, so SecretsList opens on the map view by default
  // and the threading check can see the plane.
  secrets: [],
  frameworks: [],
  dependencies: [],
  vulnerabilities: [],
  posture,
} as unknown as Parameters<typeof ReportView>[0]["report"];
const reportHtml = stripComments(renderToString(React.createElement(ReportView, { report })));
check(
  "threading: ReportView passes posture to the map (nodes + legend render)",
  reportHtml.includes("map-plane") && (reportHtml.match(/map-posture-node/g) ?? []).length === 8 && reportHtml.includes("Code risks (1)"),
);
check("threading: ReportView posture section still lists all 8 issues", reportHtml.includes("Security posture (8)") && reportHtml.includes("SQL injection in login"));

// --- 15. No em dash in the new copy ----------------------------------
const newCopy = [
  "Found in - posture issue in that file",
  "Category buttons above the plane show or hide each category; the lists below never change.",
  "Usage map - follow a finding through the repo.",
  "Map caps: 24 secrets, 24 posture issues, 32 files.",
];
for (const s of newCopy) {
  check(`copy: '${s.slice(0, 40)}...' renders with hyphens, no em dash`, mapHtml.includes(s) || cappedHtml.includes(s));
}
for (const f of ["src/lib/map-view.ts", "src/components/ReportLists.tsx"]) {
  const lines = readFileSync(new URL(`../${f}`, import.meta.url).pathname, "utf8").split("\n");
  const bad = lines.filter((l) => l.includes("Phase 19") && l.includes("—"));
  check(`copy: no em dash on any 'Phase 19' line in ${f}`, bad.length === 0, bad.join(" | ").slice(0, 200));
}

console.log(failures === 0 ? `\nPASS ${total}/${total}` : `\n${failures} test(s) FAILED out of ${total}.`);
process.exit(failures === 0 ? 0 : 1);
