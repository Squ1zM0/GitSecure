// Map ordering test - connected nodes sit on the same side so their
// edges do not intersect (Freddy, 2026-11-28).
// Run: npm run test:map-ordering
//
// Covers src/lib/map-view.ts computeSectorLayout: the greedy parent
// order (parents sharing files sit together, a shared own file
// counts 10x a shared reference) and the median claim (a file sits
// in the sector of its median owner, else its median referencer).
// The fixture mirrors the live self-scan report's connection
// structure (24 drawn findings, 10 files): eight findings share
// four test files, and three files are owned by several findings
// each. On the live report the old first-claim rule gave 33
// own-edge crossings; this layout gives 0. No secret-pattern values
// anywhere: file names are single letters.

import { computeSectorLayout, type SectorLayoutParent } from "../src/lib/map-view";

let failures = 0;
let total = 0;
function check(name: string, ok: boolean, extra = "") {
  total++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

// Fixture: files A-I mirror the live self-scan's shared files.
// A = owned by S8, S35, S2-S7; B = owned by S15, S23, S10-S14;
// C = owned by S17, S18, S21, S22; D, E = owned by nobody, only
// referenced by the eight heavy findings; F, G, I = single owners;
// H = owned by S16, S20.
const parents: SectorLayoutParent[] = [
  { id: "S8", radius: 225, ownFile: "A", refs: ["D", "E", "B"] },
  { id: "S35", radius: 225, ownFile: "A", refs: ["D", "E", "B"] },
  { id: "S17", radius: 225, ownFile: "C", refs: ["D", "E", "A", "B"] },
  { id: "S18", radius: 225, ownFile: "C", refs: ["D", "E", "A", "B"] },
  { id: "S21", radius: 225, ownFile: "C", refs: ["D", "E", "A", "B"] },
  { id: "S22", radius: 225, ownFile: "C", refs: ["D", "E", "A", "B"] },
  { id: "S15", radius: 225, ownFile: "B", refs: ["D", "E", "A", "C"] },
  { id: "S23", radius: 225, ownFile: "B", refs: ["D", "E", "A", "C"] },
  { id: "S1", radius: 225, ownFile: "F", refs: [] },
  { id: "S2", radius: 225, ownFile: "A", refs: [] },
  { id: "S3", radius: 225, ownFile: "A", refs: [] },
  { id: "S4", radius: 225, ownFile: "A", refs: [] },
  { id: "S5", radius: 225, ownFile: "A", refs: [] },
  { id: "S6", radius: 225, ownFile: "A", refs: [] },
  { id: "S7", radius: 225, ownFile: "A", refs: [] },
  { id: "S9", radius: 225, ownFile: "G", refs: [] },
  { id: "S10", radius: 225, ownFile: "B", refs: [] },
  { id: "S11", radius: 225, ownFile: "B", refs: [] },
  { id: "S12", radius: 225, ownFile: "B", refs: [] },
  { id: "S13", radius: 225, ownFile: "B", refs: [] },
  { id: "S14", radius: 225, ownFile: "B", refs: [] },
  { id: "S16", radius: 225, ownFile: "H", refs: [] },
  { id: "S19", radius: 225, ownFile: "I", refs: [] },
  { id: "S20", radius: 225, ownFile: "H", refs: [] },
];
const fileIds = ["A", "B", "C", "D", "E", "F", "G", "H", "I"];
const centre = { x: 240, y: 240 };
const { positions, order, claimParent } = computeSectorLayout(parents, fileIds, centre, 140);

// --- 1. Greedy order groups owners of the same file together ---
const expectedOrder = [
  "S8", "S35", "S2", "S3", "S4", "S5", "S6", "S7",
  "S17", "S18", "S21", "S22",
  "S15", "S23", "S10", "S11", "S12", "S13", "S14",
  "S1", "S9", "S16", "S20", "S19",
];
check("order: owners of the same file cluster together", JSON.stringify(order) === JSON.stringify(expectedOrder), order.join(" "));
const contiguous = (ids: string[]) => {
  const idxs = ids.map((id) => order.indexOf(id)).sort((a, b) => a - b);
  return idxs[idxs.length - 1] - idxs[0] === idxs.length - 1;
};
check("order: owners of A are contiguous", contiguous(["S8", "S35", "S2", "S3", "S4", "S5", "S6", "S7"]));
check("order: owners of B are contiguous", contiguous(["S15", "S23", "S10", "S11", "S12", "S13", "S14"]));
check("order: owners of C are contiguous", contiguous(["S17", "S18", "S21", "S22"]));
check("order: owners of H are contiguous", contiguous(["S16", "S20"]));

// --- 2. Median claim puts each file in the middle of its owners ---
check("claim: A (8 owners) goes to the lower-median owner S3", claimParent.get("A") === "S3", `got ${claimParent.get("A")}`);
check("claim: B (7 owners) goes to the lower-median owner S11", claimParent.get("B") === "S11", `got ${claimParent.get("B")}`);
check("claim: C (4 owners) goes to the lower-median owner S18", claimParent.get("C") === "S18", `got ${claimParent.get("C")}`);
check("claim: D (no owner) goes to the lower-median referencer S18", claimParent.get("D") === "S18", `got ${claimParent.get("D")}`);
check("claim: E (no owner) goes to the lower-median referencer S18", claimParent.get("E") === "S18", `got ${claimParent.get("E")}`);
check("claim: H (2 owners) goes to the lower-median owner S16", claimParent.get("H") === "S16", `got ${claimParent.get("H")}`);
check("claim: F goes to its only owner S1", claimParent.get("F") === "S1");

// --- 3. Positions exist and stay inside the 480x480 world ---
check("positions: every parent and file has a position", parents.every((p) => positions.has(p.id)) && fileIds.every((f) => positions.has(`file:${f}`)) && positions.has("repo"));
check(
  "positions: all inside the world",
  [...positions.values()].every((p) => p.x >= 0 && p.x <= 480 && p.y >= 0 && p.y <= 480),
  [...positions.entries()].filter(([, p]) => p.x < 0 || p.x > 480 || p.y < 0 || p.y > 480).map(([id]) => id).join(","),
);
check("positions: repo at the centre", positions.get("repo")!.x === 240 && positions.get("repo")!.y === 240);

// --- 4. Edge crossings: the visible own edges never intersect ---
type Pt = { x: number; y: number };
const orient = (a: Pt, b: Pt, c: Pt) => (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x);
const crosses = (p1: Pt, p2: Pt, p3: Pt, p4: Pt) => {
  const d1 = orient(p3, p4, p1), d2 = orient(p3, p4, p2), d3 = orient(p1, p2, p3), d4 = orient(p1, p2, p4);
  return ((d1 > 0 && d2 < 0) || (d1 < 0 && d2 > 0)) && ((d3 > 0 && d4 < 0) || (d3 < 0 && d4 > 0));
};
const edgeSet = new Map<string, { kind: string; fromId: string; toId: string; from: Pt; to: Pt }>();
const addEdge = (kind: string, fromId: string, toId: string) => {
  const key = `${fromId}|${toId}`;
  if (!edgeSet.has(key)) edgeSet.set(key, { kind, fromId, toId, from: positions.get(fromId)!, to: positions.get(toId)! });
};
for (const p of parents) {
  addEdge("own", p.id, `file:${p.ownFile}`);
  for (const f of p.refs) addEdge("test", p.id, `file:${f}`);
}
const edges = [...edgeSet.values()];
let ownCrossings = 0;
let totalCrossings = 0;
for (let i = 0; i < edges.length; i++) {
  for (let j = i + 1; j < edges.length; j++) {
    const a = edges[i], b = edges[j];
    if (a.fromId === b.fromId || a.toId === b.toId || a.fromId === b.toId || a.toId === b.fromId) continue;
    if (crosses(a.from, a.to, b.from, b.to)) {
      totalCrossings++;
      if (a.kind === "own" && b.kind === "own") ownCrossings++;
    }
  }
}
check("crossings: own edges never intersect (the default view)", ownCrossings === 0, `${ownCrossings} own crossings`);
check("crossings: total is well below the old 202", totalCrossings < 160, `${totalCrossings} total`);

// --- 5. Degenerate inputs do not crash ---
const empty = computeSectorLayout([], [], centre, 140);
check("empty: only the repo position, no crash", empty.positions.size === 1 && empty.positions.has("repo") && empty.order.length === 0);
const single = computeSectorLayout([{ id: "only", radius: 225, ownFile: "", refs: [] }], [], centre, 140);
check("single childless parent: placed on its ring", single.positions.has("only") && Math.abs(Math.hypot(single.positions.get("only")!.x - 240, single.positions.get("only")!.y - 240) - 225) < 1e-9);

console.log(failures === 0 ? `\nPASS ${total}/${total}` : `\n${failures} test(s) FAILED out of ${total}.`);
process.exit(failures === 0 ? 0 : 1);
