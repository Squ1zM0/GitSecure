// Phase 5: progressive rendering + real navigation for huge reports.
//
// The API and MCP responses always carry the COMPLETE lists - no caps.
// The human page must stay usable when a list has thousands of entries
// (DefinitelyTyped: 61,814 files, 9,401 dependencies, secrets well over
// 100), so each list renders in chunks of PAGE_SIZE with "Show more" /
// "Show all". That is a rendering chunk, NOT a data cap: the full list
// is in the report, the count shown is the true total, and every entry
// is reachable on the page.
//
// Navigation (added for the DefinitelyTyped case - hundreds to
// thousands of findings):
//   - Collapsible groups by type / advisory / file, with counts,
//     collapsed by default when the list is large.
//   - Filters: dropdowns for type and severity, plus text search by
//     file name (secrets) / package (vulnerabilities) / name
//     (dependencies). Counts shown are always the true filtered and
//     total counts, never a truncated count.
//   - Map view: an interactive file -> findings map. Files are
//     aggregated first (one node per file, sized by finding count, top
//     24 drawn as an SVG spider around the repo); clicking a file
//     filters the list to it. No DOM node per finding, so it stays fast
//     with thousands of findings and works at phone width.
//   - Every finding has a direct GitHub link to the exact file and line
//     (the "go fix this" action) and an in-page anchor (#secret-12 …)
//     with a copy-link button, so one finding can be shared. A shared
//     anchor link opens the page with that finding expanded and scrolled
//     into view, even past the first 100.
// Phase 11: the triage verdicts become SECTIONS, not just a filter -
// likely-test findings live in their own collapsed "Likely test keys"
// section, genuine leaks in their own open section, uncertain findings
// in their own open section - and the spider map becomes a usage
// graph (finding -> the files that reference it). Redaction unchanged:
// only the redacted fragment ever appears - never a full secret,
// including in graph tooltips and link labels.

"use client";

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { Dependency, Framework, PostureIssue, SecretFinding, SecretUsage, Severity, TriageVerdict, Vulnerability } from "@/lib/types";
import { findingAnchorId, githubBlobUrl, osvAdvisoryUrl } from "@/lib/links";
import { recommendedFixVersions } from "@/lib/versions";
// Phase 18: all view/transform/traversal math lives in the pure
// map-view module - the component owns rendering and event wiring.
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
  edgeDetailText,
  edgeLabelText,
  edgeLabelThresholdWorld,
  filterByCategory,
  fitView,
  neighboursOf,
  panBy,
  postureCategoryOf,
  resolveLabelCollisions,
  resolveNodePositions,
  togglePin,
  traverseBack,
  traverseStep,
  viewTransformString,
  zoomAt,
  zoomByFactor,
  zoomToNode,
  type EdgeKind,
  type EdgeLabelAnchor,
  type MapCategory,
  type ViewTransform,
} from "@/lib/map-view";

// Phase 11: usage annotation (SecretUsage on SecretFinding, see
// src/lib/types.ts). `getUsage` validates the shape - a finding
// without `usage` (older report) renders exactly as before, never crashes.
export function getUsage(s: SecretFinding): SecretUsage | undefined {
  const u = (s as SecretFinding & { usage?: unknown }).usage;
  if (!u || typeof u !== "object") return undefined;
  const o = u as unknown as Record<string, unknown>;
  if (typeof o.deadEnd !== "boolean") return undefined;
  const refs = (v: unknown): { file: string; line: number }[] =>
    Array.isArray(v)
      ? v.filter(
          (r): r is { file: string; line: number } =>
            !!r && typeof r === "object" && typeof (r as { file: unknown }).file === "string" && typeof (r as { line: unknown }).line === "number",
        )
      : [];
  const by = refs(o.referencedBy);
  const byTests = refs(o.referencedByTests);
  return {
    referencedBy: by,
    referencedByTotal: typeof o.referencedByTotal === "number" ? o.referencedByTotal : by.length,
    referencedByTests: byTests,
    referencedByTestsTotal: typeof o.referencedByTestsTotal === "number" ? o.referencedByTestsTotal : byTests.length,
    deadEnd: o.deadEnd,
    historyOnly: o.historyOnly === true ? true : undefined,
  };
}

/** Phase 15 finding 9: the "Used by" segments for the usage-map
 *  track detail - one segment per list that actually has entries.
 *  A finding used only in tests renders ["in tests: …"] with no empty
 *  "Used by: ;" segment; a finding with no listed references renders
 *  []. Exported for the UI test. */
export function trackDetailSegments(usage: SecretUsage): string[] {
  const segments: string[] = [];
  const nonTest = usage.referencedBy.slice(0, 10).map((r) => `${r.file}:${r.line}`);
  const tests = usage.referencedByTests.slice(0, 10).map((r) => `${r.file}:${r.line}`);
  if (nonTest.length > 0) segments.push(`Used by: ${nonTest.join(", ")}`);
  if (tests.length > 0) segments.push(`in tests: ${tests.join(", ")}`);
  return segments;
}

/** A finding with no triage annotation reads as uncertain - it is
 *  never silently counted as a test key or a genuine leak. */
function verdictOf(s: SecretFinding): TriageVerdict | "uncertain" {
  return s.triage?.verdict ?? "uncertain";
}

/** Phase 15 finding 4: a file label that never clips mid-word with no
 *  sign it was cut. Basenames of 14 chars or fewer render whole;
 *  longer ones keep the head and the tail (extension included) with
 *  an ellipsis in the middle: "test-usage-phase11.ts" becomes
 *  "test-usa…11.ts". The full path stays in the node's <title> and
 *  aria-label, and in the file-chip buttons below the map. */
export function shortLabel(file: string): string {
  const base = file.split("/").pop() ?? file;
  if (base.length <= 14) return base;
  return `${base.slice(0, 8)}…${base.slice(-5)}`;
}

/** Phase 15 finding 9: the "Used by:" line for one finding, or null
 *  when there is nothing to list. The old code rendered "Used by: ;"
 *  when the non-test list was empty but tests existed, and "Used by:
 *  (+N more)" when the totals said there were references but the
 *  lists were empty. Callers render the fallback sentence instead of
 *  an empty label. */
export function usageRefText(usage: SecretUsage, limit = 3): string | null {
  const nonTest = usage.referencedBy.slice(0, limit).map((r) => `${r.file}:${r.line}`);
  const tests = usage.referencedByTests.slice(0, limit).map((r) => `${r.file}:${r.line} (test)`);
  const parts = [...nonTest, ...tests];
  const total = usage.referencedByTotal + usage.referencedByTestsTotal;
  if (parts.length === 0) {
    if (total <= 0) return null;
    return `Used by: ${total} reference${total === 1 ? "" : "s"} (file list not shown)`;
  }
  return `Used by: ${parts.join(", ")}${total > parts.length ? ` (+${total - parts.length} more)` : ""}`;
}

const PAGE_SIZE = 100;
/** Groups start open only when the filtered list is small; a wall of
 *  thousands starts collapsed so the page is traversable. */
const GROUP_OPEN_BELOW = 50;
/** How many file nodes the SVG map draws (largest files first).
 *  Phase 19: raised from 24 to 32 (MAP_MAX_FILE_NODES). */
const MAP_NODES = MAP_MAX_FILE_NODES;

type Indexed<T> = { item: T; idx: number };

function withIndex<T>(items: T[]): Indexed<T>[] {
  return items.map((item, idx) => ({ item, idx }));
}

/** "Copy link" button for one finding: copies the full page URL with
 *  the finding's anchor. Same clipboard + textarea fallback as the MCP
 *  copy buttons. */
function CopyLinkButton({ anchor, label }: { anchor: string; label: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    const url = `${window.location.origin}${window.location.pathname}#${anchor}`;
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = url;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  return (
    <button type="button" className="copy-btn secondary" onClick={copy} aria-label={`Copy link to ${label}`}>
      {copied ? "Copied" : "Copy link"}
    </button>
  );
}

function Pager({ total, shown, onMore, onAll }: { total: number; shown: number; onMore: () => void; onAll: () => void }) {
  const remaining = total - shown;
  if (remaining <= 0) return null;
  return (
    <p className="pager">
      <button type="button" onClick={onMore}>
        Show more ({Math.min(PAGE_SIZE, remaining)} of {remaining} remaining)
      </button>{" "}
      <button type="button" className="secondary" onClick={onAll}>
        Show all {total}
      </button>
    </p>
  );
}

/** One paged chunk of rows. `initialShown` lets a shared anchor link
 *  force the chunk open past the finding being linked to. */
function Paged<T>({ items, initialShown = PAGE_SIZE, renderItem }: { items: Indexed<T>[]; initialShown?: number; renderItem: (entry: Indexed<T>) => ReactNode }) {
  const [shown, setShown] = useState(Math.max(PAGE_SIZE, initialShown));
  // When the filter changes the item list is replaced: start over at
  // the first page (unless an anchor link forced it open - that state
  // lives in the parent, which passes a fresh initialShown).
  useEffect(() => {
    setShown(Math.max(PAGE_SIZE, initialShown));
  }, [items, initialShown]);
  return (
    <>
      {items.slice(0, shown).map(renderItem)}
      <Pager total={items.length} shown={shown} onMore={() => setShown((s) => Math.min(s + PAGE_SIZE, items.length))} onAll={() => setShown(items.length)} />
    </>
  );
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function SeveritySelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <label>
      Severity
      <select value={value} onChange={(e) => onChange(e.target.value)} aria-label="Filter by severity">
        <option value="all">All severities</option>
        {SEVERITIES.map((s) => (
          <option key={s} value={s}>{s}</option>
        ))}
      </select>
    </label>
  );
}

// ---------------------------------------------------------------- secrets

function SecretRow({ entry, owner, repo, branch }: { entry: Indexed<SecretFinding>; owner: string; repo: string; branch: string }) {
  const s = entry.item;
  const anchor = findingAnchorId("secret", entry.idx);
  const blob = githubBlobUrl(owner, repo, branch, s.file, s.line, s.commit);
  const usage = getUsage(s);
  const triageLabel =
    s.triage?.verdict === "likely-test-key"
      ? "Likely test key"
      : s.triage?.verdict === "likely-genuine-leak"
        ? "Likely genuine leak"
        : s.triage
          ? "Uncertain - needs a human check"
          : null;
  const triagePill =
    s.triage?.verdict === "likely-test-key"
      ? "triage-test"
      : s.triage?.verdict === "likely-genuine-leak"
        ? "triage-genuine"
        : "triage-uncertain";
  // The dead-end note in plain English. When the triage explanation
  // already says it (the usual case - the explanation names the
  // dead end), don't repeat the sentence; the pill alone marks it.
  const deadEndNote =
    usage?.deadEnd && !(s.triage?.explanation ?? "").toLowerCase().includes("references")
      ? "Nothing in this repo references this key - a true dead end."
      : null;
  // Phase 15 finding 9: usageRefText returns null when there is
  // nothing to list, so this line never renders an empty "Used by:".
  const usageText = usage && !usage.deadEnd ? usageRefText(usage, 3) : null;
  return (
    <div className={`finding sev-${s.severity}`} id={anchor}>
      <p className="finding-title"><span className={`pill ${s.severity}`}>{s.severity}</span>{usage?.deadEnd ? <span className="pill dead-end">Dead end</span> : null}<b>{s.title}</b> <span className="muted">· {s.confidence} confidence</span></p>
      <p>{s.plainEnglish}</p>
      {s.triage && triageLabel ? (
        <p className="triage">
          <span className={`pill ${triagePill}`}>{triageLabel}</span>
          {s.triage.explanation}{" "}
          <span className="muted">(Triage assessed severity: {s.triage.adjustedSeverity}, confidence: {s.triage.adjustedConfidence}.)</span>
        </p>
      ) : null}
      {usage?.deadEnd && (deadEndNote || usage.historyOnly) ? (
        <p className="dead-end-note">
          {deadEndNote ?? ""}
          {usage.historyOnly ? " (Usage checked against the current files only.)" : ""}
        </p>
      ) : null}
      {usageText ? (
        <p className="small usage-line">
          {usageText}
          {usage?.historyOnly ? " - usage checked against the current files only." : ""}
        </p>
      ) : null}
      <p className="small"><code className="inline">{s.file}:{s.line}</code> · commit <code className="inline">{s.commit ?? "HEAD"}</code> · fragment <code className="inline">{s.fragment}</code> (redacted - never the full secret)</p>
      <p className="small finding-actions">
        {/* Phase 15 finding 2: the link label is just "View on GitHub" -
          the long path used to be part of the label and pushed a 360 px
          report 66 px wide. The path is already shown in the line
          directly above, so nothing is lost. The CSS also lets
          .github-link wrap, as a backstop. */}
        <a className="github-link" href={blob} target="_blank" rel="noreferrer">View on GitHub</a>
        <a href={`#${anchor}`}>Link to this finding</a>
        <CopyLinkButton anchor={anchor} label={`secret finding ${entry.idx + 1}`} />
      </p>
      <p className="fix"><b>Fix:</b> {s.triage?.fix ?? s.fix}</p>
    </div>
  );
}

/** File -> findings map: one node per file (top MAP_NODES by count in
 *  the SVG spider, the rest reachable through the paged chip list
 *  below it). Clicking a file filters the list to it. Tooltips carry
 *  only the file path and count - never a secret fragment.
 *  Exported for the render test (scripts/test-scanner.ts does not cover
 *  it; the map is verified by a render-to-string check below). */
export function FileMap({ byFile, onSelectFile }: { byFile: { file: string; count: number }[]; onSelectFile: (file: string) => void }) {
  const [filesShown, setFilesShown] = useState(PAGE_SIZE);
  useEffect(() => {
    setFilesShown(PAGE_SIZE);
  }, [byFile]);
  const top = byFile.slice(0, MAP_NODES);
  const cx = 200;
  const cy = 150;
  const radius = 118;
  const nodePos = (i: number, n: number) => {
    const angle = (2 * Math.PI * i) / Math.max(n, 1) - Math.PI / 2;
    return { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
  };
  const baseName = (file: string) => file.split("/").pop() ?? file;
  return (
    <div>
      <p className="small">
        Map of files holding secrets - node size is the finding count. Showing the {top.length} largest of {byFile.length} files with secrets. Click a file to filter the list to it.
      </p>
      <p className="map-legend" aria-label="Map legend">
        <span><b>●</b> Centre - this repo</span>
        <span><b>●</b> Bigger node - more findings in that file</span>
        <span>Every node is keyboard reachable: Tab to it, Enter to filter</span>
      </p>
      <div className="map-wrap">
        <svg viewBox="0 0 400 300" role="group" aria-label="Map of files holding secrets">
          {/* Phase 15 finding 4: the centre is painted after the spokes,
            so no spoke can strike through the "This repo" label. */}
          {top.map((f, i) => {
            const { x, y } = nodePos(i, top.length);
            const r = 9 + Math.min(15, Math.sqrt(f.count) * 2.2);
            // Phase 15 finding 4: middle-truncated basename with an
            // ellipsis (never a silent mid-word clip) + a halo so the
            // label stays readable where a spoke passes behind it.
            const label = shortLabel(f.file);
            return (
              <g
                key={f.file}
                className="map-node"
                onClick={() => onSelectFile(f.file)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    onSelectFile(f.file);
                  }
                }}
                tabIndex={0}
                role="button"
                aria-label={`${f.file}, ${f.count} findings - filter the list to this file`}
              >
                <title>{`${f.file} - ${f.count} finding${f.count === 1 ? "" : "s"}`}</title>
                <line x1={cx} y1={cy} x2={x} y2={y} stroke="#9ecdb2" strokeWidth={1.5} />
                <circle cx={x} cy={y} r={r} />
                <text className="map-label" x={x} y={y - r - 4} textAnchor="middle">{label}</text>
                <text x={x} y={y + r + 12} textAnchor="middle" fontWeight={700}>{f.count}</text>
              </g>
            );
          })}
          <circle className="map-centre" cx={cx} cy={cy} r={34} />
          <text className="map-centre-text" x={cx} y={cy + 4} textAnchor="middle" fontSize={10} fontWeight={700}>This repo</text>
        </svg>
      </div>
      <p>
        {byFile.slice(0, filesShown).map((f) => (
          <button key={f.file} type="button" className="secondary file-chip" title={`${f.file} - ${f.count} findings`} onClick={() => onSelectFile(f.file)}>
            {baseName(f.file)} ({f.count})
          </button>
        ))}
      </p>
      {byFile.length > filesShown && (
        <p>
          <button type="button" onClick={() => setFilesShown((s) => Math.min(s + PAGE_SIZE, byFile.length))}>
            Show more files ({Math.min(PAGE_SIZE, byFile.length - filesShown)} of {byFile.length - filesShown} remaining)
          </button>{" "}
          <button type="button" className="secondary" onClick={() => setFilesShown(byFile.length)}>
            Show all {byFile.length} files
          </button>
        </p>
      )}
    </div>
  );
}

// ------------------------------------------------------- Phase 11 map

/** How many secret finding nodes the usage map draws (most-used
 *  first). A rendering cap, NOT a data cap - every finding stays in
 *  the list. Phase 19: raised from 12 to 24 (MAP_MAX_SECRET_NODES);
 *  posture nodes have their own cap, MAP_MAX_POSTURE_NODES. */
const MAP_FINDINGS = MAP_MAX_SECRET_NODES;

/** How many posture finding nodes the usage map draws (highest
 *  severity first). Same rule as MAP_FINDINGS: a rendering cap,
 *  never a data cap. */
const MAP_POSTURE_FINDINGS = MAP_MAX_POSTURE_NODES;

/** Fix round 2026-11-27 (defect 3): below this zoom, edge labels
 *  for edges OFF the selected track are not rendered. At fit zoom
 *  the self-scan map carries 92 edge labels stacked into an
 *  unreadable hairball at the centre (headless evidence, 1280px
 *  and 360px, light and dark) - a deliberate deviation from the
 *  original "labels at every zoom" rule. The selected track's
 *  labels always render, the legend + edge styles (solid/dashed/
 *  thin) still distinguish every edge at fit zoom, and any edge's
 *  meaning is one click away (edge detail) or one zoom-in away
 *  (all labels appear at this zoom). */
const EDGE_LABEL_MIN_ZOOM = 1.5;

/** Phase 19: the legend glyph for one map category - the same
 *  shape the plane draws for its nodes (circle for secrets, polygon
 *  per posture category), so the legend explains the shape, not just
 *  the name. Rendered at 14x14 in the legend row. */
function CategoryGlyph({ category }: { category: MapCategory }) {
  const meta = MAP_CATEGORY_META[category];
  if (meta.sides === 0) {
    return (
      <svg width={14} height={14} viewBox="0 0 14 14" aria-hidden="true">
        <circle cx={7} cy={7} r={5.5} fill="none" stroke="currentColor" strokeWidth={1.5} />
      </svg>
    );
  }
  return (
    <svg width={14} height={14} viewBox="0 0 14 14" aria-hidden="true">
      <polygon points={categoryPolygonPoints(meta.sides, meta.rotation, 7, 7, 5.5)} fill="none" stroke="currentColor" strokeWidth={1.5} />
    </svg>
  );
}

/** Phase 11 usage graph. Repo node at the centre, finding nodes on an
 *  inner ring, file nodes on an outer ring, EDGES from each finding to
 *  the files that reference it (solid = non-test code, dashed = test
 *  code) plus a thin edge to the file the finding itself lives in.
 *  Click a finding node to highlight its track (finding -> the files
 *  that use it -> the finding's own file, one hop each way); click a
 *  file node to filter the list to it. Dead-end findings are greyed,
 *  labelled "dead end", and have no outgoing edges. When no finding
 *  carries `usage` (older report), this falls back to the Phase 5
 *  file-count spider unchanged.
 *
 *  Phase 15 finding 4 - legibility at 12 findings / 8 files: the
 *  rings are spread (finding 82 -> 100, file 138 -> 140, taller
 *  viewBox), file labels are middle-truncated basenames with an
 *  ellipsis (shortLabel, never a silent mid-word clip) placed
 *  radially OUTWARD from their node so they can never collide with a
 *  finding's "N uses" caption, file counts sit INSIDE their node
 *  circles (no count ever sits on an edge again), finding nodes grow
 *  with their reference count (like file nodes grow with finding
 *  count), the centre is painted after the edges so no edge can
 *  strike through "This repo", and every label outside a circle
 *  carries the .map-label halo so a dashed edge passing behind it
 *  cannot strike the text through. The "N uses" captions alternate
 *  a sideways step so neighbours' captions stop stacking. Click,
 *  keyboard, dark mode, and reduced-motion behaviour are unchanged. */
// Phase 18: the usage map is a dynamic visual plane - pannable,
// zoomable, draggable nodes, pinnable nodes, traversable neighbours.
// One <g transform> wraps everything; pan/zoom only change that one
// transform, nodes never re-lay out per frame. All state is per-view
// session state (never sent to the server, never persisted).
//
// Gesture split (see test-results/phase18/design.md):
//   Desktop: wheel = zoom at cursor; drag background = pan; drag a
//   node = move that node; click a node = select + zoom to it; click
//   an edge = select it; click background = deselect.
//   Touch: the fixed-height plane owns ALL gestures inside its box
//   (touch-action: none on the svg): one finger drag = pan, a drag
//   starting on a node = move that node, pinch = zoom, tap = select.
//   The page scrolls from anywhere OUTSIDE the map box.
//   Keyboard: Tab reaches every node and edge; Enter/Space selects;
//   [ / ] step neighbours, p pins the selected/focused node, 0 resets
//   the view, Escape deselects.
//
// Pointer handling is ONE code path (Pointer Events for mouse, touch
// and pen): a single set of handlers on the <svg> inspects the event
// target (data-node-id / data-edge-id) to tell a node press from a
// background press, so a node press never starts a background pan.
// A pointer cache (Map<pointerId, {x,y}>) drives the two-pointer
// pinch. Tap vs drag is the 5 px / 500 ms rule; selection happens on
// pointerup from the id recorded in the gesture at pointerdown time
// - NOT via onClick on the node/edge groups (fix round 2026-11-27:
// setPointerCapture on the svg retargets the click to the svg, so
// those onClick handlers never fired). Keyboard Enter/Space
// selection is a separate path (onNodeKeyDown / onEdgeKeyDown) and
// is unaffected.
//
// Pin semantics: dragging a node sets a position override but does
// NOT pin it. A pinned node keeps its world position when the
// findings change (unpinned nodes re-ring); reset-view resets the
// CAMERA only, never node positions. Pins/overrides reset with the
// findings list, like `selected` always has.
//
// Behaviour change (Phase 18, intentional): clicking a file node no
// longer filters the list immediately - it selects + zooms + shows
// the detail panel first, and filtering happens via the "Filter list
// to this file" button in that panel.
export function UsageMap({
  findings,
  posture = [],
  byFile,
  onSelectFile,
  onShowFinding,
  showDetail = false,
}: {
  findings: Indexed<SecretFinding>[];
  /** Phase 19: posture issues for the map (threaded from
   *  ReportView via SecretsList). Optional so older callers that
   *  only pass secrets keep working. */
  posture?: PostureIssue[];
  byFile: { file: string; count: number }[];
  onSelectFile: (file: string) => void;
  onShowFinding?: (idx: number) => void;
  /** Render the zoomed-in detail at fit zoom too: node captions
   *  ("N uses", "dead end", severity) and test edges. The live
   *  map hides both at fit zoom and shows them on zoom or
   *  selection; tests render the detail state with this prop. */
  showDetail?: boolean;
}) {
  const planeRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  // Fix round 2 (defect 2): the initial fit and Reset view call
  // fitView with padding 48, not the default 8. fitView fits the
  // 400x380 WORLD, but file labels sit radially OUTWARD from the
  // outer ring (up to ~r+14 world units beyond it), i.e. outside the
  // fitted rect - at 360px the side labels butted hard against the
  // plane border and read as clipped. 48 screen px of breathing
  // room on every side (raised from 32 in the 2026-11-27 second
  // pass - Freddy: default a little more zoomed out, rings spread
  // wider); the map gets slightly smaller (fit k drops ~9% at
  // 640px, ~11% at 360px) and the labels fit inside. fitView's
  // default stays 8; the zoom-to-node target (zoomTargetK) is
  // unchanged.
  const [view, setView] = useState<ViewTransform>(() => fitView(640, 420, 48));
  const [selected, setSelected] = useState<{ type: "node" | "edge"; id: string } | null>(null);
  const [pins, setPins] = useState<Set<string>>(new Set());
  const [overrides, setOverrides] = useState<Map<string, { x: number; y: number }>>(new Map());
  const [path, setPath] = useState<string[]>(["repo"]);
  const [neighbourIdx, setNeighbourIdx] = useState(0);
  const [reducedMotion, setReducedMotion] = useState(false);
  // Phase 19: categories hidden from the plane by the filter
  // toggles. Plane-only state: it never changes the report counts
  // or the lists below the map, and a hidden category keeps its
  // pins and drag positions for when it is shown again.
  const [hiddenCats, setHiddenCats] = useState<Set<MapCategory>>(new Set());
  const toggleCategory = (cat: MapCategory) => {
    setHiddenCats((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };
  // Refs the handlers need without re-binding: the live view scale
  // (node drags divide screen deltas by it), the container size in
  // px, the pointer cache, the in-flight gesture, and the press
  // record the tap-vs-drag rule reads.
  const viewRef = useRef(view);
  const sizeRef = useRef({ w: 640, h: 420 });
  const pointersRef = useRef(new Map<number, { x: number; y: number }>());
  const pinchRef = useRef<{ prevDist: number; prevMid: { x: number; y: number } } | null>(null);
  const gestureRef = useRef<
    | { mode: "pan"; start: { x: number; y: number }; last: { x: number; y: number } }
    | { mode: "node"; nodeId: string; start: { x: number; y: number }; startPos: { x: number; y: number } }
    | { mode: "edge"; edgeId: string; start: { x: number; y: number } }
    | { mode: "pinch" }
    | null
  >(null);
  const pressRef = useRef({ time: 0, moved: false });
  const interactedRef = useRef(false);
  const focusedNodeRef = useRef<string | null>(null);

  useEffect(() => {
    viewRef.current = view;
  }, [view]);
  useEffect(() => {
    setReducedMotion(window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  }, []);
  // Initial view = fitView measured on mount (ResizeObserver +
  // window resize). Only until the first interaction: after the user
  // has panned/zoomed/selected, a resize must not snap the camera
  // back. Server render uses the 640x420 default (view is state, so
  // no hydration mismatch).
  useEffect(() => {
    const el = planeRef.current;
    if (!el) return;
    const fit = () => {
      const w = el.clientWidth || 640;
      const h = el.clientHeight || 420;
      sizeRef.current = { w, h };
      if (!interactedRef.current) setView(fitView(w, h, 48));
    };
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    window.addEventListener("resize", fit);
    return () => {
      ro.disconnect();
      window.removeEventListener("resize", fit);
    };
  }, []);
  // Wheel zoom: React's onWheel cannot reliably preventDefault, so
  // the handler is attached NATIVELY (passive: false). Wheel over
  // the map zooms cursor-centred; the page scrolls normally outside
  // the map box.
  useEffect(() => {
    const el = planeRef.current;
    if (!el) return;
    const onWheel = (ev: WheelEvent) => {
      ev.preventDefault();
      interactedRef.current = true;
      const rect = el.getBoundingClientRect();
      const { w, h } = sizeRef.current;
      const factor = Math.exp(-ev.deltaY * 0.0015);
      setView((v) => zoomAt(v, ev.clientX - rect.left, ev.clientY - rect.top, factor, w, h));
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const hasUsage = findings.some(({ item }) => getUsage(item) !== undefined);

  // Most-used findings first so the tracks worth following are the
  // ones drawn; dead ends still appear (greyed) when there is room.
  const usageOf = (e: Indexed<SecretFinding>) => getUsage(e.item);
  const drawnSecretsAll = useMemo(
    () =>
      [...findings]
        .sort((a, b) => {
          const ua = usageOf(a);
          const ub = usageOf(b);
          const ta = ua && !ua.deadEnd ? ua.referencedByTotal + ua.referencedByTestsTotal : -1;
          const tb = ub && !ub.deadEnd ? ub.referencedByTotal + ub.referencedByTestsTotal : -1;
          return tb - ta || a.idx - b.idx;
        })
        .slice(0, MAP_FINDINGS),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [findings],
  );
  // The secrets actually on the plane: the category filter hides
  // the whole secrets category, same as any posture category.
  const drawn = useMemo(
    () => (hiddenCats.has("secrets") ? [] : drawnSecretsAll),
    [drawnSecretsAll, hiddenCats],
  );
  // Phase 19: posture nodes, highest severity first (then stable by
  // index), capped at MAP_POSTURE_FINDINGS. Issues without a
  // category count as hygiene (see postureCategoryOf), so older
  // reports still map every issue.
  const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  type PostureNode = Indexed<PostureIssue> & { category: MapCategory };
  const drawnPostureAll = useMemo(() => {
    const sorted: PostureNode[] = withIndex(posture)
      .map((e) => ({ ...e, category: postureCategoryOf(e.item) }))
      .sort((a, b) => (SEVERITY_RANK[a.item.severity] ?? 9) - (SEVERITY_RANK[b.item.severity] ?? 9) || a.idx - b.idx);
    return cappedSlice(sorted, MAP_POSTURE_FINDINGS).shown;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [posture]);
  const visiblePosture = useMemo(() => filterByCategory(drawnPostureAll, hiddenCats), [drawnPostureAll, hiddenCats]);
  // Short in-node label per posture node: category code plus a
  // per-category number (CR1, CR2, AC1 ...), so nodes of one
  // category stay distinguishable at a glance.
  const postureDisplayLabel = useMemo(() => {
    const counts = new Map<string, number>();
    const out = new Map<number, string>();
    for (const e of drawnPostureAll) {
      const n = (counts.get(e.category) ?? 0) + 1;
      counts.set(e.category, n);
      out.set(e.idx, `${MAP_CATEGORY_META[e.category].code}${n}`);
    }
    return out;
  }, [drawnPostureAll]);
  // Categories on the plane (for the legend and the filter row),
  // in display order, with the drawn count each holds. The counts
  // are the drawn counts, not the visible ones, so a toggle label
  // never changes when it is pressed.
  const categoriesPresent = useMemo(() => {
    const out: { category: MapCategory; count: number }[] = [];
    if (drawnSecretsAll.length > 0) out.push({ category: "secrets", count: drawnSecretsAll.length });
    for (const cat of MAP_CATEGORY_ORDER) {
      if (cat === "secrets") continue;
      const count = drawnPostureAll.filter((e) => e.category === cat).length;
      if (count > 0) out.push({ category: cat, count });
    }
    return out;
  }, [drawnSecretsAll, drawnPostureAll]);
  // File nodes: every file a drawn finding is used from, every file
  // a visible posture issue comes from, then the largest files by
  // finding count, capped at MAP_NODES. A file node count covers
  // both secrets and posture issues in that file.
  const postureFileCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of visiblePosture) {
      const f = e.item.file;
      if (typeof f === "string" && f.length > 0) counts.set(f, (counts.get(f) ?? 0) + 1);
    }
    return counts;
  }, [visiblePosture]);
  const fileNodes = useMemo(() => {
    const refFiles = new Set<string>();
    for (const e of drawn) {
      const u = usageOf(e);
      if (!u || u.deadEnd) continue;
      for (const r of [...u.referencedBy, ...u.referencedByTests]) refFiles.add(r.file);
      refFiles.add(e.item.file);
    }
    for (const f of postureFileCounts.keys()) refFiles.add(f);
    return [
      ...[...refFiles].map((file) => ({
        file,
        count: (byFile.find((f) => f.file === file)?.count ?? 0) + (postureFileCounts.get(file) ?? 0),
      })),
      ...byFile.filter((f) => !refFiles.has(f.file)),
    ].slice(0, MAP_NODES);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [drawn, byFile, postureFileCounts]);
  const nodeIdOfFinding = (idx: number) => `finding:${idx}`;
  const nodeIdOfPosture = (idx: number) => `posture:${idx}`;
  const nodeIdOfFile = (file: string) => `file:${file}`;
  const labelOf = (id: string): string => {
    if (id === "repo") return "This repo";
    if (id.startsWith("finding:")) return `Secret ${Number(id.slice("finding:".length)) + 1}`;
    if (id.startsWith("posture:")) return `Posture ${Number(id.slice("posture:".length)) + 1}`;
    if (id.startsWith("file:")) return shortLabel(id.slice("file:".length));
    return id;
  };
  // Sector tree is the STARTING arrangement (world 480x440, centre
  // (240,220)): the circle is divided into leaf slots, one per file
  // plus one per childless finding or posture issue. Each finding or
  // posture issue owns the sector covering its files and sits at the
  // sector centre on its ring (findings r=125, posture r=165); its
  // files sit in their slots on the outer ring (r=205), inside that
  // sector, so no two parents fan into the same space. Files no
  // drawn finding or visible posture issue references get slots of
  // their own at the end. Overrides win for dragged/pinned nodes.
  // The posture ring sits between the findings and the files so its
  // short "found in" edges never cross the findings ring.
  const cx = 240;
  const cy = 220;
  const basePositions = useMemo(() => {
    const base = new Map<string, { x: number; y: number }>();
    base.set("repo", { x: cx, y: cy });
    // First claim wins: each file branches off the first finding
    // (own file, then referenced files) or posture issue that
    // references it.
    const fanOf = new Map<string, string[]>();
    const claimFile = (file: unknown, parentId: string) => {
      if (typeof file !== "string" || file.length === 0) return;
      for (const files of fanOf.values()) if (files.includes(file)) return;
      if (!fanOf.has(parentId)) fanOf.set(parentId, []);
      fanOf.get(parentId)!.push(file);
    };
    for (const e of drawn) {
      const parentId = nodeIdOfFinding(e.idx);
      claimFile(e.item.file, parentId);
      const u = usageOf(e);
      if (u && !u.deadEnd) {
        for (const r of [...u.referencedBy, ...u.referencedByTests]) claimFile(r.file, parentId);
      }
    }
    for (const e of visiblePosture) claimFile(e.item.file, nodeIdOfPosture(e.idx));
    const level1: { id: string; radius: number; files: string[] }[] = [];
    for (const e of drawn) level1.push({ id: nodeIdOfFinding(e.idx), radius: 125, files: fanOf.get(nodeIdOfFinding(e.idx)) ?? [] });
    for (const e of visiblePosture) level1.push({ id: nodeIdOfPosture(e.idx), radius: 165, files: fanOf.get(nodeIdOfPosture(e.idx)) ?? [] });
    const unparented: string[] = [];
    for (const f of fileNodes) {
      let claimed = false;
      for (const files of fanOf.values()) if (files.includes(f.file)) { claimed = true; break; }
      if (!claimed) unparented.push(f.file);
    }
    const leaves = level1.reduce((n, p) => n + Math.max(1, p.files.length), 0) + unparented.length;
    const slot = leaves > 0 ? (2 * Math.PI) / leaves : 0;
    const place = (angle: number, radius: number) => ({ x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) });
    let cursor = -Math.PI / 2;
    for (const p of level1) {
      const count = Math.max(1, p.files.length);
      base.set(p.id, place(cursor + (slot * count) / 2, p.radius));
      p.files.forEach((file, j) => base.set(nodeIdOfFile(file), place(cursor + slot * (j + 0.5), 205)));
      cursor += slot * count;
    }
    unparented.forEach((file, j) => base.set(nodeIdOfFile(file), place(cursor + slot * (j + 0.5), 205)));
    return base;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [drawn, visiblePosture, fileNodes]);
  const positions = useMemo(() => resolveNodePositions(basePositions, overrides), [basePositions, overrides]);
  // File-label stagger follows the ANGULAR order, not the list
  // order: neighbouring files on the plane sit on two label rings
  // (r+14 and r+42) so adjacent labels never share a line. The
  // placement order is sorted by angle from the top, so sorting by
  // wrapped angle recovers it.
  const fileLabelParity = useMemo(() => {
    const wrapped = (a: number) => (((a + Math.PI / 2) % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);
    const ranked = fileNodes
      .map((f) => {
        const p = positions.get(nodeIdOfFile(f.file)) ?? { x: cx, y: cy };
        return { id: nodeIdOfFile(f.file), angle: wrapped(Math.atan2(p.y - cy, p.x - cx)) };
      })
      .sort((a, b) => a.angle - b.angle);
    return new Map(ranked.map((e, i) => [e.id, i % 2]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [positions, fileNodes]);
  const drawnIds = useMemo(
    () => new Set(["repo", ...drawn.map((e) => nodeIdOfFinding(e.idx)), ...visiblePosture.map((e) => nodeIdOfPosture(e.idx)), ...fileNodes.map((f) => nodeIdOfFile(f.file))]),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [drawn, visiblePosture, fileNodes],
  );

  // When the findings list is replaced: clear the selection and the
  // breadcrumb, drop pins for nodes that no longer exist, and clear
  // overrides for unpinned nodes (they re-ring) while KEEPING the
  // overrides of pinned nodes that still exist.
  useEffect(() => {
    setSelected(null);
    setPath(["repo"]);
    setNeighbourIdx(0);
    setPins((prev) => {
      const next = new Set<string>();
      for (const id of prev) if (drawnIds.has(id)) next.add(id);
      return next;
    });
    setOverrides((prev) => {
      const next = new Map<string, { x: number; y: number }>();
      for (const [id, pos] of prev) if (pins.has(id) && drawnIds.has(id)) next.set(id, pos);
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findings]);

  type MapEdge = {
    key: string;
    findingIdx: number;
    /** Phase 19: set on "found in" edges - the posture issue index
     *  (its own numbering, separate from secret findingIdx). */
    postureIdx?: number;
    /** Phase 19: set on "found in" edges - the posture issue title,
     *  for the edge aria-label and detail. */
    title?: string;
    fromId: string;
    toId: string;
    kind: EdgeKind;
    refFile: string;
    refLine: number;
    from: { x: number; y: number };
    to: { x: number; y: number };
    // Fix round 2 (defect 1): fraction along the adjusted segment
    // where this edge's label sits - staggered per finding (see the
    // assignment below), so a fan of edges from one finding stops
    // stacking all its labels on one midpoint.
    labelT: number;
  };
  const edges = useMemo(() => {
    const raw: Omit<MapEdge, "from" | "to" | "labelT">[] = [];
    for (const e of drawn) {
      const u = usageOf(e);
      if (!u || u.deadEnd) continue;
      const fromId = nodeIdOfFinding(e.idx);
      const own = nodeIdOfFile(e.item.file);
      if (positions.has(own)) raw.push({ key: `own-${e.idx}`, findingIdx: e.idx, fromId, toId: own, kind: "own", refFile: e.item.file, refLine: e.item.line });
      for (const r of u.referencedBy) {
        const toId = nodeIdOfFile(r.file);
        if (positions.has(toId)) raw.push({ key: `code-${e.idx}-${r.file}-${r.line}`, findingIdx: e.idx, fromId, toId, kind: "code", refFile: r.file, refLine: r.line });
      }
      for (const r of u.referencedByTests) {
        const toId = nodeIdOfFile(r.file);
        if (positions.has(toId)) raw.push({ key: `test-${e.idx}-${r.file}-${r.line}`, findingIdx: e.idx, fromId, toId, kind: "test", refFile: r.file, refLine: r.line });
      }
    }
    // Phase 19: every posture node with a file links to that file
    // with a "found in" edge. An issue with no file (no SECURITY.md,
    // no .gitignore) has no file to link to, so it draws unconnected
    // - same as a dead-end secret. The line is 0 when the issue has
    // no single line.
    for (const e of visiblePosture) {
      const f = e.item.file;
      if (typeof f !== "string" || f.length === 0) continue;
      const toId = nodeIdOfFile(f);
      if (!positions.has(toId)) continue;
      raw.push({
        key: `found-${e.idx}`,
        findingIdx: e.idx,
        postureIdx: e.idx,
        title: e.item.title,
        fromId: nodeIdOfPosture(e.idx),
        toId,
        kind: "found",
        refFile: f,
        refLine: typeof e.item.line === "number" ? e.item.line : 0,
      });
    }
    // Parallel edges (same finding -> same file, different lines or
    // kinds) get a perpendicular offset of (index - (n-1)/2) * 6 world
    // units, so each is separately visible and clickable; the label
    // sits at the adjusted segment's midpoint.
    const groups = new Map<string, typeof raw>();
    for (const e of raw) {
      const g = groups.get(`${e.fromId}|${e.toId}`) ?? [];
      g.push(e);
      groups.set(`${e.fromId}|${e.toId}`, g);
    }
    const out: MapEdge[] = [];
    for (const group of groups.values()) {
      const n = group.length;
      group.forEach((e, i) => {
        const from = positions.get(e.fromId) ?? { x: cx, y: cy };
        const to = positions.get(e.toId) ?? { x: cx, y: cy };
        const dx = to.x - from.x;
        const dy = to.y - from.y;
        const len = Math.hypot(dx, dy) || 1;
        const off = (i - (n - 1) / 2) * 6;
        const px = -dy / len;
        const py = dx / len;
        out.push({ ...e, from: { x: from.x + px * off, y: from.y + py * off }, to: { x: to.x + px * off, y: to.y + py * off }, labelT: 0.5 });
      });
    }
    // Fix round 2 (defect 1): stagger edge labels ALONG their edge
    // instead of all at the midpoint. The ±6 perpendicular offset
    // separates the LINES, not the ~70px-wide identical label TEXTS -
    // in the recheck screenshot, finding S8's 11 "used in tests"
    // edges stacked every label onto one blob over the node. For the
    // edges of one finding (in draw order), cycle the label fraction
    // t through [0.35, 0.5, 0.65] (t = from + (to - from) * t), so
    // neighbouring edges in a fan carry their labels on different
    // arcs. A finding with a single edge keeps the midpoint (t=0.5).
    // Phase 19: the track key separates secret tracks from posture
    // tracks - a secret and a posture issue share index numbers, so
    // a bare findingIdx would stagger them as one track.
    const perFinding = new Map<string, MapEdge[]>();
    for (const e of out) {
      const trackKey = e.kind === "found" ? `posture:${e.postureIdx}` : `secret:${e.findingIdx}`;
      const list = perFinding.get(trackKey) ?? [];
      list.push(e);
      perFinding.set(trackKey, list);
    }
    for (const list of perFinding.values()) {
      if (list.length === 1) continue; // labelT already 0.5
      list.forEach((e, i) => {
        e.labelT = [0.35, 0.5, 0.65][i % 3];
      });
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [drawn, visiblePosture, positions]);

  // The dynamic plane always renders - even with no findings or no
  // usage data (2026-11-27, Freddy: the map view needs to exist
  // even when there are no test keys). With no findings it shows
  // just the repo node plus an empty-state note; with findings but
  // no usage it shows the finding and file nodes with no edges.
  // The old FileMap fallback is gone from this path (the component
  // stays exported and tested, but nothing in the app renders it).

  const selNodeId = selected?.type === "node" ? selected.id : null;
  // Phase 19: a node hidden by the category filter is not the
  // active node - its highlight, neighbours, and detail hide with
  // it, while the selection itself stays so unhiding restores it.
  const activeNodeId = selNodeId != null && drawnIds.has(selNodeId) ? selNodeId : null;
  const selFinding = activeNodeId?.startsWith("finding:") ? drawn.find((e) => nodeIdOfFinding(e.idx) === activeNodeId) ?? null : null;
  const selFindingUsage = selFinding ? usageOf(selFinding) : null;
  const selPosture = activeNodeId?.startsWith("posture:") ? visiblePosture.find((e) => nodeIdOfPosture(e.idx) === activeNodeId) ?? null : null;
  const selFile = activeNodeId?.startsWith("file:") ? fileNodes.find((f) => nodeIdOfFile(f.file) === activeNodeId) ?? null : null;
  const selEdge = selected?.type === "edge" ? edges.find((e) => e.key === selected.id) ?? null : null;
  const selEdgeFinding = selEdge && selEdge.kind !== "found" ? drawn.find((e) => nodeIdOfFinding(e.idx) === selEdge.fromId) ?? null : null;
  const neighbours = activeNodeId
    ? neighboursOf(activeNodeId, edges.map((e) => ({ fromId: e.fromId, toId: e.toId, kind: e.kind })))
    : [];
  const currentNeighbour = neighbours.length > 0 ? neighbours[((neighbourIdx % neighbours.length) + neighbours.length) % neighbours.length] : null;
  // The related set stays full-strength; everything else dims (the
  // existing dim behaviour). The repo node is related to everything.
  // Phase 19: a hidden selection counts as no selection here, so
  // hiding a category never dims the nodes left on the plane.
  const related = new Set<string>();
  if (activeNodeId && activeNodeId !== "repo") {
    related.add(activeNodeId);
    for (const n of neighbours) related.add(n.id);
  } else if (selEdge) {
    related.add(selEdge.fromId);
    related.add(selEdge.toId);
  }
  const dimNode = (id: string) => (activeNodeId != null || selEdge != null) && activeNodeId !== "repo" && !related.has(id);
  const edgeActive = (e: MapEdge) =>
    (activeNodeId == null && selEdge == null) || activeNodeId === "repo" || (activeNodeId != null && (e.fromId === activeNodeId || e.toId === activeNodeId)) || (selected?.type === "edge" && e.key === selected.id);

  // Fix round 3 (2026-11-27): coincident identical edge labels are
  // COLLAPSED into one counted label instead of rendered per edge.
  // The visible set is the same gating as before (all edges once
  // k >= EDGE_LABEL_MIN_ZOOM, else only the selected track); each
  // visible edge contributes an anchor at its label position (the
  // adjusted segment point at labelT - the round-2 t-stagger stays,
  // it is harmless now), and clusterEdgeLabels merges same-kind
  // anchors within the threshold. A cluster of N renders one
  // label, "used in tests ×11"; a singleton renders the plain kind
  // text. The label is pointer-events: none, so a tap on it falls
  // through to the edge hit line beneath it - the edges themselves
  // stay individually clickable with their own detail.
  //
  // Fix round 4 (2026-11-27): TWO changes here.
  // (1) Threshold: the round-3 `70 / view.k` was backwards -
  // recheck-4 proved it at k=1.831 (38 world units vs ~71 needed
  // for "used in tests ×18", 6 overlapping pairs). Labels live
  // inside the transformed <g>, so label width and anchor distance
  // both scale with k and the overlap condition is scale-invariant:
  // the threshold is now edgeLabelThresholdWorld(perKindCounts),
  // counted from this same visible set - a constant for a given
  // visible set, NOT divided by k. clusterEdgeLabels is unchanged.
  // (2) Push-out: BEFORE clustering, an anchor within (endpoint
  // radius + 14) world units of either endpoint node's centre is
  // pushed outward along the edge direction (away from that
  // endpoint) until it is exactly that far from the centre - so a
  // label can never sit under its own finding node (recheck-4: 46px
  // of "used in tests ×10" hidden behind the S8 node) or graze a
  // finding caption. Finding radius is the node's `fr`, file radius
  // its `r`, same formulas as the node rendering below. Applied
  // for both endpoints, in from-then-to order.
  const edgeByKey = useMemo(() => new Map(edges.map((e) => [e.key, e])), [edges]);
  const labelClusters = useMemo(() => {
    const visible = edges.filter(
      (e) =>
        view.k >= EDGE_LABEL_MIN_ZOOM ||
        (activeNodeId != null && activeNodeId !== "repo" && (e.fromId === activeNodeId || e.toId === activeNodeId)) ||
        (selected?.type === "edge" && e.key === selected.id),
    );
    const perKindCounts: { kind: EdgeKind; count: number }[] = [];
    for (const e of visible) {
      const entry = perKindCounts.find((c) => c.kind === e.kind);
      if (entry) entry.count += 1;
      else perKindCounts.push({ kind: e.kind, count: 1 });
    }
    const threshold = edgeLabelThresholdWorld(perKindCounts);
    const radiusOf = (id: string): number => {
      if (id === "repo") return 30;
      if (id.startsWith("finding:")) {
        const entry = drawn.find((e) => nodeIdOfFinding(e.idx) === id);
        if (!entry) return 11;
        const u = usageOf(entry);
        const refs = u && !u.deadEnd ? u.referencedByTotal + u.referencedByTestsTotal : 0;
        return 11 + Math.min(3, Math.round(Math.sqrt(refs) * 0.7));
      }
      // Phase 19: posture nodes are fixed-size polygons, radius 12.
      if (id.startsWith("posture:")) return 12;
      if (id.startsWith("file:")) {
        const f = fileNodes.find((file) => nodeIdOfFile(file.file) === id);
        return 9 + Math.min(4, Math.sqrt(Math.max(f?.count ?? 1, 1)) * 1.2);
      }
      return 11;
    };
    const anchors: EdgeLabelAnchor[] = visible.map((e) => {
      const t = e.labelT ?? 0.5;
      let x = e.from.x + (e.to.x - e.from.x) * t;
      let y = e.from.y + (e.to.y - e.from.y) * t;
      const dx = e.to.x - e.from.x;
      const dy = e.to.y - e.from.y;
      const len = Math.hypot(dx, dy) || 1;
      const ux = dx / len;
      const uy = dy / len;
      // Push the anchor along the edge direction (dirX/dirY points
      // AWAY from this endpoint) until it is exactly radius + 14
      // world units from the endpoint centre. Moving by s along a
      // unit direction solves |a + s*d - c| = minDist exactly:
      // s = -b + sqrt(b^2 - (|w|^2 - minDist^2)) with w = a - c and
      // b = w.d; the root is always positive when |w| < minDist.
      // (A plain shift of minDist - dist would only be exact if the
      // anchor lay on the line through the centre; the parallel
      // offset means it generally does not.)
      const pushFrom = (centre: { x: number; y: number }, radius: number, dirX: number, dirY: number) => {
        const minDist = radius + 14;
        const wx = x - centre.x;
        const wy = y - centre.y;
        if (Math.hypot(wx, wy) >= minDist) return;
        const b = wx * dirX + wy * dirY;
        const s = -b + Math.sqrt(b * b - (wx * wx + wy * wy - minDist * minDist));
        x += dirX * s;
        y += dirY * s;
      };
      pushFrom(positions.get(e.fromId) ?? e.from, radiusOf(e.fromId), ux, uy);
      pushFrom(positions.get(e.toId) ?? e.to, radiusOf(e.toId), -ux, -uy);
      return { x, y, kind: e.kind, edgeId: e.key };
    });
    const clusters = clusterEdgeLabels(anchors, threshold);
    // Second-pass collision pass (Phase 18 fix, 2026-11-27): the
    // round-4 push-out only clears a label from its OWN endpoints,
    // so a cluster could still land on a neighbouring node (worst
    // 2006px² vs the repo centre) or across a caption ("lives in
    // ×2" reading as "10 uslives in ×2"). Every blocker below uses
    // the SAME geometry as the render: node circles (radiusOf),
    // file labels (radial outward, clamped [42, 358]), finding
    // captions ("N uses" / "dead end", alternating ±20, fr+14
    // below the node). Edge directions come from the cluster's
    // first edge, so nudges run along/across its own track.
    const blockers: { x: number; y: number; w: number; h: number }[] = [{ x: cx, y: cy, w: 60, h: 60 }];
    for (const f of fileNodes) {
      const pos = positions.get(nodeIdOfFile(f.file));
      if (!pos) continue;
      const r = radiusOf(nodeIdOfFile(f.file));
      blockers.push({ x: pos.x, y: pos.y, w: r * 2, h: r * 2 });
      const angle = Math.atan2(pos.y - cy, pos.x - cx);
      const lo = r + 14 + ((fileLabelParity.get(nodeIdOfFile(f.file)) ?? 0) === 1 ? 28 : 0);
      const lx = Math.max(42, Math.min(438, pos.x + Math.cos(angle) * lo));
      const ly = Math.max(8, Math.min(432, pos.y + Math.sin(angle) * lo));
      blockers.push({ x: lx, y: ly, w: shortLabel(f.file).length * 4 + 8, h: 14 });
    }
    drawn.forEach((e, i) => {
      const pos = positions.get(nodeIdOfFinding(e.idx));
      if (!pos) return;
      const fr = radiusOf(nodeIdOfFinding(e.idx));
      blockers.push({ x: pos.x, y: pos.y, w: fr * 2, h: fr * 2 });
      const u = usageOf(e);
      const dead = u?.deadEnd === true;
      const refs = u && !dead ? u.referencedByTotal + u.referencedByTestsTotal : 0;
      const caption = dead ? "dead end" : u ? `${refs} use${refs === 1 ? "" : "s"}` : "";
      if (caption) {
        blockers.push({ x: pos.x + (i % 2 === 0 ? 20 : -20), y: pos.y + fr + 14, w: caption.length * 4 + 8, h: 14 });
      }
    });
    // Phase 19: posture nodes and their severity captions are
    // blockers too, with the same alternating sideways step the
    // render uses, so a "found in" label never lands on them.
    visiblePosture.forEach((e, i) => {
      const pos = positions.get(nodeIdOfPosture(e.idx));
      if (!pos) return;
      blockers.push({ x: pos.x, y: pos.y, w: 24, h: 24 });
      blockers.push({ x: pos.x + (i % 2 === 0 ? 20 : -20), y: pos.y + 12 + 14, w: e.item.severity.length * 4 + 8, h: 14 });
    });
    const edgeDirs = new Map<string, { x: number; y: number }>();
    for (const c of clusters) {
      const e = edgeByKey.get(c.edgeIds[0]);
      if (e) edgeDirs.set(c.edgeIds[0], { x: e.to.x - e.from.x, y: e.to.y - e.from.y });
    }
    return resolveLabelCollisions(clusters, blockers, edgeDirs);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edges, view.k, selected, positions, drawn, visiblePosture, fileNodes]);

  const containerSize = () => sizeRef.current;
  // Fix round 2026-11-27 (defect 4): the zoom-to-node target scales
  // with the container - k=2 on a 360px viewport leaves most of the
  // 400-wide world off-screen, and only Reset view recovers. Target
  // is fitK*1.75, capped at 2 (fitK is the fit scale for this
  // container, so a 360px plane zooms to ~1.5 instead of 2).
  const zoomTargetK = (w: number, h: number) => Math.min(2, fitView(w, h).k * 1.75);
  const selectNode = (id: string) => {
    interactedRef.current = true;
    setSelected({ type: "node", id });
    setPath(id === "repo" ? ["repo"] : ["repo", id]);
    setNeighbourIdx(0);
    const pos = positions.get(id);
    if (pos) {
      const { w, h } = containerSize();
      setView((v) => zoomToNode(v, pos, w, h, zoomTargetK(w, h)));
    }
  };
  const selectEdge = (key: string) => {
    interactedRef.current = true;
    setSelected({ type: "edge", id: key });
    setPath(["repo"]);
    setNeighbourIdx(0);
  };
  const deselect = () => {
    setSelected(null);
    setPath(["repo"]);
    setNeighbourIdx(0);
  };
  const resetView = () => {
    const { w, h } = containerSize();
    setView(fitView(w, h, 48));
  };
  const goToCrumb = (index: number) => {
    const id = path[index];
    if (index === 0) {
      deselect();
      resetView();
      return;
    }
    let p = path;
    while (p.length > index + 1) p = traverseBack(p);
    setPath(p);
    setSelected({ type: "node", id });
    setNeighbourIdx(0);
    const pos = positions.get(id);
    if (pos) {
      const { w, h } = containerSize();
      setView((v) => zoomToNode(v, pos, w, h, zoomTargetK(w, h)));
    }
  };
  const stepNeighbour = (dir: 1 | -1) => {
    if (neighbours.length === 0) return;
    setNeighbourIdx((i) => (i + dir + neighbours.length) % neighbours.length);
  };
  const goToNeighbour = () => {
    if (!currentNeighbour) return;
    const id = currentNeighbour.id;
    setPath((p) => traverseStep(p, id));
    setSelected({ type: "node", id });
    setNeighbourIdx(0);
    const pos = positions.get(id);
    if (pos) {
      const { w, h } = containerSize();
      setView((v) => zoomToNode(v, pos, w, h, zoomTargetK(w, h)));
    }
  };

  // --- pointer handling (one code path for mouse/touch/pen) --------
  const pointFromEvent = (e: { clientX: number; clientY: number; currentTarget: Element }) => {
    const rect = e.currentTarget.getBoundingClientRect();
    return { x: e.clientX - rect.left, y: e.clientY - rect.top };
  };
  const nodeIdFromTarget = (t: EventTarget | null): string | null => {
    const el = (t as Element | null)?.closest?.("[data-node-id]");
    return el?.getAttribute("data-node-id") ?? null;
  };
  const edgeIdFromTarget = (t: EventTarget | null): string | null => {
    const el = (t as Element | null)?.closest?.("[data-edge-id]");
    return el?.getAttribute("data-edge-id") ?? null;
  };
  const onPointerDown = (e: React.PointerEvent<SVGSVGElement>) => {
    // A right-click never starts a gesture: selection is a
    // left-click/tap action, same as the old onClick behaviour.
    if (e.pointerType === "mouse" && e.button !== 0) return;
    interactedRef.current = true;
    try {
      e.currentTarget.setPointerCapture(e.pointerId);
    } catch {
      // A released pointer has nothing to capture; the gesture ends.
    }
    const pt = pointFromEvent(e);
    pointersRef.current.set(e.pointerId, pt);
    pressRef.current = { time: Date.now(), moved: false };
    if (pointersRef.current.size === 2) {
      const [a, b] = [...pointersRef.current.values()];
      pinchRef.current = { prevDist: Math.hypot(a.x - b.x, a.y - b.y), prevMid: { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 } };
      gestureRef.current = { mode: "pinch" };
      return;
    }
    const nodeId = nodeIdFromTarget(e.target);
    if (nodeId) {
      const startPos = positions.get(nodeId) ?? { x: cx, y: cy };
      gestureRef.current = { mode: "node", nodeId, start: pt, startPos };
      return;
    }
    const edgeId = edgeIdFromTarget(e.target);
    if (edgeId) {
      gestureRef.current = { mode: "edge", edgeId, start: pt };
      return;
    }
    gestureRef.current = { mode: "pan", start: pt, last: pt };
  };
  const onPointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    if (!pointersRef.current.has(e.pointerId)) return;
    const pt = pointFromEvent(e);
    pointersRef.current.set(e.pointerId, pt);
    const g = gestureRef.current;
    if (!g) return;
    const { w, h } = containerSize();
    if (pointersRef.current.size === 2 && pinchRef.current) {
      const [a, b] = [...pointersRef.current.values()];
      const dist = Math.hypot(a.x - b.x, a.y - b.y);
      const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
      const prev = pinchRef.current;
      if (dist > 0 && prev.prevDist > 0) {
        const factor = dist / prev.prevDist;
        // Fix round 2026-11-27 (defect 2 audit): the midpoint pan
        // deltas are hoisted into locals BEFORE setView, never
        // computed inside the updater - the same stale-read hazard
        // as the pan branch. (This branch read a captured `prev`
        // object, so it was not itself broken; hoisting removes the
        // hazard outright.)
        const pdx = mid.x - prev.prevMid.x;
        const pdy = mid.y - prev.prevMid.y;
        setView((v) => zoomAt(panBy(v, pdx, pdy, w, h), mid.x, mid.y, factor, w, h));
      }
      pinchRef.current = { prevDist: dist, prevMid: mid };
      pressRef.current.moved = true;
      return;
    }
    if (g.mode === "node") {
      if (Math.hypot(pt.x - g.start.x, pt.y - g.start.y) > 5) pressRef.current.moved = true;
      if (pressRef.current.moved) {
        // Screen delta / scale = world delta; edges follow because
        // they read the resolved positions every render. Dragging
        // sets an override but does NOT pin the node.
        const k = viewRef.current.k;
        const pos = { x: g.startPos.x + (pt.x - g.start.x) / k, y: g.startPos.y + (pt.y - g.start.y) / k };
        setOverrides((prev) => new Map(prev).set(g.nodeId, pos));
      }
      return;
    }
    if (g.mode === "pan") {
      if (Math.hypot(pt.x - g.start.x, pt.y - g.start.y) > 5) pressRef.current.moved = true;
      // Fix round 2026-11-27 (defect 2): the deltas are hoisted
      // into locals BEFORE setView. The old code computed
      // pt.x - g.last.x INSIDE the updater but assigned g.last = pt
      // synchronously right after the setView call, so by the time
      // React ran the updater g.last === pt and dx=dy=0 always.
      const dx = pt.x - g.last.x;
      const dy = pt.y - g.last.y;
      g.last = pt;
      setView((v) => panBy(v, dx, dy, w, h));
    }
  };
  // Fix round 2026-11-27 (defect 1): selection happens HERE, on
  // pointerup, from the node/edge id recorded in the gesture at
  // pointerdown time. The old code selected via React onClick on
  // the node/edge <g>, but onPointerDown calls setPointerCapture
  // on the svg, which retargets pointerup AND click to the svg -
  // so the <g> onClick never fired (headless probe 1: pointerdown
  // target=text, click target=svg). Capture retargets the
  // pointerup target too, which is why the id must come from the
  // gesture record, never from the pointerup event target.
  const onPointerUp = (e: React.PointerEvent<SVGSVGElement>) => {
    pointersRef.current.delete(e.pointerId);
    if (pointersRef.current.size < 2) pinchRef.current = null;
    if (pointersRef.current.size === 0) {
      const g = gestureRef.current;
      if (g && isTap()) {
        if (g.mode === "node") selectNode(g.nodeId);
        else if (g.mode === "edge") selectEdge(g.edgeId);
        else if (g.mode === "pan") deselect();
      }
      gestureRef.current = null;
    }
  };
  // A cancelled gesture (the browser took over) never selects -
  // it only cleans up, unlike pointerup.
  const onPointerCancel = (e: React.PointerEvent<SVGSVGElement>) => {
    pointersRef.current.delete(e.pointerId);
    if (pointersRef.current.size < 2) pinchRef.current = null;
    if (pointersRef.current.size === 0) gestureRef.current = null;
  };
  // Tap: a press that moved <5 px in <500 ms. Read by onPointerUp
  // from the press record the move handler maintains.
  const isTap = () => !pressRef.current.moved && Date.now() - pressRef.current.time < 500;
  const onNodeKeyDown = (id: string) => (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      selectNode(id);
    }
  };
  const onEdgeKeyDown = (key: string) => (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      selectEdge(key);
    }
  };
  const onPlaneKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      deselect();
    } else if (e.key === "0") {
      resetView();
    } else if (e.key === "[" || e.key === "]") {
      stepNeighbour(e.key === "]" ? 1 : -1);
    } else if (e.key === "p" || e.key === "P") {
      const id = selNodeId ?? focusedNodeRef.current;
      if (id) setPins((prev) => togglePin(prev, id));
    }
  };

  const totalRefs = selFindingUsage && !selFindingUsage.deadEnd ? selFindingUsage.referencedByTotal + selFindingUsage.referencedByTestsTotal : 0;
  const trackSegments = selFindingUsage && !selFindingUsage.deadEnd ? trackDetailSegments(selFindingUsage) : [];
  const triageLabel =
    selFinding?.item.triage?.verdict === "likely-test-key"
      ? "Likely test key"
      : selFinding?.item.triage?.verdict === "likely-genuine-leak"
        ? "Likely genuine leak"
        : selFinding?.item.triage
          ? "Uncertain - needs a human check"
          : null;
  const codeRefs = edges.filter((e) => e.kind === "code").length;
  const testRefs = edges.filter((e) => e.kind === "test").length;
  const ownRefs = edges.filter((e) => e.kind === "own").length;
  const foundRefs = edges.filter((e) => e.kind === "found").length;
  // Phase 19: with no posture issues the summary keeps the exact
  // legacy wording (older tests assert it verbatim); with posture
  // it names secrets and posture issues separately, plus the
  // "found in" links. Either way the counts are what the plane
  // shows, and the lists below never change.
  const srSummary =
    posture.length === 0
      ? `Usage map: ${drawn.length} findings and ${fileNodes.length} files drawn. ${codeRefs} code references, ${testRefs} test references, ${ownRefs} own-file links.`
      : `Usage map: ${drawn.length} secrets and ${visiblePosture.length} posture issues drawn across ${fileNodes.length} files. ${codeRefs} code references, ${testRefs} test references, ${ownRefs} own-file links, ${foundRefs} found-in links.`;
  // Honest cap lines: null when a cap did not bind. The plane
  // states the cap maxima whenever any of these is non-null. The
  // file total counts every file holding a finding in the report
  // (all posture files, not just the drawn ones), matching the
  // full-total convention of the secret and posture notes.
  const secretCapNote = capNote(drawnSecretsAll.length, findings.length, "secrets");
  const postureCapNote = capNote(drawnPostureAll.length, posture.length, "posture issues");
  const totalFileCount = useMemo(() => {
    const files = new Set(byFile.map((f) => f.file));
    for (const p of posture) {
      if (typeof p.file === "string" && p.file.length > 0) files.add(p.file);
    }
    return files.size;
  }, [byFile, posture]);
  const fileCapNote = capNote(fileNodes.length, totalFileCount, "files");
  const anyCapBinds = secretCapNote !== null || postureCapNote !== null || fileCapNote !== null;
  // Small SVG pin glyph (a path, never an emoji) drawn above a pinned
  // node's circle.
  const pinGlyph = (x: number, y: number, r: number) => (
    <g className="map-pinned-mark" transform={`translate(${x} ${y - r - 8})`} aria-hidden="true">
      <path d="M 0 7 C -5 1 -6 -2 -6 -3 A 6 6 0 1 1 6 -3 C 6 -2 5 1 0 7 Z" />
      <circle cx={0} cy={-3} r={2} />
    </g>
  );
  const neighbourControls = (
    <>
      {neighbours.length > 0 && currentNeighbour ? (
        <>
          <p className="small">
            Connected to {neighbours.length} {neighbours.length === 1 ? "neighbour" : "neighbours"} - {neighbourIdx + 1} of {neighbours.length}: {labelOf(currentNeighbour.id)}.
          </p>
          <p>
            <button type="button" className="secondary" onClick={() => stepNeighbour(-1)} aria-label="Previous neighbour">Previous neighbour</button>{" "}
            <button type="button" className="secondary" onClick={() => stepNeighbour(1)} aria-label="Next neighbour">Next neighbour</button>{" "}
            <button type="button" onClick={goToNeighbour}>Go to {labelOf(currentNeighbour.id)}</button>
          </p>
        </>
      ) : null}
    </>
  );

  return (
    <div>
      {posture.length === 0 ? (
        <p className="small">
          Usage map - follow a secret through the repo. Showing {drawn.length} of {findings.length} findings and {fileNodes.length} files. Click a finding to highlight its track; click a file to see its detail, then filter the list from there.
        </p>
      ) : (
        <p className="small">
          Usage map - follow a finding through the repo. Showing {drawn.length} of {findings.length} secrets and {visiblePosture.length} of {posture.length} posture issues across {fileNodes.length} files. Click a finding to highlight its track; click a file to see its detail, then filter the list from there.
        </p>
      )}
      {anyCapBinds ? (
        <p className="small">
          Map caps: {MAP_MAX_SECRET_NODES} secrets, {MAP_MAX_POSTURE_NODES} posture issues, {MAP_MAX_FILE_NODES} files.{secretCapNote ? ` ${secretCapNote}` : ""}{postureCapNote ? ` ${postureCapNote}` : ""}{fileCapNote ? ` ${fileCapNote}` : ""}
        </p>
      ) : null}
      <p className="map-legend" aria-label="Map legend">
        <span><b>●</b> Centre - this repo</span>
        <span><b>━━</b> Used in non-test code</span>
        <span><b>┄┄</b> Used in tests only</span>
        <span><b>●</b> Grey node - dead end, nothing references it</span>
        <span><b>━━</b> Found in - posture issue in that file</span>
        {categoriesPresent.map(({ category, count }) => (
          <span key={category}>
            <CategoryGlyph category={category} /> {categoryLabel(category)} ({count})
          </span>
        ))}
        <span>Every node is keyboard reachable: Tab to it, Enter to select</span>
      </p>
      {/* Phase 19: category filter. The row renders only when the
        plane holds more than one category - a filter with one option
        is not a filter. Hiding a category only hides its nodes and
        edges from the plane; the report counts and the lists below
        never change. */}
      {categoriesPresent.length > 1 ? (
        <div className="map-toolbar" role="group" aria-label="Map category filters">
          {categoriesPresent.map(({ category, count }) => (
            <button
              key={category}
              type="button"
              className="secondary"
              aria-pressed={!hiddenCats.has(category)}
              onClick={() => toggleCategory(category)}
            >
              {categoryLabel(category)} ({count})
            </button>
          ))}
        </div>
      ) : null}
      <div className="map-toolbar" role="group" aria-label="Map controls">
        <button
          type="button"
          aria-label="Zoom in"
          onClick={() => {
            interactedRef.current = true;
            const { w, h } = containerSize();
            setView((v) => zoomByFactor(v, 1.25, w, h));
          }}
        >
          Zoom in
        </button>
        <button
          type="button"
          aria-label="Zoom out"
          onClick={() => {
            interactedRef.current = true;
            const { w, h } = containerSize();
            setView((v) => zoomByFactor(v, 0.8, w, h));
          }}
        >
          Zoom out
        </button>
        <button
          type="button"
          aria-label="Reset view"
          onClick={() => {
            interactedRef.current = true;
            resetView();
          }}
        >
          Reset view
        </button>
        <button
          type="button"
          aria-label="Reset layout"
          onClick={() => {
            setOverrides(new Map());
            setPins(new Set());
          }}
        >
          Reset layout
        </button>
      </div>
      <div
        className="map-plane"
        ref={planeRef}
        tabIndex={0}
        role="group"
        aria-label="Usage map plane. Drag to pan, scroll to zoom, Tab to reach nodes and connections."
        onKeyDown={onPlaneKeyDown}
      >
        <p className="map-sr-summary">{srSummary}</p>
        <svg
          ref={svgRef}
          role="group"
          aria-label="Usage map: secrets and the files that reference them"
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerCancel={onPointerCancel}
        >
          <g transform={viewTransformString(view)} className={reducedMotion ? undefined : "map-animated"}>
            {edges.map((e) => {
              const active = edgeActive(e);
              // Test connections (one test file referencing many
              // secrets) bundle into a thicket at fit zoom, so they
              // stay hidden until zoomed in, like edge labels, or
              // on the selected track. Own, code, and found edges
              // always render.
              const onSelectedTrack =
                (activeNodeId != null && activeNodeId !== "repo" && (e.fromId === activeNodeId || e.toId === activeNodeId)) || (selected?.type === "edge" && e.key === selected.id);
              if (e.kind === "test" && view.k < EDGE_LABEL_MIN_ZOOM && !onSelectedTrack && !showDetail) return null;
              // Fix round 3 (2026-11-27): no per-edge label here
              // any more - labels render as clusters below (see
              // labelClusters). The line itself (solid/dashed/thin)
              // always renders, so every edge stays distinguishable,
              // and the gating (k >= EDGE_LABEL_MIN_ZOOM, else the
              // selected track only) now applies to the anchor set
              // the clusters are built from. The labelT stagger
              // stays: it positions each edge's anchor along its
              // adjusted segment.
              const aria =
                e.kind === "found"
                  ? `Connection: ${e.title ?? "Posture issue"} found in ${e.refFile}${e.refLine > 0 ? ` line ${e.refLine}` : ""}`
                  : e.kind === "own"
                    ? `Connection: Secret ${e.findingIdx + 1} lives in ${e.refFile} line ${e.refLine}`
                    : `Connection: Secret ${e.findingIdx + 1} ${edgeLabelText(e.kind)} in ${e.refFile} line ${e.refLine}`;
              return (
                <g
                  key={e.key}
                  className="map-edge-focus"
                  data-edge-id={e.key}
                  tabIndex={0}
                  role="button"
                  aria-label={aria}
                  onKeyDown={onEdgeKeyDown(e.key)}
                >
                  <title>{aria}</title>
                  <line x1={e.from.x} y1={e.from.y} x2={e.to.x} y2={e.to.y} className={`map-edge map-edge-${e.kind}${active ? " map-edge-track" : " map-edge-dim"}`} />
                  <line x1={e.from.x} y1={e.from.y} x2={e.to.x} y2={e.to.y} stroke="transparent" strokeWidth={12} pointerEvents="stroke" />
                </g>
              );
            })}
            {/* The centre is painted after the edges, so no edge can
              strike through the "This repo" label. */}
            <g
              className="map-centre-node"
              data-node-id="repo"
              tabIndex={0}
              role="button"
              aria-label="This repo - select to see the whole map"
              onKeyDown={onNodeKeyDown("repo")}
              onFocus={() => {
                focusedNodeRef.current = "repo";
              }}
              onBlur={() => {
                if (focusedNodeRef.current === "repo") focusedNodeRef.current = null;
              }}
            >
              <title>This repo</title>
              <circle className="map-centre" cx={cx} cy={cy} r={30} />
              <text className="map-centre-text" x={cx} y={cy + 4} textAnchor="middle" fontSize={10} fontWeight={700}>This repo</text>
            </g>
            {fileNodes.map((f) => {
              const pos = positions.get(nodeIdOfFile(f.file)) ?? { x: cx, y: cy };
              const { x, y } = pos;
              const r = 9 + Math.min(4, Math.sqrt(Math.max(f.count, 1)) * 1.2);
              const dimmed = dimNode(nodeIdOfFile(f.file));
              const isNeighbour = neighbours.some((n) => n.id === nodeIdOfFile(f.file));
              const pinned = pins.has(nodeIdOfFile(f.file));
              // The label sits radially OUTWARD from its node (away
              // from the finding ring), so it can never collide with
              // a finding's "N uses" caption, which lives in the band
              // between the rings. The x is clamped so a side node's
              // label stays inside the viewBox; the y is clamped so
              // the top node's label stays inside it now the outer
              // ring is wider (2026-11-27).
              const angle = Math.atan2(y - cy, x - cx);
              const lo = r + 14 + ((fileLabelParity.get(nodeIdOfFile(f.file)) ?? 0) === 1 ? 28 : 0);
              const lx = Math.max(42, Math.min(438, x + Math.cos(angle) * lo));
              const ly = Math.max(8, Math.min(432, y + Math.sin(angle) * lo));
              return (
                <g
                  key={f.file}
                  className={`map-node${dimmed ? " map-dim" : ""}${isNeighbour ? " map-neighbour" : ""}`}
                  data-node-id={nodeIdOfFile(f.file)}
                  onKeyDown={onNodeKeyDown(nodeIdOfFile(f.file))}
                  onFocus={() => {
                    focusedNodeRef.current = nodeIdOfFile(f.file);
                  }}
                  onBlur={() => {
                    if (focusedNodeRef.current === nodeIdOfFile(f.file)) focusedNodeRef.current = null;
                  }}
                  tabIndex={0}
                  role="button"
                  aria-label={`${f.file}, ${f.count} findings${pinned ? ", pinned" : ""}`}
                >
                  <title>{`${f.file} - ${f.count} finding${f.count === 1 ? "" : "s"}`}</title>
                  <circle className="map-hit" cx={x} cy={y} r={24} />
                  <circle cx={x} cy={y} r={r} />
                  {/* The count lives INSIDE the node (on solid fill,
                    no edge can cross it); the label is a
                    middle-truncated basename with a halo. */}
                  <text x={x} y={y + 4} textAnchor="middle" fontWeight={700} fontSize={11}>{f.count}</text>
                  <text className="map-label" x={lx} y={ly} textAnchor="middle" dominantBaseline="central">{shortLabel(f.file)}</text>
                  {pinned ? pinGlyph(x, y, r) : null}
                </g>
              );
            })}
            {drawn.map((e, i) => {
              const pos = positions.get(nodeIdOfFinding(e.idx)) ?? { x: cx, y: cy };
              const { x, y } = pos;
              const u = usageOf(e);
              const dead = u?.deadEnd === true;
              const refs = u && !dead ? u.referencedByTotal + u.referencedByTestsTotal : 0;
              const isSelected = activeNodeId === nodeIdOfFinding(e.idx);
              const dimmed = dimNode(nodeIdOfFinding(e.idx));
              const isNeighbour = neighbours.some((n) => n.id === nodeIdOfFinding(e.idx));
              const pinned = pins.has(nodeIdOfFinding(e.idx));
              const label = `secret ${e.idx + 1}`;
              // The node grows slightly with its reference count, so
              // the most-used findings read a touch bigger at a
              // glance - capped tight (max 14) so neighbours on the
              // ring can never touch.
              const fr = 11 + Math.min(3, Math.round(Math.sqrt(refs) * 0.7));
              // The caption steps sideways, alternating per node, so
              // neighbours' captions stop stacking on one another;
              // the halo keeps it readable where an edge passes
              // behind it. Fix round 2 (defect 3): the step grows
              // from ±14 to ±20 world units and the line moves from
              // fr+12 to fr+14 below the node - "70 uses" / "62 uses"
              // of adjacent nodes overlapped in the centre cluster
              // at fit zoom.
              const captionX = x + (i % 2 === 0 ? 20 : -20);
              const captionY = y + fr + 14;
              // Captions stay hidden at fit zoom, like edge labels:
              // twenty-four "0 uses" captions in a small ring read as
              // soup. They appear once zoomed in, or for the selected
              // node, where they have room.
              const showCaption = showDetail || view.k >= EDGE_LABEL_MIN_ZOOM || activeNodeId === nodeIdOfFinding(e.idx);
              return (
                <g
                  key={e.idx}
                  className={`map-node map-finding-node${dead ? " map-finding-deadend" : ""}${isSelected ? " map-node-selected" : ""}${dimmed ? " map-dim" : ""}${isNeighbour ? " map-neighbour" : ""}`}
                  data-node-id={nodeIdOfFinding(e.idx)}
                  onKeyDown={onNodeKeyDown(nodeIdOfFinding(e.idx))}
                  onFocus={() => {
                    focusedNodeRef.current = nodeIdOfFinding(e.idx);
                  }}
                  onBlur={() => {
                    if (focusedNodeRef.current === nodeIdOfFinding(e.idx)) focusedNodeRef.current = null;
                  }}
                  tabIndex={0}
                  role="button"
                  aria-label={
                    dead
                      ? `${label}, ${e.item.title}, ${e.item.file} line ${e.item.line} - dead end, nothing references it${pinned ? ", pinned" : ""}`
                      : u
                        ? `${label}, ${e.item.title}, ${e.item.file} line ${e.item.line} - used by ${refs} reference${refs === 1 ? "" : "s"}${pinned ? ", pinned" : ""}`
                        : `${label}, ${e.item.title}, ${e.item.file} line ${e.item.line} - no usage data${pinned ? ", pinned" : ""}`
                  }
                >
                  <title>{`${label} - ${e.item.file}:${e.item.line}${dead ? " - dead end" : u ? ` - ${refs} reference${refs === 1 ? "" : "s"}` : " - no usage data"}`}</title>
                  <circle className="map-hit" cx={x} cy={y} r={24} />
                  <circle cx={x} cy={y} r={fr} />
                  <text x={x} y={y + 4} textAnchor="middle" fontWeight={700}>{`S${e.idx + 1}`}</text>
                  {showCaption ? <text className="map-label" x={captionX} y={captionY} textAnchor="middle">{dead ? "dead end" : u ? `${refs} use${refs === 1 ? "" : "s"}` : ""}</text> : null}
                  {pinned ? pinGlyph(x, y, fr) : null}
                </g>
              );
            })}
            {/* Phase 19: posture nodes on the middle ring. Shape +
              in-node code carry the category (see MAP_CATEGORY_META);
              the caption below is the severity, stepping sideways on
              alternate nodes like the finding captions. Inline SVG
              presentation (no new CSS): surface fill, accent stroke,
              focus stroke when selected or a neighbour. A posture
              issue with no file still draws - it just has no edge. */}
            {visiblePosture.map((e, i) => {
              const pos = positions.get(nodeIdOfPosture(e.idx)) ?? { x: cx, y: cy };
              const { x, y } = pos;
              const meta = MAP_CATEGORY_META[e.category];
              const r = 12;
              const isSelected = activeNodeId === nodeIdOfPosture(e.idx);
              const dimmed = dimNode(nodeIdOfPosture(e.idx));
              const isNeighbour = neighbours.some((n) => n.id === nodeIdOfPosture(e.idx));
              const pinned = pins.has(nodeIdOfPosture(e.idx));
              const captionX = x + (i % 2 === 0 ? 20 : -20);
              const captionY = y + r + 14;
              const showCaption = showDetail || view.k >= EDGE_LABEL_MIN_ZOOM || activeNodeId === nodeIdOfPosture(e.idx);
              const fileLoc = typeof e.item.file === "string" && e.item.file.length > 0
                ? `${e.item.file}${typeof e.item.line === "number" && e.item.line > 0 ? `:${e.item.line}` : ""}`
                : "no single file";
              return (
                <g
                  key={e.idx}
                  className={`map-node map-posture-node${isSelected ? " map-node-selected" : ""}${dimmed ? " map-dim" : ""}${isNeighbour ? " map-neighbour" : ""}`}
                  data-node-id={nodeIdOfPosture(e.idx)}
                  onKeyDown={onNodeKeyDown(nodeIdOfPosture(e.idx))}
                  onFocus={() => {
                    focusedNodeRef.current = nodeIdOfPosture(e.idx);
                  }}
                  onBlur={() => {
                    if (focusedNodeRef.current === nodeIdOfPosture(e.idx)) focusedNodeRef.current = null;
                  }}
                  tabIndex={0}
                  role="button"
                  aria-label={`${postureDisplayLabel.get(e.idx)}, ${e.item.title}, ${fileLoc} - ${categoryLabel(e.category)}, ${e.item.severity}${pinned ? ", pinned" : ""}`}
                >
                  <title>{`${postureDisplayLabel.get(e.idx)} - ${e.item.title} - ${fileLoc} - ${categoryLabel(e.category)}, ${e.item.severity}`}</title>
                  <circle className="map-hit" cx={x} cy={y} r={24} />
                  <polygon
                    points={categoryPolygonPoints(meta.sides, meta.rotation, x, y, r)}
                    style={{ fill: "var(--surface)", stroke: isSelected || isNeighbour ? "var(--focus)" : "var(--accent)", strokeWidth: isSelected || isNeighbour ? 3 : 2 }}
                  />
                  <text x={x} y={y + 3} textAnchor="middle" fontWeight={700} fontSize={8}>{postureDisplayLabel.get(e.idx)}</text>
                  {showCaption ? <text className="map-label" x={captionX} y={captionY} textAnchor="middle">{e.item.severity}</text> : null}
                  {pinned ? pinGlyph(x, y, r) : null}
                </g>
              );
            })}
            {/* Fix round 3 (2026-11-27): clustered edge labels.
              One <text> per cluster at the cluster centroid, halo
              class kept. Count > 1 appends " ×N" to the kind text
              ("used in tests ×11"). pointerEvents="none" so a tap
              on a label falls through to the edge hit line beneath
              it. A cluster dims only when none of its edges is on
              the active track.
              Fix round 4 (2026-11-27): these labels render LAST in
              the SVG - after the centre, file, and finding node
              groups - so no node can paint over a label (recheck-4:
              the S8 node circle hid ~46px of "used in tests ×10").
              The centre keeps its existing rule (painted after the
              edges); labels go after everything. */}
            {labelClusters.map((c) => {
              const active = c.edgeIds.some((id) => {
                const e = edgeByKey.get(id);
                return e ? edgeActive(e) : false;
              });
              return (
                <text
                  key={c.edgeIds.join("|")}
                  className={`map-label map-edge-label${active ? "" : " map-edge-dim"}`}
                  x={c.x}
                  y={c.y}
                  textAnchor="middle"
                  dominantBaseline="central"
                  pointerEvents="none"
                >
                  {c.count === 1 ? edgeLabelText(c.kind) : `${edgeLabelText(c.kind)} ×${c.count}`}
                </text>
              );
            })}
          </g>
        </svg>
      </div>
      <p className="small map-hint">
        Click a node to zoom to it. Drag the background to pan, drag a node to move it, pinch to zoom. Node captions, edge labels, and test connections appear as you zoom in, and always for the selected track. Press p to pin a node, [ and ] to step between neighbours, 0 to reset the view, Esc to deselect.
      </p>
      {categoriesPresent.length > 1 ? (
        <p className="small map-hint">Category buttons above the plane show or hide each category; the lists below never change.</p>
      ) : null}
      {findings.length === 0 && posture.length === 0 ? (
        <p className="small">No secrets in this report and no posture issues either, so the map shows just this repo. Scan a repo with secrets to see its findings and files mapped here.</p>
      ) : findings.length > 0 && !hasUsage && foundRefs === 0 ? (
        <p className="small">These findings carry no usage data, so there are no edges yet - the nodes are the findings and the files that hold them.</p>
      ) : null}
      {activeNodeId ? (
        <nav className="map-breadcrumb" aria-label="Map breadcrumb">
          {path.map((id, i) => (
            <span key={`${id}-${i}`}>
              {i > 0 ? <span aria-hidden="true"> › </span> : null}
              <button type="button" className="secondary" onClick={() => goToCrumb(i)} aria-label={i === 0 ? "Back to the full map view" : `Back to ${labelOf(id)}`}>
                {labelOf(id)}
              </button>
            </span>
          ))}
        </nav>
      ) : null}
      <div className="map-track-detail" aria-live="polite">
        {selFinding && selFindingUsage ? (
          <>
            <p>
              <b>Secret {selFinding.idx + 1} - {selFinding.item.title}</b> · <code className="inline">{selFinding.item.file}:{selFinding.item.line}</code>
              {triageLabel ? <> · {triageLabel}</> : null}
              {pins.has(nodeIdOfFinding(selFinding.idx)) ? <> · Pinned</> : null}
              {selFindingUsage.deadEnd ? (
                <> · <span className="pill dead-end">Dead end</span> Nothing in this repo references this key - a true dead end{selFindingUsage.historyOnly ? " (usage checked against the current files only)" : ""}.</>
              ) : totalRefs === 0 ? (
                <> · No references recorded.</>
              ) : trackSegments.length > 0 ? (
                <>
                  {" "}· This file reads this secret, so rotating it means updating this file too. {trackSegments.join("; ")}
                  {totalRefs > 10 ? ` (+${totalRefs - 10} more)` : ""}
                  {selFindingUsage.historyOnly ? " (usage checked against the current files only)" : ""}
                </>
              ) : (
                <> · Used by: {totalRefs} reference{totalRefs === 1 ? "" : "s"} (file list not shown){selFindingUsage.historyOnly ? " (usage checked against the current files only)" : ""}.</>
              )}
            </p>
            <p>
              <button type="button" className="secondary" aria-pressed={pins.has(nodeIdOfFinding(selFinding.idx))} onClick={() => setPins((prev) => togglePin(prev, nodeIdOfFinding(selFinding.idx)))}>
                {pins.has(nodeIdOfFinding(selFinding.idx)) ? "Unpin" : "Pin"}
              </button>{" "}
              {onShowFinding ? (
                <button type="button" className="secondary" onClick={() => onShowFinding(selFinding.idx)}>Show this finding in the list</button>
              ) : null}
            </p>
            {neighbourControls}
          </>
        ) : selPosture ? (
          <>
            <p>
              <b>{postureDisplayLabel.get(selPosture.idx)} - {selPosture.item.title}</b> · {categoryLabel(selPosture.category)} · {selPosture.item.severity}
              {typeof selPosture.item.file === "string" && selPosture.item.file.length > 0 ? (
                <> · <code className="inline">{selPosture.item.file}{typeof selPosture.item.line === "number" && selPosture.item.line > 0 ? `:${selPosture.item.line}` : ""}</code></>
              ) : (
                <> · No single file</>
              )}
              {pins.has(nodeIdOfPosture(selPosture.idx)) ? <> · Pinned</> : null}
            </p>
            <p>{selPosture.item.detail}</p>
            <p className="fix"><b>Fix:</b> {selPosture.item.fix}</p>
            <p>
              <button type="button" className="secondary" aria-pressed={pins.has(nodeIdOfPosture(selPosture.idx))} onClick={() => setPins((prev) => togglePin(prev, nodeIdOfPosture(selPosture.idx)))}>
                {pins.has(nodeIdOfPosture(selPosture.idx)) ? "Unpin" : "Pin"}
              </button>
            </p>
            {neighbourControls}
          </>
        ) : selFile ? (
          <>
            <p>
              <b>{selFile.file}</b> · {selFile.count} finding{selFile.count === 1 ? "" : "s"} live in this file
              {pins.has(nodeIdOfFile(selFile.file)) ? <> · Pinned</> : null}
            </p>
            <p>
              <button type="button" className="secondary" aria-pressed={pins.has(nodeIdOfFile(selFile.file))} onClick={() => setPins((prev) => togglePin(prev, nodeIdOfFile(selFile.file)))}>
                {pins.has(nodeIdOfFile(selFile.file)) ? "Unpin" : "Pin"}
              </button>{" "}
              <button type="button" onClick={() => onSelectFile(selFile.file)}>Filter list to this file</button>
            </p>
            {neighbourControls}
          </>
        ) : selEdge ? (
          <>
            <p>
              {edgeDetailText({
                findingTitle: selEdge.kind === "found" ? (selEdge.title ?? "Posture issue") : (selEdgeFinding?.item.title ?? ""),
                findingFile: selEdge.kind === "found" ? selEdge.refFile : (selEdgeFinding?.item.file ?? selEdge.refFile),
                findingLine: selEdge.kind === "found" ? selEdge.refLine : (selEdgeFinding?.item.line ?? selEdge.refLine),
                refFile: selEdge.refFile,
                refLine: selEdge.refLine,
                kind: selEdge.kind,
              })}
            </p>
            <p className="small">
              {selEdge.refFile}{selEdge.refLine > 0 ? `:${selEdge.refLine}` : ""} · {edgeLabelText(selEdge.kind)}
              {selEdge.kind === "found" && selEdge.postureIdx != null ? ` · ${categoryLabel(postureCategoryOf(drawnPostureAll.find((e) => e.idx === selEdge.postureIdx)?.item ?? {}))}` : ""}
            </p>
            <p>
              <button type="button" className="secondary" onClick={() => selectNode(selEdge.fromId)}>{selEdge.kind === "found" ? "Show this posture issue" : `Show Secret ${selEdge.findingIdx + 1}`}</button>
            </p>
          </>
        ) : activeNodeId === "repo" ? (
          <p>
            {posture.length === 0 ? (
              <><b>This repo</b> · {drawn.length} findings and {fileNodes.length} files drawn on this map. Select a finding or a file to follow its connections.</>
            ) : (
              <><b>This repo</b> · {drawn.length} secrets and {visiblePosture.length} posture issues drawn on this map. Select a finding or a file to follow its connections.</>
            )}
          </p>
        ) : (
          <p className="small">Click a finding node to follow its track - the secret, the files that use it, and the file it lives in.</p>
        )}
      </div>
    </div>
  );
}

export function SecretsList({ secrets, owner, repo, branch, posture = [], defaultTestSectionOpen = false, defaultView = "map" }: { secrets: SecretFinding[]; owner: string; repo: string; branch: string; posture?: PostureIssue[]; defaultTestSectionOpen?: boolean; defaultView?: "list" | "map" }) {
  const [groupBy, setGroupBy] = useState<"none" | "type" | "file">("none");
  const [typeFilter, setTypeFilter] = useState("all");
  const [sevFilter, setSevFilter] = useState("all");
  const [triageFilter, setTriageFilter] = useState("all");
  const [fileQuery, setFileQuery] = useState("");
  // The map is the default view on every report (2026-11-27, Freddy):
  // a report opens on the plane, with the list one tap away. A clean
  // repo opens on the map too, showing just the repo node. Tests that
  // assert list content render with defaultView="list".
  const [view, setView] = useState<"list" | "map">(defaultView);
  // Phase 11 verdict sections. Genuine leaks and uncertain findings
  // are open by default - they are the ones that need a human. Likely
  // test keys are collapsed by default: still listed, still counted,
  // one click away, never mixed in with the genuine leaks.
  const [genuineOpen, setGenuineOpen] = useState(true);
  const [uncertainOpen, setUncertainOpen] = useState(true);
  const [testOpen, setTestOpen] = useState(defaultTestSectionOpen);
  // A shared #secret-N link: clear the filters, force the flat list,
  // and open it past the linked finding so the anchor exists to scroll to.
  const [hashTarget, setHashTarget] = useState<number | null>(null);
  useEffect(() => {
    const parse = () => {
      const m = /^#secret-(\d+)$/.exec(window.location.hash);
      if (!m) return;
      const n = Number(m[1]);
      if (n < 0 || n >= secrets.length) return;
      setTypeFilter("all");
      setSevFilter("all");
      setTriageFilter("all");
      setFileQuery("");
      setGroupBy("none");
      setView("list");
      setHashTarget(n);
    };
    parse();
    window.addEventListener("hashchange", parse);
    return () => window.removeEventListener("hashchange", parse);
  }, [secrets.length]);
  useEffect(() => {
    if (hashTarget == null) return;
    const t = setTimeout(() => {
      document.getElementById(findingAnchorId("secret", hashTarget))?.scrollIntoView({ block: "start" });
    }, 60);
    return () => clearTimeout(t);
  }, [hashTarget]);

  const types = useMemo(() => [...new Set(secrets.map((s) => s.type))].sort(), [secrets]);
  const testKeyCount = useMemo(() => secrets.filter((s) => s.triage?.verdict === "likely-test-key").length, [secrets]);
  const genuineCount = useMemo(() => secrets.filter((s) => s.triage?.verdict === "likely-genuine-leak").length, [secrets]);
  const uncertainCount = useMemo(() => secrets.filter((s) => verdictOf(s) === "uncertain").length, [secrets]);
  const indexed = useMemo(() => withIndex(secrets), [secrets]);
  const filtered = useMemo(
    () =>
      indexed.filter(
        ({ item: s }) =>
          (typeFilter === "all" || s.type === typeFilter) &&
          (sevFilter === "all" || s.severity === sevFilter) &&
          (triageFilter === "all" || verdictOf(s) === triageFilter) &&
          (fileQuery === "" || s.file.toLowerCase().includes(fileQuery.toLowerCase())),
      ),
    [indexed, typeFilter, sevFilter, triageFilter, fileQuery],
  );
  // Phase 11: the filtered list is partitioned by triage verdict, so a
  // genuine leak is never shown in the same section as a test key.
  const genuineEntries = useMemo(() => filtered.filter((e) => verdictOf(e.item) === "likely-genuine-leak"), [filtered]);
  const uncertainEntries = useMemo(() => filtered.filter((e) => verdictOf(e.item) === "uncertain"), [filtered]);
  const testEntries = useMemo(() => filtered.filter((e) => verdictOf(e.item) === "likely-test-key"), [filtered]);
  // A shared #secret-N link opens the section holding that finding,
  // even the collapsed test-keys section, so the anchor exists.
  useEffect(() => {
    if (hashTarget == null) return;
    const v = verdictOf(secrets[hashTarget]);
    if (v === "likely-test-key") setTestOpen(true);
    else if (v === "likely-genuine-leak") setGenuineOpen(true);
    else setUncertainOpen(true);
  }, [hashTarget, secrets]);
  // The triage filter also opens the section it selects.
  const testEffectiveOpen = testOpen || triageFilter === "likely-test-key" || (hashTarget != null && verdictOf(secrets[hashTarget]) === "likely-test-key");
  const genuineEffectiveOpen = genuineOpen || triageFilter === "likely-genuine-leak";
  const uncertainEffectiveOpen = uncertainOpen || triageFilter === "uncertain";
  const fileCount = useMemo(() => new Set(filtered.map(({ item: s }) => s.file)).size, [filtered]);
  const byFile = useMemo(() => {
    const counts = new Map<string, number>();
    for (const { item: s } of filtered) counts.set(s.file, (counts.get(s.file) ?? 0) + 1);
    return [...counts.entries()].map(([file, count]) => ({ file, count })).sort((a, b) => b.count - a.count || a.file.localeCompare(b.file));
  }, [filtered]);

  const groupEntries = (entries: Indexed<SecretFinding>[]) => {
    if (groupBy === "none") return [];
    const keyOf = groupBy === "type" ? (s: SecretFinding) => s.type : (s: SecretFinding) => s.file;
    const map = new Map<string, Indexed<SecretFinding>[]>();
    for (const entry of entries) {
      const k = keyOf(entry.item);
      const arr = map.get(k) ?? [];
      arr.push(entry);
      map.set(k, arr);
    }
    return [...map.entries()]
      .map(([key, items]) => ({ key, items }))
      .sort((a, b) => b.items.length - a.items.length || a.key.localeCompare(b.key));
  };

  const selectFile = (file: string) => {
    setFileQuery(file);
    setView("list");
  };
  // From the map: jump to one finding in the list. Setting the hash
  // reuses the shared-link handler above (clears filters, opens the
  // finding's section, scrolls to it).
  const showFinding = (idx: number) => {
    setView("list");
    window.location.hash = findingAnchorId("secret", idx);
  };
  const renderSectionItems = (entries: Indexed<SecretFinding>[]) => {
    if (groupBy === "none") {
      const pos = hashTarget != null ? entries.findIndex((e) => e.idx === hashTarget) : -1;
      return (
        <Paged
          items={entries}
          initialShown={pos >= 0 ? pos + 1 : PAGE_SIZE}
          renderItem={(entry) => <SecretRow key={`${entry.item.type}-${entry.item.file}-${entry.item.line}-${entry.idx}`} entry={entry} owner={owner} repo={repo} branch={branch} />}
        />
      );
    }
    return groupEntries(entries).map((g) => (
      <details key={g.key} className="group" open={entries.length <= GROUP_OPEN_BELOW}>
        <summary>
          <span className="chevron" aria-hidden="true">▸</span>
          {g.key} <span className="count-badge">({g.items.length} finding{g.items.length === 1 ? "" : "s"})</span>
        </summary>
        <div className="group-body">
          <Paged
            items={g.items}
            renderItem={(entry) => <SecretRow key={`${entry.item.type}-${entry.item.file}-${entry.item.line}-${entry.idx}`} entry={entry} owner={owner} repo={repo} branch={branch} />}
          />
        </div>
      </details>
    ));
  };

  return (
    <div>
      <div className="filters">
        <label>
          Group by
          <select value={groupBy} onChange={(e) => setGroupBy(e.target.value as "none" | "type" | "file")} aria-label="Group findings by">
            <option value="none">No grouping</option>
            <option value="type">Secret type</option>
            <option value="file">File</option>
          </select>
        </label>
        <label>
          Type
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} aria-label="Filter by secret type">
            <option value="all">All types</option>
            {types.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </label>
        <SeveritySelect value={sevFilter} onChange={setSevFilter} />
        <label>
          Triage
          <select value={triageFilter} onChange={(e) => setTriageFilter(e.target.value)} aria-label="Filter by triage verdict">
            <option value="all">All findings</option>
            <option value="likely-test-key">Likely test keys</option>
            <option value="likely-genuine-leak">Likely genuine leaks</option>
            <option value="uncertain">Uncertain</option>
          </select>
        </label>
        <label>
          File name
          <input type="search" value={fileQuery} onChange={(e) => setFileQuery(e.target.value)} placeholder="Filter by file name…" aria-label="Filter by file name" />
        </label>
        <div className="view-toggle" role="group" aria-label="View">
          <button type="button" className="secondary" aria-pressed={view === "list"} onClick={() => setView("list")}>List</button>
          <button type="button" className="secondary" aria-pressed={view === "map"} onClick={() => setView("map")}>Map</button>
        </div>
        {fileQuery !== "" && (
          <button type="button" className="secondary" onClick={() => setFileQuery("")}>Clear file filter</button>
        )}
      </div>
      <p className="small" aria-live="polite">
        Showing {filtered.length} of {secrets.length} secrets{fileQuery !== "" ? ` matching “${fileQuery}”` : ""} · {fileCount} file{fileCount === 1 ? "" : "s"}.
        {testKeyCount > 0 ? ` Of the ${secrets.length} secrets, ${testKeyCount} look${testKeyCount === 1 ? "s" : ""} like test keys - still listed and still counted, with a test-key fix instead of "rotate it".` : ""}
        {genuineCount > 0 || uncertainCount > 0 ? ` ${genuineCount} look${genuineCount === 1 ? "s" : ""} like genuine leaks, ${uncertainCount} uncertain.` : ""}
      </p>
      {view === "map" ? (
        <UsageMap findings={filtered} posture={posture} byFile={byFile} onSelectFile={selectFile} onShowFinding={showFinding} />
      ) : (
        <>
          {secrets.length === 0 && (
            <p>No leaked secrets were found in the files and recent history scanned.</p>
          )}
          {genuineEntries.length > 0 && (
            <details className="group verdict-section verdict-genuine" open={genuineEffectiveOpen} onToggle={(e) => setGenuineOpen(e.currentTarget.open)}>
              <summary>
                <span className="chevron" aria-hidden="true">▸</span>
                Likely genuine leaks <span className="count-badge">({genuineEntries.length} finding{genuineEntries.length === 1 ? "" : "s"})</span>
              </summary>
              <p className="small">These look like real credentials. Treat each one as compromised until you have checked it.</p>
              <div className="group-body">{renderSectionItems(genuineEntries)}</div>
            </details>
          )}
          {uncertainEntries.length > 0 && (
            <details className="group verdict-section verdict-uncertain" open={uncertainEffectiveOpen} onToggle={(e) => setUncertainOpen(e.currentTarget.open)}>
              <summary>
                <span className="chevron" aria-hidden="true">▸</span>
                Uncertain - needs a human check <span className="count-badge">({uncertainEntries.length} finding{uncertainEntries.length === 1 ? "" : "s"})</span>
              </summary>
              <p className="small">Triage could not call these either way. Check each one by hand before deciding.</p>
              <div className="group-body">{renderSectionItems(uncertainEntries)}</div>
            </details>
          )}
          {testEntries.length > 0 && (
            <details className="group verdict-section verdict-test" open={testEffectiveOpen} onToggle={(e) => setTestOpen(e.currentTarget.open)}>
              <summary>
                <span className="chevron" aria-hidden="true">▸</span>
                Likely test keys <span className="count-badge">({testEntries.length} finding{testEntries.length === 1 ? "" : "s"})</span>
              </summary>
              <p className="small">These look like intentional test keys. They are still listed and still counted in the score - expand to check each one and its test-key fix.</p>
              <div className="group-body">{renderSectionItems(testEntries)}</div>
            </details>
          )}
        </>
      )}
    </div>
  );
}

// ------------------------------------------------------------- frameworks

export function FrameworksList({ frameworks }: { frameworks: Framework[] }) {
  const { visible, shown, showMore, showAll } = usePagedSimple(frameworks);
  return (
    <>
      {/* Phase 15 finding 2 (real-DT follow-up): report-list li wraps
        anywhere - a framework name/version can be a 40-char SHA with no
        break opportunity, and the live DT provisional report was 411 px
        wide at a 360 px viewport because of it. */}
      <ul className="report-list">
        {visible.map((f, i) => (
          <li key={`${f.name}-${f.sourceFile}-${i}`}>
            <b>{f.name}</b> - {f.version ?? "version could not be determined"} ({f.versionSource})
            {f.unpinned ? " · unpinned version" : ""} · <code className="inline">{f.sourceFile}</code>
          </li>
        ))}
      </ul>
      <Pager total={frameworks.length} shown={shown} onMore={showMore} onAll={showAll} />
    </>
  );
}

function usePagedSimple<T>(items: T[]) {
  const [shown, setShown] = useState(PAGE_SIZE);
  return {
    visible: items.slice(0, shown),
    shown,
    showMore: () => setShown((s) => Math.min(s + PAGE_SIZE, items.length)),
    showAll: () => setShown(items.length),
  };
}

// ---------------------------------------------------------- vulnerabilities

function VulnRow({ entry, reconciledFix }: { entry: Indexed<Vulnerability>; reconciledFix?: string | null }) {
  const v = entry.item;
  const anchor = findingAnchorId("vuln", entry.idx);
  return (
    <div className={`finding sev-${v.severity}`} id={anchor}>
      <p className="finding-title"><span className={`pill ${v.severity}`}>{v.severity}</span><b>{v.id}</b> - {v.packageName} {v.installedVersion ?? ""}</p>
      <p>{v.plainEnglish}</p>
      <p className="small finding-actions">
        <a className="github-link" href={osvAdvisoryUrl(v.id)} target="_blank" rel="noreferrer">View advisory on OSV.dev</a>
        <a href={`#${anchor}`}>Link to this finding</a>
        <CopyLinkButton anchor={anchor} label={`vulnerability ${entry.idx + 1}`} />
      </p>
      <p className="fix"><b>Fix:</b> {reconciledFix ?? v.upgrade}</p>
    </div>
  );
}

export function VulnerabilitiesList({ vulnerabilities }: { vulnerabilities: Vulnerability[] }) {
  const [groupBy, setGroupBy] = useState<"none" | "advisory" | "package">("none");
  const [sevFilter, setSevFilter] = useState("all");
  const [query, setQuery] = useState("");
  const indexed = useMemo(() => withIndex(vulnerabilities), [vulnerabilities]);
  const filtered = useMemo(
    () =>
      indexed.filter(
        ({ item: v }) =>
          (sevFilter === "all" || v.severity === sevFilter) &&
          (query === "" || v.id.toLowerCase().includes(query.toLowerCase()) || v.packageName.toLowerCase().includes(query.toLowerCase())),
      ),
    [indexed, sevFilter, query],
  );
  const groups = useMemo(() => {
    if (groupBy === "none") return [];
    const keyOf = groupBy === "advisory" ? (v: Vulnerability) => v.id : (v: Vulnerability) => v.packageName;
    const map = new Map<string, Indexed<Vulnerability>[]>();
    for (const entry of filtered) {
      const k = keyOf(entry.item);
      const arr = map.get(k) ?? [];
      arr.push(entry);
      map.set(k, arr);
    }
    return [...map.entries()]
      .map(([key, items]) => ({ key, items }))
      .sort((a, b) => b.items.length - a.items.length || a.key.localeCompare(b.key));
  }, [filtered, groupBy]);
  // Phase 15 finding 15: one recommended version per package, so four
  // advisories for the same installed version never tell the user to
  // upgrade to four different versions.
  const reconciled = useMemo(() => recommendedFixVersions(vulnerabilities), [vulnerabilities]);
  const fixFor = (v: Vulnerability): string | null => {
    if (!v.fixedVersion) return null;
    const rec = reconciled.get(`${v.packageName}@${v.installedVersion ?? ""}`);
    if (!rec) return null;
    return `Upgrade ${v.packageName} to ${rec.recommended} or later - this covers all ${rec.advisoryCount} advisories for this version.`;
  };
  const renderVuln = (entry: Indexed<Vulnerability>) => <VulnRow key={`${entry.item.id}-${entry.item.packageName}-${entry.idx}`} entry={entry} reconciledFix={fixFor(entry.item)} />;
  return (
    <div>
      <div className="filters">
        <label>
          Group by
          <select value={groupBy} onChange={(e) => setGroupBy(e.target.value as "none" | "advisory" | "package")} aria-label="Group vulnerabilities by">
            <option value="none">No grouping</option>
            <option value="advisory">Advisory</option>
            <option value="package">Package</option>
          </select>
        </label>
        <SeveritySelect value={sevFilter} onChange={setSevFilter} />
        <label>
          Advisory / package
          <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by advisory or package…" aria-label="Filter by advisory or package" />
        </label>
      </div>
      <p className="small" aria-live="polite">
        Showing {filtered.length} of {vulnerabilities.length} vulnerabilities.
      </p>
      {groupBy === "none" ? (
        <Paged items={filtered} renderItem={renderVuln} />
      ) : (
        groups.map((g) => (
          <details key={g.key} className="group" open={filtered.length <= GROUP_OPEN_BELOW}>
            <summary>
              <span className="chevron" aria-hidden="true">▸</span>
              {g.key} <span className="count-badge">({g.items.length} finding{g.items.length === 1 ? "" : "s"})</span>
            </summary>
            <div className="group-body">
              <Paged items={g.items} renderItem={renderVuln} />
            </div>
          </details>
        ))
      )}
    </div>
  );
}

// ----------------------------------------------------------- dependencies

export function DependenciesList({ dependencies }: { dependencies: Dependency[] }) {
  const [ecoFilter, setEcoFilter] = useState("all");
  const [directFilter, setDirectFilter] = useState("all");
  const [query, setQuery] = useState("");
  const ecosystems = useMemo(() => [...new Set(dependencies.map((d) => d.ecosystem))].sort(), [dependencies]);
  const indexed = useMemo(() => withIndex(dependencies), [dependencies]);
  const filtered = useMemo(
    () =>
      indexed.filter(
        ({ item: d }) =>
          (ecoFilter === "all" || d.ecosystem === ecoFilter) &&
          (directFilter === "all" || (directFilter === "direct") === d.direct) &&
          (query === "" || d.name.toLowerCase().includes(query.toLowerCase())),
      ),
    [indexed, ecoFilter, directFilter, query],
  );
  const { visible, shown, showMore, showAll } = usePagedSimple(filtered);
  return (
    <div>
      <div className="filters">
        <label>
          Ecosystem
          <select value={ecoFilter} onChange={(e) => setEcoFilter(e.target.value)} aria-label="Filter by ecosystem">
            <option value="all">All ecosystems</option>
            {ecosystems.map((e) => (
              <option key={e} value={e}>{e}</option>
            ))}
          </select>
        </label>
        <label>
          Direct / transitive
          <select value={directFilter} onChange={(e) => setDirectFilter(e.target.value)} aria-label="Filter by direct or transitive">
            <option value="all">All dependencies</option>
            <option value="direct">Direct only</option>
            <option value="transitive">Transitive only</option>
          </select>
        </label>
        <label>
          Name
          <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by name…" aria-label="Filter by dependency name" />
        </label>
      </div>
      <p className="small" aria-live="polite">
        Showing {filtered.length} of {dependencies.length} dependencies.
      </p>
      {/* Phase 15 finding 2 (real-DT follow-up): same as FrameworksList -
        a dependency name/version can be a 40-char SHA with no break
        opportunity. */}
      <ul className="report-list">
        {visible.map(({ item: d, idx }) => (
          <li key={`${d.ecosystem}-${d.name}-${d.sourceFile}-${idx}`} id={findingAnchorId("dep", idx)}>
            <b>{d.name}</b> {d.version ?? "(no version)"} · {d.ecosystem} · {d.direct ? "direct" : "transitive"} · <code className="inline">{d.sourceFile}</code>{" "}
            <CopyLinkButton anchor={findingAnchorId("dep", idx)} label={`dependency ${idx + 1}`} />
          </li>
        ))}
      </ul>
      <Pager total={filtered.length} shown={shown} onMore={showMore} onAll={showAll} />
    </div>
  );
}

// ---------------------------------------------------------------- posture

function PostureRow({ entry }: { entry: Indexed<PostureIssue> }) {
  const p = entry.item;
  const anchor = findingAnchorId("posture", entry.idx);
  return (
    <div className={`finding sev-${p.severity}`} id={anchor}>
      <p className="finding-title"><span className={`pill ${p.severity}`}>{p.severity}</span><b>{p.title}</b></p>
      <p>{p.detail}</p>
      <p className="small finding-actions">
        <a href={`#${anchor}`}>Link to this finding</a>
        <CopyLinkButton anchor={anchor} label={`posture issue ${entry.idx + 1}`} />
      </p>
      <p className="fix"><b>Fix:</b> {p.fix}</p>
    </div>
  );
}

export function PostureList({ posture }: { posture: PostureIssue[] }) {
  const [groupBy, setGroupBy] = useState<"none" | "title" | "severity">("none");
  const [sevFilter, setSevFilter] = useState("all");
  const [query, setQuery] = useState("");
  const indexed = useMemo(() => withIndex(posture), [posture]);
  const filtered = useMemo(
    () =>
      indexed.filter(
        ({ item: p }) =>
          (sevFilter === "all" || p.severity === sevFilter) &&
          (query === "" || p.title.toLowerCase().includes(query.toLowerCase()) || p.detail.toLowerCase().includes(query.toLowerCase())),
      ),
    [indexed, sevFilter, query],
  );
  const groups = useMemo(() => {
    if (groupBy === "none") return [];
    const keyOf = groupBy === "title" ? (p: PostureIssue) => p.title : (p: PostureIssue) => p.severity;
    const map = new Map<string, Indexed<PostureIssue>[]>();
    for (const entry of filtered) {
      const k = keyOf(entry.item);
      const arr = map.get(k) ?? [];
      arr.push(entry);
      map.set(k, arr);
    }
    return [...map.entries()]
      .map(([key, items]) => ({ key, items }))
      .sort((a, b) => b.items.length - a.items.length || a.key.localeCompare(b.key));
  }, [filtered, groupBy]);
  return (
    <div>
      <div className="filters">
        <label>
          Group by
          <select value={groupBy} onChange={(e) => setGroupBy(e.target.value as "none" | "title" | "severity")} aria-label="Group posture issues by">
            <option value="none">No grouping</option>
            <option value="title">Issue</option>
            <option value="severity">Severity</option>
          </select>
        </label>
        <SeveritySelect value={sevFilter} onChange={setSevFilter} />
        <label>
          Search
          <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by title or detail…" aria-label="Filter posture issues" />
        </label>
      </div>
      <p className="small" aria-live="polite">
        Showing {filtered.length} of {posture.length} posture issues.
      </p>
      {groupBy === "none" ? (
        <Paged items={filtered} renderItem={(entry) => <PostureRow key={`${entry.item.id}-${entry.idx}`} entry={entry} />} />
      ) : (
        groups.map((g) => (
          <details key={g.key} className="group" open={filtered.length <= GROUP_OPEN_BELOW}>
            <summary>
              <span className="chevron" aria-hidden="true">▸</span>
              {g.key} <span className="count-badge">({g.items.length} finding{g.items.length === 1 ? "" : "s"})</span>
            </summary>
            <div className="group-body">
              <Paged items={g.items} renderItem={(entry) => <PostureRow key={`${entry.item.id}-${entry.idx}`} entry={entry} />} />
            </div>
          </details>
        ))
      )}
    </div>
  );
}
