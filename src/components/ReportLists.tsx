// Phase 5: progressive rendering + real navigation for huge reports.
//
// The API and MCP responses always carry the COMPLETE lists — no caps.
// The human page must stay usable when a list has thousands of entries
// (DefinitelyTyped: 61,814 files, 9,401 dependencies, secrets well over
// 100), so each list renders in chunks of PAGE_SIZE with "Show more" /
// "Show all". That is a rendering chunk, NOT a data cap: the full list
// is in the report, the count shown is the true total, and every entry
// is reachable on the page.
//
// Navigation (added for the DefinitelyTyped case — hundreds to
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
// Phase 11: the triage verdicts become SECTIONS, not just a filter —
// likely-test findings live in their own collapsed "Likely test keys"
// section, genuine leaks in their own open section, uncertain findings
// in their own open section — and the spider map becomes a usage
// graph (finding -> the files that reference it). Redaction unchanged:
// only the redacted fragment ever appears — never a full secret,
// including in graph tooltips and link labels.

"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import type { Dependency, Framework, PostureIssue, SecretFinding, SecretUsage, Severity, TriageVerdict, Vulnerability } from "@/lib/types";
import { findingAnchorId, githubBlobUrl, osvAdvisoryUrl } from "@/lib/links";

// Phase 11: usage annotation (SecretUsage on SecretFinding, see
// src/lib/types.ts). `getUsage` validates the shape — a finding
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

/** A finding with no triage annotation reads as uncertain — it is
 *  never silently counted as a test key or a genuine leak. */
function verdictOf(s: SecretFinding): TriageVerdict | "uncertain" {
  return s.triage?.verdict ?? "uncertain";
}

const PAGE_SIZE = 100;
/** Groups start open only when the filtered list is small; a wall of
 *  thousands starts collapsed so the page is traversable. */
const GROUP_OPEN_BELOW = 50;
/** How many file nodes the SVG map draws (largest files first). */
const MAP_NODES = 24;

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
  // the first page (unless an anchor link forced it open — that state
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
          ? "Uncertain — needs a human check"
          : null;
  const triagePill =
    s.triage?.verdict === "likely-test-key"
      ? "triage-test"
      : s.triage?.verdict === "likely-genuine-leak"
        ? "triage-genuine"
        : "triage-uncertain";
  // The dead-end note in plain English. When the triage explanation
  // already says it (the usual case — the explanation names the
  // dead end), don't repeat the sentence; the pill alone marks it.
  const deadEndNote =
    usage?.deadEnd && !(s.triage?.explanation ?? "").toLowerCase().includes("references")
      ? "Nothing in this repo references this key — a true dead end."
      : null;
  const usageRefs =
    usage && !usage.deadEnd
      ? [
          ...usage.referencedBy.slice(0, 3).map((r) => `${r.file}:${r.line}`),
          ...usage.referencedByTests.slice(0, 3).map((r) => `${r.file}:${r.line} (test)`),
        ]
      : [];
  const usageTotal = (usage?.referencedByTotal ?? 0) + (usage?.referencedByTestsTotal ?? 0);
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
      {usage && !usage.deadEnd && usageTotal > 0 ? (
        <p className="small usage-line">
          Used by: {usageRefs.join(", ")}
          {usageTotal > usageRefs.length ? ` (+${usageTotal - usageRefs.length} more)` : ""}
          {usage.historyOnly ? " — usage checked against the current files only." : ""}
        </p>
      ) : null}
      <p className="small"><code className="inline">{s.file}:{s.line}</code> · commit <code className="inline">{s.commit ?? "HEAD"}</code> · fragment <code className="inline">{s.fragment}</code> (redacted — never the full secret)</p>
      <p className="small finding-actions">
        <a className="github-link" href={blob} target="_blank" rel="noreferrer">View on GitHub — {s.file}, line {s.line}</a>
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
 *  only the file path and count — never a secret fragment.
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
        Map of files holding secrets — node size is the finding count. Showing the {top.length} largest of {byFile.length} files with secrets. Click a file to filter the list to it.
      </p>
      <p className="map-legend" aria-label="Map legend">
        <span><b>●</b> Centre — this repo</span>
        <span><b>●</b> Bigger node — more findings in that file</span>
        <span>Every node is keyboard reachable: Tab to it, Enter to filter</span>
      </p>
      <div className="map-wrap">
        <svg viewBox="0 0 400 300" role="group" aria-label="Map of files holding secrets">
          <circle className="map-centre" cx={cx} cy={cy} r={34} />
          <text className="map-centre-text" x={cx} y={cy + 4} textAnchor="middle" fontSize={10} fontWeight={700}>This repo</text>
          {top.map((f, i) => {
            const { x, y } = nodePos(i, top.length);
            const r = 9 + Math.min(15, Math.sqrt(f.count) * 2.2);
            const label = baseName(f.file).slice(0, 14);
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
                aria-label={`${f.file}, ${f.count} findings — filter the list to this file`}
              >
                <title>{`${f.file} — ${f.count} finding${f.count === 1 ? "" : "s"}`}</title>
                <line x1={cx} y1={cy} x2={x} y2={y} stroke="#9ecdb2" strokeWidth={1.5} />
                <circle cx={x} cy={y} r={r} />
                <text x={x} y={y - r - 4} textAnchor="middle">{label}</text>
                <text x={x} y={y + r + 12} textAnchor="middle" fontWeight={700}>{f.count}</text>
              </g>
            );
          })}
        </svg>
      </div>
      <p>
        {byFile.slice(0, filesShown).map((f) => (
          <button key={f.file} type="button" className="secondary file-chip" title={`${f.file} — ${f.count} findings`} onClick={() => onSelectFile(f.file)}>
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

/** How many finding nodes the usage map draws (most-used first). A
 *  rendering cap, NOT a data cap — every finding stays in the list. */
const MAP_FINDINGS = 12;

/** Phase 11 usage graph. Repo node at the centre, finding nodes on an
 *  inner ring, file nodes on an outer ring, EDGES from each finding to
 *  the files that reference it (solid = non-test code, dashed = test
 *  code) plus a thin edge to the file the finding itself lives in.
 *  Click a finding node to highlight its track (finding -> the files
 *  that use it -> the finding's own file, one hop each way); click a
 *  file node to filter the list to it. Dead-end findings are greyed,
 *  labelled "dead end", and have no outgoing edges. When no finding
 *  carries `usage` (older report), this falls back to the Phase 5
 *  file-count spider unchanged. */
export function UsageMap({
  findings,
  byFile,
  onSelectFile,
  onShowFinding,
}: {
  findings: Indexed<SecretFinding>[];
  byFile: { file: string; count: number }[];
  onSelectFile: (file: string) => void;
  onShowFinding?: (idx: number) => void;
}) {
  const [selected, setSelected] = useState<number | null>(null);
  useEffect(() => {
    setSelected(null);
  }, [findings]);
  const hasUsage = findings.some(({ item }) => getUsage(item) !== undefined);
  if (!hasUsage) return <FileMap byFile={byFile} onSelectFile={onSelectFile} />;

  const baseName = (file: string) => file.split("/").pop() ?? file;
  // Most-used findings first so the tracks worth following are the
  // ones drawn; dead ends still appear (greyed) when there is room.
  const usageOf = (e: Indexed<SecretFinding>) => getUsage(e.item);
  const drawn = [...findings]
    .sort((a, b) => {
      const ua = usageOf(a);
      const ub = usageOf(b);
      const ta = ua && !ua.deadEnd ? ua.referencedByTotal + ua.referencedByTestsTotal : -1;
      const tb = ub && !ub.deadEnd ? ub.referencedByTotal + ub.referencedByTestsTotal : -1;
      return tb - ta || a.idx - b.idx;
    })
    .slice(0, MAP_FINDINGS);
  // File nodes: every file a drawn finding is used from, then the
  // largest files by finding count, capped at MAP_NODES.
  const refFiles = new Set<string>();
  for (const e of drawn) {
    const u = usageOf(e);
    if (!u || u.deadEnd) continue;
    for (const r of [...u.referencedBy, ...u.referencedByTests]) refFiles.add(r.file);
    refFiles.add(e.item.file);
  }
  const fileNodes = [
    ...[...refFiles].map((file) => ({ file, count: byFile.find((f) => f.file === file)?.count ?? 0 })),
    ...byFile.filter((f) => !refFiles.has(f.file)),
  ].slice(0, MAP_NODES);

  const cx = 200;
  const cy = 170;
  const findingRadius = 82;
  const fileRadius = 138;
  const nodePos = (i: number, n: number, radius: number) => {
    const angle = (2 * Math.PI * i) / Math.max(n, 1) - Math.PI / 2;
    return { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
  };
  const filePos = new Map<string, { x: number; y: number }>();
  fileNodes.forEach((f, i) => filePos.set(f.file, nodePos(i, fileNodes.length, fileRadius)));
  const findingPos = new Map<number, { x: number; y: number }>();
  drawn.forEach((e, i) => findingPos.set(e.idx, nodePos(i, drawn.length, findingRadius)));

  type Edge = { key: string; findingIdx: number; from: { x: number; y: number }; to: { x: number; y: number }; kind: "code" | "test" | "own" };
  const edges: Edge[] = [];
  for (const e of drawn) {
    const u = usageOf(e);
    const fp = findingPos.get(e.idx);
    if (!fp || !u || u.deadEnd) continue;
    const own = filePos.get(e.item.file);
    if (own) edges.push({ key: `own-${e.idx}`, findingIdx: e.idx, from: fp, to: own, kind: "own" });
    for (const r of u.referencedBy) {
      const to = filePos.get(r.file);
      if (to) edges.push({ key: `code-${e.idx}-${r.file}-${r.line}`, findingIdx: e.idx, from: fp, to, kind: "code" });
    }
    for (const r of u.referencedByTests) {
      const to = filePos.get(r.file);
      if (to) edges.push({ key: `test-${e.idx}-${r.file}-${r.line}`, findingIdx: e.idx, from: fp, to, kind: "test" });
    }
  }
  const selectedEntry = selected != null ? drawn.find((e) => e.idx === selected) ?? null : null;
  const selectedUsage = selectedEntry ? usageOf(selectedEntry) : null;
  // The track of the selected finding: the files its edges reach.
  const trackFiles = new Set<string>();
  if (selectedEntry) {
    trackFiles.add(selectedEntry.item.file);
    for (const e of edges) if (e.findingIdx === selectedEntry.idx) {
      for (const [file, pos] of filePos) if (pos === e.to) trackFiles.add(file);
    }
  }
  const totalRefs = selectedUsage && !selectedUsage.deadEnd ? selectedUsage.referencedByTotal + selectedUsage.referencedByTestsTotal : 0;

  return (
    <div>
      <p className="small">
        Usage map — follow a secret through the repo. Showing {drawn.length} of {findings.length} findings and {fileNodes.length} files. Click a finding to highlight its track; click a file to filter the list to it.
      </p>
      <p className="map-legend" aria-label="Map legend">
        <span><b>●</b> Centre — this repo</span>
        <span><b>━━</b> Used in non-test code</span>
        <span><b>┄┄</b> Used in tests only</span>
        <span><b>●</b> Grey node — dead end, nothing references it</span>
        <span>Every node is keyboard reachable: Tab to it, Enter to select</span>
      </p>
      <div className="map-wrap">
        <svg viewBox="0 0 400 340" role="group" aria-label="Usage map: secrets and the files that reference them">
          <circle className="map-centre" cx={cx} cy={cy} r={30} />
          <text className="map-centre-text" x={cx} y={cy + 4} textAnchor="middle" fontSize={10} fontWeight={700}>This repo</text>
          {edges.map((e) => (
            <line
              key={e.key}
              x1={e.from.x}
              y1={e.from.y}
              x2={e.to.x}
              y2={e.to.y}
              className={`map-edge map-edge-${e.kind}${selected == null || e.findingIdx === selected ? " map-edge-track" : " map-edge-dim"}`}
            />
          ))}
          {fileNodes.map((f, i) => {
            const { x, y } = nodePos(i, fileNodes.length, fileRadius);
            const r = 9 + Math.min(15, Math.sqrt(Math.max(f.count, 1)) * 2.2);
            const dimmed = selected != null && !trackFiles.has(f.file);
            return (
              <g
                key={f.file}
                className={`map-node${dimmed ? " map-dim" : ""}`}
                onClick={() => onSelectFile(f.file)}
                onKeyDown={(ev) => {
                  if (ev.key === "Enter" || ev.key === " ") {
                    ev.preventDefault();
                    onSelectFile(f.file);
                  }
                }}
                tabIndex={0}
                role="button"
                aria-label={`${f.file}, ${f.count} findings — filter the list to this file`}
              >
                <title>{`${f.file} — ${f.count} finding${f.count === 1 ? "" : "s"}`}</title>
                <circle className="map-hit" cx={x} cy={y} r={24} />
                <circle cx={x} cy={y} r={r} />
                <text x={x} y={y - r - 4} textAnchor="middle">{baseName(f.file).slice(0, 14)}</text>
                <text x={x} y={y + r + 12} textAnchor="middle" fontWeight={700}>{f.count}</text>
              </g>
            );
          })}
          {drawn.map((e) => {
            const { x, y } = findingPos.get(e.idx) ?? { x: cx, y: cy };
            const u = usageOf(e);
            const dead = u?.deadEnd === true;
            const refs = u && !dead ? u.referencedByTotal + u.referencedByTestsTotal : 0;
            const isSelected = selected === e.idx;
            const dimmed = selected != null && !isSelected;
            const label = `secret ${e.idx + 1}`;
            return (
              <g
                key={e.idx}
                className={`map-node map-finding-node${dead ? " map-finding-deadend" : ""}${isSelected ? " map-node-selected" : ""}${dimmed ? " map-dim" : ""}`}
                onClick={() => setSelected(isSelected ? null : e.idx)}
                onKeyDown={(ev) => {
                  if (ev.key === "Enter" || ev.key === " ") {
                    ev.preventDefault();
                    setSelected(isSelected ? null : e.idx);
                  }
                }}
                tabIndex={0}
                role="button"
                aria-label={
                  dead
                    ? `${label}, ${e.item.title}, ${e.item.file} line ${e.item.line} — dead end, nothing references it`
                    : u
                      ? `${label}, ${e.item.title}, ${e.item.file} line ${e.item.line} — used by ${refs} reference${refs === 1 ? "" : "s"}`
                      : `${label}, ${e.item.title}, ${e.item.file} line ${e.item.line} — no usage data`
                }
              >
                <title>{`${label} — ${e.item.file}:${e.item.line}${dead ? " — dead end" : u ? ` — ${refs} reference${refs === 1 ? "" : "s"}` : " — no usage data"}`}</title>
                <circle className="map-hit" cx={x} cy={y} r={24} />
                <circle cx={x} cy={y} r={11} />
                <text x={x} y={y + 3} textAnchor="middle" fontWeight={700}>{`S${e.idx + 1}`}</text>
                <text x={x} y={y + 23} textAnchor="middle">{dead ? "dead end" : u ? `${refs} use${refs === 1 ? "" : "s"}` : ""}</text>
              </g>
            );
          })}
        </svg>
      </div>
      <div className="map-track-detail" aria-live="polite">
        {selectedEntry && selectedUsage ? (
          <>
            <p>
              <b>Secret {selectedEntry.idx + 1} — {selectedEntry.item.title}</b> · <code className="inline">{selectedEntry.item.file}:{selectedEntry.item.line}</code>
              {selectedUsage.deadEnd ? (
                <> · <span className="pill dead-end">Dead end</span> Nothing in this repo references this key — a true dead end{selectedUsage.historyOnly ? " (usage checked against the current files only)" : ""}.</>
              ) : totalRefs === 0 ? (
                <> · No references recorded.</>
              ) : (
                <>
                  {" "}· Used by: {selectedUsage.referencedBy.slice(0, 10).map((r) => `${r.file}:${r.line}`).join(", ")}
                  {selectedUsage.referencedByTests.length > 0 ? `; in tests: ${selectedUsage.referencedByTests.slice(0, 10).map((r) => `${r.file}:${r.line}`).join(", ")}` : ""}
                  {totalRefs > 10 ? ` (+${totalRefs - 10} more)` : ""}
                  {selectedUsage.historyOnly ? " (usage checked against the current files only)" : ""}
                </>
              )}
            </p>
            {onShowFinding ? (
              <p>
                <button type="button" className="secondary" onClick={() => onShowFinding(selectedEntry.idx)}>Show this finding in the list</button>
              </p>
            ) : null}
          </>
        ) : (
          <p className="small">Click a finding node to follow its track — the secret, the files that use it, and the file it lives in.</p>
        )}
      </div>
    </div>
  );
}

export function SecretsList({ secrets, owner, repo, branch, defaultTestSectionOpen = false }: { secrets: SecretFinding[]; owner: string; repo: string; branch: string; defaultTestSectionOpen?: boolean }) {
  const [groupBy, setGroupBy] = useState<"none" | "type" | "file">("none");
  const [typeFilter, setTypeFilter] = useState("all");
  const [sevFilter, setSevFilter] = useState("all");
  const [triageFilter, setTriageFilter] = useState("all");
  const [fileQuery, setFileQuery] = useState("");
  const [view, setView] = useState<"list" | "map">("list");
  // Phase 11 verdict sections. Genuine leaks and uncertain findings
  // are open by default — they are the ones that need a human. Likely
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
        {testKeyCount > 0 ? ` Of the ${secrets.length} secrets, ${testKeyCount} look${testKeyCount === 1 ? "s" : ""} like test keys — still listed and still counted, with a test-key fix instead of "rotate it".` : ""}
        {genuineCount > 0 || uncertainCount > 0 ? ` ${genuineCount} look${genuineCount === 1 ? "s" : ""} like genuine leaks, ${uncertainCount} uncertain.` : ""}
      </p>
      {view === "map" ? (
        <UsageMap findings={filtered} byFile={byFile} onSelectFile={selectFile} onShowFinding={showFinding} />
      ) : (
        <>
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
                Uncertain — needs a human check <span className="count-badge">({uncertainEntries.length} finding{uncertainEntries.length === 1 ? "" : "s"})</span>
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
              <p className="small">These look like intentional test keys. They are still listed and still counted in the score — expand to check each one and its test-key fix.</p>
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
      <ul>
        {visible.map((f, i) => (
          <li key={`${f.name}-${f.sourceFile}-${i}`}>
            <b>{f.name}</b> — {f.version ?? "version could not be determined"} ({f.versionSource})
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

function VulnRow({ entry }: { entry: Indexed<Vulnerability> }) {
  const v = entry.item;
  const anchor = findingAnchorId("vuln", entry.idx);
  return (
    <div className={`finding sev-${v.severity}`} id={anchor}>
      <p className="finding-title"><span className={`pill ${v.severity}`}>{v.severity}</span><b>{v.id}</b> — {v.packageName} {v.installedVersion ?? ""}</p>
      <p>{v.plainEnglish}</p>
      <p className="small finding-actions">
        <a className="github-link" href={osvAdvisoryUrl(v.id)} target="_blank" rel="noreferrer">View advisory on OSV.dev</a>
        <a href={`#${anchor}`}>Link to this finding</a>
        <CopyLinkButton anchor={anchor} label={`vulnerability ${entry.idx + 1}`} />
      </p>
      <p className="fix"><b>Fix:</b> {v.upgrade}</p>
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
        <Paged items={filtered} renderItem={(entry) => <VulnRow key={`${entry.item.id}-${entry.item.packageName}-${entry.idx}`} entry={entry} />} />
      ) : (
        groups.map((g) => (
          <details key={g.key} className="group" open={filtered.length <= GROUP_OPEN_BELOW}>
            <summary>
              <span className="chevron" aria-hidden="true">▸</span>
              {g.key} <span className="count-badge">({g.items.length} finding{g.items.length === 1 ? "" : "s"})</span>
            </summary>
            <div className="group-body">
              <Paged items={g.items} renderItem={(entry) => <VulnRow key={`${entry.item.id}-${entry.item.packageName}-${entry.idx}`} entry={entry} />} />
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
      <ul>
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
