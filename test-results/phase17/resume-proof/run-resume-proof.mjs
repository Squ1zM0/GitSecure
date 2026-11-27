// Resume-proof harness — GitSecure Phase 17, Part 1 (Worker D).
//
// Demonstrates the Phase 9 accumulation hole with real numbers, and
// re-runs after the fix to prove it closed.
//
// THE HOLE (see src/lib/chunks.ts): runScanLoop() accumulates
// historyFindings in-process and passes them to advanceScan() at
// assemble time. GET /api/scan/[owner]/[repo] and MCP resume_scan call
// runScanLoop() fresh on every invocation with no historyFindings, so
// every history finding from an earlier invocation is dropped from
// the finished report. Only POST /api/scan/chunk callers carry the
// accumulation (the browser driver: POST /api/scan/start, then
// POST /api/scan/chunk, keeping head + historyFindings in
// sessionStorage — see src/lib/resume.ts and
// src/app/[owner]/[repo]/page.tsx).
//
// WHAT IT DOES — two full scans of the same repo against the same
// server, then a diff of the secret-finding sets:
//
//   Path A ("chunk", the accumulating path):
//     POST /api/scan/start {owner, repo}            — one HEAD chunk
//     POST /api/scan/chunk {cursor, head,
//                           historyFindings}        — one history chunk
//       per call, appending that call's chunkFindings to the
//       accumulated set, until {status:"done", report}.
//     This mirrors the browser driver exactly.
//
//   Path B ("get", the resume path):
//     GET /api/scan/{owner}/{repo}                  — 200 report, or
//     202 {cursor, ...} and then GET ...?cursor=... per resume, fresh
//     every time, carrying nothing between calls — exactly what the
//     route does server-side (it passes only the cursor to
//     runScanLoop; the 202 body does not even contain the accumulated
//     findings for a caller to carry).
//
// FINDING IDENTITY (per the task): file + line + type + redacted
// fragment — never a full secret value. The harness records the
// commit (short sha) alongside each finding for traceability and
// also reports a commit-qualified count, because the server's own
// dedupe (dedupeSecrets in src/lib/scan.ts) keys on
// type:file:line:fragment:commit. The primary diff is on the
// task's identity; the commit-qualified diff is reported alongside
// so a same-secret-at-many-commits case cannot hide loss.
//
// EXIT CODE: 0 when the two finding sets match (hole closed, or a
// vacuous match — see evidence.md for which), 1 when they differ
// (hole demonstrated: the diff lists exactly which findings the GET
// path lost), 2 on harness error (no report, headSha mismatch
// because the repo moved mid-scan, HTTP failure after retries).
//
// USAGE:
//   node test-results/phase17/resume-proof/run-resume-proof.mjs \
//     --base http://localhost:3100 --repo vinta/awesome-python
//   node test-results/phase17/resume-proof/run-resume-proof.mjs \
//     --base https://git-secure.com --repo vinta/awesome-python \
//     --mode get          # live-site spot check (burns no GitHub
//                         # REST quota on the happy path; history
//                         # runs over the git protocol)
//   --mode diff             # compare only: load both reports from
//                         # --out and write diff.json + summary.json
//                         # (no HTTP calls; used after the two paths
//                         # ran in separate invocations, e.g. with a
//                         # server restart between them for a cold
//                         # cache each)
//
// OUTPUTS (under --out, default test-results/phase17/resume-proof/):
//   chunk-calls.jsonl / get-calls.jsonl  — one JSON object per HTTP
//     call (endpoint, http status, ms, stage, historyScanned,
//     chunkFindings count, cumulative findings)
//   chunk-report.json / get-report.json  — the finished reports
//   chunk-findings.json / get-findings.json — the secret sets
//   diff.json, summary.json
//
// Node built-ins only. No new dependencies. Kept out of the main
// test suite (slow, network-dependent): nothing here is imported by
// scripts/ or tests/, and package.json has no test glob over
// test-results/.

import fs from "node:fs";
import path from "node:path";

const DEFAULT_OUT = "test-results/phase17/resume-proof";

function parseArgs(argv) {
  const args = {
    base: "http://localhost:3100",
    repo: "vinta/awesome-python",
    mode: "both", // chunk | get | both
    out: DEFAULT_OUT,
    maxCalls: 200,
    maxHistoryChunks: 0, // 0 = no cap (probe mode sets e.g. 2)
    callTimeoutMs: 180_000, // local `next start` does not enforce the 60 s Vercel ceiling, so a slow cold chunk can legitimately run past 120 s (trufflehog's first history chunk did)
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const take = (name) => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`missing value for ${name}`);
      return v;
    };
    if (a === "--base") args.base = take(a).replace(/\/$/, "");
    else if (a === "--repo") args.repo = take(a);
    else if (a === "--mode") args.mode = take(a);
    else if (a === "--out") args.out = take(a);
    else if (a === "--max-calls") args.maxCalls = Number(take(a));
    else if (a === "--max-history-chunks") args.maxHistoryChunks = Number(take(a));
    else if (a === "--call-timeout-ms") args.callTimeoutMs = Number(take(a));
    else throw new Error(`unknown argument: ${a}`);
  }
  if (!["chunk", "get", "both", "diff"].includes(args.mode)) throw new Error(`--mode must be chunk|get|both|diff, got ${args.mode}`);
  const [owner, repo] = args.repo.split("/");
  if (!owner || !repo || args.repo.split("/").length !== 2) throw new Error(`--repo must be owner/repo, got ${args.repo}`);
  args.owner = owner;
  args.repoName = repo;
  return args;
}

// --- finding identity -------------------------------------------------------

function identity(f) {
  return `${f.type}|${f.file}|${f.line}|${f.fragment}`;
}
function commitQualified(f) {
  return `${identity(f)}|${f.commit ?? ""}`;
}
function shortSha(c) {
  return typeof c === "string" && c.length >= 7 ? c.slice(0, 7) : String(c ?? "");
}
function dedupeByCommitQualified(findings) {
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    const k = commitQualified(f);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
  }
  return out;
}
function isHistoryFinding(f) {
  return typeof f.commit === "string" && f.commit !== "HEAD" && f.commit !== null;
}

// --- HTTP -------------------------------------------------------------------

async function fetchJson(url, opts, timeoutMs) {
  const res = await fetch(url, { ...opts, signal: AbortSignal.timeout(timeoutMs) });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // Non-JSON body: keep the raw text for the log.
  }
  return { http: res.status, json, text: json === null ? text.slice(0, 500) : undefined };
}

// One retry on HTTP 502/503/504 only. Deliberately NO retry on a
// transport error or client timeout: aborting the client does NOT
// stop the server-side chunk (the walk keeps running in the server
// process), so retrying just starts a second chunk alongside the
// first and doubles the load. Observed 2026-11-26: after several
// timed-out probes the server sat at ~111% CPU with 33 CPU-minutes
// of abandoned walks still grinding, and later probes timed out
// against that backlog.
async function fetchJsonRetried(url, opts, timeoutMs, log) {
  try {
    const r = await fetchJson(url, opts, timeoutMs);
    if (r.http >= 502 && r.http <= 504) {
      log(`  retrying ${opts?.method ?? "GET"} ${url} after HTTP ${r.http}`);
      return await fetchJson(url, opts, timeoutMs);
    }
    return r;
  } catch (err) {
    throw err;
  }
}

function cursorStage(cursor) {
  if (!cursor) return null;
  try {
    const d = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
    return { stage: d.stage, histScanned: d.histScanned, histDone: d.histDone, historyMethod: d.historyMethod };
  } catch {
    return { stage: "?undecodable?", histScanned: null, histDone: null, historyMethod: null };
  }
}

// --- Path A: POST /api/scan/start + POST /api/scan/chunk -------------------

async function runChunkPath(args, outDir, log) {
  const calls = [];
  const callLogPath = path.join(outDir, "chunk-calls.jsonl");
  fs.writeFileSync(callLogPath, "");
  const record = (entry) => {
    calls.push(entry);
    fs.appendFileSync(callLogPath, JSON.stringify(entry) + "\n");
    log(
      `  [chunk #${entry.call}] ${entry.endpoint} http=${entry.http} ${entry.ms}ms ` +
        `stage=${entry.stage ?? "-"} scanned=${entry.historyScanned ?? "-"} ` +
        `chunkFindings=${entry.chunkFindings} cumulative=${entry.cumulativeFindings}`,
    );
  };

  const t0 = Date.now();
  let cursor = null;
  let head = null;
  let accumulated = [];
  let historyChunks = 0;

  // Call 1: exactly one HEAD chunk. chunkFindings is [] here by
  // construction; the cursor sits at the history stage.
  let r = await fetchJsonRetried(
    `${args.base}/api/scan/start`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ owner: args.owner, repo: args.repoName }),
    },
    args.callTimeoutMs,
    log,
  );
  const startMs = Date.now() - t0;
  if (r.http !== 200 || !r.json || r.json.status !== "partial") {
    throw new Error(`start call failed: http=${r.http} body=${JSON.stringify(r.json ?? r.text)?.slice(0, 300)}`);
  }
  cursor = r.json.cursor;
  head = r.json.partial?.head ?? null;
  record({
    call: 1, endpoint: "POST /api/scan/start", http: r.http, ms: startMs,
    stage: cursorStage(cursor)?.stage, historyScanned: r.json.partial?.historyScanned ?? 0,
    chunkFindings: (r.json.chunkFindings ?? []).length, cumulativeFindings: 0,
    headSha: head?.headSha ?? null,
  });

  let report = null;
  for (let call = 2; call <= args.maxCalls; call++) {
    if (args.maxHistoryChunks > 0 && historyChunks >= args.maxHistoryChunks) {
      log(`  probe cap reached (${args.maxHistoryChunks} history chunks); stopping without a final report`);
      break;
    }
    const ct0 = Date.now();
    r = await fetchJsonRetried(
      `${args.base}/api/scan/chunk`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cursor, head, historyFindings: accumulated }),
      },
      args.callTimeoutMs,
      log,
    );
    const ms = Date.now() - ct0;
    if (r.http !== 200 || !r.json) {
      throw new Error(`chunk call ${call} failed: http=${r.http} body=${JSON.stringify(r.json ?? r.text)?.slice(0, 300)}`);
    }
    if (r.json.status === "done") {
      report = r.json.report;
      record({
        call, endpoint: "POST /api/scan/chunk (assemble)", http: r.http, ms,
        stage: "done", historyScanned: report?.counts?.historyCommitsScanned ?? null,
        chunkFindings: 0, cumulativeFindings: accumulated.length,
        headSha: report?.commit ?? null,
      });
      break;
    }
    if (r.json.status !== "partial") {
      throw new Error(`chunk call ${call}: unexpected status ${JSON.stringify(r.json)?.slice(0, 300)}`);
    }
    historyChunks++;
    const fresh = r.json.chunkFindings ?? [];
    accumulated = dedupeByCommitQualified([...accumulated, ...fresh]);
    cursor = r.json.cursor;
    if (r.json.partial?.head) head = r.json.partial.head;
    record({
      call, endpoint: "POST /api/scan/chunk", http: r.http, ms,
      stage: cursorStage(cursor)?.stage, historyScanned: r.json.partial?.historyScanned ?? null,
      chunkFindings: fresh.length, cumulativeFindings: accumulated.length,
      headSha: head?.headSha ?? null,
    });
  }
  if (!report && args.maxHistoryChunks === 0) {
    throw new Error(`chunk path did not finish within ${args.maxCalls} calls`);
  }
  return {
    path: "chunk",
    wallMs: Date.now() - t0,
    calls: calls.length,
    historyChunks,
    report,
    accumulated,
    headSha: report?.commit ?? head?.headSha ?? null,
    probeOnly: args.maxHistoryChunks > 0,
  };
}

// --- Path B: GET /api/scan/[owner]/[repo] (?cursor= resumes) ---------------

async function runGetPath(args, outDir, log) {
  const calls = [];
  const callLogPath = path.join(outDir, "get-calls.jsonl");
  fs.writeFileSync(callLogPath, "");
  const record = (entry) => {
    calls.push(entry);
    fs.appendFileSync(callLogPath, JSON.stringify(entry) + "\n");
    log(
      `  [get #${entry.call}] GET /api/scan/... http=${entry.http} ${entry.ms}ms ` +
        `status=${entry.status} scanned=${entry.historyScanned ?? "-"} ` +
        `cursorStage=${entry.stage ?? "-"} bodyHasHistoryFindings=${entry.bodyHasHistoryFindings}`,
    );
  };

  const t0 = Date.now();
  let cursor = null;
  let report = null;
  for (let call = 1; call <= args.maxCalls; call++) {
    const url = cursor
      ? `${args.base}/api/scan/${args.owner}/${args.repoName}?cursor=${encodeURIComponent(cursor)}`
      : `${args.base}/api/scan/${args.owner}/${args.repoName}`;
    const ct0 = Date.now();
    const r = await fetchJsonRetried(url, {}, args.callTimeoutMs, log);
    const ms = Date.now() - ct0;
    if (!r.json) {
      throw new Error(`GET call ${call} failed: http=${r.http} body=${String(r.text ?? "").slice(0, 300)}`);
    }
    if (r.http === 200 && r.json.kind === "full") {
      report = r.json;
      record({
        call, endpoint: "GET /api/scan/[owner]/[repo]", http: r.http, ms,
        status: "done", historyScanned: report?.counts?.historyCommitsScanned ?? null,
        stage: "done", bodyHasHistoryFindings: false, headSha: report?.commit ?? null,
      });
      break;
    }
    if (r.http === 202 && r.json.status === "running") {
      // The 202 body carries cursor/partial/progress/note — and NO
      // historyFindings. Record that explicitly: it is the mechanism
      // by which a GET-only caller cannot carry accumulation even if
      // it wanted to.
      const next = r.json.cursor;
      record({
        call, endpoint: "GET /api/scan/[owner]/[repo]", http: r.http, ms,
        status: "running", historyScanned: r.json.progress?.commitsScanned ?? r.json.partial?.historyScanned ?? null,
        stage: cursorStage(next)?.stage, bodyHasHistoryFindings: "historyFindings" in r.json,
        headSha: r.json.partial?.headSha ?? null,
      });
      cursor = next;
      continue;
    }
    throw new Error(`GET call ${call}: unexpected http=${r.http} body=${JSON.stringify(r.json)?.slice(0, 300)}`);
  }
  if (!report) throw new Error(`GET path did not finish within ${args.maxCalls} calls`);
  return {
    path: "get",
    wallMs: Date.now() - t0,
    calls: calls.length,
    report,
    findings: report.secrets ?? [],
    headSha: report.commit ?? null,
  };
}

// --- diff -------------------------------------------------------------------

function summariseFindings(findings) {
  return findings.map((f) => ({
    identity: identity(f),
    commitQualified: commitQualified(f),
    type: f.type,
    file: f.file,
    line: f.line,
    fragment: f.fragment,
    commit: shortSha(f.commit),
    commitFull: f.commit,
    triage: f.triage?.verdict ?? null,
  }));
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  fs.mkdirSync(args.out, { recursive: true });
  const log = (s) => {
    console.log(s);
  };
  log(`resume-proof harness — repo ${args.repo} — base ${args.base} — mode ${args.mode}`);
  log(`out: ${args.out}`);

  const startedAt = new Date().toISOString();
  let chunk = null;
  let get = null;

  (async () => {
    try {
      if (args.mode === "chunk" || args.mode === "both") {
        log("Path A (chunk accumulation: POST /api/scan/start + POST /api/scan/chunk) …");
        chunk = await runChunkPath(args, args.out, log);
        if (chunk.report) {
          fs.writeFileSync(path.join(args.out, "chunk-report.json"), JSON.stringify(chunk.report, null, 2));
        }
        fs.writeFileSync(path.join(args.out, "chunk-findings.json"), JSON.stringify(summariseFindings(chunk.accumulated), null, 2));
        log(
          `Path A done: ${chunk.calls} calls, ${chunk.historyChunks} history chunks, ` +
            `${(chunk.wallMs / 1000).toFixed(1)}s wall, ` +
            `${chunk.accumulated.length} accumulated history+HEAD-dedupe findings in hand ` +
            `${chunk.report ? `(final report secrets: ${(chunk.report.secrets ?? []).length})` : "(probe only, no final report)"}`,
        );
      }
      if (args.mode === "get" || args.mode === "both") {
        log("Path B (GET resume: GET /api/scan/[owner]/[repo], fresh each call) …");
        get = await runGetPath(args, args.out, log);
        fs.writeFileSync(path.join(args.out, "get-report.json"), JSON.stringify(get.report, null, 2));
        fs.writeFileSync(path.join(args.out, "get-findings.json"), JSON.stringify(summariseFindings(get.findings), null, 2));
        log(
          `Path B done: ${get.calls} calls, ${(get.wallMs / 1000).toFixed(1)}s wall, ` +
            `final report secrets: ${get.findings.length}`,
        );
      }
    } catch (err) {
      console.error(`HARNESS ERROR: ${err.message}`);
      fs.writeFileSync(path.join(args.out, "summary.json"), JSON.stringify({ startedAt, repo: args.repo, base: args.base, mode: args.mode, error: err.message }, null, 2));
      process.exit(2);
    }

    // --- comparison (only when both paths produced a final report) ---
    // A path run in an earlier invocation can be loaded from disk:
    // this lets the operator restart the server between paths so each
    // path runs against a COLD in-memory history cache (src/lib/
    // history.ts historyCache is module-level and shared by both
    // paths — a warm cache lets the second path finish in far fewer
    // invocations and can mask the hole). Fresh-in-this-run wins
    // over disk; disk is only a fallback.
    if (!chunk?.report) {
      const p = path.join(args.out, "chunk-report.json");
      if (fs.existsSync(p)) {
        const rep = JSON.parse(fs.readFileSync(p, "utf8"));
        let accLen = null;
        const fp = path.join(args.out, "chunk-findings.json");
        if (fs.existsSync(fp)) accLen = JSON.parse(fs.readFileSync(fp, "utf8")).length;
        chunk = { report: rep, accumulated: [], accumulatedLength: accLen, loadedFromDisk: true, path: "chunk" };
        // Keep the earlier run's timing/call counts when they were
        // recorded (a --mode diff re-run would otherwise blank them).
        const sp = path.join(args.out, "summary.json");
        if (fs.existsSync(sp)) {
          try {
            const prev = JSON.parse(fs.readFileSync(sp, "utf8"))?.chunkPath;
            if (prev) { chunk.calls = prev.calls; chunk.historyChunks = prev.historyChunks; chunk.wallMs = prev.wallMs; }
          } catch { /* stale summary is not fatal */ }
        }
        log("Path A report loaded from disk (earlier invocation).");
      }
    }
    if (!get?.report) {
      const p = path.join(args.out, "get-report.json");
      if (fs.existsSync(p)) {
        const rep = JSON.parse(fs.readFileSync(p, "utf8"));
        get = { report: rep, findings: rep.secrets ?? [], loadedFromDisk: true, path: "get" };
        const sp = path.join(args.out, "summary.json");
        if (fs.existsSync(sp)) {
          try {
            const prev = JSON.parse(fs.readFileSync(sp, "utf8"))?.getPath;
            if (prev) { get.calls = prev.calls; get.wallMs = prev.wallMs; }
          } catch { /* stale summary is not fatal */ }
        }
        log("Path B report loaded from disk (earlier invocation).");
      }
    }
    let diff = null;
    let exitCode = 0;
    if (chunk?.report && get?.report) {
      const aSecrets = chunk.report.secrets ?? [];
      const bSecrets = get.report.secrets ?? [];
      const aIds = new Set(aSecrets.map(identity));
      const bIds = new Set(bSecrets.map(identity));
      const aCq = new Set(aSecrets.map(commitQualified));
      const bCq = new Set(bSecrets.map(commitQualified));
      const lostIds = [...aIds].filter((x) => !bIds.has(x));
      const gainedIds = [...bIds].filter((x) => !aIds.has(x));
      const lostCq = [...aCq].filter((x) => !bCq.has(x));
      const gainedCq = [...bCq].filter((x) => !aCq.has(x));
      const byId = new Map(aSecrets.map((f) => [identity(f), f]));
      const lost = lostIds.map((id) => {
        const f = byId.get(id);
        // Every commit carrying this identity in path A (the same
        // secret can sit at the same file+line in many commits).
        const commits = [...new Set(aSecrets.filter((x) => identity(x) === id).map((x) => shortSha(x.commit)))];
        return { identity: id, type: f.type, file: f.file, line: f.line, fragment: f.fragment, commits, historyOnly: isHistoryFinding(f) };
      });
      const headShaMatch = chunk.report.commit === get.report.commit;
      const chunkReport = {
        secrets: aSecrets.length,
        historySecrets: aSecrets.filter(isHistoryFinding).length,
        headSecrets: aSecrets.filter((f) => !isHistoryFinding(f)).length,
        score: chunk.report.score, grade: chunk.report.grade,
        historyCommitsScanned: chunk.report.counts?.historyCommitsScanned ?? null,
        filesScanned: chunk.report.counts?.filesScanned ?? null,
        commit: chunk.report.commit,
      };
      const getReport = {
        secrets: bSecrets.length,
        historySecrets: bSecrets.filter(isHistoryFinding).length,
        headSecrets: bSecrets.filter((f) => !isHistoryFinding(f)).length,
        score: get.report.score, grade: get.report.grade,
        historyCommitsScanned: get.report.counts?.historyCommitsScanned ?? null,
        filesScanned: get.report.counts?.filesScanned ?? null,
        commit: get.report.commit,
      };
      // History-depth check: the two reports must agree on how many
      // history commits were scanned. A mismatch is a second,
      // distinct defect from lost findings — e.g. the in-memory
      // history cache (src/lib/history.ts) can be poisoned by a
      // chunked scan's final chunk, which walks only the last chunk's
      // commits yet caches them as the repo's "complete" history, so
      // a later scan on the same server instance reports only that
      // tail (observed 2026-11-26: awesome-python chunk path scanned
      // 3,350 commits, the GET path run right after on the same
      // server reported 150 — the final chunk's 150).
      const historyDepthMatch =
        chunkReport.historyCommitsScanned === getReport.historyCommitsScanned;
      diff = {
        repo: args.repo,
        chunkReport,
        getReport,
        headShaMatch,
        historyDepthMatch,
        historyDepthNote: historyDepthMatch
          ? "both reports scanned the same number of history commits"
          : `HISTORY DEPTH MISMATCH: chunk path scanned ${chunkReport.historyCommitsScanned} history commits, GET path scanned ${getReport.historyCommitsScanned} — the GET report's history is not the full history (see evidence.md)`,
        identityDiff: { lostCount: lostIds.length, gainedCount: gainedIds.length, lost, gained: gainedIds },
        commitQualifiedDiff: { lostCount: lostCq.length, gainedCount: gainedCq.length, lost: lostCq, gained: gainedCq },
      };
      fs.writeFileSync(path.join(args.out, "diff.json"), JSON.stringify(diff, null, 2));
      log(`DIFF: chunk=${aSecrets.length} secrets (${diff.chunkReport.historySecrets} history) vs get=${bSecrets.length} secrets (${diff.getReport.historySecrets} history)`);
      log(`DIFF: lost on GET path (identity): ${lostIds.length}; gained on GET path: ${gainedIds.length}; commit-qualified lost: ${lostCq.length}`);
      log(`DIFF: history depth chunk=${diff.chunkReport.historyCommitsScanned} vs get=${diff.getReport.historyCommitsScanned} (match=${historyDepthMatch})`);
      if (!headShaMatch) {
        log(`WARNING: headSha differs between paths (chunk ${chunk.report.commit} vs get ${get.report.commit}) — the repo moved mid-run; the diff is not a clean comparison.`);
        exitCode = 2;
      } else if (lostIds.length > 0 || gainedIds.length > 0 || !historyDepthMatch) {
        exitCode = 1;
      } else {
        exitCode = 0;
      }
    }

    if (diff === null) {
      // No comparison was possible (a path produced no final report
      // — e.g. probe mode — or a report file is missing in --mode
      // diff). That is not a match; fail loudly instead of
      // exiting 0 on an absent diff.
      exitCode = 2;
      log("ERROR: no comparison produced — at least one path has no final report in this out dir.");
    }

    const summary = {
      startedAt,
      finishedAt: new Date().toISOString(),
      repo: args.repo,
      base: args.base,
      mode: args.mode,
      chunkPath: chunk ? { calls: chunk.calls ?? null, historyChunks: chunk.historyChunks ?? null, wallMs: chunk.wallMs ?? null, wallSeconds: chunk.wallMs != null ? +(chunk.wallMs / 1000).toFixed(1) : null, accumulatedFindings: chunk.loadedFromDisk ? (chunk.accumulatedLength ?? null) : (chunk.accumulated ? chunk.accumulated.length : null), finalReportSecrets: chunk.report ? (chunk.report.secrets ?? []).length : null, headSha: chunk.headSha ?? chunk.report?.commit ?? null, probeOnly: chunk.probeOnly ?? false, loadedFromDisk: chunk.loadedFromDisk ?? false } : null,
      getPath: get ? { calls: get.calls ?? null, wallMs: get.wallMs ?? null, wallSeconds: get.wallMs != null ? +(get.wallMs / 1000).toFixed(1) : null, finalReportSecrets: get.findings.length, headSha: get.headSha ?? get.report?.commit ?? null, loadedFromDisk: get.loadedFromDisk ?? false } : null,
      diff,
      exitCode,
      verdict:
        exitCode === 0
          ? "MATCH — the two finding sets are identical (hole closed, or vacuous: see evidence.md for whether the repo had any history findings to lose)"
          : exitCode === 1
            ? "DIFFER — the GET resume path lost findings the chunk path kept (hole demonstrated)"
            : "ERROR / INCONCLUSIVE — see error above",
    };
    fs.writeFileSync(path.join(args.out, "summary.json"), JSON.stringify(summary, null, 2));
    log(`VERDICT: ${summary.verdict} (exit ${exitCode})`);
    process.exit(exitCode);
  })();
}

main();
