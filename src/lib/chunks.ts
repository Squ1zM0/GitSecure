// Stateless chunked scans (Phase 9) — the replacement for Phase 8's
// in-memory jobs (src/lib/jobs.ts, deleted this phase).
//
// A scan is a sequence of CHUNKS, each one a single serverless
// invocation that does one bounded piece of work and returns a cursor
// (see cursor.ts) for the next piece:
//
//   head     — the current files (scanHead): secrets, frameworks,
//              dependencies, posture. One invocation.
//   history  — history, newest-first, in commit chunks (git protocol:
//              up to 200 commits or ~30 s per chunk; GitHub API: 10
//              commits per chunk). As many invocations as it takes.
//   assemble — merge HEAD + history, run the OSV flaw check, score.
//              Idempotent: safe to retry with the same inputs.
//
// The server holds NO state between chunks. The caller holds the
// partial results (the browser: sessionStorage, see resume.ts; an API
// caller: its own memory) and passes the accumulated history findings
// back with the assemble call. A server restart, cold start, redeploy,
// or a poll landing on a different instance changes nothing — the next
// chunk simply continues from the cursor. There is no job to lose, so
// the Phase 8 dead-end cannot happen: the worst case is one chunk
// retried from its cursor.
//
// runScanLoop drives chunks in-process until the scan finishes or a
// wall-clock budget runs out (the fast path the API / report page /
// MCP use: small repos still answer in one request). advanceScan runs
// exactly one chunk (the resumable endpoint POST /api/scan/chunk).

import { decodeCursor, encodeCursor, initialHistoryCursor, type ScanCursorData } from "./cursor";
import { emptyProgress, type ScanProgress } from "./progress";
import { scanHistoryApiChunk, scanHistoryViaGit, rateLimitNote } from "./history";
import {
  assembleReport,
  dedupeSecrets,
  fetchHeadSha,
  scanHead,
  scanHistoryPatchFallback,
  ScanError,
  validateOwnerRepo,
} from "./scan";
import type { FullReport, HeadPartial, SecretFinding } from "./types";

/** Fast-path wait: how long one request drives chunks before answering
 *  202 with the cursor (was the job fast-path wait in Phase 8). */
export const FAST_PATH_WAIT_MS = 50_000;
/** History commits per chunk on the GitHub API path (10 commits ≈ 11
 *  REST calls — a few chunks fit the unauthenticated quota). */
export const API_HISTORY_CHUNK_COMMITS = 10;
/** History commits per chunk on the git-protocol path. */
export const GIT_HISTORY_CHUNK_COMMITS = 200;
/** Wall-clock budget for one git-protocol history chunk. */
export const GIT_HISTORY_CHUNK_BUDGET_MS = 30_000;

export interface ScanPartial {
  owner: string;
  repo: string;
  branch: string;
  headSha: string;
  /** Null until the HEAD chunk has run. */
  head: HeadPartial | null;
  /** History commits scanned so far, newest-first. */
  historyScanned: number;
  /** True once every history commit has been walked. */
  historyComplete: boolean;
  /** Why history stopped early, if it did. */
  historyStopped: "rate-limit" | "truncated" | null;
  progress: ScanProgress;
  note: string | null;
}

export type AdvanceResult =
  | {
      status: "partial";
      cursor: string;
      partial: ScanPartial;
      /** Findings from THIS chunk only — the caller appends them to
       *  its accumulated history findings. */
      chunkFindings: SecretFinding[];
      progress: ScanProgress;
      note: string | null;
    }
  | { status: "done"; report: FullReport };

export interface AdvanceInput {
  owner: string;
  repo: string;
  /** Null to start a fresh scan; otherwise the cursor to continue from. */
  cursor: string | null;
  /** HEAD partial the caller already holds (browser sessionStorage).
   *  Only needed at assemble time; re-derived server-side when absent. */
  head?: HeadPartial | null;
  /** History findings accumulated so far. Only needed at assemble time. */
  historyFindings?: SecretFinding[];
  /** History chunk size override (tests use 1). */
  chunkCommits?: number;
  /** Test-only: mock GitHub API base for the API history path. */
  apiBase?: string;
  /** Test-only: smart-HTTP URL for the git history path. */
  cloneUrlOverride?: string;
  onProgress?: (p: ScanProgress) => void;
}

function headMovedError(): ScanError {
  return new ScanError(
    409,
    "head-moved",
    "The repo changed while the scan was running (new commits landed). Start a fresh scan for the new HEAD — the saved progress belongs to the previous HEAD.",
  );
}

/** Phase 15 (finding 1 — torvalds/linux failed outright): a fetch
 *  timeout inside the HEAD chunk must NOT throw. The tarball download
 *  for a huge repo can stall past its budget after the repo meta is
 *  already known, and throwing there lands the user on a terminal
 *  error page with no resume path — exactly the dead-end Phase 9 was
 *  built to remove. Instead the HEAD chunk returns a partial result
 *  with a cursor still at the "head" stage, so ScanProgress mounts,
 *  the live progress (files scanned before the stall, if any) is
 *  kept, and the next chunk retries the HEAD chunk from its cursor.
 *  The cursor format, chunk API shapes, and scoring are unchanged:
 *  a head-stage cursor is a normal cursor the driver already
 *  understands, and the retry re-runs scanHead from scratch — the
 *  timed-out attempt scanned files but kept no partial HEAD, so
 *  there is nothing half-reported to carry forward. When the timeout
 *  hits before the HEAD meta is known (the repo-info fetch itself
 *  stalled) there is no sha to pin a cursor to, so it still throws —
 *  nothing was scanned yet, and the page-level error state offers a
 *  "Retry this scan" button for exactly that case. */
async function headChunkOrTimeoutPartial(
  owner: string,
  repo: string,
  onProgress?: (p: ScanProgress) => void,
): Promise<
  | { head: HeadPartial }
  | { partial: AdvanceResult & { status: "partial" } }
> {
  let lastProgress: ScanProgress = emptyProgress();
  // A holder object, not a bare `let`: TypeScript narrows a `let`
  // assigned only inside a closure to its initializer (`null`), so
  // the timeout branch below would see `never`. A property read is
  // never narrowed that way.
  const headMetaRef: { current: { branch: string; headSha: string; historyMethod: "git" | "api" } | null } = { current: null };
  try {
    const head = await scanHead(owner, repo, {
      onProgress: (p) => {
        lastProgress = p;
        onProgress?.(p);
      },
      onHeadMeta: (meta) => {
        headMetaRef.current = meta;
      },
    });
    return { head };
  } catch (err) {
    if (!(err instanceof ScanError) || err.kind !== "timeout" || headMetaRef.current === null) throw err;
    const meta = headMetaRef.current;
    const scanned = lastProgress.filesScanned;
    const note =
      scanned > 0
        ? `The current-files download timed out after ${scanned.toLocaleString("en-US")} file${scanned === 1 ? "" : "s"} — this chunk stopped before finishing. Nothing was half-reported; the scan picks up from the start of the current-files step.`
        : "The current-files download timed out, so this chunk stopped before finishing. Nothing was half-reported; the scan picks up from the start of the current-files step.";
    const cursorData: ScanCursorData = {
      v: 1,
      owner,
      repo,
      branch: meta.branch,
      headSha: meta.headSha,
      stage: "head",
      historyMethod: meta.historyMethod,
      histScanned: 0,
      histResumeAfter: null,
      histPage: 1,
      histIdx: 0,
      histPageShas: [],
      histDone: false,
      histStop: null,
      histNote: null,
    };
    const partial = partialFrom(cursorData, null, note);
    partial.progress = lastProgress;
    const result: AdvanceResult & { status: "partial" } = {
      status: "partial",
      cursor: encodeCursor(cursorData),
      partial,
      chunkFindings: [],
      progress: lastProgress,
      note,
    };
    return { partial: result };
  }
}

function progressFor(partial: ScanPartial): ScanProgress {
  const p: ScanProgress = {
    step: partial.head ? (partial.historyComplete ? "dependencies" : "history") : "files",
    filesScanned: partial.head?.filesScanned ?? 0,
    filesTotal: partial.head?.filesTotal ?? 0,
    commitsScanned: partial.historyScanned,
    depsChecked: 0,
    depsTotal: 0,
    advisoriesDetailed: 0,
    advisoriesTotal: 0,
  };
  return p;
}

function partialFrom(
  cursor: ScanCursorData,
  head: HeadPartial | null,
  note: string | null,
): ScanPartial {
  const partial: ScanPartial = {
    owner: cursor.owner,
    repo: cursor.repo,
    branch: cursor.branch,
    headSha: cursor.headSha,
    head,
    historyScanned: cursor.histScanned,
    historyComplete: cursor.histDone,
    historyStopped: cursor.histStop,
    progress: emptyProgress(),
    note,
  };
  partial.progress = progressFor(partial);
  return partial;
}

/** Run exactly one chunk. Throws ScanError (plain English, honest HTTP
 *  status) for bad cursors, missing/private repos, rate limits, and a
 *  HEAD that moved mid-scan — never a crash, never a stack trace. */
export async function advanceScan(input: AdvanceInput): Promise<AdvanceResult> {
  const { owner, repo } = input;
  validateOwnerRepo(owner, repo);

  // --- HEAD chunk (fresh scan, or a cursor that still says "head"). ---
  if (input.cursor === null) {
    const outcome = await headChunkOrTimeoutPartial(owner, repo, input.onProgress);
    if ("partial" in outcome) return outcome.partial;
    const head = outcome.head;
    const cursor = initialHistoryCursor(head);
    const partial = partialFrom(cursor, head, null);
    return { status: "partial", cursor: encodeCursor(cursor), partial, chunkFindings: [], progress: partial.progress, note: null };
  }

  const cursor = decodeCursor(input.cursor, owner, repo);
  if (cursor.stage === "head") {
    const outcome = await headChunkOrTimeoutPartial(owner, repo, input.onProgress);
    if ("partial" in outcome) return outcome.partial;
    const head = outcome.head;
    const next = initialHistoryCursor(head);
    const partial = partialFrom(next, head, null);
    return { status: "partial", cursor: encodeCursor(next), partial, chunkFindings: [], progress: partial.progress, note: null };
  }

  // --- ASSEMBLE chunk: merge HEAD + accumulated history, OSV, score. ---
  if (cursor.stage === "assemble") {
    let head = input.head ?? null;
    if (!head) {
      head = await scanHead(owner, repo);
    }
    if (head.owner !== cursor.owner || head.repo !== cursor.repo || head.branch !== cursor.branch || head.headSha !== cursor.headSha) {
      throw new ScanError(
        400,
        "bad-format",
        "That scan's saved progress doesn't match this repo — it may be from a different scan. Starting a fresh scan instead.",
      );
    }
    // The repo must not have moved since the scan started: a report
    // for a stale HEAD would be wrong, so a moved HEAD restarts.
    const tip = await fetchHeadSha(owner, repo, cursor.branch);
    if (tip !== cursor.headSha) throw headMovedError();
    const findings = dedupeSecrets(
      (Array.isArray(input.historyFindings) ? input.historyFindings : []).filter(
        (f): f is SecretFinding =>
          typeof f === "object" && f !== null &&
          typeof (f as SecretFinding).type === "string" &&
          typeof (f as SecretFinding).file === "string" &&
          typeof (f as SecretFinding).fragment === "string",
      ),
    );
    const report = await assembleReport(
      head,
      {
        findings,
        commitsScanned: cursor.histScanned,
        ok: cursor.histDone && cursor.histStop === null,
        method: cursor.historyMethod,
        note: cursor.histNote,
      },
      { onProgress: (p) => input.onProgress?.(p) },
    );
    return { status: "done", report };
  }

  // --- HISTORY chunk (stage "history"). ---
  const chunkCommits = input.chunkCommits ?? (cursor.historyMethod === "api" ? API_HISTORY_CHUNK_COMMITS : GIT_HISTORY_CHUNK_COMMITS);
  const headForPartial = input.head ?? null;
  let chunkFindings: SecretFinding[] = [];
  let next: ScanCursorData = { ...cursor };
  let note: string | null = cursor.histNote;

  if (cursor.historyMethod === "git") {
    const result = await scanHistoryViaGit(owner, repo, cursor.branch, {
      cloneUrlOverride: input.cloneUrlOverride,
      headSha: cursor.headSha,
      resumeAfterSha: cursor.histResumeAfter,
      maxCommits: chunkCommits,
      budgetMs: GIT_HISTORY_CHUNK_BUDGET_MS,
      progressBase: cursor.histScanned,
      onProgress: (n) => input.onProgress?.({ ...progressFor(partialFrom(cursor, headForPartial, note)), commitsScanned: n }),
    });
    if (!result.ok) {
      if (result.headMoved) throw headMovedError();
      // The git path failed outright (clone error, network): fall back
      // to the API path for this chunk instead of failing the scan —
      // the cursor records the switch, and the report says which path
      // was used. If the API path also fails, that error stands.
      const apiChunk = await scanHistoryApiChunk(
        owner, repo, cursor.branch,
        { page: cursor.histPage, idx: cursor.histIdx, pageShas: cursor.histPageShas },
        Math.min(chunkCommits, API_HISTORY_CHUNK_COMMITS),
        { apiBase: input.apiBase, expectedHeadSha: cursor.headSha },
      );
      return apiChunkResult(cursor, apiChunk, headForPartial, "git");
    }
    chunkFindings = result.findings;
    // commitsScanned for this chunk is the commits it covered (new
    // walk + any cached suffix). A full cache hit covers commits an
    // earlier chunk may already have counted, so it replaces the
    // total instead of adding to it.
    const histScanned =
      result.commitsFetched === 0 && result.cachedCommits > 0
        ? result.commitsScanned
        : cursor.histScanned + result.commitsScanned;
    const complete = result.complete ?? false;
    const truncated = result.truncated;
    if (truncated) {
      next = {
        ...cursor,
        histScanned,
        histResumeAfter: result.lastScannedSha ?? cursor.histResumeAfter,
        histDone: false,
        histStop: "truncated",
        histNote: result.note,
        stage: "assemble",
      };
      note = result.note;
    } else {
      next = {
        ...cursor,
        histScanned,
        histResumeAfter: result.lastScannedSha ?? cursor.histResumeAfter,
        histDone: complete,
        histStop: null,
        histNote: null,
        stage: complete ? "assemble" : "history",
      };
      note = null;
    }
  } else {
    const apiChunk = await scanHistoryApiChunk(
      owner, repo, cursor.branch,
      { page: cursor.histPage, idx: cursor.histIdx, pageShas: cursor.histPageShas },
      chunkCommits,
      { apiBase: input.apiBase, expectedHeadSha: cursor.headSha },
    );
    return apiChunkResult(cursor, apiChunk, headForPartial, "api");
  }

  const partial = partialFrom(next, headForPartial, note);
  return { status: "partial", cursor: encodeCursor(next), partial, chunkFindings, progress: partial.progress, note };
}

/** Shared tail of a history chunk that came from the API path: build
 *  the next cursor and the partial. `fallbackFrom` names the method the
 *  scan started with (the report's history line uses the API method
 *  either way — the path that produced the findings is what matters). */
function apiChunkResult(
  cursor: ScanCursorData,
  chunk: Awaited<ReturnType<typeof scanHistoryApiChunk>>,
  head: HeadPartial | null,
  _fallbackFrom: "git" | "api",
): AdvanceResult {
  if (chunk.headMoved) throw headMovedError();
  if (chunk.failed) {
    throw new ScanError(502, "upstream", chunk.note ?? "GitHub didn't answer as expected. Try again in a bit.");
  }
  const histScanned = cursor.histScanned + chunk.commitsScanned;
  let histStop: ScanCursorData["histStop"] = null;
  let histNote: string | null = null;
  let stage: ScanCursorData["stage"] = "history";
  if (chunk.rateLimited) {
    histStop = "rate-limit";
    histNote = rateLimitNote(histScanned);
    stage = "assemble"; // history stops here; assemble reports it honestly
  } else if (chunk.done) {
    stage = "assemble";
  }
  if (chunk.skipped > 0) {
    const skipNote = `${chunk.skipped} commit${chunk.skipped === 1 ? "" : "s"} could not be fetched and ${chunk.skipped === 1 ? "was" : "were"} skipped.`;
    histNote = histNote ? `${histNote} ${skipNote}` : skipNote;
  }
  const next: ScanCursorData = {
    ...cursor,
    historyMethod: "api",
    histScanned,
    histPage: chunk.nextPage,
    histIdx: chunk.nextIdx,
    histPageShas: chunk.nextPageShas,
    histDone: chunk.done,
    histStop,
    histNote,
    stage,
  };
  const partial = partialFrom(next, head, histNote);
  return { status: "partial", cursor: encodeCursor(next), partial, chunkFindings: chunk.findings, progress: partial.progress, note: histNote };
}

export interface LoopResult {
  status: "done" | "partial";
  report?: FullReport;
  cursor?: string;
  partial?: ScanPartial;
  head?: HeadPartial | null;
  historyFindings?: SecretFinding[];
  progress?: ScanProgress;
  note?: string | null;
}

/** Drive chunks until the scan finishes or the wall-clock budget runs
 *  out. Returns the finished report, or the cursor + partial results
 *  so far (the caller resumes with advanceScan). `cursor` resumes an
 *  in-progress scan; `head` / `historyFindings` are the caller's
 *  accumulated results, passed back at assemble time. */
export async function runScanLoop(
  owner: string,
  repo: string,
  opts: {
    cursor?: string | null;
    head?: HeadPartial | null;
    historyFindings?: SecretFinding[];
    budgetMs?: number;
    chunkCommits?: number;
    apiBase?: string;
    cloneUrlOverride?: string;
    onProgress?: (p: ScanProgress) => void;
  } = {},
): Promise<LoopResult> {
  validateOwnerRepo(owner, repo);
  const deadline = Date.now() + (opts.budgetMs ?? FAST_PATH_WAIT_MS);
  let cursor: string | null = opts.cursor ?? null;
  let head: HeadPartial | null = opts.head ?? null;
  let historyFindings: SecretFinding[] = [...(opts.historyFindings ?? [])];
  for (;;) {
    const result = await advanceScan({
      owner, repo, cursor, head, historyFindings,
      chunkCommits: opts.chunkCommits,
      apiBase: opts.apiBase,
      cloneUrlOverride: opts.cloneUrlOverride,
      onProgress: opts.onProgress,
    });
    if (result.status === "done") {
      return { status: "done", report: result.report };
    }
    cursor = result.cursor;
    if (result.partial.head) head = result.partial.head;
    if (result.chunkFindings.length > 0) {
      historyFindings = dedupeSecrets([...historyFindings, ...result.chunkFindings]);
    }
    if (Date.now() >= deadline) {
      return {
        status: "partial",
        cursor,
        partial: result.partial,
        head,
        historyFindings,
        progress: result.progress,
        note: result.note,
      };
    }
  }
}

/** Patch fallback for a history stage that failed outright (all paths
 *  down): scan API patches of the most recent commits, as scanRepo
 *  does for a whole-scan history failure. Kept in the driver so a
 *  chunked scan degrades exactly like a one-shot scan. */
export async function historyPatchFallbackForCursor(
  cursor: ScanCursorData,
  count = 5,
): Promise<{ findings: SecretFinding[]; commitsScanned: number }> {
  return scanHistoryPatchFallback(cursor.owner, cursor.repo, cursor.branch, count);
}
