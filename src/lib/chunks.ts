// Stateless chunked scans (Phase 9) - the replacement for Phase 8's
// in-memory jobs (src/lib/jobs.ts, deleted this phase).
//
// A scan is a sequence of CHUNKS, each one a single serverless
// invocation that does one bounded piece of work and returns a cursor
// (see cursor.ts) for the next piece:
//
//   head     - the current files (scanHead): secrets, frameworks,
//              dependencies, posture. One invocation.
//   history  - history, newest-first, in commit chunks (git protocol:
//              up to 200 commits or ~30 s per chunk; GitHub API: 10
//              commits per chunk). As many invocations as it takes.
//   assemble - merge HEAD + history, run the OSV flaw check, score.
//              Idempotent: safe to retry with the same inputs.
//
// The server holds no scan job between chunks; in-progress findings live in the short-lived store (see scan-state.ts). The caller holds the
// partial results (the browser: sessionStorage, see resume.ts; an API
// caller: its own memory) and passes the accumulated history findings
// back with the assemble call. A server restart, cold start, redeploy,
// or a poll landing on a different instance changes nothing - the next
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
  getScanStateStore,
  scanStateKey,
  SCAN_STATE_TTL_SECONDS,
  type ScanStateStore,
  type StoredScanState,
} from "./scan-state";
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
 *  202 with the cursor (was the job fast-path wait in Phase 8).
 *  Kept for the report page (Worker A, Phase 16). The scan API and
 *  MCP use API_FAST_PATH_WAIT_MS below - same 60 s function ceiling,
 *  tighter budget, see there. */
export const FAST_PATH_WAIT_MS = 50_000;
/** Phase 16 (Worker B - API ceiling-risk audit): the loop budget the
 *  scan API (GET /api/scan/[owner]/[repo]) and MCP pass to
 *  runScanLoop. 40 s, not 50: a chunk that starts just before the
 *  deadline still runs to its own end (its work is deadline-capped
 *  now - see deadlineMs threading below - but its uncapped prefix,
 *  clone + full git.log parse, is not). Measured locally (slow VM,
 *  conservative): the git-history prefix (clone + log parse) is
 *  ~29 s on vinta/awesome-python (11.6 s clone + 17.6 s log parse
 *  for 3,350 commits) and a history chunk totals ~31 s once the
 *  post-walk corpus read is deadline-capped. Worst-case arithmetic
 *  for one invocation, with the start floor in runScanLoop: budget
 *  40 − floor 19 + worst late chunk ~32 = ~53 s, under the ~55 s
 *  headroom below Vercel's 60 s ceiling (cold start ~1–3 s +
 *  response serialisation included). Live evidence the 50 s budget
 *  was too big: the report page took 52.8–63.6 s on
 *  vinta/awesome-python and the stream was cut at 60 s
 *  (test-results/phase16/repro.md). The 202 + cursor contract is
 *  unchanged: a scan that outruns 40 s answers 202 and resumes. */
export const API_FAST_PATH_WAIT_MS = 40_000;
/** History commits per chunk on the GitHub API path (10 commits ≈ 11
 *  REST calls - a few chunks fit the unauthenticated quota). */
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
      /** Findings from THIS chunk only - the caller appends them to
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
  /** Phase 16 (Worker B): absolute wall-clock deadline (epoch ms)
   *  for this chunk - the loop's deadline, passed by runScanLoop so
   *  a chunk that starts late stops at the deadline instead of
   *  running a full chunk past it. Unset = no deadline (the chunk
   *  endpoint POST /api/scan/chunk and one-shot callers): every
   *  per-chunk budget below falls back to its old fixed value, so
   *  behaviour there is unchanged. */
  deadlineMs?: number;
  onProgress?: (p: ScanProgress) => void;
}

function headMovedError(): ScanError {
  return new ScanError(
    409,
    "head-moved",
    "The repo changed while the scan was running (new commits landed). Start a fresh scan for the new HEAD - the saved progress belongs to the previous HEAD.",
  );
}

/** Phase 15 (finding 1 - torvalds/linux failed outright): a fetch
 *  timeout inside the HEAD chunk must NOT throw. The tarball download
 *  for a huge repo can stall past its budget after the repo meta is
 *  already known, and throwing there lands the user on a terminal
 *  error page with no resume path - exactly the dead-end Phase 9 was
 *  built to remove. Instead the HEAD chunk returns a partial result
 *  with a cursor still at the "head" stage, so ScanProgress mounts,
 *  the live progress (files scanned before the stall, if any) is
 *  kept, and the next chunk retries the HEAD chunk from its cursor.
 *  The cursor format, chunk API shapes, and scoring are unchanged:
 *  a head-stage cursor is a normal cursor the driver already
 *  understands, and the retry re-runs scanHead from scratch - the
 *  timed-out attempt scanned files but kept no partial HEAD, so
 *  there is nothing half-reported to carry forward. When the timeout
 *  hits before the HEAD meta is known (the repo-info fetch itself
 *  stalled) there is no sha to pin a cursor to, so it still throws -
 *  nothing was scanned yet, and the page-level error state offers a
 *  "Retry this scan" button for exactly that case. */
async function headChunkOrTimeoutPartial(
  owner: string,
  repo: string,
  onProgress?: (p: ScanProgress) => void,
  deadlineMs?: number,
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
      deadlineMs,
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
        ? `The current-files download timed out after ${scanned.toLocaleString("en-US")} file${scanned === 1 ? "" : "s"} - this chunk stopped before finishing. Nothing was half-reported; the scan picks up from the start of the current-files step.`
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

/** A HEAD partial is usable for assemble only when it carries the
 *  shape assembleReport reads: the identity fields matching the
 *  cursor, plus the four arrays it spreads and counts. The client
 *  carries the head through sessionStorage and the POST body, so a
 *  stale, partial, or older-build saved head can arrive without
 *  them - and assembleReport then threw a raw TypeError on the first
 *  missing array, which the chunk route answered as a 500 at the
 *  dependencies step (live TechDirect failure, 2026-11-27). A bad
 *  head is never trusted here: it is re-derived server-side with a
 *  fresh scanHead, exactly like an absent head, so the scan finishes
 *  instead of 500ing. */
export function isUsableHead(head: unknown, cursor: ScanCursorData): head is HeadPartial {
  if (typeof head !== "object" || head === null) return false;
  const h = head as Record<string, unknown>;
  if (h.owner !== cursor.owner || h.repo !== cursor.repo || h.branch !== cursor.branch || h.headSha !== cursor.headSha) return false;
  if (!Array.isArray(h.secrets) || !Array.isArray(h.frameworks) || !Array.isArray(h.dependencies) || !Array.isArray(h.posture)) return false;
  if (typeof h.filesScanned !== "number" || !Number.isFinite(h.filesScanned)) return false;
  if (typeof h.filesTotal !== "number" || !Number.isFinite(h.filesTotal)) return false;
  if (typeof h.unpinnedCount !== "number" || !Number.isFinite(h.unpinnedCount)) return false;
  if (typeof h.treeTruncated !== "boolean" || typeof h.tarballFallback !== "boolean" || typeof h.retainedIncomplete !== "boolean") return false;
  if (h.historyMethod !== "git" && h.historyMethod !== "api") return false;
  return true;
}

/** Run exactly one chunk. Throws ScanError (plain English, honest HTTP
 *  status) for bad cursors, missing/private repos, rate limits, and a
 *  HEAD that moved mid-scan - never a crash, never a stack trace. */
export async function advanceScan(input: AdvanceInput): Promise<AdvanceResult> {
  const { owner, repo } = input;
  validateOwnerRepo(owner, repo);

  // --- HEAD chunk (fresh scan, or a cursor that still says "head"). ---
  if (input.cursor === null) {
    const outcome = await headChunkOrTimeoutPartial(owner, repo, input.onProgress, input.deadlineMs);
    if ("partial" in outcome) return outcome.partial;
    const head = outcome.head;
    const cursor = initialHistoryCursor(head);
    const partial = partialFrom(cursor, head, null);
    return { status: "partial", cursor: encodeCursor(cursor), partial, chunkFindings: [], progress: partial.progress, note: null };
  }

  const cursor = decodeCursor(input.cursor, owner, repo);
  if (cursor.stage === "head") {
    const outcome = await headChunkOrTimeoutPartial(owner, repo, input.onProgress, input.deadlineMs);
    if ("partial" in outcome) return outcome.partial;
    const head = outcome.head;
    const next = initialHistoryCursor(head);
    const partial = partialFrom(next, head, null);
    return { status: "partial", cursor: encodeCursor(next), partial, chunkFindings: [], progress: partial.progress, note: null };
  }

  // --- ASSEMBLE chunk: merge HEAD + accumulated history, OSV, score. ---
  if (cursor.stage === "assemble") {
    let head = input.head ?? null;
    if (!isUsableHead(head, cursor)) {
      head = await scanHead(owner, repo, { deadlineMs: input.deadlineMs });
    }
    if (head.owner !== cursor.owner || head.repo !== cursor.repo || head.branch !== cursor.branch || head.headSha !== cursor.headSha) {
      throw new ScanError(
        400,
        "bad-format",
        "That scan's saved progress doesn't match this repo - it may be from a different scan. Starting a fresh scan instead.",
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
    const remainingAtAssemble = input.deadlineMs != null ? input.deadlineMs - Date.now() : null;
    const report = await assembleReport(
      head,
      {
        findings,
        commitsScanned: cursor.histScanned,
        ok: cursor.histDone && cursor.histStop === null,
        method: cursor.historyMethod,
        note: cursor.histNote,
      },
      {
        onProgress: (p) => input.onProgress?.(p),
        // Phase 16: OSV is the assemble step's only long pole (no
        // budget by default). Cap both OSV phases at the time left
        // to the loop deadline so assemble returns a report - with
        // the honest "not checked" limits lines when the budget
        // binds - instead of the function being killed mid-assemble.
        // No deadline (the chunk endpoint) keeps the unbounded
        // default, so its behaviour is unchanged.
        deadlineMs: input.deadlineMs,
        ...(remainingAtAssemble != null
          ? { osv: { queryBudgetMs: Math.max(0, remainingAtAssemble), detailBudgetMs: Math.max(0, remainingAtAssemble) } }
          : {}),
      },
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
      // Phase 16: the walk budget is the smaller of the chunk's own
      // 30 s and the time left to the loop deadline - a history chunk
      // that starts with 8 s left stops its walk at 8 s instead of
      // running a full 30 s past the deadline. (The clone + log-parse
      // prefix sits outside the walk budget; the clone aborts at the
      // deadline via deadlineMs, and the log parse is the documented
      // residual - see the API_FAST_PATH_WAIT_MS comment.)
      budgetMs:
        input.deadlineMs != null
          ? Math.min(GIT_HISTORY_CHUNK_BUDGET_MS, Math.max(0, input.deadlineMs - Date.now()))
          : GIT_HISTORY_CHUNK_BUDGET_MS,
      deadlineMs: input.deadlineMs,
      progressBase: cursor.histScanned,
      onProgress: (n) => input.onProgress?.({ ...progressFor(partialFrom(cursor, headForPartial, note)), commitsScanned: n }),
    });
    if (!result.ok) {
      if (result.headMoved) throw headMovedError();
      // The git path failed outright (clone error, network): fall back
      // to the API path for this chunk instead of failing the scan -
      // the cursor records the switch, and the report says which path
      // was used. If the API path also fails, that error stands.
      const apiChunk = await scanHistoryApiChunk(
        owner, repo, cursor.branch,
        { page: cursor.histPage, idx: cursor.histIdx, pageShas: cursor.histPageShas },
        Math.min(chunkCommits, API_HISTORY_CHUNK_COMMITS),
        { apiBase: input.apiBase, expectedHeadSha: cursor.headSha, deadlineMs: input.deadlineMs },
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
      { apiBase: input.apiBase, expectedHeadSha: cursor.headSha, deadlineMs: input.deadlineMs },
    );
    return apiChunkResult(cursor, apiChunk, headForPartial, "api");
  }

  const partial = partialFrom(next, headForPartial, note);
  return { status: "partial", cursor: encodeCursor(next), partial, chunkFindings, progress: partial.progress, note };
}

/** Shared tail of a history chunk that came from the API path: build
 *  the next cursor and the partial. `fallbackFrom` names the method the
 *  scan started with (the report's history line uses the API method
 *  either way - the path that produced the findings is what matters). */
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

/** Phase 17 - the honest limits line. Fires on a finished report
 *  when a scan resumed from a cursor that had already walked
 *  `commits` history commits, but the findings from those commits
 *  could not be recovered - no store provisioned, stored state
 *  expired or corrupt, or a store operation failed - and the caller
 *  passed no historyFindings of its own. The history count in the
 *  report is how far the scan walked, not how many findings
 *  survived; this line says so instead of letting the report
 *  silently claim a clean history. Worded as a possibility ("may
 *  be missing"): when the walked commits held no secrets, nothing
 *  was lost - the line only records that the scan cannot prove it.
 *  The public "never stored" promise (mcp.ts, README, page.tsx,
 *  layout.tsx) was updated when the store was provisioned on 2026-11-27
 *  (see test-results/phase17/copy-after-provisioning.md): in-progress
 *  findings now live in the short-lived store; finished reports are
 *  still never stored. */
export function historyFindingsMissingLine(commits: number): string {
  return `History findings from earlier parts of this scan could not be recovered, so this report may be missing secrets from the first ${commits} commit${commits === 1 ? "" : "s"} checked - the history count above is how far the scan walked, not how many findings survived.`;
}

/** Drive chunks until the scan finishes or the wall-clock budget runs
 *  out. Returns the finished report, or the cursor + partial results
 *  so far (the caller resumes with advanceScan). `cursor` resumes an
 *  in-progress scan; `head` / `historyFindings` are the caller's
 *  accumulated results, passed back at assemble time.
 *
 *  Phase 16 (Worker B): the old loop checked the deadline only
 *  AFTER each chunk returned, so a chunk that started at 49 s of a
 *  50 s budget ran a full chunk past it - a git history chunk alone
 *  measures ~31–40 s on vinta/awesome-python, which is how live
 *  invocations reached 52.8–63.6 s and got cut at Vercel's 60 s
 *  ceiling. Two changes close it: (1) the loop's deadline is passed
 *  into every chunk as deadlineMs, so each chunk's own budgets are
 *  capped at the time left (walk budget, API fetches, tarball
 *  stream, OSV phases, clone abort); (2) the loop does not START
 *  another chunk unless enough budget is left that the chunk can
 *  still land the invocation under ~55 s. A late chunk costs at
 *  most ~32 s (its uncapped prefix - clone + git.log parse, ~29 s
 *  measured worst locally - or its 30 s walk budget, plus ~2 s
 *  unwind), so the start floor is budget − 21 s (55 − 32 − 2 margin)
 *  and the invocation ends by budget − floor + 32 = ~53 s for any
 *  budget; small budgets get no floor (a 10 s loop has nothing to
 *  protect: 10 + 32 = 42 s). At the production 40 s budget the
 *  floor is 19 s - TechDirect reaches assemble with ~22 s left, so
 *  it still answers 200 in one call. The first chunk always runs:
 *  a fresh scan must produce a cursor. */
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
    /** Phase 17: the short-lived scan-state store (see
     *  scan-state.ts). Defaults to getScanStateStore() - NoopStore
     *  when no store env vars are set. Test-only override, like
     *  apiBase / cloneUrlOverride. advanceScan is NOT wired: the
     *  POST-chunk caller already carries its own accumulation. */
    store?: ScanStateStore;
  } = {},
): Promise<LoopResult> {
  validateOwnerRepo(owner, repo);
  const budgetMs = opts.budgetMs ?? FAST_PATH_WAIT_MS;
  const deadline = Date.now() + budgetMs;
  // Phase 16: the start floor - see the doc comment above. A chunk
  // started with less than this left could still cost ~32 s and push
  // the invocation past ~55 s, so with a cursor already in hand the
  // loop answers 202 here instead of starting it.
  const startFloorMs = Math.max(0, budgetMs - 21_000);
  let cursor: string | null = opts.cursor ?? null;
  let head: HeadPartial | null = opts.head ?? null;
  let historyFindings: SecretFinding[] = [...(opts.historyFindings ?? [])];
  let lastPartial: Extract<AdvanceResult, { status: "partial" }> | null = null;
  // --- Phase 17: short-lived scan state (see scan-state.ts). ---
  // The store is touched at invocation boundaries only: one load
  // at entry (when resuming a scan that already walked history),
  // one save per partial return, one delete at assemble. A store
  // failure never fails the scan - it is caught, recorded, and the
  // loop continues with in-process accumulation; the finished
  // report then carries the honest limits line (below).
  const store = opts.store ?? getScanStateStore();
  let stateHeadSha: string | null = null;
  let findingsMayBeMissing = false;
  let missingCommits = 0;
  const markMissing = (commits: number) => {
    findingsMayBeMissing = true;
    missingCommits = Math.max(missingCommits, commits);
  };
  const saveState = async (histScanned: number, findings: SecretFinding[]): Promise<void> => {
    if (!stateHeadSha || histScanned <= 0) return;
    const state: StoredScanState = { v: 1, headSha: stateHeadSha, histScanned, historyFindings: findings };
    try {
      await store.save(scanStateKey(owner, repo, stateHeadSha), state, SCAN_STATE_TTL_SECONDS);
    } catch {
      // Store write failed: the next invocation cannot recover
      // these findings. The scan continues; the finished report
      // says so (markMissing), instead of silently dropping them.
      markMissing(histScanned);
    }
  };
  if (cursor) {
    const entryCursor = decodeCursor(cursor, owner, repo);
    stateHeadSha = entryCursor.headSha;
    if (entryCursor.histScanned > 0) {
      let stored: StoredScanState | null = null;
      try {
        stored = await store.load(scanStateKey(owner, repo, entryCursor.headSha));
      } catch {
        stored = null;
      }
      if (stored && stored.headSha === entryCursor.headSha) {
        // Recovered: seed the in-process accumulation with the
        // stored findings, deduped against anything the caller
        // passed (caller-carried fallback). A stored count ahead of
        // the cursor means a newer invocation already wrote - take
        // the stored array; a stored count behind means stale - the
        // walk re-finds those findings and dedupes them.
        historyFindings = dedupeSecrets([...stored.historyFindings, ...historyFindings]);
      } else if (historyFindings.length === 0) {
        // Nothing to recover from (store unconfigured, state
        // expired/corrupt, head mismatch, or the load failed) and
        // the caller carried nothing either: findings from the
        // first entryCursor.histScanned commits may be gone.
        markMissing(entryCursor.histScanned);
      }
    }
  }
  for (;;) {
    // A chunk started with almost no budget left would still pay its
    // uncapped prefix (clone + log parse) past the deadline. With a
    // cursor already in hand, answer 202 here instead of starting it.
    // EXCEPTION - the assemble stage is exempt from the floor: assemble
    // is bounded and cheap (deadline-capped OSV + scoring, ~seconds),
    // and stopping before it strands the scan across invocations -
    // where GET / MCP callers cannot carry the accumulated history
    // findings back, so the first invocation's history findings would
    // be lost from the finished report. Worst case with the exemption:
    // a history chunk started at ~21 s ends by ~53 s and assemble adds
    // ~4 s, still under the 60 s ceiling.
    let nextStage: string | null = null;
    if (cursor) {
      try {
        nextStage = decodeCursor(cursor, owner, repo).stage;
      } catch {
        nextStage = null;
      }
    }
    if (lastPartial !== null && nextStage !== "assemble" && Date.now() >= deadline - startFloorMs) {
      // Phase 17: invocation boundary - persist the merged
      // accumulation before answering 202 (one write per
      // invocation, not per chunk). Best-effort; a failure is
      // recorded, never thrown.
      await saveState(lastPartial.partial.historyScanned, historyFindings);
      return {
        status: "partial",
        cursor: cursor ?? lastPartial.cursor,
        partial: lastPartial.partial,
        head,
        historyFindings,
        progress: lastPartial.progress,
        note: lastPartial.note,
      };
    }
    const result = await advanceScan({
      owner, repo, cursor, head, historyFindings,
      chunkCommits: opts.chunkCommits,
      apiBase: opts.apiBase,
      cloneUrlOverride: opts.cloneUrlOverride,
      deadlineMs: deadline,
      onProgress: opts.onProgress,
    });
    if (result.status === "done") {
      // Phase 17: the scan finished - delete its state (primary
      // cleanup: a finished scan leaves nothing in the store; a
      // failed delete is harmless, the TTL cleans it in 7 days).
      // Then, if earlier findings could not be recovered, say so
      // on the finished report instead of silently misreporting.
      if (stateHeadSha) {
        try {
          await store.del(scanStateKey(owner, repo, stateHeadSha));
        } catch {
          // Harmless: the 7-day TTL is the backstop.
        }
      }
      if (findingsMayBeMissing) {
        result.report.limits.push(historyFindingsMissingLine(missingCommits));
      }
      return { status: "done", report: result.report };
    }
    lastPartial = result;
    cursor = result.cursor;
    if (result.partial.head) head = result.partial.head;
    if (result.partial.headSha) stateHeadSha = result.partial.headSha;
    if (result.chunkFindings.length > 0) {
      historyFindings = dedupeSecrets([...historyFindings, ...result.chunkFindings]);
    }
    if (Date.now() >= deadline) {
      // Phase 17: invocation boundary - persist the merged
      // accumulation before answering 202 (one write per
      // invocation, not per chunk). Best-effort; a failure is
      // recorded, never thrown.
      await saveState(result.partial.historyScanned, historyFindings);
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
