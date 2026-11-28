// Full-history secret scanning (Phase 2).
//
// Strategy: ephemeral `git clone --no-checkout` of the public repo into a
// fresh mkdtemp dir under /tmp, then stream `git log -p --all` (newest
// commit first - that is git log's default order) through the same
// detectors as the HEAD scan, scanning ADDED lines only, with redacted
// fragments only. The clone dir is deleted in a finally block; nothing
// about the repo is stored after the scan.
//
// PHASE 8 (2026-11-25): git-protocol history + per-commit cache.
// The clone path above still works where a git binary exists, and the
// API path below stays as a last-resort fallback - but the primary path
// is now `scanHistoryViaGit`: isomorphic-git (pure JS, no binary, no
// GitHub REST API) clones over the git smart-HTTP protocol
// (github.com, not api.github.com), walks the full log with
// includeChanges, and diffs each commit against its first parent with
// jsdiff, scanning ADDED lines only - exactly like the clone path.
// Merge commits get no diff, matching `git log -p` behaviour.
// Findings are cached per commit SHA (in-memory only, redacted
// fragments only - no secret values are ever stored); a re-scan
// resolves the remote HEAD over the git protocol and, when the tip is
// unchanged, returns the cached findings without re-fetching a single
// commit. When the tip moved, only commits newer than the cached tip
// are walked; older findings come from the cache.
//
// CAPS (Phase 8): the old 1000-commit / 50 MB / 45 s history caps are
// GONE from the clone and git-protocol paths - history runs to the
// oldest commit, patches streamed/diffed one file at a time, never
// buffered whole. The only remaining limit is HISTORY_MEMORY_GUARD_BYTES,
// an emergency memory guard: if it ever trips, the result is
// truncated=true with a note saying exactly which commits were scanned
// and which were not - a partial scan is never presented as complete.
// (The API path keeps its caps: it is the last-resort fallback, and
// its per-commit REST fetches are what the quota limits. MAX_* /
// HISTORY_TIMEOUT_MS stay exported for it and for scan.ts's limits
// copy - they no longer cap the clone or git paths.)
//
// Honesty: if git is unavailable (some serverless runtimes ship no git
// binary) or the clone fails, this returns { ok: false } and the caller
// falls back to the MVP API patch path (5 most recent commits) and says
// so in the report's limits. If the byte/commit/time cap is hit mid-log,
// the findings scanned so far are kept and the report says the history
// scan was truncated at that cap. Public repos only, no auth, no shell:
// git is spawned with an argument array and owner/repo are validated.

import fs from "node:fs";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import git from "isomorphic-git";
import http from "isomorphic-git/http/node";
import { diffLines } from "diff";
import { scanLinesForSecrets, type ScannedLine } from "./secrets";
import { triageFindings, triageHistoryFindings } from "./triage";
import { computeUsageForFindings, type FindingContext } from "./usage";
import { isSkippablePath } from "./paths";
import { COMPARE_WINDOW_MAX_COMMITS, parsePatchAddedLines, resolveCompareBase, scanCompareWindow } from "./compare-windows";
import type { SecretFinding } from "./types";

export const MAX_HISTORY_COMMITS = 1000;
export const MAX_HISTORY_PATCH_BYTES = 50_000_000;
export const HISTORY_TIMEOUT_MS = 45_000;
/** Emergency memory guard ONLY (Phase 8) - see the header. Not a cap
 *  on how much history is scanned; it only stops a pathological repo
 *  from exhausting serverless memory. */
export const HISTORY_MEMORY_GUARD_BYTES = 500_000_000;

/** Phase 15 (worker D): the history-clone size gate is a STREAMING
 *  byte bound on the pack download, not a REST pre-check. The old
 *  gate read the repo's `size` from the GitHub REST API and skipped
 *  the clone paths above 100 MB - that call was the scan's last
 *  REST request on the happy path, so the gate had to go. The gate
 *  exists because isomorphic-git buffers the whole pack in memory
 *  before writing it (`collect(response.packfile)`), so an unbounded
 *  clone OOM-crashes a 1 GB function (measured live: DefinitelyTyped
 *  500s at ~23 s). The bound below is enforced while the pack
 *  streams in (see boundedGitHttp): past it the download is aborted
 *  and the clone fails with PackTooLargeError, and the orchestrator
 *  falls through to the API path, which pages and stops honestly.
 *  This is a physical bound of the runtime, not a scan cap: HEAD is
 *  still scanned in full whatever the repo size. */
export const PACK_MAX_BYTES = 150_000_000;

/** Thrown by the bounded git HTTP client when a pack download passes
 *  its byte bound. Carries the byte count so the caller can say
 *  plainly why the git path gave up. */
export class PackTooLargeError extends Error {
  readonly bytes: number;
  constructor(bytes: number, maxPackBytes: number = PACK_MAX_BYTES) {
    super(`history pack download passed ${maxPackBytes} bytes (${bytes} bytes read) - too large to clone inside a serverless function`);
    this.name = "PackTooLargeError";
    this.bytes = bytes;
  }
}

/** Wrap an isomorphic-git HTTP client so the pack download
 *  (POST .../git-upload-pack) is byte-bounded: chunks are counted as
 *  they stream in, and past the bound the underlying request is
 *  aborted and the iterator throws PackTooLargeError. Every other
 *  request (notably the info/refs GET that resolves the branch and
 *  HEAD) passes through untouched - it is small and needs no bound.
 *  An incoming AbortSignal, when the caller supplies one, is
 *  forwarded to the inner request. */
export function boundedGitHttp(inner: typeof http, maxPackBytes: number = PACK_MAX_BYTES): typeof http {
  return {
    async request(args) {
      const isPack =
        (args.method ?? "GET").toUpperCase() === "POST" &&
        typeof args.url === "string" &&
        args.url.endsWith("/git-upload-pack");
      const controller = new AbortController();
      if (args.signal) {
        if (args.signal.aborted) controller.abort();
        else args.signal.addEventListener("abort", () => controller.abort(), { once: true });
      }
      const res = await inner.request({ ...args, signal: controller.signal });
      if (!isPack || !res.body) return res;
      const body = res.body as AsyncIterable<Uint8Array>;
      let bytes = 0;
      const counted: AsyncIterable<Uint8Array> = {
        async *[Symbol.asyncIterator]() {
          for await (const chunk of body) {
            bytes += chunk.byteLength;
            if (bytes > maxPackBytes) {
              controller.abort();
              throw new PackTooLargeError(bytes, maxPackBytes);
            }
            yield chunk;
          }
        },
      };
      return { ...res, body: counted as unknown as typeof res.body };
    },
  };
}

/** The production git HTTP client: the default isomorphic-git node
 *  client with the pack-download bound applied. */
const boundedHttp = boundedGitHttp(http);
/** One-line plain-English description of the API history path, for the report's limits. */
export const API_HISTORY_NOTE =
  `Full history via the GitHub API (no git binary needed): up to ${MAX_HISTORY_COMMITS} commits / ${MAX_HISTORY_PATCH_BYTES / 1_000_000} MB of patches, ${HISTORY_TIMEOUT_MS / 1000}s cap, newest-first.`;
/** Per-fetch abort timeout, matching scan.ts's ghJson. */
const API_FETCH_TIMEOUT_MS = 12_000;
/** Detail fetches run in a small pool - parallel, never unbounded. */
const API_CONCURRENCY = 5;
/** Added lines buffered per file before a detector pass - bounds memory. */
const CHUNK_LINES = 2000;

export interface HistoryScanResult {
  /** False when git is missing or the clone failed - caller falls back. */
  ok: boolean;
  findings: SecretFinding[];
  /** Total commits this result covers (newly scanned + reused from cache). */
  commitsScanned: number;
  patchBytes: number;
  truncated: boolean;
  timedOut: boolean;
  /** Human-readable reason when ok is false, or truncation note. */
  note: string | null;
  /** Milliseconds the clone + log step took. */
  ms: number;
  /** Which path produced this result - clone (git binary), git-protocol
   *  (isomorphic-git, no binary, no REST quota), or GitHub API. */
  method: "clone" | "api" | "git";
  /** Commits reused from the per-commit cache (Phase 8, git path only). */
  cachedCommits: number;
  /** Commits actually walked/fetched this run (0 on a full cache hit). */
  commitsFetched: number;
  /** api.github.com requests this history call made (0 on the git path). */
  restCalls: number;
  /** Git-protocol remote-info (info/refs) requests made - the HEAD
   *  check. The clone's own pack requests go through isomorphic-git's
   *  HTTP client and are not counted here; they hit github.com, never
   *  the REST API, so they cost zero REST quota either way. */
  gitRequests: number;
  /** Phase 15 (worker D): true when the git path gave up because the
   *  pack download passed PACK_MAX_BYTES. The orchestrator reads it
   *  to say plainly why history went through the API instead. */
  packTooLarge?: boolean;
  /** Phase 9 (git chunked walk only): full sha of the last commit
   *  scanned in this call, or null when nothing was scanned. The next
   *  chunk resumes older than this sha. */
  lastScannedSha?: string | null;
  /** Phase 9: true when the walk reached the oldest commit (or a
   *  cached suffix covering the rest) - the history is complete.
   *  False when a chunk limit or budget stopped the walk early. */
  complete?: boolean;
  /** Phase 9: true when the resume point (`resumeAfterSha`) is no
   *  longer in the log - the repo's history moved since the scan
   *  started, so the scan must restart history cleanly. */
  headMoved?: boolean;
}

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;

function runGit(args: string[], opts: { timeoutMs?: number; cwd?: string }): Promise<{ code: number | null; timedOut: boolean }> {
  return new Promise((resolve) => {
    const child = spawn("git", args, { cwd: opts.cwd, stdio: "ignore" });
    let done = false;
    // No timeout by default (Phase 8): the scan's 55 s route timeout is
    // the backstop for a hung clone. Callers that need a bound pass one.
    const timer = opts.timeoutMs
      ? setTimeout(() => {
          if (done) return;
          done = true;
          child.kill("SIGKILL");
          resolve({ code: null, timedOut: true });
        }, opts.timeoutMs)
      : undefined;
    child.on("error", () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ code: null, timedOut: false });
    });
    child.on("close", (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ code, timedOut: false });
    });
  });
}

async function gitAvailable(): Promise<boolean> {
  const r = await runGit(["--version"], { timeoutMs: 5000 });
  return r.code === 0;
}

/** Stream `git log -p` and scan added lines as they arrive.
 *  Phase 8: no commit / byte / time caps - the stream runs to the
 *  oldest commit. The only stop is the emergency memory guard
 *  (HISTORY_MEMORY_GUARD_BYTES on patch bytes); tripping it sets
 *  truncated=true and the caller names exactly what was not scanned. */
function streamLog(dir: string): Promise<{
  findings: SecretFinding[];
  commitsScanned: number;
  patchBytes: number;
  truncated: boolean;
  timedOut: boolean;
}> {
  return new Promise((resolve) => {
    const findings: SecretFinding[] = [];
    let commitsScanned = 0;
    let patchBytes = 0;
    let truncated = false;
    const timedOut = false;
    let finished = false;

    const child = spawn(
      "git",
      ["-C", dir, "log", "-p", "--all", "--no-color", "--no-textconv", "--no-ext-diff", "--format=__GS_COMMIT__%H"],
      { stdio: ["ignore", "pipe", "ignore"] },
    );

    // --- incremental diff parser state ---
    let buf = ""; // partial line carried across chunks
    let commit: string | null = null;
    let file: string | null = null;
    let fileSkipped = false;
    let newLine = 0;
    let chunk: ScannedLine[] = [];

    const flushChunk = () => {
      if (chunk.length > 0 && file && !fileSkipped) {
        const found = scanLinesForSecrets({ path: file }, chunk, commit);
        // Phase 10: triage from the added lines (path, filename, and
        // nearby-line signals; a PEM block added by the commit is
        // fully present in them).
        triageHistoryFindings(found, file, chunk);
        findings.push(...found);
      }
      chunk = [];
    };

    const handleLine = (rawLine: string) => {
      const line = rawLine.replace(/\r$/, "");
      if (line.startsWith("__GS_COMMIT__")) {
        flushChunk();
        commit = line.slice("__GS_COMMIT__".length).slice(0, 7) || null;
        file = null;
        commitsScanned++;
        return;
      }
      const diffM = /^diff --git a\/(.+?) b\/(.+)$/.exec(line);
      if (diffM) {
        flushChunk();
        file = diffM[2];
        fileSkipped = isSkippablePath(file);
        newLine = 0;
        return;
      }
      if (line.startsWith("+++ ")) {
        const p = line.slice(4).trim();
        const name = p.startsWith("b/") ? p.slice(2) : p;
        if (name !== "/dev/null") {
          flushChunk();
          file = name;
          fileSkipped = isSkippablePath(name);
        }
        return;
      }
      if (line.startsWith("Binary files ")) {
        flushChunk();
        fileSkipped = true;
        return;
      }
      const hunkM = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
      if (hunkM) {
        newLine = parseInt(hunkM[1], 10);
        return;
      }
      if (!file || fileSkipped || commit == null) return;
      if (line.startsWith("+") && !line.startsWith("+++")) {
        chunk.push({ line: newLine, text: line.slice(1) });
        newLine++;
        if (chunk.length >= CHUNK_LINES) flushChunk();
      } else if (line.startsWith(" ")) {
        newLine++;
      }
      // "-" (removed) lines and "\ No newline" do not advance newLine.
    };

    child.stdout.on("data", (data: Buffer) => {
      if (finished) return;
      patchBytes += data.length;
      if (patchBytes > HISTORY_MEMORY_GUARD_BYTES) {
        truncated = true;
        child.kill("SIGKILL");
        return;
      }
      buf += data.toString("utf8");
      let idx: number;
      while ((idx = buf.indexOf("\n")) >= 0) {
        handleLine(buf.slice(0, idx));
        buf = buf.slice(idx + 1);
        if (finished) return;
      }
    });

    const finish = () => {
      if (finished) return;
      finished = true;
      if (buf.length > 0) handleLine(buf);
      flushChunk();
      resolve({ findings, commitsScanned, patchBytes, truncated, timedOut });
    };
    child.on("error", finish);
    child.on("close", finish);
  });
}

export async function scanFullHistory(
  owner: string,
  repo: string,
  branch: string,
  cloneUrlOverride?: string,
): Promise<HistoryScanResult> {
  const started = Date.now();
  const fail = (note: string): HistoryScanResult => ({
    ok: false, findings: [], commitsScanned: 0, patchBytes: 0,
    truncated: false, timedOut: false, note, ms: Date.now() - started, method: "clone",
    cachedCommits: 0, commitsFetched: 0, restCalls: 0, gitRequests: 0,
  });
  if (!NAME_RE.test(owner) || !NAME_RE.test(repo) || owner.includes("..") || repo.includes("..")) {
    return fail("Invalid owner/repo name - history clone skipped.");
  }
  if (!(await gitAvailable())) {
    return fail("No git binary in this runtime - history clone skipped.");
  }
  // cloneUrlOverride exists only so tests can point the clone at a local
  // fixture repo (scripts/test-history.ts). Production callers never pass
  // it: the URL is always the public github.com repo.
  const cloneUrl = cloneUrlOverride ?? `https://github.com/${owner}/${repo}.git`;
  const dir = await mkdtemp(join(tmpdir(), "gitsecure-"));
  try {
    const clone = await runGit(
      ["clone", "--quiet", "--no-checkout", "--single-branch", "--branch", branch, cloneUrl, dir + "/repo"],
      {},
    );
    if (clone.timedOut) return fail("History clone timed out.");
    if (clone.code !== 0) return fail("History clone failed (repo may be too large or unreachable).");
    const repoDir = dir + "/repo";
    const log = await streamLog(repoDir);
    const ms = Date.now() - started;
    let note: string | null = null;
    if (log.timedOut) note = `History scan hit the ${HISTORY_TIMEOUT_MS / 1000}s cap - scanned ${log.commitsScanned} newest commits before stopping.`;
    else if (log.truncated) note = `History scan stopped at the emergency memory guard after scanning ${log.commitsScanned} newest commits - commits older than the last one scanned were not checked, so this report's history is incomplete.`;
    return { ok: true, findings: log.findings, commitsScanned: log.commitsScanned, patchBytes: log.patchBytes, truncated: log.truncated, timedOut: log.timedOut, note, ms, method: "clone", cachedCommits: 0, commitsFetched: log.commitsScanned, restCalls: 0, gitRequests: 0 };
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}

// ---------------------------------------------------------------------------
// API history path (Phase 6). Same guarantees as the clone path, but over
// the GitHub REST API - this is the fallback when the git path fails
// (clone error, pack past the bound, or timeout), not the primary
// path: the git path runs on Vercel too, through isomorphic-git, and
// is tried first. No import from scan.ts here (scan.ts imports this
// module); all fetch / rate-limit handling lives in this file.
//
// Flow: page the commits list (newest-first, 100/page, Link headers) up
// to MAX_HISTORY_COMMITS, then scan it in compare windows of up to 250
// commits (Phase 21, Workstream B): one compare call per window scans
// the window's aggregate diff, and only a window with a hit - or one
// the compare cannot vouch for - falls back to fetching each commit's
// detail in a pool of 5. Either way the ADDED lines of each file's
// patch are scanned with the same detectors, the same skippable-path
// rules, and the same caps (commits / patch bytes / deadline). Findings
// scanned before a cap are kept. Attribution is per-commit: a finding's
// commit is the 7-char sha of the commit whose patch contained it.
//
// Auth: Bearer GITHUB_TOKEN when set (never logged), same headers as
// scan.ts's ghJson. A 429, or a 403 with x-ratelimit-remaining: 0, stops
// the scan gracefully (ok: true, findings so far, plain-English note).
// A 404 is "not found (or private)". Any other per-commit failure skips
// that one commit; only a failed commits LIST fails the whole scan.
// ---------------------------------------------------------------------------

function apiHeaders(): Record<string, string> {
  const headers: Record<string, string> = { Accept: "application/vnd.github+json", "User-Agent": "GitSecure/0.1" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return headers;
}

function isApiRateLimited(res: Response): boolean {
  return res.status === 429 || (res.status === 403 && res.headers.get("x-ratelimit-remaining") === "0");
}

export function rateLimitNote(commitsScanned: number): string {
  return `GitHub API rate limit was hit - scanned ${commitsScanned} commit${commitsScanned === 1 ? "" : "s"} before stopping. Setting a GITHUB_TOKEN raises the limit.`;
}

/** Fetch with a per-request abort timeout (12 s, or the time left to the
 *  deadline, whichever is smaller). Returns null on network failure or
 *  abort - the caller decides whether that fails the scan or just skips
 *  one commit. `stats.restCalls` counts every api.github.com request
 *  this history call makes (Phase 8: proves the git-protocol path,
 *  which never calls this, uses zero REST quota). */
async function apiFetch(url: string, timeoutMs: number, stats: { restCalls: number }): Promise<Response | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(50, Math.min(API_FETCH_TIMEOUT_MS, timeoutMs)));
  stats.restCalls++;
  try {
    return await fetch(url, { headers: apiHeaders(), signal: controller.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function scanHistoryViaApi(
  owner: string,
  repo: string,
  branch: string,
  opts?: { apiBase?: string; deadlineMs?: number },
): Promise<HistoryScanResult> {
  const started = Date.now();
  const timeoutMs = opts?.deadlineMs ?? HISTORY_TIMEOUT_MS;
  const deadline = started + timeoutMs;
  // apiBase exists only so tests can point at a local mock server.
  // Production callers never pass it.
  const apiBase = (opts?.apiBase ?? "https://api.github.com").replace(/\/$/, "");
  const stats = { restCalls: 0 };
  const fail = (note: string): HistoryScanResult => ({
    ok: false, findings: [], commitsScanned: 0, patchBytes: 0,
    truncated: false, timedOut: false, note, ms: Date.now() - started, method: "api",
    cachedCommits: 0, commitsFetched: 0, restCalls: stats.restCalls, gitRequests: 0,
  });
  if (!NAME_RE.test(owner) || !NAME_RE.test(repo) || owner.includes("..") || repo.includes("..")) {
    return fail("Invalid owner/repo name - history API scan skipped.");
  }

  const findings: SecretFinding[] = [];
  let commitsScanned = 0;
  let patchBytes = 0;
  let truncated = false; // byte cap hit while scanning patches
  let listTruncated = false; // more commits exist than the commit cap
  let timedOut = false;
  let rateLimited = false;

  // --- Phase 1: page the commits list, newest-first, up to the cap. ---
  // firstParents[i] is the first parent of shas[i] (null for the root
  // commit, or when the list entry carries no parents) - the compare
  // pre-filter in Phase 2 needs it as the base for a window that runs
  // to the end of the listed history.
  const shas: string[] = [];
  const firstParents: (string | null)[] = [];
  let listUrl: string | null = `${apiBase}/repos/${owner}/${repo}/commits?per_page=100&sha=${encodeURIComponent(branch)}`;
  while (listUrl && shas.length < MAX_HISTORY_COMMITS) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      timedOut = true;
      break;
    }
    const res = await apiFetch(listUrl, remaining, stats);
    if (!res) return fail("GitHub API could not be reached - history API scan skipped.");
    if (res.status === 404) return fail("Repository not found (or it is private).");
    if (isApiRateLimited(res)) {
      return { ok: true, findings, commitsScanned, patchBytes, truncated: false, timedOut: false, note: rateLimitNote(0), ms: Date.now() - started, method: "api", cachedCommits: 0, commitsFetched: commitsScanned, restCalls: stats.restCalls, gitRequests: 0 };
    }
    if (!res.ok) return fail(`GitHub API answered with an unexpected error (${res.status}) - history API scan skipped.`);
    let page: { sha?: string; parents?: { sha?: string }[] }[];
    try {
      page = (await res.json()) as { sha?: string; parents?: { sha?: string }[] }[];
    } catch {
      return fail("GitHub API returned an unreadable response - history API scan skipped.");
    }
    if (!Array.isArray(page)) return fail("GitHub API returned an unexpected response - history API scan skipped.");
    for (const c of page) {
      if (shas.length >= MAX_HISTORY_COMMITS) break;
      if (typeof c.sha === "string" && c.sha) {
        shas.push(c.sha);
        firstParents.push(
          Array.isArray(c.parents) && typeof c.parents[0]?.sha === "string" ? c.parents[0].sha : null,
        );
      }
    }
    const link = res.headers.get("link");
    const next = link ? /<([^>]+)>;\s*rel="next"/.exec(link)?.[1] ?? null : null;
    if (shas.length >= MAX_HISTORY_COMMITS && next) listTruncated = true;
    listUrl = next;
  }

  // --- Phase 2: compare-window pre-filter, then per-commit fetches
  // only where the pre-filter cannot clear the window. ---
  // Windows are newest-first slices of up to COMPARE_WINDOW_MAX_COMMITS
  // (250) SHAs. One compare call covers a whole window's aggregate
  // diff: a clean window costs exactly 1 call and skips the per-commit
  // fetches below. A window with a hit, or one the compare cannot vouch
  // for (no base, truncated diff, diverged range), falls through to the
  // per-commit loop, which attributes each finding to its exact commit -
  // the per-commit fetch is the confirmation step, not the search step.
  // A rate-limited compare stops the scan without advancing, exactly as
  // a rate-limited detail fetch does.
  const scanCommit = async (sha: string): Promise<void> => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      timedOut = true;
      return;
    }
    const res = await apiFetch(`${apiBase}/repos/${owner}/${repo}/commits/${sha}`, remaining, stats);
    if (!res) return; // one bad commit must not fail the whole scan
    if (isApiRateLimited(res)) {
      rateLimited = true;
      return;
    }
    if (!res.ok) return; // skip this commit, keep going
    let detail: { files?: { filename?: string; patch?: string }[] };
    try {
      detail = (await res.json()) as { files?: { filename?: string; patch?: string }[] };
    } catch {
      return;
    }
    commitsScanned++;
    for (const f of detail.files ?? []) {
      if (!f.patch || typeof f.filename !== "string" || isSkippablePath(f.filename)) continue;
      const bytes = Buffer.byteLength(f.patch, "utf8");
      if (patchBytes + bytes > MAX_HISTORY_PATCH_BYTES) {
        truncated = true;
        return;
      }
      patchBytes += bytes;
      const addedLines = parsePatchAddedLines(f.patch);
      const found = scanLinesForSecrets({ path: f.filename }, addedLines, sha.slice(0, 7));
      // Phase 10: triage from the added lines.
      triageHistoryFindings(found, f.filename, addedLines);
      findings.push(...found);
    }
  };

  const scanWindowPerCommit = async (windowShas: string[]): Promise<void> => {
    let nextIdx = 0;
    const worker = async (): Promise<void> => {
      for (;;) {
        if (rateLimited || truncated || timedOut) return;
        if (Date.now() >= deadline) {
          timedOut = true;
          return;
        }
        const idx = nextIdx++;
        if (idx >= windowShas.length) return;
        await scanCommit(windowShas[idx]);
      }
    };
    await Promise.all(Array.from({ length: Math.min(API_CONCURRENCY, windowShas.length) }, () => worker()));
  };

  let windowStart = 0;
  while (windowStart < shas.length) {
    if (rateLimited || truncated || timedOut) break;
    if (Date.now() >= deadline) {
      timedOut = true;
      break;
    }
    const windowShas = shas.slice(windowStart, windowStart + COMPARE_WINDOW_MAX_COMMITS);
    const windowEnd = windowStart + windowShas.length;
    // The compare base is the commit immediately older than the window:
    // the next SHA on the list, or the oldest window commit's first
    // parent when the window runs to the end of the listed history.
    // No base (the window ends at the root commit) means the per-commit
    // fetches - no compare can express the root commit's own diff.
    const nextSha = windowEnd < shas.length ? shas[windowEnd] : null;
    const oldestFirstParent = firstParents[windowEnd - 1] ?? null;
    const baseSha = resolveCompareBase(windowShas, nextSha, oldestFirstParent);
    let usePerCommit = true;
    if (baseSha !== null) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        timedOut = true;
        break;
      }
      // KNOWN LIMIT (Phase 21, deliberate tradeoff): the aggregate diff
      // is a NET diff from base to head, so a secret added and then
      // removed again inside this same window leaves no trace in it
      // and the pre-filter cannot see it. The git path has no such hole;
      // this affects only the API path. The window size stays at 250
      // and no extra fetching closes it - the exposure is bounded by
      // the window.
      const compared = await scanCompareWindow(
        apiBase, owner, repo, baseSha, windowShas[0], windowShas.length,
        (url, timeoutMs) => apiFetch(url, timeoutMs, stats),
        remaining,
      );
      if (compared.outcome === "rate-limited") {
        rateLimited = true;
        break;
      } else if (compared.outcome === "clean") {
        commitsScanned += windowShas.length;
        usePerCommit = false;
      }
      // "hit" or "unusable": fall through to the per-commit fetches.
    }
    if (usePerCommit) await scanWindowPerCommit(windowShas);
    windowStart = windowEnd;
  }

  const wasTruncated = truncated || listTruncated;
  const ms = Date.now() - started;
  let note: string | null = null;
  if (rateLimited) note = rateLimitNote(commitsScanned);
  else if (timedOut) note = `History scan hit the ${timeoutMs / 1000}s cap - scanned ${commitsScanned} newest commits before stopping.`;
  else if (wasTruncated) note = `History scan hit its cap (${MAX_HISTORY_COMMITS} commits / ${MAX_HISTORY_PATCH_BYTES / 1_000_000} MB of patches, newest-first) - scanned ${commitsScanned} newest commits.`;
  return { ok: true, findings, commitsScanned, patchBytes, truncated: wasTruncated, timedOut, note, ms, method: "api", cachedCommits: 0, commitsFetched: commitsScanned, restCalls: stats.restCalls, gitRequests: 0 };
}

// ---------------------------------------------------------------------------
// API history CHUNK (Phase 9) - one resumable slice of the API path.
//
// The whole-API scan (above) pages the commits list and fetches every
// commit's patch in a single call, which is why a 92k-commit repo can
// only ever report a partial history with a note. The chunk version
// scans exactly `count` commits (default 10) and returns a cursor
// (next page / next index / that page's SHAs) so the caller can resume
// with zero server state. One chunk costs ~count+1 REST calls, so it
// fits the unauthenticated quota a few chunks at a time, and a rate
// limit mid-chunk stops cleanly at the next unscanned commit - the
// cursor points at it, and a later call retries it when quota returns.
// A chunk ALWAYS advances (a commit whose detail fetch fails for any
// other reason is skipped and counted, never retried forever), so a
// chunked scan cannot stall on one bad commit. The HEAD check (when
// expectedHeadSha is given) costs one extra call and guarantees a scan
// whose repo moved mid-flight restarts instead of reporting stale
// history for the old HEAD.
// ---------------------------------------------------------------------------

export interface ApiHistoryChunkState {
  /** Next commits-list page (1-based). */
  page: number;
  /** Next index into pageShas. */
  idx: number;
  /** SHAs of the current list page (empty = list it first). */
  pageShas: string[];
}

export interface ApiHistoryChunkResult {
  findings: SecretFinding[];
  /** Commits whose detail was fetched in this chunk. */
  commitsScanned: number;
  /** Commits attempted but not fetched (detail fetch failed) - the
   *  chunk moved past them, so the report can say so honestly. */
  skipped: number;
  nextPage: number;
  nextIdx: number;
  nextPageShas: string[];
  /** True when the oldest commit was reached - history is complete. */
  done: boolean;
  /** True when the GitHub API rate limit stopped this chunk early. */
  rateLimited: boolean;
  /** True when the branch HEAD moved since the scan started. */
  headMoved: boolean;
  /** True when the chunk could not run at all (bad input, list failed). */
  failed: boolean;
  note: string | null;
  restCalls: number;
}

export async function scanHistoryApiChunk(
  owner: string,
  repo: string,
  branch: string,
  state: ApiHistoryChunkState,
  count: number,
  opts?: { apiBase?: string; expectedHeadSha?: string; deadlineMs?: number },
): Promise<ApiHistoryChunkResult> {
  const apiBase = (opts?.apiBase ?? "https://api.github.com").replace(/\/$/, "");
  const stats = { restCalls: 0 };
  const empty: ApiHistoryChunkResult = {
    findings: [], commitsScanned: 0, skipped: 0,
    nextPage: state.page, nextIdx: state.idx, nextPageShas: state.pageShas,
    done: false, rateLimited: false, headMoved: false, failed: false, note: null, restCalls: 0,
  };
  // Phase 16 (Worker B): time left to the loop deadline. A chunk
  // that starts with none left returns its (unchanged) position at
  // once - the caller answers 202 with that cursor instead of
  // burning fetches past the deadline. Each fetch is also capped at
  // the time left. Unset = the old fixed 12 s per fetch, as before.
  const remainingMs = () => (opts?.deadlineMs != null ? opts.deadlineMs - Date.now() : null);
  const outOfTime = () => {
    const r = remainingMs();
    return r != null && r <= 0;
  };
  const fetchTimeoutMs = () => {
    const r = remainingMs();
    return r != null ? Math.max(50, r) : API_FETCH_TIMEOUT_MS;
  };
  if (outOfTime()) return { ...empty, restCalls: stats.restCalls };
  const fail = (note: string): ApiHistoryChunkResult => ({ ...empty, failed: true, note, restCalls: stats.restCalls });
  if (!NAME_RE.test(owner) || !NAME_RE.test(repo) || owner.includes("..") || repo.includes("..")) {
    return fail("Invalid owner/repo name - history API scan skipped.");
  }
  if (!Number.isInteger(count) || count < 1 || count > 100) {
    return fail("Invalid history chunk size.");
  }

  // HEAD check: one list call, newest commit only. A moved HEAD means
  // the scan's pinned sha is stale - the caller restarts cleanly.
  if (opts?.expectedHeadSha) {
    const headRes = await apiFetch(`${apiBase}/repos/${owner}/${repo}/commits?per_page=1&sha=${encodeURIComponent(branch)}`, fetchTimeoutMs(), stats);
    if (headRes && headRes.ok) {
      try {
        const headPage = (await headRes.json()) as { sha?: string }[];
        const headSha = Array.isArray(headPage) ? headPage[0]?.sha : undefined;
        if (typeof headSha === "string" && headSha !== opts.expectedHeadSha) {
          return {
            ...empty, headMoved: true, failed: true, restCalls: stats.restCalls,
            note: "The repo changed while the scan was running (new commits landed). History will restart cleanly from the newest commit.",
          };
        }
      } catch {
        // Unreadable HEAD response: proceed - the list/detail calls
        // below will fail honestly if the repo is really gone.
      }
    } else if (headRes && isApiRateLimited(headRes)) {
      return { ...empty, rateLimited: true, restCalls: stats.restCalls };
    }
    // Any other HEAD failure (404, network): proceed - the list call
    // below reports the real failure with its own note.
  }

  // List the current page if the cursor does not already hold its SHAs.
  let pageShas = state.pageShas;
  // Phase 21 (Workstream B): first-parent SHA per listed commit,
  // parallel to pageShas. Populated only when the page is listed
  // fresh in this call - the cursor carries SHAs only, so a resumed
  // page has no parents and the compare pre-filter below falls back
  // to the per-commit fetches for a window ending at that page.
  let pageFirstParents: (string | null)[] = [];
  let page = state.page;
  let idx = state.idx;
  if (idx >= pageShas.length) {
    if (outOfTime()) return { ...empty, restCalls: stats.restCalls };
    const listRes = await apiFetch(
      `${apiBase}/repos/${owner}/${repo}/commits?per_page=100&sha=${encodeURIComponent(branch)}&page=${page}`,
      fetchTimeoutMs(),
      stats,
    );
    if (!listRes) return fail("GitHub API could not be reached - history API scan skipped.");
    if (listRes.status === 404) return fail("Repository not found (or it is private).");
    if (isApiRateLimited(listRes)) return { ...empty, rateLimited: true, restCalls: stats.restCalls };
    if (!listRes.ok) return fail(`GitHub API answered with an unexpected error (${listRes.status}) - history API scan skipped.`);
    let listPage: { sha?: string; parents?: { sha?: string }[] }[];
    try {
      listPage = (await listRes.json()) as { sha?: string; parents?: { sha?: string }[] }[];
    } catch {
      return fail("GitHub API returned an unreadable response - history API scan skipped.");
    }
    if (!Array.isArray(listPage)) return fail("GitHub API returned an unexpected response - history API scan skipped.");
    const listed = listPage.filter((c) => typeof c.sha === "string");
    pageShas = listed.map((c) => c.sha as string);
    pageFirstParents = listed.map((c) =>
      Array.isArray(c.parents) && typeof c.parents[0]?.sha === "string" ? (c.parents[0].sha as string) : null,
    );
    idx = 0;
    if (pageShas.length === 0) {
      // No commits at all on this page - history is complete.
      return { ...empty, done: true, nextPage: page, nextIdx: 0, nextPageShas: [], restCalls: stats.restCalls };
    }
  }
  // A page shorter than 100 is the last page - whether it was listed
  // just now or carried over in the cursor.
  const lastPage = pageShas.length < 100;

  // Scan the next `count` commits from this page, SEQUENTIALLY: a chunk
  // is small (10 commits), and sequential keeps the cursor exact - the
  // rate-limited commit is the one the cursor points at on retry, and
  // no commit is ever counted twice. (The whole-API path above keeps
  // its pool of 5; the chunk path trades that for exact resume.)
  const take = Math.min(count, pageShas.length - idx);
  const shas = pageShas.slice(idx, idx + take);
  const findings: SecretFinding[] = [];
  let commitsScanned = 0;
  let rateLimited = false;
  let nextIdx = idx;

  // Phase 21 (Workstream B): compare-window pre-filter. One compare
  // call covers the whole window's aggregate diff; a clean window
  // costs exactly 1 call and skips the per-commit fetches below. A
  // window with a hit, or one the compare cannot vouch for (no base,
  // truncated diff, diverged range), falls through to the per-commit
  // loop, which attributes each finding to its exact commit.
  let usePerCommit = true;
  if (!outOfTime() && shas.length > 0) {
    const nextPageSha = idx + take < pageShas.length ? pageShas[idx + take] : null;
    const oldestFirstParent =
      pageFirstParents.length === pageShas.length ? pageFirstParents[idx + take - 1] : null;
    const baseSha = resolveCompareBase(shas, nextPageSha, oldestFirstParent);
    if (baseSha !== null) {
      const compared = await scanCompareWindow(
        apiBase, owner, repo, baseSha, shas[0], shas.length,
        (url, timeoutMs) => apiFetch(url, timeoutMs, stats),
        fetchTimeoutMs(),
      );
      if (compared.outcome === "rate-limited") {
        // Stop here WITHOUT advancing: the cursor points at this
        // window, so a later call retries it when quota returns.
        rateLimited = true;
        usePerCommit = false;
      } else if (compared.outcome === "clean") {
        commitsScanned += shas.length;
        nextIdx = idx + shas.length;
        usePerCommit = false;
      }
      // "hit" or "unusable": fall through to the per-commit loop.
    }
  }
  const confirmShas = usePerCommit ? shas : [];
  for (const sha of confirmShas) {
    // Phase 16: stop at the deadline - the cursor stays on this
    // commit (nextIdx is not advanced), so the next chunk retries
    // it, exactly like the rate-limit break below.
    if (outOfTime()) break;
    const res = await apiFetch(`${apiBase}/repos/${owner}/${repo}/commits/${sha}`, fetchTimeoutMs(), stats);
    if (!res) {
      nextIdx++; // one bad commit must not fail the chunk - move past it
      continue;
    }
    if (isApiRateLimited(res)) {
      // Stop here WITHOUT advancing: the cursor points at this commit,
      // so a later call retries it when quota returns.
      rateLimited = true;
      break;
    }
    if (!res.ok) {
      nextIdx++; // skip this commit, keep going
      continue;
    }
    let detail: { files?: { filename?: string; patch?: string }[] };
    try {
      detail = (await res.json()) as { files?: { filename?: string; patch?: string }[] };
    } catch {
      nextIdx++;
      continue;
    }
    commitsScanned++;
    nextIdx++;
    for (const f of detail.files ?? []) {
      if (!f.patch || typeof f.filename !== "string" || isSkippablePath(f.filename)) continue;
      const addedLines = parsePatchAddedLines(f.patch);
      const found = scanLinesForSecrets({ path: f.filename }, addedLines, sha.slice(0, 7));
      // Phase 10: triage from the added lines.
      triageHistoryFindings(found, f.filename, addedLines);
      findings.push(...found);
    }
  }

  const pageDone = nextIdx >= pageShas.length;
  const done = !rateLimited && pageDone && lastPage;
  // Attempted = how far the cursor advanced on this page; skipped =
  // attempted commits whose detail could not be fetched.
  const attempted = nextIdx - idx;
  return {
    findings,
    commitsScanned,
    skipped: Math.max(0, attempted - commitsScanned),
    nextPage: pageDone ? page + 1 : page,
    nextIdx: pageDone ? 0 : nextIdx,
    nextPageShas: pageDone ? [] : pageShas,
    done,
    rateLimited,
    headMoved: false,
    failed: false,
    note: null,
    restCalls: stats.restCalls,
  };
}

// ---------------------------------------------------------------------------
// Git-protocol history path + per-commit cache (Phase 8).
//
// Why: the API path (above) needs ~1 REST request per commit plus the
// list pages, and the unauthenticated quota is 60 req/hour from the
// shared Vercel IP - a 62-commit repo needs ~65 requests, so live
// history stopped at 56/62. A GITHUB_TOKEN is forbidden (Freddy's
// ruling), so the fix is to stop using the REST API for history at
// all: isomorphic-git speaks the git smart-HTTP protocol against
// github.com (the same protocol `git clone` uses), which has no REST
// quota. Measured on Squ1zM0/TechDirect: clone ~4.6 s, full log 62
// commits ~2.2 s, diff+scan ~2 s (with a shared isomorphic-git object
// cache; without it the same walk took ~40 s).
//
// What is cached: per commit SHA, the (redacted-fragment-only) findings
// that commit introduced, plus the bytes read for that commit's diffs.
// In-memory only, module-level, keyed by "owner/repo@branch" with the
// cached HEAD tip. Nothing durable exists in this project (no DB /
// Redis), and none is added - a serverless instance that restarts just
// re-walks cold. A secret value is never cached: findings carry the
// same redacted fragments as everywhere else.
// ---------------------------------------------------------------------------

/** One repo's cached history: newest-first full SHAs, findings per SHA. */
interface CachedHistory {
  tip: string;
  order: string[];
  bySha: Map<string, SecretFinding[]>;
  bytesBySha: Map<string, number>;
  patchBytes: number;
}

const historyCache = new Map<string, CachedHistory>();

/** Phase 11: the HEAD file corpus used to compute usage for history
 *  findings, keyed by repo@branch with the tip it was read at. A
 *  re-scan at the same tip reuses it (chunked history walks run one
 *  clone per chunk); a moved tip re-reads it. Bounded - see
 *  readHeadUsageCorpus - so a giant HEAD tree never blows up the
 *  function. In-memory only, like historyCache. */
const headUsageCorpusCache = new Map<string, { tip: string; corpus: Map<string, string> }>();
/** Most HEAD files a corpus read will hold (and most total bytes).
 *  Past either bound the read is abandoned and history findings
 *  carry no usage annotation - an absent annotation, never a
 *  half-searched one. */
export const HEAD_USAGE_CORPUS_MAX_FILES = 20_000;
export const HEAD_USAGE_CORPUS_MAX_BYTES = 100_000_000;

/** Test/support hook: drop the whole in-memory history cache. */
export function clearHistoryCache(): void {
  historyCache.clear();
  headUsageCorpusCache.clear();
}

/** Read the HEAD tree's text files out of the cloned repo, for the
 *  Phase 11 usage search (history findings are searched against the
 *  HEAD files only - the old commit's files are gone). Same bounds
 *  as scanHead's finding-content retention: binary files skipped,
 *  skippable paths skipped, files over 1 MB skipped. Returns null
 *  when the tree is over the corpus bounds or the read fails, so the
 *  caller triages without usage instead of with a partial corpus. */
async function readHeadUsageCorpus(
  dir: string,
  branch: string,
  cache: object,
  cacheKey: string,
  tip: string,
  // Phase 16: absolute wall-clock deadline (epoch ms). Past it the
  // read gives up and returns null - the caller triages without
  // usage, exactly as when the corpus is over its bounds. Unset =
  // no deadline, as before.
  deadlineMs?: number,
): Promise<Map<string, string> | null> {
  const hit = headUsageCorpusCache.get(cacheKey);
  if (hit && hit.tip === tip) return hit.corpus;
  const corpus = new Map<string, string>();
  let files = 0;
  let bytes = 0;
  let over = false;
  try {
    // Phase 14: the old `git.walk` over `git.TREE({ ref: branch })`
    // visited exactly 1 entry (the root) and 0 blobs in a
    // `noCheckout: true` clone, so the corpus came back an empty
    // (non-null) Map and every history finding was labelled a dead
    // end. `git.walk` does not descend the tree in that clone shape
    // (proved in the standalone repro: TREE by ref AND by resolved
    // tip oid both visit 1 entry / 0 blobs, while `git.readTree`
    // from the tip commit's tree lists every entry). Read the tree
    // directly instead: resolve the branch tip to its commit, take
    // the commit's tree oid, and recurse with `git.readTree`,
    // reading each blob with the same readBlobText as the diff walk.
    const tipOid = await git.resolveRef({ fs, dir, ref: branch });
    const { commit } = await git.readCommit({ fs, dir, oid: tipOid, cache });
    let entriesSeen = 0;
    const readTree = async (treeOid: string, prefix: string): Promise<void> => {
      if (over) return;
      const { tree } = await git.readTree({ fs, dir, oid: treeOid, cache });
      for (const entry of tree) {
        if (over) return;
        // Phase 16: a corpus read that runs past the loop deadline
        // gives up (null = no usage annotations) instead of adding
        // unbounded minutes to a chunk that already used its budget.
        if (deadlineMs != null && ++entriesSeen % 64 === 0 && Date.now() > deadlineMs) {
          over = true;
          return;
        }
        const filepath = prefix ? `${prefix}/${entry.path}` : entry.path;
        if (entry.type === "tree") {
          await readTree(entry.oid, filepath);
        } else if (entry.type === "blob") {
          if (isSkippablePath(filepath)) continue;
          const text = await readBlobText(dir, entry.oid, cache);
          if (text === null) continue; // binary
          const size = Buffer.byteLength(text, "utf8");
          if (size > 1_000_000) continue; // same 1 MB per-file rule as scanHead
          files++;
          bytes += size;
          if (files > HEAD_USAGE_CORPUS_MAX_FILES || bytes > HEAD_USAGE_CORPUS_MAX_BYTES) {
            over = true;
            return;
          }
          corpus.set(filepath, text);
        }
      }
    };
    await readTree(commit.tree, "");
  } catch {
    return null;
  }
  if (over) return null;
  headUsageCorpusCache.set(cacheKey, { tip, corpus });
  return corpus;
}

/** Split a file into lines the way jsdiff's diffLines counts them: a
 *  trailing newline ends the last line, it does not start an empty
 *  one; "" has zero lines. */
function splitDiffLines(text: string): string[] {
  if (text === "") return [];
  const parts = text.split("\n");
  if (parts[parts.length - 1] === "") parts.pop();
  return parts;
}

/** Count lines the way splitDiffLines would (no allocation - the
 *  dispatcher below needs only the count to pick a path). */
function countDiffLines(text: string): number {
  if (text === "") return 0;
  let n = 1;
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  if (text.endsWith("\n")) n--;
  return n;
}

/** Max lines (on either side) for the jsdiff path - see addedLinesFast.
 *  Measured knee on this VM (lockfile-like lines, 5%/50%/90% churn):
 *  jsdiff costs <= ~25 ms at 500 lines, <= ~95 ms at 1,000 lines,
 *  ~260 ms at 2,000 lines (819 ms fully reversed), ~1.9 s at 5,000
 *  lines - and tens of seconds on real 10k-line lockfiles. At or
 *  under 1,000 lines jsdiff is always cheap, so small files keep the
 *  exact Myers attribution; above it the fast path takes over before
 *  jsdiff can run away. */
export const ADDED_LINES_JSDIFF_MAX_LINES = 1000;

/** Fast added-lines computation for large files: multiset difference
 *  on line hashes (a Map keyed by line content) between old and new
 *  text, attributed to new-file positions in order - O(n) in the
 *  number of lines, where jsdiff's Myers diffLines is O(ND) in the
 *  edit distance and explodes on regenerated lockfiles (profiled
 *  2026-11-26: one package-lock.json diff with only 75 added lines
 *  took 43.8 s; two lockfiles in one commit took 51.5 s + 46.4 s).
 *  The fast path costs ~1 ms per 1,000 lines at every size (55 ms
 *  at 50k lines, 90 ms at 100k).
 *
 *  HONEST DIVERGENCE from jsdiff - same added lines for normal
 *  diffs, different attribution when a line text repeats:
 *  (1) For diffs with no moved lines, the multiset of added line
 *  texts is identical to jsdiff's (proved by the equivalence test
 *  in scripts/test-phase17-worker-f.ts), and a line whose text is
 *  unique in the new file is reported at the identical line number
 *  by both. (2) When an added line's text also occurs elsewhere in
 *  the file, jsdiff pins it to its minimal-edit-script position
 *  while the fast path pins it to the first unmatched occurrence
 *  in new-file order - the reported line number can differ (e.g.
 *  an inserted `},` closing line in a lockfile). Secret lines are
 *  unique by nature (a token value appears once), so findings are
 *  identical for normal files; only the reported line of an added
 *  line whose text repeats can shift. (3) A line deleted and
 *  re-added in the same commit at equal count (a move) is reported
 *  as added by jsdiff but is invisible to the multiset - its counts
 *  balance, so it is missing from the added multiset too. That
 *  cannot hide a secret from the full walk: the line's first
 *  introduction in history always raises its count and is reported
 *  there. It only changes attribution: a moved secret is reported
 *  at its introduction commit, not again at the move.
 *
 *  Lines are keyed by content in a hash map - no lossy hashing, so
 *  there is no collision risk: two different lines can never cancel
 *  each other out. */
export function addedLinesFast(oldText: string, newText: string): ScannedLine[] {
  // jsdiff treats a final line without a trailing newline as a
  // different line from the same text WITH one ("b" vs "b\n" are
  // different tokens), so a commit that only gains a trailing
  // newline re-reports its last line as added. The multiset keys
  // an unterminated final line with a NUL marker so the two paths
  // agree exactly there too (the marker never reaches the output,
  // and scanned text never contains NUL - readBlobText rejects
  // binary content before any diff runs).
  const EOL_MARK = "\0";
  const oldLines = splitDiffLines(oldText);
  const newLines = splitDiffLines(newText);
  const oldNoEol = oldText !== "" && !oldText.endsWith("\n");
  const newNoEol = newText !== "" && !newText.endsWith("\n");
  const oldCounts = new Map<string, number>();
  oldLines.forEach((line, i) => {
    const key = i === oldLines.length - 1 && oldNoEol ? line + EOL_MARK : line;
    oldCounts.set(key, (oldCounts.get(key) ?? 0) + 1);
  });
  const out: ScannedLine[] = [];
  newLines.forEach((line, i) => {
    const key = i === newLines.length - 1 && newNoEol ? line + EOL_MARK : line;
    const remaining = oldCounts.get(key) ?? 0;
    if (remaining > 0) oldCounts.set(key, remaining - 1);
    else out.push({ line: i + 1, text: line });
  });
  return out;
}

/** jsdiff added lines of newText vs oldText, with new-file line numbers.
 *  Removed and context lines are not returned - only added lines are
 *  ever scanned, exactly like the clone path's `git log -p` parsing.
 *  Kept for small files (exact Myers attribution); large files go
 *  through addedLinesFast above. */
function addedLinesJsDiff(oldText: string, newText: string): ScannedLine[] {
  const out: ScannedLine[] = [];
  let newLine = 1;
  for (const part of diffLines(oldText, newText)) {
    const count = part.count ?? 0;
    if (part.added) {
      const lines = part.value.split("\n");
      for (let i = 0; i < count; i++) {
        out.push({ line: newLine + i, text: lines[i] ?? "" });
      }
    }
    if (!part.removed) newLine += count;
  }
  return out;
}

/** Added lines of newText vs oldText, with new-file line numbers.
 *  Small files take the jsdiff path (exact Myers attribution);
 *  files over ADDED_LINES_JSDIFF_MAX_LINES on either side take the
 *  O(n) multiset path (addedLinesFast) - jsdiff's cost on a
 *  regenerated lockfile is unbounded (tens of seconds per file),
 *  and a single such file blew past every walk budget and Vercel's
 *  60 s ceiling. */
export function addedLines(oldText: string, newText: string): ScannedLine[] {
  if (
    countDiffLines(oldText) > ADDED_LINES_JSDIFF_MAX_LINES ||
    countDiffLines(newText) > ADDED_LINES_JSDIFF_MAX_LINES
  ) {
    return addedLinesFast(oldText, newText);
  }
  return addedLinesJsDiff(oldText, newText);
}

/** Read one blob as text. Returns "" for a missing side (added/deleted
 *  file) and null for binary content (NUL byte) - binary files are
 *  skipped, like everywhere else in the scanner. */
async function readBlobText(dir: string, oid: string | null, cache: object): Promise<string | null> {
  if (!oid) return "";
  const { blob } = await git.readBlob({ fs, dir, oid, cache });
  const text = Buffer.from(blob).toString("utf8");
  return text.includes("\0") ? null : text;
}

/** Resolve the branch tip over the git protocol (one info/refs request
 *  to github.com - NOT api.github.com, so it costs zero REST quota).
 *  Returns null when the ref cannot be read (network error, missing or
 *  private repo) - the caller then fails over to the next path. */
async function resolveRemoteTip(url: string, branch: string): Promise<{ tip: string | null; gitRequests: number }> {
  try {
    const info = await git.getRemoteInfo({ http: boundedHttp, url });
    const heads = (info.refs as unknown as Record<string, Record<string, string>>)?.heads;
    return { tip: heads?.[branch] ?? null, gitRequests: 1 };
  } catch {
    return { tip: null, gitRequests: 1 };
  }
}

/** Phase 15 (worker D): resolve the default branch AND the HEAD sha
 *  over the git protocol in one info/refs request to github.com -
 *  NOT api.github.com, so it costs zero REST quota. This is what
 *  scanHead uses instead of the REST repo-info call
 *  (GET /repos/{owner}/{repo}) plus the commits-list call that used
 *  to fetch the HEAD sha: `getRemoteInfo` returns both the HEAD
 *  symref (`refs/heads/main`) and the sha of every branch head.
 *  Returns not-found when GitHub answers 401/404 on info/refs -
 *  that is how GitHub reports a missing or private repo to an
 *  unauthenticated git client - "timeout" when the request does not
 *  answer inside 12 s (same bound ghJson used to give the REST
 *  calls), and unreachable for anything else (network error, other
 *  status, unparseable refs). An empty repo
 *  (no HEAD, no branch heads) is not-found too: it has no HEAD to
 *  scan, matching the old commits-list behaviour. The caller must
 *  have validated owner/repo already (scanHead does). */
export type RemoteHeadResult =
  | { ok: true; branch: string; headSha: string; gitRequests: number }
  | { ok: false; reason: "not-found" | "unreachable" | "timeout"; gitRequests: number };

/** Test-only: replace the remote-HEAD resolver for the whole
 *  process. Lets the chunked-scan tests point scanHead at a mock
 *  git server (or a scripted failure) without threading an option
 *  through the driver (chunks.ts). Production code never sets this;
 *  tests must reset it to null in a finally block. */
let remoteHeadResolverOverride: ((owner: string, repo: string) => Promise<RemoteHeadResult>) | null = null;
export function setRemoteHeadResolverForTests(fn: ((owner: string, repo: string) => Promise<RemoteHeadResult>) | null): void {
  remoteHeadResolverOverride = fn;
}

/** Wrap a git HTTP client so every request carries the given signal
 *  (isomorphic-git itself supplies none on these paths, so the
 *  caller's signal is the only abort source). */
function withSignal(inner: typeof http, signal: AbortSignal): typeof http {
  return {
    async request(args) {
      return inner.request({ ...args, signal });
    },
  };
}

export async function resolveRemoteHead(
  owner: string,
  repo: string,
  opts: { cloneUrlOverride?: string; timeoutMs?: number } = {},
): Promise<RemoteHeadResult> {
  if (remoteHeadResolverOverride) return remoteHeadResolverOverride(owner, repo);
  if (!NAME_RE.test(owner) || !NAME_RE.test(repo) || owner.includes("..") || repo.includes("..")) {
    return { ok: false, reason: "not-found", gitRequests: 0 };
  }
  const url = opts.cloneUrlOverride ?? `https://github.com/${owner}/${repo}.git`;
  // Phase 15 (worker D): the info/refs request has the same 12 s
  // abort timeout ghJson used to give the REST calls - without it a
  // hung git-protocol request would hang the scan instead of failing
  // plainly with a 504.
  const timeoutMs = opts.timeoutMs ?? 12_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const info = await git.getRemoteInfo({ http: withSignal(boundedHttp, controller.signal), url });
    const headRef = typeof info.HEAD === "string" ? info.HEAD : null;
    const branch = headRef?.startsWith("refs/heads/") ? headRef.slice("refs/heads/".length) : null;
    const heads = (info.refs as unknown as Record<string, Record<string, string>>)?.heads;
    const headSha = branch ? heads?.[branch] : null;
    if (!branch || !headSha) return { ok: false, reason: "not-found", gitRequests: 1 };
    return { ok: true, branch, headSha, gitRequests: 1 };
  } catch (err) {
    if (controller.signal.aborted) return { ok: false, reason: "timeout", gitRequests: 1 };
    const status = (err as { data?: { statusCode?: number } })?.data?.statusCode;
    if (status === 401 || status === 404) return { ok: false, reason: "not-found", gitRequests: 1 };
    return { ok: false, reason: "unreachable", gitRequests: 1 };
  } finally {
    clearTimeout(timer);
  }
}

export interface GitHistoryOptions {
  /** Test-only: smart-HTTP URL of a mock git server (the test suite
   *  serves a fixture repo through `git http-backend`). Production
   *  callers never pass it - the URL is always the public github.com repo.
   *  Note: isomorphic-git cannot clone from a local filesystem path,
   *  which is why the tests use a real smart-HTTP server, not a path. */
  cloneUrlOverride?: string;
  /** Known HEAD sha - skips the remote-info round trip. */
  headSha?: string;
  /** Live progress: called with the number of commits walked so far. */
  onProgress?: (commitsScanned: number) => void;
  /** Phase 9 chunking: full sha of the last commit already scanned
   *  (exclusive) - the walk skips newer commits and continues older.
   *  When it is no longer in the log, the result carries
   *  headMoved: true and the caller restarts history cleanly. */
  resumeAfterSha?: string | null;
  /** Phase 9 chunking: stop after scanning this many commits (a chunk
   *  boundary, not a truncation - the result carries complete: false
   *  and lastScannedSha so the next chunk continues). Unset = walk to
   *  the oldest commit, as before. */
  maxCommits?: number;
  /** Phase 9 chunking: stop the walk after this many milliseconds
   *  (chunk boundary, same as maxCommits). Unset = no chunk budget. */
  budgetMs?: number;
  /** Phase 16 (Worker B): absolute wall-clock deadline (epoch ms)
   *  for this chunk, passed by the chunked driver. The pack download
   *  aborts at it (via the git HTTP client's AbortSignal); the walk
   *  budget (budgetMs) is capped at the time left by the caller;
   *  the HEAD-usage corpus read gives up at it and returns null
   *  (findings are triaged without usage, as when the corpus is over
   *  its bounds). Unset = no deadline, as before. */
  deadlineMs?: number;
  /** Phase 9 chunking: added to the onProgress count, so progress
   *  reports the scan-wide total, not just this chunk's count. */
  progressBase?: number;
  /** Phase 15 (worker D), test-only: byte bound for the pack
   *  download (default PACK_MAX_BYTES). Lets the test suite prove
   *  the too-large fallback against a small mock repo without
   *  needing a 150 MB pack. */
  maxPackBytes?: number;
}

/** Full history over the git protocol, no REST API calls, no git binary.
 *  Clones (single branch, no checkout) into an ephemeral temp dir,
 *  walks `git.log` newest-first with includeChanges, diffs each commit
 *  against its first parent, and scans added lines only. Merge commits
 *  get no diff - matching `git log -p`, which also shows no patch for
 *  a merge. The root commit is diffed against the empty tree, so a
 *  secret planted in the very first commit is found. Runs to the oldest
 *  commit: no commit cap, no time cap - only the emergency memory
 *  guard (HISTORY_MEMORY_GUARD_BYTES) can stop it early, and then the
 *  note says exactly what was not scanned. */
export async function scanHistoryViaGit(
  owner: string,
  repo: string,
  branch: string,
  opts: GitHistoryOptions = {},
): Promise<HistoryScanResult> {
  const started = Date.now();
  let gitRequests = 0;
  const fail = (note: string, packTooLarge = false): HistoryScanResult => ({
    ok: false, findings: [], commitsScanned: 0, patchBytes: 0,
    truncated: false, timedOut: false, note, ms: Date.now() - started, method: "git",
    cachedCommits: 0, commitsFetched: 0, restCalls: 0, gitRequests, packTooLarge,
  });
  if (!NAME_RE.test(owner) || !NAME_RE.test(repo) || owner.includes("..") || repo.includes("..")) {
    return fail("Invalid owner/repo name - history git scan skipped.");
  }
  const cacheKey = `${owner}/${repo}@${branch}`;
  const url = opts.cloneUrlOverride ?? `https://github.com/${owner}/${repo}.git`;
  // Phase 15 (worker D): the clone runs through the bounded HTTP
  // client (pack-download byte bound - see PACK_MAX_BYTES). A
  // test-only maxPackBytes builds a per-call client with that bound.
  const gitHttp = opts.maxPackBytes != null ? boundedGitHttp(http, opts.maxPackBytes) : boundedHttp;
  let tip: string | null = opts.headSha ?? null;
  if (!tip) {
    const resolved = await resolveRemoteTip(url, branch);
    gitRequests += resolved.gitRequests;
    tip = resolved.tip;
    if (!tip) return fail("Could not read the repo's HEAD over the git protocol - history git scan skipped.");
  }
  const cached = historyCache.get(cacheKey);
  if (cached && cached.tip === tip) {
    // Full cache hit: no clone, no walk, no commit fetched.
    opts.onProgress?.(cached.order.length);
    return {
      ok: true,
      findings: cached.order.flatMap((sha) => cached.bySha.get(sha) ?? []),
      commitsScanned: cached.order.length,
      patchBytes: cached.patchBytes,
      truncated: false, timedOut: false, note: null, ms: Date.now() - started, method: "git",
      cachedCommits: cached.order.length, commitsFetched: 0, restCalls: 0, gitRequests,
      lastScannedSha: cached.order.length > 0 ? cached.order[cached.order.length - 1] : null,
      complete: true, headMoved: false,
    };
  }

  const dir = await mkdtemp(join(tmpdir(), "gitsecure-git-"));
  try {
    // Phase 16: abort a clone that runs past the loop deadline -
    // without this a slow pack download is the one part of the chunk
    // no budget reaches (the walk budget is only checked once the
    // walk starts). An aborted clone fails this path; the driver
    // falls through to the API chunk, which is deadline-aware and
    // returns its position at once when no time is left.
    const cloneDeadlineMs = opts.deadlineMs;
    const cloneTimeoutMs = cloneDeadlineMs != null ? Math.max(0, cloneDeadlineMs - Date.now()) : 0;
    const cloneController = cloneDeadlineMs != null ? new AbortController() : null;
    const cloneTimer =
      cloneController != null
        ? setTimeout(() => cloneController.abort(), cloneTimeoutMs)
        : undefined;
    try {
      await git.clone({
        fs,
        http: cloneController != null ? withSignal(gitHttp, cloneController.signal) : gitHttp,
        dir, url, ref: branch, singleBranch: true, noCheckout: true,
      });
    } finally {
      clearTimeout(cloneTimer);
    }
    // One shared object cache across log + readBlob: without it the
    // same TechDirect walk took ~40 s (packfile re-parsed per blob);
    // with it, ~4 s. The cache is per-scan and discarded with the dir.
    const cacheObj: Record<string, unknown> = {};
    const commits = await git.log({ fs, dir, ref: branch, includeChanges: true, cache: cacheObj });

    const newBySha = new Map<string, SecretFinding[]>();
    const newBytesBySha = new Map<string, number>();
    const newOrder: string[] = [];
    let newPatchBytes = 0;
    let truncated = false;
    let stopSha: string | null = null;
    // Phase 11: triage is DEFERRED until after the walk (see below).
    // Each file that produced findings keeps its triage context
    // (the full new-file content, capped at 1 MB like scanHead, plus
    // the added lines) so usage can be computed from the HEAD corpus
    // first and triage can consume it in one call.
    const pendingTriage: { findings: SecretFinding[]; content?: string; lines: ScannedLine[] }[] = [];
    // Phase 9 chunking: the walk skips commits newer than (and including)
    // resumeAfterSha and stops at a chunk boundary (maxCommits / budget).
    // A chunk boundary is NOT a truncation - the next chunk continues
    // from lastScannedSha, and the report never calls it incomplete.
    let pastResumePoint = !opts.resumeAfterSha;
    let chunkStopped = false;
    const progressBase = opts.progressBase ?? 0;
    // Phase 17 (Worker F): file-granularity walk budget. The checks
    // above run every 16/64 commits, so a single commit whose files
    // each cost tens of seconds (a lockfile diff took 43.8 s for 75
    // added lines; two in one commit took 100 s) blows straight past
    // every deadline and Vercel's 60 s ceiling. The per-file check
    // inside the loop below stops the chunk at the first file past
    // the budget instead. Same bound as the 16-commit check
    // (budgetMs from walk start), plus the absolute loop deadline
    // when one was passed.
    const walkOverBudget = (): boolean =>
      (opts.budgetMs != null && Date.now() - started > opts.budgetMs) ||
      (opts.deadlineMs != null && Date.now() > opts.deadlineMs);

    for (const entry of commits) {
      const oid = entry.oid;
      if (!pastResumePoint) {
        if (oid === opts.resumeAfterSha) pastResumePoint = true;
        continue; // already scanned in an earlier chunk - skip, no blob reads
      }
      if (cached?.bySha.has(oid)) {
        // Everything from here on is already cached - reuse it.
        stopSha = oid;
        break;
      }
      // Phase 8.1 safety valve: a walk that runs too long or grows too
      // big in memory stops cleanly with truncated:true and an honest
      // note - it never OOM-crashes the function (DefinitelyTyped's
      // 92k-commit walk did exactly that on Vercel). Checked every 64
      // commits so the check itself costs nothing.
      if (newOrder.length > 0 && newOrder.length % 64 === 0) {
        if (Date.now() - started > 40_000 || process.memoryUsage().heapUsed > 700_000_000) {
          truncated = true;
          break;
        }
      }
      // Phase 9 chunk boundary: stop here, keep what was scanned, and
      // let the next chunk continue from the last scanned commit.
      if (opts.maxCommits != null && newOrder.length >= opts.maxCommits) {
        chunkStopped = true;
        break;
      }
      if (opts.budgetMs != null && newOrder.length > 0 && newOrder.length % 16 === 0 && Date.now() - started > opts.budgetMs) {
        chunkStopped = true;
        break;
      }
      newOrder.push(oid);
      const parents = entry.commit.parent ?? [];
      const changes = entry.commit.changes ?? [];
      // Entries added for this commit are rolled back with it when
      // the memory guard discards the commit whole (below).
      const pendingBefore = pendingTriage.length;
      if (parents.length > 1) {
        newBySha.set(oid, []);
        newBytesBySha.set(oid, 0);
        opts.onProgress?.(progressBase + newOrder.length);
        continue; // merge commit: no diff, like `git log -p`.
      }
      const commitFindings: SecretFinding[] = [];
      let commitBytes = 0;
      // Stopping mid-commit discards this commit whole (rolled back
      // below, same as the memory guard): the cursor resumes from the
      // last fully scanned commit, findings kept.
      let midCommitStop = false;
      for (const [newOid, oldOid, filepath] of changes) {
        if (truncated) break;
        // Phase 17 (Worker F): check the walk budget before EACH
        // file's diff+scan - a single slow file must end the chunk,
        // not the next 16-commit checkpoint. A chunk that stops here
        // keeps every fully scanned commit and resumes cleanly.
        if (walkOverBudget()) {
          midCommitStop = true;
          break;
        }
        if (!filepath || isSkippablePath(filepath)) continue;
        let oldText: string | null;
        let newText: string | null;
        try {
          oldText = await readBlobText(dir, oldOid, cacheObj);
          newText = await readBlobText(dir, newOid, cacheObj);
        } catch {
          continue; // one unreadable file must not fail the scan
        }
        if (oldText === null || newText === null) continue; // binary
        commitBytes += Buffer.byteLength(oldText, "utf8") + Buffer.byteLength(newText, "utf8");
        // Emergency memory guard, checked per file: if it trips, this
        // commit is discarded whole (popped below) and the walk stops.
        if (newPatchBytes + commitBytes > HISTORY_MEMORY_GUARD_BYTES) truncated = true;
        else {
          const added = addedLines(oldText, newText);
          const found = scanLinesForSecrets({ path: filepath }, added, oid.slice(0, 7));
          // Phase 11: triage is deferred until after the walk (usage
          // needs the HEAD corpus, which is read once the walk is
          // done). Keep the context - a PEM block added by the
          // commit is complete in the new-file content, and the
          // path/filename signals come from the file path.
          if (found.length > 0) {
            pendingTriage.push({
              findings: found,
              content: Buffer.byteLength(newText, "utf8") <= 1_000_000 ? newText : undefined,
              lines: added,
            });
          }
          commitFindings.push(...found);
        }
      }
      if (truncated || midCommitStop) {
        newOrder.pop();
        pendingTriage.length = pendingBefore;
        // A mid-commit budget stop is a chunk boundary, not a
        // truncation: complete=false, and the next chunk resumes from
        // the last fully scanned commit.
        if (midCommitStop) chunkStopped = true;
        break;
      }
      newBySha.set(oid, commitFindings);
      newBytesBySha.set(oid, commitBytes);
      newPatchBytes += commitBytes;
      opts.onProgress?.(progressBase + newOrder.length);
    }

    // Phase 9: the resume point is gone from the log - the repo's
    // history moved (force-push / rebase) since the scan started.
    // Nothing scanned in this chunk is usable as a continuation.
    if (opts.resumeAfterSha && !pastResumePoint) {
      return {
        ok: false, findings: [], commitsScanned: 0, patchBytes: 0,
        truncated: false, timedOut: false,
        note: "The repo's history changed while the scan was running (the commit it was resuming from is no longer in the log). History will restart cleanly from the newest commit.",
        ms: Date.now() - started, method: "git",
        cachedCommits: 0, commitsFetched: 0, restCalls: 0, gitRequests,
        lastScannedSha: null, complete: false, headMoved: true,
      };
    }

    // Phase 11: usage for the newly walked findings, searched
    // against the HEAD files in this same clone (historyOnly) -
    // then triage, with the full context, exactly once. A finding
    // whose identifier is referenced by today's files is in use;
    // one nothing references is a dead end. When no corpus is
    // available (HEAD tree over the bounds, or the read failed),
    // findings are triaged exactly as Phase 10 did and carry no
    // usage annotation - absent, never half-searched. Cached-suffix
    // findings (below) already carry the usage computed when they
    // were first walked, at the same tip.
    const newFindings = pendingTriage.flatMap((p) => p.findings);
    if (newFindings.length > 0) {
      const corpus = await readHeadUsageCorpus(dir, branch, cacheObj, cacheKey, tip, opts.deadlineMs);
      if (corpus) {
        const ctxByFinding = new Map<SecretFinding, FindingContext>();
        for (const p of pendingTriage) {
          for (const f of p.findings) {
            ctxByFinding.set(f, {
              content: p.content,
              lineText: p.content !== undefined ? (p.content.split("\n")[f.line - 1] ?? null) : null,
            });
          }
        }
        computeUsageForFindings(newFindings, corpus, (f) => ctxByFinding.get(f) ?? {}, { historyOnly: true });
      }
      for (const p of pendingTriage) {
        triageFindings(p.findings, (f) => ({ content: p.content, lines: p.lines, usage: f.usage }));
      }
    }

    // Merge the newly walked commits with the cached suffix (if the walk
    // stopped at a cached commit, everything from it onward is reused).
    const cachedSuffix: string[] = [];
    if (stopSha && cached) {
      const idx = cached.order.indexOf(stopSha);
      if (idx >= 0) cachedSuffix.push(...cached.order.slice(idx));
    }
    const mergedOrder = [...newOrder, ...cachedSuffix];
    const mergedBySha = new Map<string, SecretFinding[]>();
    const mergedBytes = new Map<string, number>();
    for (const sha of newOrder) {
      mergedBySha.set(sha, newBySha.get(sha) ?? []);
      mergedBytes.set(sha, newBytesBySha.get(sha) ?? 0);
    }
    for (const sha of cachedSuffix) {
      mergedBySha.set(sha, cached?.bySha.get(sha) ?? []);
      mergedBytes.set(sha, cached?.bytesBySha.get(sha) ?? 0);
    }
    const patchBytes = [...mergedBytes.values()].reduce((a, b) => a + b, 0);
    const findings = mergedOrder.flatMap((sha) => mergedBySha.get(sha) ?? []);
    // Phase 9: only a COMPLETE walk may be cached as the repo's history.
    // Caching a partial (chunk-stopped or truncated) order would make a
    // later scan mistake it for the whole history and silently miss the
    // older commits. A chunk that stops early simply does not write.
    // Phase 17 (Worker E - cache poisoning): a RESUMED walk is partial
    // too, even when it reaches the oldest commit. It skipped every
    // commit newer than its resume point, so its merged order is only
    // the tail - caching it as complete would make the next scan on
    // this instance report the tail count as the whole history (live:
    // awesome-python answered 150 commits instead of 3,350). Only a
    // walk that started at the tip may write a complete entry; a
    // resumed walk writes nothing and the next scan re-walks cold.
    // `complete` itself is untouched: the chunk driver still needs it
    // to know this scan finished (histDone / stage assemble).
    const complete = !truncated && !chunkStopped;
    const cacheable = complete && !opts.resumeAfterSha;
    if (cacheable) {
      historyCache.set(cacheKey, { tip, order: mergedOrder, bySha: mergedBySha, bytesBySha: mergedBytes, patchBytes });
    }

    let note: string | null = null;
    if (truncated) {
      const last = newOrder.length > 0 ? `${newOrder[newOrder.length - 1].slice(0, 7)}` : "none";
      note = `History scan stopped early at a safety guard (time or memory) after scanning ${newOrder.length} newest commit${newOrder.length === 1 ? "" : "s"} (through ${last}) - commits older than ${last} were not checked, so this report's history is incomplete.`;
    }
    return {
      ok: true, findings, commitsScanned: mergedOrder.length, patchBytes,
      truncated, timedOut: false, note, ms: Date.now() - started, method: "git",
      cachedCommits: cachedSuffix.length, commitsFetched: newOrder.length, restCalls: 0, gitRequests,
      lastScannedSha: newOrder.length > 0 ? newOrder[newOrder.length - 1] : (opts.resumeAfterSha ?? null),
      complete, headMoved: false,
    };
  } catch (e) {
    // Phase 15 (worker D): a pack past the byte bound is a distinct,
    // expected outcome - the orchestrator falls through to the API
    // path and says why. Anything else is the old generic clone
    // failure.
    if (e instanceof PackTooLargeError) {
      return fail("History is too large to clone inside a serverless function - the git-protocol path gave up on the pack download.", true);
    }
    return fail("History git-protocol clone failed (repo may be too large or unreachable).");
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}

// ---------------------------------------------------------------------------
// Orchestrator (Phase 8): the one entry point scan.ts should call.
// Order - git protocol first (no REST quota, works on Vercel, cached on
// repeats), then the git-binary clone (fastest cold path where a binary
// exists), then the GitHub API as a last resort only. A path that
// returns ok:false falls through to the next one; only when every path
// fails does the scan report the last failure. `method` pins a path
// for tests: "git" tries git then API, "clone" tries clone then git
// then API, "api" tries API only.
// ---------------------------------------------------------------------------

export interface ScanHistoryOptions {
  owner: string;
  repo: string;
  branch: string;
  /** Known HEAD sha - skips the remote-info round trip on the git path. */
  commit?: string;
  method?: "auto" | "git" | "clone" | "api";
  /** Test-only override, passed to both the git path (smart-HTTP URL)
   *  and the clone path (local filesystem path or remote URL). */
  cloneUrlOverride?: string;
  /** Test-only: mock GitHub API base for the last-resort API path. */
  apiBase?: string;
  /** Live progress: called with the number of commits walked so far
   *  (git path only; clone/API paths report on return). */
  onProgress?: (commitsScanned: number) => void;
  /** Phase 15 (worker D), test-only: byte bound for the git path's
   *  pack download (default PACK_MAX_BYTES). Passed through to
   *  scanHistoryViaGit so the test suite can prove the too-large
   *  fallback against a small mock repo. */
  maxPackBytes?: number;
}

export async function scanHistory(opts: ScanHistoryOptions): Promise<HistoryScanResult> {
  const { owner, repo, branch } = opts;
  const want = opts.method ?? "auto";
  const gitPath = () => scanHistoryViaGit(owner, repo, branch, { cloneUrlOverride: opts.cloneUrlOverride, headSha: opts.commit, onProgress: opts.onProgress, maxPackBytes: opts.maxPackBytes });
  const clonePath = () => scanFullHistory(owner, repo, branch, opts.cloneUrlOverride);
  const apiPath = () => scanHistoryViaApi(owner, repo, branch, { apiBase: opts.apiBase });
  // Phase 15 (worker D): NO repo-size pre-check any more - the size
  // used to come from the REST repo-info call, which the scan no
  // longer makes. The git path is now bounded while it runs (the
  // pack-download guard in boundedGitHttp): a pack past
  // PACK_MAX_BYTES aborts the clone and the orchestrator falls
  // through to the next path, which pages and stops honestly. The
  // "git" pin is honoured as documented (git then API, no git-binary
  // clone in between) - previously it fell through to the default
  // order, which could return a clone-path result for a "git" pin.
  const attempts: Array<() => Promise<HistoryScanResult>> =
    want === "api" ? [apiPath]
    : want === "clone" ? [clonePath, gitPath, apiPath]
    : want === "git" ? [gitPath, apiPath]
    : [gitPath, clonePath, apiPath];
  let last: HistoryScanResult | null = null;
  let packTooLarge = false;
  for (const attempt of attempts) {
    let result: HistoryScanResult;
    try {
      result = await attempt();
    } catch (e) {
      // A history path must never throw the whole scan: record it and
      // try the next path. Only when every path fails does scan.ts
      // fall back to patches of the most recent commits.
      result = {
        ok: false, findings: [], commitsScanned: 0, patchBytes: 0,
        truncated: false, timedOut: false,
        note: `History path failed (${e instanceof Error ? e.message : "unknown error"}) - trying the next path.`,
        ms: 0, method: "git", cachedCommits: 0, commitsFetched: 0,
        restCalls: 0, gitRequests: 0,
      };
    }
    if (result.ok) {
      if (packTooLarge && result.method === "api") {
        result = {
          ...result,
          note: `This repo's history is too large to clone inside a serverless function, so history was checked through the GitHub API instead.${result.note ? ` ${result.note}` : ""}`,
        };
      }
      return result;
    }
    if (result.packTooLarge) packTooLarge = true;
    last = result;
  }
  // Unreachable in practice (attempts is never empty), but typed.
  return last ?? {
    ok: false, findings: [], commitsScanned: 0, patchBytes: 0,
    truncated: false, timedOut: false, note: "History scan unavailable.", ms: 0, method: "git",
    cachedCommits: 0, commitsFetched: 0, restCalls: 0, gitRequests: 0,
  };
}

/** One plain-English limits line for a history result, for scan.ts to
 *  push into the report's limits. Names the path used, so a partial or
 *  fallback scan is never mistaken for a complete one. */
export function historyLimitsLine(r: HistoryScanResult): string {
  const path =
    r.method === "git" ? "git protocol (no GitHub API quota used)"
    : r.method === "clone" ? "ephemeral git clone"
    : "GitHub API (last resort)";
  const cached = r.cachedCommits > 0 ? `, ${r.cachedCommits} reused from cache` : "";
  return `History scan (${path}): ${r.commitsScanned} commits${cached}, ${(r.patchBytes / 1_000_000).toFixed(1)} MB of patches, ${(r.ms / 1000).toFixed(1)}s.`;
}
