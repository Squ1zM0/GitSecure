// Full-history secret scanning (Phase 2).
//
// Strategy: ephemeral `git clone --no-checkout` of the public repo into a
// fresh mkdtemp dir under /tmp, then stream `git log -p --all` (newest
// commit first — that is git log's default order) through the same
// detectors as the HEAD scan, scanning ADDED lines only, with redacted
// fragments only. The clone dir is deleted in a finally block; nothing
// about the repo is stored after the scan.
//
// Caps — measured on Squ1zM0/TechDirect on 2026-11-25 (see README):
//   62 commits, full `git log -p` 40.8 MB / 255k lines, log generated in
//   0.7 s, detector scan of the 23.4 MB of added lines in 0.7 s, clone
//   ~10 s. Total history step for that repo: ~12 s, inside the 60 s
//   serverless route limit with room for the HEAD scan.
//   MAX_HISTORY_COMMITS = 1000, MAX_HISTORY_PATCH_BYTES = 50 MB,
//   HISTORY_TIMEOUT_MS = 45 s (clone + log together). The patch stream is
//   parsed incrementally, so memory stays bounded even at the cap — the
//   whole patch text is never held in memory at once.
//
// Honesty: if git is unavailable (some serverless runtimes ship no git
// binary) or the clone fails, this returns { ok: false } and the caller
// falls back to the MVP API patch path (5 most recent commits) and says
// so in the report's limits. If the byte/commit/time cap is hit mid-log,
// the findings scanned so far are kept and the report says the history
// scan was truncated at that cap. Public repos only, no auth, no shell:
// git is spawned with an argument array and owner/repo are validated.

import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanLinesForSecrets, type ScannedLine } from "./secrets";
import { isSkippablePath } from "./paths";
import type { SecretFinding } from "./types";

export const MAX_HISTORY_COMMITS = 1000;
export const MAX_HISTORY_PATCH_BYTES = 50_000_000;
export const HISTORY_TIMEOUT_MS = 45_000;
/** One-line plain-English description of the API history path, for the report's limits. */
export const API_HISTORY_NOTE =
  `Full history via the GitHub API (no git binary needed): up to ${MAX_HISTORY_COMMITS} commits / ${MAX_HISTORY_PATCH_BYTES / 1_000_000} MB of patches, ${HISTORY_TIMEOUT_MS / 1000}s cap, newest-first.`;
/** Per-fetch abort timeout, matching scan.ts's ghJson. */
const API_FETCH_TIMEOUT_MS = 12_000;
/** Detail fetches run in a small pool — parallel, never unbounded. */
const API_CONCURRENCY = 5;
/** Added lines buffered per file before a detector pass — bounds memory. */
const CHUNK_LINES = 2000;

export interface HistoryScanResult {
  /** False when git is missing or the clone failed — caller falls back. */
  ok: boolean;
  findings: SecretFinding[];
  commitsScanned: number;
  patchBytes: number;
  truncated: boolean;
  timedOut: boolean;
  /** Human-readable reason when ok is false, or truncation note. */
  note: string | null;
  /** Milliseconds the clone + log step took. */
  ms: number;
  /** Which path produced this result — clone (git) or GitHub API. */
  method: "clone" | "api";
}

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;

function runGit(args: string[], opts: { timeoutMs: number; cwd?: string }): Promise<{ code: number | null; timedOut: boolean }> {
  return new Promise((resolve) => {
    const child = spawn("git", args, { cwd: opts.cwd, stdio: "ignore" });
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      child.kill("SIGKILL");
      resolve({ code: null, timedOut: true });
    }, opts.timeoutMs);
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

/** Stream `git log -p` and scan added lines as they arrive. */
function streamLog(dir: string, deadlineMs: number): Promise<{
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
    let timedOut = false;
    let finished = false;

    const child = spawn(
      "git",
      ["-C", dir, "log", "-p", "--all", "--no-color", "--no-textconv", "--no-ext-diff", "--format=__GS_COMMIT__%H"],
      { stdio: ["ignore", "pipe", "ignore"] },
    );

    const timer = setTimeout(() => {
      if (finished) return;
      timedOut = true;
      child.kill("SIGKILL");
    }, Math.max(1000, deadlineMs - Date.now()));

    // --- incremental diff parser state ---
    let buf = ""; // partial line carried across chunks
    let commit: string | null = null;
    let file: string | null = null;
    let fileSkipped = false;
    let newLine = 0;
    let chunk: ScannedLine[] = [];

    const flushChunk = () => {
      if (chunk.length > 0 && file && !fileSkipped) {
        findings.push(...scanLinesForSecrets({ path: file }, chunk, commit));
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
        if (commitsScanned > MAX_HISTORY_COMMITS) {
          truncated = true;
          child.kill("SIGKILL");
        }
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
      if (patchBytes > MAX_HISTORY_PATCH_BYTES) {
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
      clearTimeout(timer);
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
  });
  if (!NAME_RE.test(owner) || !NAME_RE.test(repo) || owner.includes("..") || repo.includes("..")) {
    return fail("Invalid owner/repo name — history clone skipped.");
  }
  if (!(await gitAvailable())) {
    return fail("No git binary in this runtime — history clone skipped.");
  }
  // cloneUrlOverride exists only so tests can point the clone at a local
  // fixture repo (scripts/test-history.ts). Production callers never pass
  // it: the URL is always the public github.com repo.
  const cloneUrl = cloneUrlOverride ?? `https://github.com/${owner}/${repo}.git`;
  const dir = await mkdtemp(join(tmpdir(), "gitsecure-"));
  try {
    const clone = await runGit(
      ["clone", "--quiet", "--no-checkout", "--single-branch", "--branch", branch, cloneUrl, dir + "/repo"],
      { timeoutMs: HISTORY_TIMEOUT_MS },
    );
    if (clone.timedOut) return fail("History clone timed out.");
    if (clone.code !== 0) return fail("History clone failed (repo may be too large or unreachable).");
    const repoDir = dir + "/repo";
    const log = await streamLog(repoDir, started + HISTORY_TIMEOUT_MS);
    const ms = Date.now() - started;
    let note: string | null = null;
    if (log.timedOut) note = `History scan hit the ${HISTORY_TIMEOUT_MS / 1000}s cap — scanned ${log.commitsScanned} newest commits before stopping.`;
    else if (log.truncated) note = `History scan hit its cap (${MAX_HISTORY_COMMITS} commits / ${MAX_HISTORY_PATCH_BYTES / 1_000_000} MB of patches, newest-first) — scanned ${log.commitsScanned} newest commits.`;
    return { ok: true, findings: log.findings, commitsScanned: log.commitsScanned, patchBytes: log.patchBytes, truncated: log.truncated, timedOut: log.timedOut, note, ms, method: "clone" };
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}

// ---------------------------------------------------------------------------
// API history path (Phase 6). Same guarantees as the clone path, but over
// the GitHub REST API — this is the path that runs on Vercel, where there
// is no git binary. No import from scan.ts here (scan.ts imports this
// module); all fetch / rate-limit handling lives in this file.
//
// Flow: page the commits list (newest-first, 100/page, Link headers) up
// to MAX_HISTORY_COMMITS, then fetch each commit's detail in a pool of 5
// and scan the ADDED lines of each file's patch only, with the same
// detectors, the same skippable-path rules, and the same caps (commits /
// patch bytes / deadline). Findings scanned before a cap are kept.
// Attribution is per-commit: a finding's commit is the 7-char sha of the
// commit whose patch contained it.
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

function rateLimitNote(commitsScanned: number): string {
  return `GitHub API rate limit was hit — scanned ${commitsScanned} commit${commitsScanned === 1 ? "" : "s"} before stopping. Setting a GITHUB_TOKEN raises the limit.`;
}

/** Fetch with a per-request abort timeout (12 s, or the time left to the
 *  deadline, whichever is smaller). Returns null on network failure or
 *  abort — the caller decides whether that fails the scan or just skips
 *  one commit. */
async function apiFetch(url: string, timeoutMs: number): Promise<Response | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(50, Math.min(API_FETCH_TIMEOUT_MS, timeoutMs)));
  try {
    return await fetch(url, { headers: apiHeaders(), signal: controller.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Parse a unified-diff patch into its added lines, with new-file line
 *  numbers taken from the hunk headers — the same shape the clone path
 *  feeds the detectors. Removed lines and context lines are not scanned. */
function parsePatchAddedLines(patch: string): ScannedLine[] {
  const lines: ScannedLine[] = [];
  let newLine = 0;
  for (const raw of patch.split("\n")) {
    const line = raw.replace(/\r$/, "");
    const hunkM = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunkM) {
      newLine = parseInt(hunkM[1], 10);
      continue;
    }
    if (line.startsWith("+++")) continue;
    if (line.startsWith("+")) {
      lines.push({ line: newLine, text: line.slice(1) });
      newLine++;
    } else if (line.startsWith(" ")) {
      newLine++;
    }
    // "-" (removed) lines do not advance newLine.
  }
  return lines;
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
  const fail = (note: string): HistoryScanResult => ({
    ok: false, findings: [], commitsScanned: 0, patchBytes: 0,
    truncated: false, timedOut: false, note, ms: Date.now() - started, method: "api",
  });
  if (!NAME_RE.test(owner) || !NAME_RE.test(repo) || owner.includes("..") || repo.includes("..")) {
    return fail("Invalid owner/repo name — history API scan skipped.");
  }

  const findings: SecretFinding[] = [];
  let commitsScanned = 0;
  let patchBytes = 0;
  let truncated = false; // byte cap hit while scanning patches
  let listTruncated = false; // more commits exist than the commit cap
  let timedOut = false;
  let rateLimited = false;

  // --- Phase 1: page the commits list, newest-first, up to the cap. ---
  const shas: string[] = [];
  let listUrl: string | null = `${apiBase}/repos/${owner}/${repo}/commits?per_page=100&sha=${encodeURIComponent(branch)}`;
  while (listUrl && shas.length < MAX_HISTORY_COMMITS) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      timedOut = true;
      break;
    }
    const res = await apiFetch(listUrl, remaining);
    if (!res) return fail("GitHub API could not be reached — history API scan skipped.");
    if (res.status === 404) return fail("Repository not found (or it is private).");
    if (isApiRateLimited(res)) {
      return { ok: true, findings, commitsScanned, patchBytes, truncated: false, timedOut: false, note: rateLimitNote(0), ms: Date.now() - started, method: "api" };
    }
    if (!res.ok) return fail(`GitHub API answered with an unexpected error (${res.status}) — history API scan skipped.`);
    let page: { sha?: string }[];
    try {
      page = (await res.json()) as { sha?: string }[];
    } catch {
      return fail("GitHub API returned an unreadable response — history API scan skipped.");
    }
    if (!Array.isArray(page)) return fail("GitHub API returned an unexpected response — history API scan skipped.");
    for (const c of page) {
      if (shas.length >= MAX_HISTORY_COMMITS) break;
      if (typeof c.sha === "string" && c.sha) shas.push(c.sha);
    }
    const link = res.headers.get("link");
    const next = link ? /<([^>]+)>;\s*rel="next"/.exec(link)?.[1] ?? null : null;
    if (shas.length >= MAX_HISTORY_COMMITS && next) listTruncated = true;
    listUrl = next;
  }

  // --- Phase 2: fetch each commit's patch (pool of 5) and scan added lines. ---
  let nextIdx = 0;
  const scanCommit = async (sha: string): Promise<void> => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      timedOut = true;
      return;
    }
    const res = await apiFetch(`${apiBase}/repos/${owner}/${repo}/commits/${sha}`, remaining);
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
      findings.push(...scanLinesForSecrets({ path: f.filename }, parsePatchAddedLines(f.patch), sha.slice(0, 7)));
    }
  };

  const worker = async (): Promise<void> => {
    for (;;) {
      if (rateLimited || truncated || timedOut) return;
      if (Date.now() >= deadline) {
        timedOut = true;
        return;
      }
      const idx = nextIdx++;
      if (idx >= shas.length) return;
      await scanCommit(shas[idx]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(API_CONCURRENCY, shas.length) }, () => worker()));

  const wasTruncated = truncated || listTruncated;
  const ms = Date.now() - started;
  let note: string | null = null;
  if (rateLimited) note = rateLimitNote(commitsScanned);
  else if (timedOut) note = `History scan hit the ${timeoutMs / 1000}s cap — scanned ${commitsScanned} newest commits before stopping.`;
  else if (wasTruncated) note = `History scan hit its cap (${MAX_HISTORY_COMMITS} commits / ${MAX_HISTORY_PATCH_BYTES / 1_000_000} MB of patches, newest-first) — scanned ${commitsScanned} newest commits.`;
  return { ok: true, findings, commitsScanned, patchBytes, truncated: wasTruncated, timedOut, note, ms, method: "api" };
}
