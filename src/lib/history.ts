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
    truncated: false, timedOut: false, note, ms: Date.now() - started,
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
    return { ok: true, findings: log.findings, commitsScanned: log.commitsScanned, patchBytes: log.patchBytes, truncated: log.truncated, timedOut: log.timedOut, note, ms };
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}
