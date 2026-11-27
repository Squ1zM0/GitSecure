// GitSecure scanner — public repos only, no auth required (optional
// GITHUB_TOKEN env raises the GitHub API rate limit; it is never logged).
//
// PHASE 8 (2026-11-25): ASYNC SCAN JOBS — no scan dies on a clock
// any more. scanRepo runs to completion in a background job (see
// jobs.ts): the old 55 s race inside the 60 s route limit is gone, so
// a big repo finishes instead of timing out. The API / report page
// wait up to ~50 s for the job (the fast path — TechDirect still
// answers in one request, ~12 s); if the job is still running they
// answer 202 with a job ID and the client polls for live progress.
// OSV detail has no time budget any more either (see osv.ts): every
// advisory gets full detail inside the background job. The tarball
// download guard is a STREAMING buffer switch (the download aborts
// mid-stream past the switch and the streaming reader takes over,
// still scanning every file) — never a scan cap. History caps live in history.ts and are
// owned by the history worker; this file states no history numbers
// any more, and the report's history line carries only the method and
// the exact count scanned. No secret values are stored or logged —
// findings carry redacted fragments only (see secrets.ts / redact.ts).
//
// PHASE 5 (2026-11-25): NO result-count caps anywhere. Every secret
// finding is listed (the old 100 cap is gone), every dependency is
// listed (the old 200 slice is gone), every advisory OSV returns is
// listed (the old 100 cap is gone), and posture / framework findings
// were never capped.
//
// HISTORY DEPTH (Phase 2, API path Phase 6): full history via an ephemeral git clone into
// /tmp, streaming `git log -p --all` newest-first through the same secret
// detectors as the HEAD scan. If git is unavailable in the runtime (Vercel serverless
// ships no git binary) or the clone fails, the scan falls back to the
// API history path (history.ts scanHistoryViaApi: page the commits API,
// fetch each commit's patch, per-commit attribution) — and
// only if that also fails to patches of the 5 most recent commits.
// The report says which path was used and how many commits it scanned.
// A secret deleted long ago in an old commit is now caught.
//
// PHASE 15 (2026-11-26, worker D): ZERO REST CALLS on the happy
// path. The scan's last api.github.com call was the repo-info fetch
// (default branch, size, private flag). All three values now come
// from elsewhere: the default branch and HEAD sha come from one
// git-protocol info/refs request (history.ts resolveRemoteHead —
// github.com, not api.github.com); the repo size is no longer read
// at all, because both gates that needed it are now streaming
// bounds measured while the bytes arrive (the tarball buffer switch
// below, and the history pack bound in history.ts). A missing or
// private repo still fails plainly with the same 404 wording — the
// git protocol answers 401 on info/refs for those, which maps to
// not-found. The REST calls that remain are fallback-only: the
// recursive tree when the tarball is unavailable (per-file fetch
// needs a file list), the API history path when cloning is
// impossible, and the 5-commit patch fallback. None of them runs on
// a happy-path scan (proved by test:zero-rest).
//
// HEAD SCAN (Phase 4): UNLIMITED. The entire HEAD tree is scanned —
// every file, manifests and configs first, then the rest. There is NO
// file-count cap, NO per-file size cap, and NO total-size cap anywhere
// in this code. The only files not
// read are binary / generated / vendored paths (dist, node_modules,
// .next, images, archives — see paths.ts): those are not source files
// to scan, not a cap. The file list comes from the tarball itself
// (its entries ARE the tree — complete by construction, unlike the
// GitHub recursive-tree call, which truncates past ~71k entries);
// the tree API is fetched only as a fallback when the tarball is
// unavailable, so the per-file fallback has a file list. Files are
// read from ONE tarball download (codeload.github.com) instead of
// one HTTPS request per file — measured: 2,802 separate raw fetches
// took ~120 s no matter the concurrency
// (raw.githubusercontent.com answers ~25 requests/s from one
// client), while the 1.7 MB TechDirect tarball downloads in ~1.4 s.
// If the tarball is unavailable, the scan falls back to per-file fetches
// and still scans everything, just slower. External boundaries still
// exist and are reported honestly, never hidden: the GitHub API has
// rate limits, and the tarball download has a streaming buffer switch
// (see TARBALL_BUFFER_SWITCH_BYTES) whose only effect is to change
// transport to the streaming reader. No secret values are stored or
// logged — findings carry redacted fragments only (see secrets.ts / redact.ts).

import { createGunzip } from "node:zlib";
import { Readable } from "node:stream";
import { gunzipSync } from "node:zlib";
import { checkDependencies } from "./osv";
import { emptyProgress, type ScanProgress } from "./progress";
import { scanHistory, resolveRemoteHead, type HistoryScanResult } from "./history";
import { detectInfraFrameworks, infraFindings, parseWorkflowActions } from "./infra";
import { isSkippablePath } from "./paths";
import { computeScore, plainSummary } from "./score";
import { envFileFinding, scanTextForSecrets, type ScannedFile } from "./secrets";
import { fingerprintFrameworks, parseCargoLock, parseCargoToml, parseComposerJson, parseComposerLock, parseCsproj, parseGemfile, parseGemfileLock, parseGoMod, parseGradle, parsePackagesConfig, parsePackageJson, parsePackageLock, parsePoetryLock, parsePomXml, parsePubspecLock, parsePubspecYaml, parsePyprojectToml, parseRequirements, parseYamlLock, viteFindings } from "./frameworks";
import { collectPublicKeyIdentities, ensureTriage, triageFindings } from "./triage";
import { computeUsageForFindings } from "./usage";
import { parseResetAtMs } from "./rate-limit";
import type { Dependency, Framework, FullReport, HeadPartial, PostureIssue, SecretFinding, Vulnerability } from "./types";

export const HISTORY_DEPTH = "Full history, newest first.";
// NOTE (Phase 8): history is scanned by scanHistory() in history.ts —
// git protocol first (no REST quota, cached on repeats), then the
// git-binary clone, then the GitHub API as a last resort. This file
// states no history numbers: the report's history line is built from
// the live result (method + exact commits scanned) in buildLimits()
// below. The git path reports live progress via onProgress; the clone
// and API paths report on return, which is honest about what is known
// when.

const GH_API = "https://api.github.com";
const HISTORY_COMMITS = 5;

/** Error kind a scan can fail with, mapped to an honest HTTP status.
 *  The report page and the scan API both render from `kind` + `message`,
 *  so a failed scan says plainly what happened instead of a bare 404. */
export type ScanErrorKind = "not-found" | "private" | "rate-limit" | "timeout" | "bad-format" | "upstream" | "head-moved";
export class ScanError extends Error {
  readonly status: number;
  readonly kind: ScanErrorKind;
  /** Phase 15 (rate-limit recovery): when GitHub's response said when
   *  its request limit resets, the epoch-ms reset time — so the error
   *  page can say honestly how long to wait instead of stranding the
   *  user. Absent when GitHub did not say (copy falls back to
   *  "resets within the hour"). */
  readonly resetAtMs?: number;
  constructor(status: number, kind: ScanErrorKind, message: string, opts?: { resetAtMs?: number }) {
    super(message);
    this.status = status;
    this.kind = kind;
    if (opts?.resetAtMs !== undefined) this.resetAtMs = opts.resetAtMs;
  }
}

/** Owner/repo names on GitHub: letters, numbers, dots, hyphens,
 *  underscores. Anything else is a typo or a pasted URL that was not
 *  cleaned up — fail fast with a 400 instead of burning a scan on it. */
const NAME_RE = /^[A-Za-z0-9_.-]+$/;
export function validateOwnerRepo(owner: string, repo: string): void {
  for (const [label, value] of [["owner", owner], ["repo", repo]] as const) {
    if (!value || value === "." || value === ".." || !NAME_RE.test(value)) {
      throw new ScanError(
        400,
        "bad-format",
        `That doesn't look like a valid ${label} name. Owner and repo names can only use letters, numbers, dots, hyphens and underscores — check for typos or extra characters.`,
      );
    }
  }
}

/** Phase 8: the 55 s scan timeout is GONE. A scan is no longer raced
 *  against a clock — it runs to completion in a background job (see
 *  jobs.ts) and the caller polls for progress. scanRepo itself has no
 *  deadline. Individual GitHub fetches still have their own short
 *  abort timeouts (12 s in ghJson, 10 s per raw file, 30 s for the
 *  tarball download) — a hung upstream request fails that fetch, not
 *  the scan, and the report says which files could not be fetched. */

function ghHeaders(): Record<string, string> {
  const headers: Record<string, string> = { Accept: "application/vnd.github+json", "User-Agent": "GitSecure/0.1" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return headers;
}

async function ghJson<T>(url: string): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const res = await fetch(url, { headers: ghHeaders(), signal: controller.signal, cache: "no-store" });
    if (res.status === 404) throw new ScanError(404, "not-found", "Repository not found (or it is private). GitSecure scans public repos only.");
    if (res.status === 429 || (res.status === 403 && res.headers.get("x-ratelimit-remaining") === "0")) {
      // Phase 15 (rate-limit recovery): GitHub's response carries the
      // reset time — keep it on the error so the page can say honestly
      // how long to wait, instead of stranding the user with no sense
      // of the wait. No token, per Freddy's standing ruling.
      throw new ScanError(429, "rate-limit", "GitHub's request limit was hit, so this scan couldn't run right now. Please try again in a few minutes.", { resetAtMs: parseResetAtMs(res.headers) ?? undefined });
    }
    if (res.status === 403) throw new ScanError(502, "upstream", "GitHub refused the request (403). The repo may be blocked or temporarily unavailable — try again later.");
    if (!res.ok) throw new ScanError(502, "upstream", `GitHub answered with an unexpected error (${res.status}). Try again in a bit.`);
    return (await res.json()) as T;
  } catch (err) {
    if (err instanceof ScanError) throw err;
    if (err instanceof Error && err.name === "AbortError") {
      throw new ScanError(504, "timeout", "GitHub took too long to answer. Try again.");
    }
    throw new ScanError(502, "upstream", "GitHub couldn't be reached. Try again in a bit.");
  } finally {
    clearTimeout(timer);
  }
}

async function fetchRaw(owner: string, repo: string, branch: string, path: string, timeoutMs: number = 10_000): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`, { signal: controller.signal, cache: "no-store" });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function isSkippable(path: string): boolean {
  return isSkippablePath(path);
}

/** Priority: manifests, configs, workflows and source first — so the file
 *  cap still covers the files that matter on a big repo like TechDirect. */
function priority(path: string): number {
  const base = path.split("/").pop() ?? "";
  if (["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.toml", "Cargo.lock", "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile", "go.mod", "go.sum", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock", "pom.xml", "build.gradle", "build.gradle.kts", "packages.config", "pubspec.yaml", "pubspec.lock"].includes(base) || base.endsWith(".csproj")) return 0;
  if (path.startsWith(".github/")) return 1;
  if (/\.(env|config\.(js|ts|mjs))$/.test(path) || base === ".gitignore" || base === "SECURITY.md") return 2;
  if (/\.(ts|tsx|js|jsx|py|rs|json|yaml|yml|toml|sh)$/.test(path)) return 3;
  if (/\.(md|txt)$/.test(path)) return 4;
  return 5;
}

export interface ScanOptions {
  historyCommits?: number;
  /** Called with honest live progress as each phase lands. */
  onProgress?: (p: ScanProgress) => void;
  /** Phase 15 (finding 1): called the moment the repo's branch, HEAD
   *  sha, and history path are known — before any file is fetched —
   *  so the chunk driver can still build a resume cursor if the
   *  current-files download later times out. Nothing scanned yet
   *  means nothing to resume from, so a timeout before this fires
   *  still throws. */
  onHeadMeta?: (meta: { branch: string; headSha: string; historyMethod: "git" | "api" }) => void;
  /** OSV budgets for this scan. Default (Phase 8): no budget — every
   *  pinned dep is queried and every advisory gets full detail. */
  osv?: { queryBudgetMs?: number | null; detailBudgetMs?: number | null };
  /** Phase 16 (Worker B): absolute wall-clock deadline (epoch ms)
   *  for this scan step, passed by the chunked driver (runScanLoop)
   *  so a step started late still ends by the loop deadline.
   *  Sub-steps cap their own timeouts at the time left (repo-meta
   *  fetch, tarball download/stream, per-file fetches, OSV phases).
   *  Unset = the old fixed timeouts, so one-shot callers (scanRepo,
   *  the chunk endpoint) behave exactly as before. */
  deadlineMs?: number;
}

/** Fetch the whole HEAD tree from ONE tarball download
 *  (codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{branch}).
 *  Returns a Map of repo-relative path -> text content for every
 *  non-skipped file. The tarball is a snapshot of the branch HEAD,
 *  so the file set and contents match the per-file raw fetches —
 *  this only changes how the bytes arrive, not what is scanned. Entries are never written to disk, only held in memory
 *  for the scan. A path-traversal entry (../ or absolute) is ignored.
 *  Throws on any failure so the caller can fall back to per-file
 *  fetching — a failed tarball must never silently shrink the scan.
 *  Phase 8: the download is read chunk by chunk and aborted
 *  mid-stream instead of buffering an unbounded response first.
 *  Phase 15 (worker D): the abort point is a BUFFER SWITCH, not a
 *  scan cap — past TARBALL_BUFFER_SWITCH_BYTES the download stops
 *  and the caller runs the streaming reader instead, which scans the
 *  same files with bounded memory. The switch replaces the old 1 GB
 *  repo-size gate (which needed the REST repo-info call): codeload
 *  sends no Content-Length, so the compressed size can only be
 *  measured while the bytes arrive. 100 MB compressed is ~300–500 MB
 *  decompressed for source-heavy repos (gzip runs ~3–5x), which
 *  fits a 1 GB function with headroom for the rest of the scan.
 *  What remains a physical bound (not a cap) is memory for the
 *  decompressed tar itself — gunzip materialises it whole, so a
 *  repo whose decompressed tree cannot fit in memory takes the
 *  streaming path instead. */
export class TarballTooLargeForBufferError extends Error {
  readonly bytes: number;
  constructor(bytes: number) {
    super(`tarball download passed ${TARBALL_BUFFER_SWITCH_BYTES} bytes (${bytes} bytes read) — switching to the streaming reader`);
    this.name = "TarballTooLargeForBufferError";
    this.bytes = bytes;
  }
}
/** Compressed tarball bytes at which the whole-buffer path gives up
 *  and the streaming reader takes over. NOT a scan cap: the streaming
 *  path scans every file, just with bounded memory. */
export const TARBALL_BUFFER_SWITCH_BYTES = 100_000_000;
async function fetchHeadFilesViaTarball(
  owner: string,
  repo: string,
  branch: string,
  onFiles?: (fetched: number) => void,
  // Phase 16: abort timeout for the download. Default 30 s; the
  // chunked driver passes the time left to its loop deadline so a
  // HEAD chunk started late still ends by that deadline.
  timeoutMs: number = 30_000,
): Promise<Map<string, string>> {
  const url = `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/heads/${encodeURIComponent(branch)}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let gz: Buffer;
  try {
    const res = await fetch(url, { signal: controller.signal, cache: "no-store" });
    if (!res.ok) throw new Error(`tarball fetch ${res.status}`);
    if (!res.body) throw new Error("tarball has no body");
    // Stream the download: abort as soon as the switch trips, instead
    // of buffering an unbounded response and checking afterwards.
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > TARBALL_BUFFER_SWITCH_BYTES) {
        controller.abort();
        throw new TarballTooLargeForBufferError(total);
      }
      chunks.push(value);
    }
    gz = Buffer.concat(chunks.map((c) => Buffer.from(c)));
  } catch (err) {
    // Phase 15 (worker D): a download ABORT (stall / 30 s timer) is a
    // timeout, not a missing tarball — it becomes the ScanError 504
    // the chunk driver turns into a resumable partial cursor, exactly
    // like the streaming path. Any other failure (404, 500, parse
    // error) still falls through to the per-file fallback in the
    // caller. The buffer-switch error above is not an abort: it is
    // thrown by this code, not by the aborted stream, so it is
    // unaffected (its name is TarballTooLargeForBufferError).
    if (err instanceof Error && err.name === "AbortError") {
      throw new ScanError(504, "timeout", "GitHub took too long to answer. Try again.");
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
  const tar = gunzipSync(gz);
  const files = new Map<string, string>();
  // Minimal tar reader: 512-byte headers, octal size at 124..136,
  // typeflag at 156 ('0'/NUL = file, '5' = dir, 'L' = GNU long name,
  // 'x'/'g' = extended headers to skip). ustar prefix at 345..500.
  let offset = 0;
  let longName: string | null = null;
  const readString = (b: Buffer, start: number, len: number) => b.toString("utf8", start, start + len).split("\0")[0];
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break; // end-of-archive marker
    const size = parseInt(readString(header, 124, 12).trim() || "0", 8);
    const typeflag = String.fromCharCode(header[156]);
    const nameField = readString(header, 0, 100);
    const prefix = readString(header, 345, 155);
    const name = longName ?? (prefix ? `${prefix}/${nameField}` : nameField);
    longName = null;
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > tar.length) throw new Error("truncated tarball");
    if (typeflag === "L") {
      longName = tar.toString("utf8", dataStart, dataEnd).split("\0")[0];
    } else if (typeflag === "0" || typeflag === "\0") {
      // Tarball root is "{owner}-{repo}-{sha}/" — strip the first segment.
      const slash = name.indexOf("/");
      const rel = slash >= 0 ? name.slice(slash + 1) : name;
      if (rel && !rel.startsWith("../") && !rel.startsWith("/") && !isSkippable(rel)) {
        files.set(rel, tar.toString("utf8", dataStart, dataEnd));
        onFiles?.(files.size);
      }
    }
    // else: directory ('5'), symlink ('2'), extended header ('x'/'g') — skip.
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  return files;
}

/** Per-file fallback: fetch each file from raw.githubusercontent.com
 *  with a worker pool. Used only when the tarball download fails.
 *  There is NO file-count or size cap here — every file in `chosen`
 *  is fetched. The pool size is only about parallelism, not about
 *  stopping early. Measured: raw fetching is ~25 files/s from one
 *  client no matter the pool size, so a 2,802-file repo takes ~120 s
 *  this way — which is why the tarball is the primary path. Progress
 *  is reported to the caller's progress callback as files land. */
const HEAD_FETCH_CONCURRENCY = 10;
async function fetchHeadFiles(
  owner: string,
  repo: string,
  branch: string,
  chosen: { path: string; size?: number }[],
  onFiles?: (fetched: number) => void,
  // Phase 16: wall-clock budget for the whole per-file fallback
  // (the tarball-unavailable path). Unset = no budget, as before.
  // A chunk that runs out of time throws the timeout ScanError the
  // chunk driver turns into a resumable partial cursor.
  opts?: { budgetMs?: number },
): Promise<Map<string, string>> {
  const files = new Map<string, string>();
  let next = 0;
  const started = Date.now();
  const budgetMs = opts?.budgetMs ?? null;
  const workers = Array.from({ length: HEAD_FETCH_CONCURRENCY }, async () => {
    while (next < chosen.length) {
      if (budgetMs != null && Date.now() - started > budgetMs) {
        throw new ScanError(
          504,
          "timeout",
          "The current-files download took too long, so this chunk stopped before finishing. Nothing was half-reported — run the scan again and it picks up from the start of the current-files step.",
        );
      }
      const entry = chosen[next++];
      // Phase 16: a fetch started just before the budget ends must
      // not run its full 10 s past the deadline — cap it at the time
      // left. Without a caller budget this is the old 10 s default.
      const fetchTimeout = budgetMs != null ? Math.min(10_000, Math.max(500, started + budgetMs - Date.now())) : 10_000;
      const content = await fetchRaw(owner, repo, branch, entry.path, fetchTimeout);
      if (content == null) continue;
      files.set(entry.path, content);
      onFiles?.(files.size);
    }
  });
  await Promise.all(workers);
  return files;
}

/** Dedupe secret findings (same type/file/line/fragment/commit).
 *  Phase 5: NO cap — every finding is kept, however many there are.
 *  Exported so tests can prove a 150-finding set comes back whole. */
export function dedupeSecrets(secrets: SecretFinding[]): SecretFinding[] {
  const seen = new Set<string>();
  return secrets.filter((s) => {
    const key = `${s.type}:${s.file}:${s.line}:${s.fragment}:${s.commit}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Build the report's "About this scan" lines (Phase 8 rewrite).
 *  There is no list of caps any more. A complete scan says so once,
 *  with the exact counts — files, history commits, dependencies
 *  checked, advisories with full detail — and nothing else. A scan
 *  that could not cover everything says exactly what it could not
 *  cover, with the exact numbers, one line per fact. The last line is
 *  always the standing facts (public repos only; secrets never
 *  stored/logged/shown in full), which are facts, not caps. Pure
 *  function of its inputs so tests can prove the copy. */
export interface BuildLimitsInput {
  filesScanned: number;
  filesTotal: number;
  historyOk: boolean;
  /** "clone" (git binary), "git" (git-protocol path, no binary, no
   *  REST quota — added by the history worker in Phase 8), or "api". */
  historyMethod: "clone" | "api" | "git";
  historyCommitsScanned: number;
  historyMs: number;
  historyNote: string | null;
  depsChecked: number;
  depsQueryable: number;
  depsTotal: number;
  advisoriesTotal: number;
  detailCapped: number;
  treeTruncated: boolean;
  tarballFallback: boolean;
  /** Phase 11: true when at least one history finding carries usage
   *  computed from the HEAD files only (historyOnly). */
  historyUsageFromHead?: boolean;
}
export function buildLimits(input: BuildLimitsInput): string[] {
  const limits: string[] = [];
  if (input.filesScanned >= input.filesTotal) {
    limits.push(`Scanned all ${input.filesTotal} files in the tree (binary, dist, node_modules and .next skipped — generated/vendored paths, not source files).`);
  } else {
    limits.push(`Fetched ${input.filesScanned} of ${input.filesTotal} files in the tree — ${input.filesTotal - input.filesScanned} could not be fetched from GitHub, so they were not scanned.`);
  }
  if (input.historyOk) {
    const methodLabel =
      input.historyMethod === "api"
        ? "GitHub API — no git binary in this runtime"
        : input.historyMethod === "git"
          ? "git protocol — no git binary, no REST quota"
          : "ephemeral git clone";
    limits.push(`History checked: ${input.historyCommitsScanned} commit${input.historyCommitsScanned === 1 ? "" : "s"}, newest first (${methodLabel}).`);
  } else {
    limits.push(`History scan took ${(input.historyMs / 1000).toFixed(1)}s (clone and API history paths both unavailable; last-resort fallback scanned ${input.historyCommitsScanned} most recent commits).`);
  }
  if (input.historyNote) limits.push(input.historyNote);
  // Phase 8: the OSV query and detail phases have no time budget, so a
  // complete scan checks every pinned dep and details every advisory.
  // These lines only appear when a caller passed an explicit budget (or
  // OSV was unreachable mid-scan) and something was left uncovered.
  if (input.depsChecked < input.depsQueryable) {
    limits.push(`Dependency flaw check: ${input.depsChecked} of ${input.depsQueryable} pinned dependencies were checked against the flaw database (OSV.dev) — the rest were not checked for flaws in this scan. All ${input.depsTotal} dependencies are still listed in this report.`);
  }
  if (input.detailCapped > 0) {
    limits.push(`Full advisory detail (a plain summary, a severity score, and the version that fixes it) fetched for ${input.advisoriesTotal - input.detailCapped} of ${input.advisoriesTotal} listed advisories; ${input.detailCapped} listed with advisory ID only.`);
  }
  if (input.treeTruncated) limits.push("GitHub returned a truncated file tree — some files were not scanned. The tree was too large for GitHub to return in one response.");
  if (input.tarballFallback) limits.push("Tarball download was unavailable, so files were fetched one by one instead — same files, just slower.");
  if (input.historyUsageFromHead) limits.push("For secrets found in history, usage (whether anything still references the key) was checked against the current files only — the old commit's files are gone, so a reference that existed then but not now is not counted.");
  limits.push("Public repos only. No secret is ever stored, logged, or shown in full.");
  return limits;
}


/** Fetch the branch HEAD sha (one commits-list call, newest commit
 *  only). Phase 15 (worker D): the happy-path scan no longer calls
 *  this — scanHead resolves the HEAD sha over the git protocol
 *  instead (history.ts resolveRemoteHead). This stays for the
 *  chunked driver's resume re-validation (chunks.ts), where the
 *  branch is already known and the pinned HEAD sha is re-checked.
 *  Throws ScanError 404 when the repo has no commits at all —
 *  an empty repo has no HEAD to scan. */
export async function fetchHeadSha(owner: string, repo: string, branch: string): Promise<string> {
  const commits = await ghJson<{ sha: string }[]>(
    `${GH_API}/repos/${owner}/${repo}/commits?per_page=1&sha=${encodeURIComponent(branch)}`,
  );
  const sha = commits[0]?.sha;
  if (!sha) throw new ScanError(404, "not-found", "Repository not found (or it is private). GitSecure scans public repos only.");
  return sha;
}

// ---------------------------------------------------------------------------
// Streaming HEAD tarball (Phase 9).
//
// The whole-buffer tarball path above (fetchHeadFilesViaTarball) works
// for repos up to ~1 GB, but a repo like torvalds/linux (~4 GB) would
// OOM-crash a 1 GB serverless function when its ~1.4 GB decompressed
// tree is materialised whole. The streaming path below processes the
// tarball as it downloads: entries are gunzipped incrementally, each
// file is secret-scanned the moment its bytes arrive, and only the
// files the later steps actually READ (manifests, configs, workflows,
// infra files — see retainHeadFile) are kept in memory. Peak memory
// is roughly the largest single file plus the gunzip window, not the
// whole tree. A chunked scan of a giant repo therefore survives the
// HEAD step instead of dying in it.
// ---------------------------------------------------------------------------

/** Retained manifest/config bytes cap in streaming mode — a bound on
 *  memory, not on coverage: files past it are still secret-scanned,
 *  just not kept for framework/infra reading (and the report says so). */
export const RETAINED_HEAD_BYTES_BUDGET = 100_000_000;

/** Which files the post-HEAD steps actually read content from, so the
 *  streaming path knows what to keep. Everything else is secret-scanned
 *  on the fly and dropped. The list is the exact union of what the
 *  downstream readers touch: manifests (priority 0), workflows and
 *  configs (priority 1–2), Docker / compose / Terraform / K8s files
 *  (infra.ts reads those by name), and .env / .ts / .js files (the
 *  VITE_ scan in frameworks.ts reads those). */
export function retainHeadFile(path: string): boolean {
  const base = path.split("/").pop() ?? "";
  if (priority(path) <= 2) return true;
  if (base === "Dockerfile" || base.startsWith("Dockerfile.")) return true;
  if (["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "vercel.json"].includes(base)) return true;
  if (path.endsWith("supabase/config.toml")) return true;
  if (/\.tf$/.test(path) || /\.ya?ml$/.test(path)) return true;
  if (/\.(ts|tsx|js|jsx)$/.test(path)) return true;
  return false;
}

interface TarEntry {
  rel: string;
  size: number;
  typeflag: string;
}

/** One all-zero 512-byte block, for the end-of-archive check — memcmp
 *  instead of a per-byte JS callback over every header (torvalds/linux
 *  has ~97k headers; `header.every` cost seconds there). */
const ZERO_BLOCK = Buffer.alloc(512);

/** Parse one 512-byte tar header. Returns null on the end-of-archive
 *  marker (all-zero block). */
function parseTarHeader(header: Buffer, longName: string | null): TarEntry | null {
  if (header.equals(ZERO_BLOCK)) return null;
  const readString = (b: Buffer, start: number, len: number) => b.toString("utf8", start, start + len).split("\0")[0];
  const size = parseInt(readString(header, 124, 12).trim() || "0", 8);
  const typeflag = String.fromCharCode(header[156]);
  const nameField = readString(header, 0, 100);
  const prefix = readString(header, 345, 155);
  const name = longName ?? (prefix ? `${prefix}/${nameField}` : nameField);
  const slash = name.indexOf("/");
  const rel = slash >= 0 ? name.slice(slash + 1) : name;
  return { rel, size, typeflag };
}

/** Stream the HEAD tarball and call onEntry(path, content) for every
 *  non-skipped file, in tarball order, as its bytes arrive. Nothing is
 *  held after onEntry returns. Throws on any transport/parse failure
 *  (the caller falls back to per-file fetches) or ScanError 504 when
 *  the chunk's time budget runs out mid-download — the HEAD chunk is
 *  then retried cleanly from its cursor, never half-reported. */
export async function streamHeadFilesViaTarball(
  owner: string,
  repo: string,
  branch: string,
  onEntry: (path: string, content: string) => void,
  opts?: { onCount?: (scanned: number) => void; budgetMs?: number },
): Promise<{ scanned: number }> {
  const started = Date.now();
  const budgetMs = opts?.budgetMs ?? 50_000;
  const url = `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/heads/${encodeURIComponent(branch)}`;
  const controller = new AbortController();
  // Phase 16: the abort timer also covers a stalled mid-body stream
  // (it used to be cleared once headers arrived, so a stall after
  // that hung forever — the per-chunk budget check below only runs
  // when a chunk arrives). Capped at the caller's budget when one is
  // passed, so a chunk started late in a loop still ends by the loop
  // deadline instead of at 55 s. Cleared in the outer finally, once
  // the stream is done.
  const timer = setTimeout(() => controller.abort(), Math.min(55_000, budgetMs));
  let res: Response;
  try {
    res = await fetch(url, { signal: controller.signal, cache: "no-store" });
    if (!res.ok) throw new Error(`tarball fetch ${res.status}`);
    if (!res.body) throw new Error("tarball has no body");
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
  const input = Readable.fromWeb(res.body as unknown as Parameters<typeof Readable.fromWeb>[0]);
  // Large zlib chunks: the default 16 KB chunkSize made the async
  // iterator turn ~1.7 GB of Linux into ~260k tiny chunks, each paying
  // iterator + Buffer.concat overhead. 1 MB chunks cut that to ~1.7k
  // without holding more than one chunk at a time.
  const gunzip = createGunzip({ chunkSize: 1024 * 1024 });
  // Phase 15 (finding 1): a body-stream error mid-download (a reset
  // codeload connection, an abort) is an unhandled 'error' event on
  // `input` unless someone listens — pipe() does not forward it, so
  // the chunk crashes instead of failing cleanly. Forward it into
  // gunzip, whose async iterator the try/catch below already watches:
  // an AbortError there becomes the ScanError 504 timeout the chunk
  // driver turns into a partial cursor.
  input.on("error", (err) => gunzip.destroy(err));
  input.pipe(gunzip);
  let pending = Buffer.alloc(0);
  let longName: string | null = null;
  let cur: { rel: string; size: number; received: number; chunks: Buffer[]; discard: boolean } | null = null;
  let padRemaining = 0;
  let scanned = 0;
  let done = false;
  try {
    for await (const chunk of gunzip) {
      pending = Buffer.concat([pending, chunk as Buffer]);
      for (;;) {
        if (done) break;
        if (padRemaining > 0) {
          const take = Math.min(padRemaining, pending.length);
          pending = pending.subarray(take);
          padRemaining -= take;
          if (padRemaining > 0) break;
          continue;
        }
        if (cur) {
          const need = cur.size - cur.received;
          const take = Math.min(need, pending.length);
          if (take > 0) {
            cur.chunks.push(pending.subarray(0, take));
            cur.received += take;
            pending = pending.subarray(take);
          }
          if (cur.received < cur.size) break; // wait for more bytes
          // File complete: hand it over, then skip its padding.
          const content = Buffer.concat(cur.chunks).toString("utf8");
          if (!cur.discard) {
            onEntry(cur.rel, content);
            scanned++;
            opts?.onCount?.(scanned);
          } else if (cur.rel === "__GS_LONGNAME__") {
            longName = content.split("\0")[0];
          }
          padRemaining = (512 - (cur.size % 512)) % 512;
          cur = null;
          continue;
        }
        // Header mode.
        if (pending.length < 512) break;
        const header = pending.subarray(0, 512);
        pending = pending.subarray(512);
        const entry = parseTarHeader(header, longName);
        longName = null;
        if (entry === null) {
          done = true; // end-of-archive marker
          break;
        }
        if (entry.typeflag === "L") {
          cur = { rel: "__GS_LONGNAME__", size: entry.size, received: 0, chunks: [], discard: true };
          continue;
        }
        if (entry.typeflag !== "0" && entry.typeflag !== "\0") {
          // Directory, symlink, extended header — skip its data.
          cur = { rel: "", size: entry.size, received: 0, chunks: [], discard: true };
          continue;
        }
        const rel = entry.rel;
        const discard = !rel || rel.startsWith("../") || rel.startsWith("/") || isSkippable(rel);
        cur = { rel, size: entry.size, received: 0, chunks: [], discard };
      }
      if (done) break;
      if (Date.now() - started > budgetMs) {
        controller.abort();
        throw new ScanError(
          504,
          "timeout",
          "The current-files download took too long, so this chunk stopped before finishing. Nothing was half-reported — run the scan again and it picks up from the start of the current-files step.",
        );
      }
    }
  } catch (err) {
    if (err instanceof ScanError) throw err;
    if (err instanceof Error && (err.name === "AbortError" || /aborted/i.test(err.message))) {
      throw new ScanError(
        504,
        "timeout",
        "The current-files download took too long, so this chunk stopped before finishing. Nothing was half-reported — run the scan again and it picks up from the start of the current-files step.",
      );
    }
    throw err;
  } finally {
    clearTimeout(timer);
    input.destroy();
    gunzip.destroy();
  }
  return { scanned };
}

/** Per-file fallback for streaming mode: same onEntry contract as the
 *  streaming tarball path, but files are fetched one by one (pool of
 *  10) and handed over the moment they land, so memory stays bounded.
 *  Used only when the tarball download fails. */
export async function streamHeadFilesPerFile(
  owner: string,
  repo: string,
  branch: string,
  chosen: { path: string; size?: number }[],
  onEntry: (path: string, content: string) => void,
  opts?: { onCount?: (scanned: number) => void; budgetMs?: number },
): Promise<{ scanned: number }> {
  const started = Date.now();
  const budgetMs = opts?.budgetMs ?? 50_000;
  let scanned = 0;
  let next = 0;
  const workers = Array.from({ length: HEAD_FETCH_CONCURRENCY }, async () => {
    while (next < chosen.length) {
      if (Date.now() - started > budgetMs) {
        throw new ScanError(
          504,
          "timeout",
          "The current-files download took too long, so this chunk stopped before finishing. Nothing was half-reported — run the scan again and it picks up from the start of the current-files step.",
        );
      }
      const entry = chosen[next++];
      // Phase 16: a fetch started just before the budget ends must
      // not run its full 10 s past the deadline — cap it at the time
      // left. Without a caller budget this is the old 10 s default.
      const fetchTimeout = Math.min(10_000, Math.max(500, started + budgetMs - Date.now()));
      const content = await fetchRaw(owner, repo, branch, entry.path, fetchTimeout);
      if (content == null) continue;
      onEntry(entry.path, content);
      scanned++;
      opts?.onCount?.(scanned);
    }
  });
  await Promise.all(workers);
  return { scanned };
}

/** Security posture from the retained HEAD files (no OSV input — the
 *  OSV-unavailable item is appended by assembleReport, which is the
 *  only place that knows whether OSV answered). Pure function of the
 *  files map, so the HEAD chunk and the assembler share it exactly. */
export function buildPosture(files: Map<string, string>): PostureIssue[] {
  const posture: PostureIssue[] = [];
  const paths = new Set(files.keys());
  const has = (p: string) => [...paths].some((x) => x === p || x.endsWith(`/${p}`));
  if (!has("SECURITY.md")) posture.push({ id: "no-security-md", title: "No SECURITY.md", severity: "low", detail: "There is no SECURITY.md telling people how to report a vulnerability.", fix: "Add a SECURITY.md with a contact address and a response timeframe." });
  if (![...paths].some((p) => p.includes("dependabot"))) posture.push({ id: "no-dependabot", title: "No Dependabot config", severity: "low", detail: "No .github/dependabot.yml was found, so dependency updates are not automated.", fix: "Add .github/dependabot.yml to get automated security update pull requests." });
  const gitignore = files.get(".gitignore") ?? [...files.entries()].find(([p]) => p.endsWith("/.gitignore"))?.[1];
  if (!gitignore) {
    posture.push({ id: "no-gitignore", title: "No .gitignore", severity: "medium", detail: "There is no .gitignore, so secrets and build output can be committed by accident.", fix: "Add a .gitignore covering .env, node_modules, *.pem and build output." });
  } else {
    const missing = [".env", "node_modules", "*.pem"].filter((pat) => !gitignore.includes(pat));
    if (missing.length > 0) posture.push({ id: "gitignore-gaps", title: ".gitignore gaps", severity: "medium", detail: `.gitignore does not cover: ${missing.join(", ")}.`, fix: `Add ${missing.join(", ")} to .gitignore.` });
  }
  if ([...paths].some((p) => /(^|\/)\.env(\.|$)/.test(p) && !p.endsWith(".env.example"))) {
    posture.push({ id: "env-committed", title: ".env file committed", severity: "high", detail: "An environment file is committed to the repo.", fix: "Remove it from the repo and git history, add .env to .gitignore, and rotate every credential in it." });
  }
  // GitHub Actions dangers.
  for (const [path, content] of files) {
    if (!path.startsWith(".github/workflows/")) continue;
    if (/pull_request_target/.test(content)) posture.push({ id: "actions-pr-target", title: "Workflow uses pull_request_target", severity: "high", detail: `${path} runs on pull_request_target, which can expose secrets to fork pull requests if it checks out untrusted code.`, fix: "Avoid pull_request_target unless you need it, and never check out PR code in that workflow." });
    if (/permissions:\s*write-all/.test(content)) posture.push({ id: "actions-write-all", title: "Workflow grants write-all permissions", severity: "medium", detail: `${path} grants write-all permissions to the workflow token.`, fix: "Grant only the permissions each job needs." });
    if (/echo\s+.*\$\{\{\s*secrets\./.test(content)) posture.push({ id: "actions-secret-echo", title: "Workflow may print a secret", severity: "high", detail: `${path} echoes a secret value, which can leak it into workflow logs.`, fix: "Never echo secrets. Mask them and pass them only to the step that needs them." });
    if (/(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:sh|bash)\b/.test(content)) posture.push({ id: "actions-curl-pipe-shell", title: "Workflow pipes a download straight into a shell", severity: "high", detail: `${path} downloads a script and pipes it straight into sh or bash, so whatever the server returns runs with the workflow's permissions — a compromised or hijacked download owns the runner.`, fix: "Download the script to a file, verify its checksum or signature, then run the file — never pipe a download into a shell." });
  }
  for (const v of viteFindings(files)) {
    posture.push({ id: `vite-${v.title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`, title: v.title, severity: v.severity, detail: v.detail, fix: v.title.includes("VITE_") ? "Move real secrets out of VITE_ variables — use server-side secrets instead." : "Restrict the dev server to localhost and review the plugins you install." });
  }
  // Phase 6, Tier 3 infra findings (Docker / K8s / Terraform / Actions).
  // Each detail ends with "Fix: …" — split it out into the fix field.
  for (const v of infraFindings(files)) {
    const fixIdx = v.detail.indexOf("Fix: ");
    posture.push({
      id: `infra-${v.title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
      title: v.title,
      severity: v.severity,
      detail: fixIdx >= 0 ? v.detail.slice(0, fixIdx).trim() : v.detail,
      fix: fixIdx >= 0 ? v.detail.slice(fixIdx + 5).trim() : v.detail,
    });
  }
  return posture;
}

/** HEAD chunk (Phase 9): everything the scan learns from the current
 *  files, in one invocation — the pinned HEAD sha, the file list
 *  (from the tarball itself — its entries ARE the tree, complete by
 *  construction, unlike the recursive-tree API, which truncates
 *  past ~71k entries, so for a repo like torvalds/linux the tarball
 *  is the only complete list), HEAD secrets, frameworks,
 *  dependencies, and posture.
 *  This is the first chunk of every scan and the only chunk that
 *  touches the file list: later chunks (history, assemble) never
 *  re-fetch it. The caller keeps the returned partial and passes it
 *  back at assemble time; the server never stores it.
 *
 *  Phase 15 (worker D): ZERO api.github.com calls on the happy
 *  path. The branch and HEAD sha come from one git-protocol
 *  info/refs request (resolveRemoteHead), and the file list comes
 *  from the tarball itself — the recursive-tree API is fetched only
 *  when the tarball is unavailable and the per-file fallback needs
 *  a file list. Two transports, chosen by the download itself: the
 *  whole-buffer tarball path for tarballs up to
 *  TARBALL_BUFFER_SWITCH_BYTES (TechDirect's 1.7 MB tarball scans
 *  this way, with the full file set kept for the usage search);
 *  past that the streaming reader takes over (see
 *  streamHeadFilesViaTarball) so the HEAD step cannot OOM the
 *  function. Either way every non-skipped file is checked for
 *  secrets — the transport only changes how the bytes arrive. */
export async function scanHead(
  owner: string,
  repo: string,
  options: ScanOptions = {},
): Promise<HeadPartial> {
  validateOwnerRepo(owner, repo);
  const progress: ScanProgress = emptyProgress();
  const emit = () => options.onProgress?.({ ...progress });
  // Phase 16: time left to the loop deadline, recomputed at each
  // sub-step so every timeout below is capped at what remains.
  const remainingMs = () => (options.deadlineMs != null ? options.deadlineMs - Date.now() : null);
  // Phase 15 (worker D): branch + HEAD sha over the git protocol —
  // no REST repo-info call, no commits-list call. A missing or
  // private repo answers 401 on info/refs, which resolveRemoteHead
  // reports as not-found (same plain-English 404 as before); any
  // other failure is an upstream 502. Nothing here guesses a branch.
  const resolveRemaining = remainingMs();
  const remoteHead = await resolveRemoteHead(
    owner, repo,
    resolveRemaining != null ? { timeoutMs: Math.min(12_000, Math.max(1_000, resolveRemaining)) } : {},
  );
  if (!remoteHead.ok) {
    if (remoteHead.reason === "not-found") {
      throw new ScanError(404, "not-found", "Repository not found (or it is private). GitSecure scans public repos only.");
    }
    if (remoteHead.reason === "timeout") {
      throw new ScanError(504, "timeout", "GitHub took too long to answer. Try again.");
    }
    throw new ScanError(502, "upstream", "GitHub couldn't be reached. Try again in a bit.");
  }
  const branch = remoteHead.branch;
  const headSha = remoteHead.headSha;
  // Phase 15 (finding 1): the HEAD meta is known from here on, so a
  // later fetch timeout can still return a resume cursor. The history
  // method is optimistic "git": the git path is now bounded while it
  // runs (history.ts PACK_MAX_BYTES), and the chunked driver flips
  // the cursor to "api" if the git path fails — there is no size
  // pre-check any more, because the size used to come from the REST
  // repo-info call this scan no longer makes.
  options.onHeadMeta?.({ branch, headSha, historyMethod: "git" });
  // Whether the HEAD step is streaming the tarball (set below when
  // the whole-buffer download trips its switch). The file list comes
  // from the tarball either way; the tree API is fetched only if a
  // tarball transport fails and the per-file fallback needs a list.
  let streaming = false;
  let treeTruncated = false;
  let chosen: { path: string; size?: number }[] = [];

  // Every file is secret-scanned the moment its content arrives, and
  // only retainable files (manifests, configs, workflows, infra — see
  // retainHeadFile) are kept for the framework / posture steps.
  const headSecrets: SecretFinding[] = [];
  const files = new Map<string, string>();
  let retainedBytes = 0;
  let retainedIncomplete = false;
  let scannedCount = 0;
  // Phase 10 triage state (see onEntry + the post-pass below).
  const findingContents = new Map<string, string>();
  const repoPublicKeyIdentities = new Set<string>();
  // Streaming mode: the tarball's own file list, in arrival order.
  const streamedPaths: string[] = [];
  const scannedPaths = new Set<string>();
  const onEntry = (path: string, content: string) => {
    scannedCount++;
    scannedPaths.add(path);
    if (streaming) streamedPaths.push(path);
    // Phase 10: repo-wide public-key identities (Layer 2 counterpart
    // check) are collected from every file as it arrives, and the
    // content of every file that produced a finding is kept (up to
    // 1 MB per file — see below) so triage can run after the loop
    // with the complete repo context. Only files with findings are
    // retained here — bounded by the finding count, not the tree size.
    if (content.includes("BEGIN PUBLIC KEY") || content.includes("BEGIN CERTIFICATE")) {
      for (const id of collectPublicKeyIdentities(content)) repoPublicKeyIdentities.add(id);
    }
    const beforeFindings = headSecrets.length;
    if (/(^|\/)\.env(\.|$)/.test(path) && !path.endsWith(".env.example")) {
      headSecrets.push(envFileFinding(path, "HEAD"));
    }
    headSecrets.push(...scanTextForSecrets({ path, content, commit: "HEAD" }));
    // Keep the content only for files under 1 MB: triage needs the
    // file text for its content/crypto signals, and a multi-MB file
    // with one finding must not defeat the streaming path's bounded
    // memory. A finding in a larger file still gets its path,
    // filename, and detector signals — only the content signals are
    // unavailable for it.
    if (headSecrets.length > beforeFindings && Buffer.byteLength(content, "utf8") <= 1_000_000) findingContents.set(path, content);
    if (retainHeadFile(path)) {
      // Manifests / configs / workflows (priority <= 2) are the files
      // the dependency and posture steps MUST have — they are small
      // and always retained, so a flood of big .ts/.js files early in
      // the tarball cannot crowd them out of the budget. Everything
      // else is kept only while the retained-bytes budget lasts; when
      // it runs out the report says framework detection may be
      // incomplete (secrets were still checked in every file).
      const mustKeep = priority(path) <= 2;
      if (!mustKeep && streaming && retainedBytes + Buffer.byteLength(content, "utf8") > RETAINED_HEAD_BYTES_BUDGET) {
        retainedIncomplete = true;
      } else {
        files.set(path, content);
        retainedBytes += Buffer.byteLength(content, "utf8");
      }
    }
    progress.filesScanned = scannedCount;
    emit();
  };
  const onCount = (n: number) => {
    progress.filesScanned = n;
    emit();
  };
  // Phase 16: the whole-buffer paths parse + secret-scan the entire
  // tree in memory after the download — CPU proportional to tree
  // size, with no timeout of its own. If the loop deadline passes
  // mid-parse, stop with the timeout the chunk driver turns into a
  // resumable partial cursor, instead of running on past Vercel's
  // 60 s ceiling and returning nothing. Checked every 256 files so
  // the check itself costs nothing.
  const HEAD_TIMEOUT_MESSAGE =
    "The current-files download took too long, so this chunk stopped before finishing. Nothing was half-reported — run the scan again and it picks up from the start of the current-files step.";
  let parseCount = 0;
  const checkParseDeadline = () => {
    if (options.deadlineMs != null && ++parseCount % 256 === 0 && Date.now() > options.deadlineMs) {
      throw new ScanError(504, "timeout", HEAD_TIMEOUT_MESSAGE);
    }
  };

  let tarballFallback = false;
  // Phase 11: the whole-buffer tarball path returns the full file
  // set as a Map — kept so the usage search below can run over every
  // scanned file. Streaming mode never holds the full set, so it
  // stays null and usage searches the retained files instead.
  let headCorpus: Map<string, string> | null = null;
  // Phase 15 (worker D): tarball first — the file list comes from
  // its entries, so the happy path makes no tree call at all. The
  // recursive-tree API is a fallback only: it supplies the file list
  // when a tarball transport fails and the per-file fallback needs
  // one. (That is the one remaining REST call in the HEAD step, and
  // it runs only on failure.)
  const fetchTree = async () => {
    const tree = await ghJson<{ tree: { path: string; type: string; size?: number }[]; truncated?: boolean }>(
      `${GH_API}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    );
    treeTruncated = tree.truncated ?? false;
    return tree.tree;
  };
  try {
    const tarballRemaining = remainingMs();
    const full = await fetchHeadFilesViaTarball(
      owner, repo, branch, onCount,
      tarballRemaining != null ? Math.min(30_000, Math.max(500, tarballRemaining)) : 30_000,
    );
    headCorpus = full;
    // The tarball is the complete file list — UNLIMITED, no slice,
    // no count cap.
    chosen = [...full.keys()]
      .map((path) => ({ path }))
      .sort((a, b) => priority(a.path) - priority(b.path) || a.path.localeCompare(b.path));
    progress.filesTotal = chosen.length;
    emit();
    for (const [path, content] of full) {
      onEntry(path, content);
      checkParseDeadline();
    }
  } catch (err) {
    // Phase 15 (worker D): a tarball TIMEOUT is not a missing
    // tarball — it propagates as the ScanError 504 the chunk driver
    // turns into a resumable partial cursor, exactly like the
    // streaming path. Only a genuinely unavailable tarball falls
    // through to the per-file fallback below.
    if (err instanceof ScanError && err.kind === "timeout") throw err;
    if (err instanceof TarballTooLargeForBufferError) {
      // Past the buffer switch: stream the same tarball instead of
      // buffering it — same files, bounded memory.
      streaming = true;
      try {
        const streamRemaining = remainingMs();
        await streamHeadFilesViaTarball(owner, repo, branch, onEntry, {
          onCount,
          budgetMs: streamRemaining != null ? Math.max(500, streamRemaining) : 50_000,
        });
      } catch (streamErr) {
        if (streamErr instanceof ScanError && streamErr.kind === "timeout") throw streamErr;
        tarballFallback = true;
        // Per-file fallback needs a file list: fetch the tree now,
        // and skip the files the tarball already delivered so
        // nothing is scanned twice.
        const remaining = (await fetchTree())
          .filter((t) => t.type === "blob" && !isSkippable(t.path) && !scannedPaths.has(t.path))
          .sort((a, b) => priority(a.path) - priority(b.path) || a.path.localeCompare(b.path));
        const perFileRemaining = remainingMs();
        await streamHeadFilesPerFile(owner, repo, branch, remaining, onEntry, {
          onCount,
          budgetMs: perFileRemaining != null ? Math.max(500, perFileRemaining) : 50_000,
        });
      }
      // The tarball is the complete file list in streaming mode — the
      // tree is never consulted, so it cannot truncate the count.
      chosen = streamedPaths
        .map((path) => ({ path }))
        .sort((a, b) => priority(a.path) - priority(b.path) || a.path.localeCompare(b.path));
      progress.filesTotal = chosen.length;
    } else {
      // Tarball unavailable: the tree API (REST fallback) supplies
      // the file list and files are fetched one by one — same files,
      // just slower.
      tarballFallback = true;
      const allFiles = (await fetchTree()).filter((t) => t.type === "blob" && !isSkippable(t.path));
      chosen = [...allFiles].sort((a, b) => priority(a.path) - priority(b.path) || a.path.localeCompare(b.path));
      // UNLIMITED: the whole non-skipped tree, no slice, no count cap.
      progress.filesTotal = chosen.length;
      emit();
      const perFileRemaining = remainingMs();
      const full = await fetchHeadFiles(
        owner, repo, branch, chosen, onCount,
        perFileRemaining != null ? { budgetMs: Math.max(500, perFileRemaining) } : undefined,
      );
      headCorpus = full;
      for (const [path, content] of full) {
        onEntry(path, content);
        checkParseDeadline();
      }
    }
  }
  progress.filesScanned = scannedCount;
  progress.step = "history";
  emit();

  // Phase 10 triage (HEAD): annotate every HEAD secret finding with
  // the layered triage verdict. Runs after the whole tree is scanned
  // so the public-counterpart and usage signals see the complete repo.
  // Phase 11 usage (HEAD) runs first — it needs the whole tree —
  // then triage consumes it as a post-verdict signal. The search
  // corpus is the full file set when the whole-buffer tarball path
  // ran (its Map is still in memory); in streaming mode it is the
  // retained files plus the files that produced findings — the same
  // retained subset Phase 10 searched, so a reference in a file
  // outside that subset cannot be seen there. Triage never removes
  // a finding — headSecrets keeps its length — and the score still
  // uses the detector severity (see triage.ts).
  const usageCorpus = headCorpus ?? new Map<string, string>([...files, ...findingContents]);
  computeUsageForFindings(headSecrets, usageCorpus, (f) => {
    const content = findingContents.get(f.file) ?? files.get(f.file);
    return {
      content,
      lineText: content !== undefined ? (content.split("\n")[f.line - 1] ?? null) : null,
    };
  });
  triageFindings(headSecrets, (f) => ({
    content: findingContents.get(f.file),
    repoPublicKeyIdentities,
    usage: f.usage,
  }));

  // Frameworks + dependencies (Tier 1 + Tier 2) — priority order, so
  // the OSV query covers the same manifests run to run.
  const deps: Dependency[] = [];
  for (const entry of chosen) {
    const content = files.get(entry.path);
    if (content === undefined) continue;
    const path = entry.path;
    const base = path.split("/").pop() ?? "";
    if (base === "package.json") deps.push(...parsePackageJson(content, path));
    else if (base === "package-lock.json") deps.push(...parsePackageLock(content, path));
    else if (base === "pnpm-lock.yaml" || base === "yarn.lock") deps.push(...parseYamlLock(content, path, "npm"));
    else if (base === "requirements.txt" || base === "Pipfile") deps.push(...parseRequirements(content, path));
    else if (base === "pyproject.toml") deps.push(...parsePyprojectToml(content, path));
    else if (base === "poetry.lock") deps.push(...parsePoetryLock(content, path));
    else if (base === "pubspec.yaml") deps.push(...parsePubspecYaml(content, path));
    else if (base === "pubspec.lock") deps.push(...parsePubspecLock(content, path));
    else if (base === "Cargo.toml") deps.push(...parseCargoToml(content, path));
    else if (base === "Cargo.lock") deps.push(...parseCargoLock(content, path));
    else if (base === "go.mod") deps.push(...parseGoMod(content, path));
    else if (base === "Gemfile") deps.push(...parseGemfile(content, path));
    else if (base === "Gemfile.lock") deps.push(...parseGemfileLock(content, path));
    else if (base === "composer.json") deps.push(...parseComposerJson(content, path));
    else if (base === "composer.lock") deps.push(...parseComposerLock(content, path));
    else if (base === "pom.xml") deps.push(...parsePomXml(content, path));
    else if (base === "build.gradle" || base === "build.gradle.kts") deps.push(...parseGradle(content, path));
    else if (base.endsWith(".csproj")) deps.push(...parseCsproj(content, path));
    else if (base === "packages.config") deps.push(...parsePackagesConfig(content, path));
    else if (path.startsWith(".github/workflows/") && (base.endsWith(".yml") || base.endsWith(".yaml"))) deps.push(...parseWorkflowActions(content, path));
  }
  // Dedupe dependencies by name+ecosystem (a package can appear in both a
  // manifest and a lockfile): keep the pinned version when one exists.
  const depByKey = new Map<string, Dependency>();
  for (const d of deps) {
    const key = `${d.ecosystem}:${d.name}`;
    const existing = depByKey.get(key);
    if (!existing) depByKey.set(key, d);
    else {
      const existingPinned = existing.version && !/[\^~><*]/.test(existing.version);
      const newPinned = d.version && !/[\^~><*]/.test(d.version);
      if (!existingPinned && newPinned) depByKey.set(key, { ...d, direct: existing.direct || d.direct });
      else if (d.direct) depByKey.set(key, { ...existing, direct: true });
    }
  }
  const dedupedDeps = [...depByKey.values()];

  const frameworks: Framework[] = fingerprintFrameworks(dedupedDeps, files);
  // Phase 6, Tier 3: infra frameworks (Docker, Kubernetes, Terraform,
  // GitHub Actions, CI/infra configs). One entry per framework name,
  // preferring a known version — same rule as fingerprintFrameworks'
  // internal dedupe (e.g. a Vercel preset naming a framework the
  // manifests already pin).
  for (const f of detectInfraFrameworks(files)) {
    const existing = frameworks.find((x) => x.name === f.name);
    if (!existing) frameworks.push(f);
    else if (!existing.version && f.version) Object.assign(existing, f);
  }
  frameworks.sort((a, b) => a.name.localeCompare(b.name));
  const unpinnedCount = dedupedDeps.filter((d) => d.direct && (!d.version || d.version === "*" || d.version.toLowerCase() === "latest")).length;

  return {
    owner,
    repo,
    branch,
    headSha,
    filesScanned: scannedCount,
    filesTotal: chosen.length,
    treeTruncated,
    tarballFallback,
    secrets: headSecrets,
    frameworks,
    dependencies: dedupedDeps,
    posture: buildPosture(files),
    unpinnedCount,
    // Phase 15 (worker D): optimistic "git" — the git history path
    // is bounded while it runs, and the chunked driver flips the
    // cursor to "api" if it fails. No repo size is carried any more:
    // nothing in the scan reads it, because both gates that needed
    // it are streaming bounds now.
    historyMethod: "git",
    retainedIncomplete,
  };
}

export interface AssembleHistoryInput {
  findings: SecretFinding[];
  commitsScanned: number;
  ok: boolean;
  method: "clone" | "api" | "git";
  /** Final limits note for the history step (rate-limit stop, guard
   *  trip, size-gate reason, or the patch-fallback sentence). */
  note: string | null;
  /** Milliseconds the history step took (only shown when it failed). */
  historyMs?: number;
}

/** Assemble (Phase 9): the last chunk. Merges the HEAD partial with
 *  the accumulated history findings, runs the dependency flaw check,
 *  and produces the finished FullReport. Idempotent: calling it twice
 *  with the same inputs produces the same report, so a client whose
 *  assemble call is interrupted simply calls it again with the same
 *  cursor and accumulated findings. */
export async function assembleReport(
  head: HeadPartial,
  history: AssembleHistoryInput,
  options: ScanOptions = {},
): Promise<FullReport> {
  const progress: ScanProgress = emptyProgress();
  progress.step = "dependencies";
  progress.filesScanned = head.filesScanned;
  progress.filesTotal = head.filesTotal;
  progress.commitsScanned = history.commitsScanned;
  const emit = () => options.onProgress?.({ ...progress });

  const dedupedSecrets = dedupeSecrets([...head.secrets, ...history.findings]);
  // Phase 10: every finding in the finished report carries a triage
  // annotation — history findings triaged at creation already have
  // one; anything that arrived without one (an older client/cursor)
  // gets a path+detector-only annotation here, never a missing one.
  ensureTriage(dedupedSecrets);
  const { vulnerabilities, unavailable: osvUnavailable, detailCapped, depsChecked, depsQueryable } = await checkDependencies(head.dependencies, {
    queryBudgetMs: options.osv?.queryBudgetMs ?? null,
    detailBudgetMs: options.osv?.detailBudgetMs ?? null,
    // Phase 16: the loop deadline, so an in-flight OSV query does
    // not run its full 15 s past it (see osv.ts).
    deadlineMs: options.deadlineMs,
    onProgress: (p) => {
      progress.depsChecked = p.depsChecked;
      progress.depsTotal = p.depsTotal;
      progress.advisoriesDetailed = p.advisoriesDetailed;
      progress.advisoriesTotal = p.advisoriesTotal;
      emit();
    },
  });
  progress.advisoriesDetailed = vulnerabilities.length - detailCapped;
  progress.advisoriesTotal = vulnerabilities.length;
  progress.depsChecked = depsChecked;
  progress.depsTotal = depsQueryable;
  progress.step = "done";
  emit();

  const posture: PostureIssue[] = [...head.posture];
  if (osvUnavailable) {
    posture.push({ id: "osv-unavailable", title: "Dependency check unavailable", severity: "info", detail: "The public flaw database (OSV.dev) could not be reached, so dependency vulnerabilities could not be checked in this scan.", fix: "Re-run the scan later." });
  }

  const scoreDetail = computeScore({ secrets: dedupedSecrets, vulnerabilities, posture, unpinnedCount: head.unpinnedCount });
  const { score, grade } = scoreDetail;
  const limits = buildLimits({
    filesScanned: head.filesScanned,
    filesTotal: head.filesTotal,
    historyOk: history.ok,
    historyMethod: history.method,
    historyCommitsScanned: history.commitsScanned,
    historyMs: history.historyMs ?? 0,
    historyNote: history.note,
    depsChecked,
    depsQueryable,
    depsTotal: head.dependencies.length,
    advisoriesTotal: vulnerabilities.length,
    detailCapped,
    treeTruncated: head.treeTruncated,
    tarballFallback: head.tarballFallback,
    // Phase 11: the line appears only when a history finding
    // actually carries HEAD-only usage.
    historyUsageFromHead: dedupedSecrets.some((s) => s.usage?.historyOnly === true),
  });
  if (head.retainedIncomplete) {
    limits.push("Some config files could not be kept in memory during the current-files download, so framework detection may be incomplete — every file was still checked for leaked secrets.");
  }
  if (!history.ok) {
    limits.push(`History incomplete: ${history.commitsScanned} newest commit${history.commitsScanned === 1 ? "" : "s"} checked — older commits were not checked in this report.`);
  }

  // Phase 4: every caller gets the full report — the repo is public, so
  // the detail is information already public in the repo. Secrets are
  // still redacted fragments only (see secrets.ts / redact.ts).
  // Phase 5: the full report lists EVERYTHING — all secrets, all
  // dependencies, all advisories. No slice, no cap.
  const full: FullReport = {
    kind: "full",
    repo: head.repo,
    owner: head.owner,
    branch: head.branch,
    commit: head.headSha,
    score,
    grade,
    scoreDetail,
    counts: {
      secrets: dedupedSecrets.length,
      // Phase 10: the honest split — likely-test findings are still
      // counted in `secrets`; Phase 12: they deduct nothing from the
      // score (uncertain deduct half, genuine / untriaged deduct full)
      // — see scoreDetail for the exact breakdown.
      testKeySecrets: dedupedSecrets.filter((s) => s.triage?.verdict === "likely-test-key").length,
      vulnerabilities: vulnerabilities.length,
      frameworks: head.frameworks.length,
      dependencies: head.dependencies.length,
      postureIssues: posture.length,
      filesScanned: head.filesScanned,
      historyCommitsScanned: history.commitsScanned,
    },
    summary: plainSummary({ secrets: dedupedSecrets.length, vulnerabilities: vulnerabilities.length, postureIssues: posture.length, frameworks: head.frameworks.length, secretsByVerdict: { genuine: dedupedSecrets.filter((s) => s.triage?.verdict === "likely-genuine-leak" || !s.triage).length, uncertain: dedupedSecrets.filter((s) => s.triage?.verdict === "uncertain").length, test: dedupedSecrets.filter((s) => s.triage?.verdict === "likely-test-key").length } }),
    scannedAt: new Date().toISOString(),
    historyDepth: HISTORY_DEPTH,
    limits,
    secrets: dedupedSecrets,
    frameworks: head.frameworks,
    dependencies: head.dependencies,
    vulnerabilities,
    posture,
  };
  return full;
}

/** Last-resort history fallback (unchanged from Phase 8): when every
 *  history path fails, scan API patches of the most recent commits.
 *  One bad commit never fails the scan. */
export async function scanHistoryPatchFallback(
  owner: string,
  repo: string,
  branch: string,
  count: number,
): Promise<{ findings: SecretFinding[]; commitsScanned: number }> {
  const commits = await ghJson<{ sha: string; commit: { message: string } }[]>(
    `${GH_API}/repos/${owner}/${repo}/commits?per_page=50&sha=${encodeURIComponent(branch)}`,
  ).catch(() => []);
  const findings: SecretFinding[] = [];
  let scanned = 0;
  for (const commit of commits.slice(0, count)) {
    try {
      const detail = await ghJson<{ files?: { filename: string; patch?: string }[] }>(`${GH_API}/repos/${owner}/${repo}/commits/${commit.sha}`);
      scanned++;
      for (const f of detail.files ?? []) {
        if (!f.patch || isSkippable(f.filename)) continue;
        // Patches are diffs: scan added lines only (lines starting with +).
        const added = f.patch.split("\n").filter((l) => l.startsWith("+") && !l.startsWith("+++")).map((l) => l.slice(1)).join("\n");
        // Phase 10: triage the finding from the added lines (path,
        // filename, and nearby-line signals; a PEM block added by the
        // commit is fully present in them).
        const addedFindings = scanTextForSecrets({ path: f.filename, content: added, commit: commit.sha.slice(0, 7) });
        triageFindings(addedFindings, () => ({ content: added }));
        findings.push(...addedFindings);
      }
    } catch {
      // One bad commit must not fail the whole scan.
    }
  }
  return { findings, commitsScanned: scanned };
}

export async function scanRepo(owner: string, repo: string, options: ScanOptions = {}): Promise<FullReport> {
  validateOwnerRepo(owner, repo);
  const progress: ScanProgress = emptyProgress();
  const emit = () => options.onProgress?.({ ...progress });

  // HEAD first (chunk 1), then history, then assemble. Sequential now
  // (Phase 8 ran history concurrently with the HEAD fetch); the chunked
  // driver is the source of truth for ordering, and scanRepo is just
  // its in-process form. Same inputs, same report.
  const head = await scanHead(owner, repo, {
    ...options,
    onProgress: (p) => {
      progress.filesScanned = p.filesScanned;
      progress.filesTotal = p.filesTotal;
      progress.step = p.step;
      emit();
    },
  });
  progress.step = "history";
  emit();

  const historyCount = options.historyCommits ?? HISTORY_COMMITS;
  const historyStarted = Date.now();
  // Phase 8.1: history must never kill the scan — if the orchestrator
  // itself throws (it should not: it catches per path), degrade to the
  // patch fallback below instead of 500ing the whole report.
  let history: HistoryScanResult;
  try {
    history = await scanHistory({
      owner, repo, branch: head.branch,
      onProgress: (n) => {
        progress.commitsScanned = n;
        emit();
      },
    });
  } catch (e) {
    history = {
      ok: false, findings: [], commitsScanned: 0, patchBytes: 0,
      truncated: false, timedOut: false,
      note: `History scan failed (${e instanceof Error ? e.message : "unknown error"}).`,
      ms: 0, method: "git", cachedCommits: 0, commitsFetched: 0,
      restCalls: 0, gitRequests: 0,
    };
  }
  let historyFindings = history.findings;
  let historyScanned = history.commitsScanned;
  let historyOk = history.ok;
  let historyNote: string | null = history.note ?? null;
  if (!history.ok) {
    historyNote = `${history.note ?? "Full-history scan unavailable."} Used API patches of the ${historyCount} most recent commits instead.`;
    const fallback = await scanHistoryPatchFallback(owner, repo, head.branch, historyCount);
    historyFindings = fallback.findings;
    historyScanned = fallback.commitsScanned;
  }
  progress.commitsScanned = historyScanned;
  progress.step = "dependencies";
  emit();

  return assembleReport(
    head,
    { findings: historyFindings, commitsScanned: historyScanned, ok: historyOk, method: history.method, note: historyNote, historyMs: Date.now() - historyStarted },
    {
      ...options,
      onProgress: (p) => {
        progress.depsChecked = p.depsChecked;
        progress.depsTotal = p.depsTotal;
        progress.advisoriesDetailed = p.advisoriesDetailed;
        progress.advisoriesTotal = p.advisoriesTotal;
        progress.step = p.step;
        emit();
      },
    },
  );
}
