// GitSecure scanner — public repos only, no auth required (optional
// GITHUB_TOKEN env raises the GitHub API rate limit; it is never logged).
//
// PHASE 5 (2026-11-25): NO result-count caps anywhere. Every secret
// finding is listed (the old 100 cap is gone), every dependency is
// listed (the old 200 slice is gone), every advisory OSV returns is
// listed (the old 100 cap is gone), and posture / framework findings
// were never capped. The OSV query + detail fetches are time-budgeted
// (see osv.ts) — a budget can leave an advisory ID-only or a dep
// unchecked for flaws, but it never drops a finding from the list, and
// the report says plainly how many got full detail / were checked.
// Score still floors at 0 (see score.ts) however many findings there
// are — DefinitelyTyped stays 0/F, it just lists everything now.
//
// HISTORY DEPTH (Phase 2): full history via an ephemeral git clone into
// /tmp, streaming `git log -p --all` newest-first through the same secret
// detectors as the HEAD scan, capped at 1000 commits / 50 MB of patches /
// 45 s (measured on Squ1zM0/TechDirect: 62 commits, 40.8 MB of patches,
// ~12 s total). If git is unavailable in the runtime or the clone fails,
// the scan falls back to the MVP path — patches of the 5 most recent
// commits via the GitHub API — and the report says so in `limits`.
// A secret deleted long ago in an old commit is now caught, up to the caps.
//
// HEAD SCAN (Phase 4): UNLIMITED. The entire HEAD tree is scanned —
// every file, manifests and configs first, then the rest. There is NO
// file-count cap, NO per-file size cap, and NO total-size cap anywhere
// in this code (no 250, no 1,000, no other number). The only files not
// read are binary / generated / vendored paths (dist, node_modules,
// .next, images, archives — see paths.ts): those are not source files
// to scan, not a cap. The GitHub recursive-tree call returns the whole
// tree in one response (up to 100k entries); if GitHub ever truncates
// it, the report says so. Files are read from ONE tarball download
// (codeload.github.com) instead of one HTTPS request per file —
// measured: 2,802 separate raw fetches took ~120 s no matter the
// concurrency (raw.githubusercontent.com answers ~25 requests/s from
// one client), while the 1.7 MB TechDirect tarball downloads in ~1.4 s.
// If the tarball is unavailable, the scan falls back to per-file fetches
// and still scans everything, just slower. External boundaries still
// exist and are reported honestly, never hidden: the Vercel route limit
// is 60 s (scan stops at 55 s with a 504 that says how many files had
// been fetched) and the GitHub API has rate limits. No secret values are
// stored or logged — findings carry redacted fragments only
// (see secrets.ts / redact.ts).

import { gunzipSync } from "node:zlib";
import { checkDependencies } from "./osv";
import { scanFullHistory, MAX_HISTORY_COMMITS, MAX_HISTORY_PATCH_BYTES, HISTORY_TIMEOUT_MS } from "./history";
import { isSkippablePath } from "./paths";
import { computeScore, plainSummary } from "./score";
import { envFileFinding, scanTextForSecrets, type ScannedFile } from "./secrets";
import { fingerprintFrameworks, parseCargoLock, parseCargoToml, parseComposerJson, parseComposerLock, parseCsproj, parseGemfile, parseGemfileLock, parseGoMod, parseGradle, parsePackagesConfig, parsePackageJson, parsePackageLock, parsePomXml, parseRequirements, parseYamlLock, viteFindings } from "./frameworks";
import type { Dependency, Framework, FullReport, PostureIssue, SecretFinding, Vulnerability } from "./types";

export const HISTORY_DEPTH = `Full history (newest-first) via ephemeral git clone: up to ${MAX_HISTORY_COMMITS} commits / ${MAX_HISTORY_PATCH_BYTES / 1_000_000} MB of patches, ${HISTORY_TIMEOUT_MS / 1000}s cap. Falls back to API patches of the 5 most recent commits when git/clone is unavailable.`;
export const HEAD_LIMITS = "HEAD: every file in the tree is scanned, manifests and configs first. Binary, dist, node_modules and .next are skipped — generated/vendored paths, not source files.";

const GH_API = "https://api.github.com";
const HISTORY_COMMITS = 5;

/** Live progress for the scan currently running for a repo, so a
 *  timeout can say honestly how far it got instead of just failing.
 *  Keyed by "owner/repo"; set at scan start, updated as HEAD files
 *  are fetched. Never stored beyond the scan. */
const scanProgress = new Map<string, { total: number; fetched: number }>();
export function getScanProgress(owner: string, repo: string): { total: number; fetched: number } | undefined {
  return scanProgress.get(`${owner}/${repo}`);
}

/** Error kind a scan can fail with, mapped to an honest HTTP status.
 *  The report page and the scan API both render from `kind` + `message`,
 *  so a failed scan says plainly what happened instead of a bare 404. */
export type ScanErrorKind = "not-found" | "private" | "rate-limit" | "timeout" | "bad-format" | "upstream";
export class ScanError extends Error {
  readonly status: number;
  readonly kind: ScanErrorKind;
  constructor(status: number, kind: ScanErrorKind, message: string) {
    super(message);
    this.status = status;
    this.kind = kind;
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

/** Whole-scan safety net: the route/page limit is 60 s, so stop at 55 s
 *  with an honest 504 instead of letting the platform kill the request
 *  with a generic error. The message says how many HEAD files had been
 *  fetched when it stopped (from the live progress tracker), so a
 *  timeout never pretends the scan finished. The underlying scan keeps
 *  running in the background; nothing is stored either way. */
export const SCAN_TIMEOUT_MS = 55_000;
export async function scanRepoWithTimeout(owner: string, repo: string): Promise<FullReport> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      scanRepo(owner, repo),
      new Promise<FullReport>((_resolve, reject) => {
        timer = setTimeout(() => {
          const progress = getScanProgress(owner, repo);
          const where =
            progress && progress.total > 0
              ? ` It had fetched ${progress.fetched} of ${progress.total} files in the tree when it stopped, so the report is incomplete — not every file was scanned.`
              : "";
          reject(
            new ScanError(
              504,
              "timeout",
              `The scan took too long (over 55 seconds) and was stopped.${where} Very large repos can take a while — try again, or try a smaller repo.`,
            ),
          );
        }, SCAN_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

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
      throw new ScanError(429, "rate-limit", "GitHub's request limit was hit, so this scan couldn't run right now. Please try again in a few minutes.");
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

async function fetchRaw(owner: string, repo: string, branch: string, path: string): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
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
  if (["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.toml", "Cargo.lock", "requirements.txt", "pyproject.toml", "Pipfile", "go.mod", "go.sum", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock", "pom.xml", "build.gradle", "build.gradle.kts", "packages.config"].includes(base) || base.endsWith(".csproj")) return 0;
  if (path.startsWith(".github/")) return 1;
  if (/\.(env|config\.(js|ts|mjs))$/.test(path) || base === ".gitignore" || base === "SECURITY.md") return 2;
  if (/\.(ts|tsx|js|jsx|py|rs|json|yaml|yml|toml|sh)$/.test(path)) return 3;
  if (/\.(md|txt)$/.test(path)) return 4;
  return 5;
}

export interface ScanOptions {
  historyCommits?: number;
}

/** Fetch the whole HEAD tree from ONE tarball download
 *  (codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{branch}).
 *  Returns a Map of repo-relative path -> text content for every
 *  non-skipped file. The tarball is a snapshot of the same HEAD the
 *  tree call listed, so the file set and contents match the per-file
 *  raw fetches — this only changes how the bytes arrive, not what is
 *  scanned. Entries are never written to disk, only held in memory
 *  for the scan. A path-traversal entry (../ or absolute) is ignored.
 *  Throws on any failure so the caller can fall back to per-file
 *  fetching — a failed tarball must never silently shrink the scan. */
const TARBALL_MAX_BYTES = 500_000_000; // memory guard on the download, NOT a scan cap: if a repo's tarball is bigger, the per-file fallback still scans every file.
async function fetchHeadFilesViaTarball(
  owner: string,
  repo: string,
  branch: string,
  progressKey: string,
): Promise<Map<string, string>> {
  const url = `https://codeload.github.com/${owner}/${repo}/tar.gz/refs/heads/${encodeURIComponent(branch)}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30_000);
  let gz: Buffer;
  try {
    const res = await fetch(url, { signal: controller.signal, cache: "no-store" });
    if (!res.ok) throw new Error(`tarball fetch ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > TARBALL_MAX_BYTES) throw new Error("tarball too large for memory");
    gz = buf;
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
        const progress = scanProgress.get(progressKey);
        if (progress) progress.fetched = files.size;
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
 *  is reported to the live tracker so a timeout can say how far the
 *  scan got. */
const HEAD_FETCH_CONCURRENCY = 10;
async function fetchHeadFiles(
  owner: string,
  repo: string,
  branch: string,
  chosen: { path: string; size?: number }[],
  progressKey: string,
): Promise<Map<string, string>> {
  const files = new Map<string, string>();
  let next = 0;
  const workers = Array.from({ length: HEAD_FETCH_CONCURRENCY }, async () => {
    while (next < chosen.length) {
      const entry = chosen[next++];
      const content = await fetchRaw(owner, repo, branch, entry.path);
      if (content == null) continue;
      files.set(entry.path, content);
      const progress = scanProgress.get(progressKey);
      if (progress) progress.fetched = files.size;
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

export async function scanRepo(owner: string, repo: string, options: ScanOptions = {}): Promise<FullReport> {
  validateOwnerRepo(owner, repo);
  const progressKey = `${owner}/${repo}`;
  scanProgress.set(progressKey, { total: 0, fetched: 0 });
  const historyCount = options.historyCommits ?? HISTORY_COMMITS;
  const repoInfo = await ghJson<{ default_branch: string; description: string | null; private: boolean }>(`${GH_API}/repos/${owner}/${repo}`);
  if (repoInfo.private) throw new ScanError(404, "private", "This repository is private. GitSecure scans public repos only.");
  const branch = repoInfo.default_branch || "main";

  // Start the history clone NOW so it runs concurrently with the HEAD
  // fetch below (clone ~10 s, HEAD fetch ~11 s in parallel instead of
  // ~22 s in series — this is what keeps TechDirect inside 60 s).
  const historyPromise = scanFullHistory(owner, repo, branch);

  const tree = await ghJson<{ tree: { path: string; type: string; size?: number }[]; truncated?: boolean }>(
    `${GH_API}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
  );
  const allFiles = tree.tree.filter((t) => t.type === "blob" && !isSkippable(t.path));
  const sorted = [...allFiles].sort((a, b) => priority(a.path) - priority(b.path) || a.path.localeCompare(b.path));
  // UNLIMITED: the whole non-skipped tree, no slice, no count cap.
  const chosen = sorted;
  scanProgress.set(progressKey, { total: chosen.length, fetched: 0 });

  // Primary path: one tarball download. Fallback: per-file fetches.
  // Either way every file in `chosen` is scanned — the fallback only
  // costs time, never coverage.
  let tarballFallback = false;
  let files: Map<string, string>;
  try {
    files = await fetchHeadFilesViaTarball(owner, repo, branch, progressKey);
  } catch {
    tarballFallback = true;
    files = await fetchHeadFiles(owner, repo, branch, chosen, progressKey);
  }

  // Secrets: HEAD files — iterate in priority (chosen) order, not fetch
  // completion order, so findings are deterministic run to run.
  const secrets: SecretFinding[] = [];
  for (const entry of chosen) {
    const content = files.get(entry.path);
    if (content === undefined) continue;
    const path = entry.path;
    if (/(^|\/)\.env(\.|$)/.test(path) && !path.endsWith(".env.example")) {
      secrets.push(envFileFinding(path, "HEAD"));
    }
    secrets.push(...scanTextForSecrets({ path, content, commit: "HEAD" }));
  }

  // Secrets: full history first (ephemeral clone, newest-first), with the
  // MVP API patch path as fallback when git/clone is unavailable.
  const commits = await ghJson<{ sha: string; commit: { message: string } }[]>(
    `${GH_API}/repos/${owner}/${repo}/commits?per_page=50&sha=${encodeURIComponent(branch)}`,
  ).catch(() => []);
  const headSha = commits[0]?.sha ?? "HEAD";
  let historyScanned = 0;
  let historyNote: string | null = null;
  const historyStarted = Date.now();
  const history = await historyPromise;
  if (history.ok) {
    historyScanned = history.commitsScanned;
    secrets.push(...history.findings);
    if (history.note) historyNote = history.note;
  } else {
    // Fallback: patches of the most recent commits via the GitHub API.
    historyNote = `${history.note ?? "Full-history clone unavailable."} Used API patches of the ${historyCount} most recent commits instead.`;
    for (const commit of commits.slice(0, historyCount)) {
      try {
        const detail = await ghJson<{ files?: { filename: string; patch?: string }[] }>(`${GH_API}/repos/${owner}/${repo}/commits/${commit.sha}`);
        historyScanned++;
        for (const f of detail.files ?? []) {
          if (!f.patch || isSkippable(f.filename)) continue;
          // Patches are diffs: scan added lines only (lines starting with +).
          const added = f.patch.split("\n").filter((l) => l.startsWith("+") && !l.startsWith("+++")).map((l) => l.slice(1)).join("\n");
          secrets.push(...scanTextForSecrets({ path: f.filename, content: added, commit: commit.sha.slice(0, 7) }));
        }
      } catch {
        // One bad commit must not fail the whole scan.
      }
    }
  }
  const historyMs = Date.now() - historyStarted;
  // Dedupe secrets (same type/file/line/fragment, HEAD vs history).
  // Phase 5: no cap — HEAD + history findings are ALL listed.
  const dedupedSecrets = dedupeSecrets(secrets);

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
  deps.length = 0;
  deps.push(...dedupedDeps);

  const frameworks: Framework[] = fingerprintFrameworks(deps, files);
  const unpinnedCount = deps.filter((d) => d.direct && (!d.version || d.version === "*" || d.version.toLowerCase() === "latest")).length;

  const { vulnerabilities, unavailable: osvUnavailable, detailCapped, depsChecked, depsQueryable } = await checkDependencies(deps);

  // Posture.
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
  }
  for (const v of viteFindings(files)) {
    posture.push({ id: `vite-${v.title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`, title: v.title, severity: v.severity, detail: v.detail, fix: v.title.includes("VITE_") ? "Move real secrets out of VITE_ variables — use server-side secrets instead." : "Restrict the dev server to localhost and review the plugins you install." });
  }
  if (osvUnavailable) {
    posture.push({ id: "osv-unavailable", title: "Dependency check unavailable", severity: "info", detail: "The public flaw database (OSV.dev) could not be reached, so dependency vulnerabilities could not be checked in this scan.", fix: "Re-run the scan later." });
  }

  const { score, grade } = computeScore({ secrets: dedupedSecrets, vulnerabilities, posture, unpinnedCount });
  const limits = [HISTORY_DEPTH, HEAD_LIMITS, "Public repos only. No secret is ever stored, logged, or shown in full."];
  if (history.ok) limits.push(`History scan: ${history.commitsScanned} commits, ${(history.patchBytes / 1_000_000).toFixed(1)} MB of patches, ${(history.ms / 1000).toFixed(1)}s (caps: ${MAX_HISTORY_COMMITS} commits / ${MAX_HISTORY_PATCH_BYTES / 1_000_000} MB / ${HISTORY_TIMEOUT_MS / 1000}s, newest-first).`);
  else limits.push(`History scan took ${(historyMs / 1000).toFixed(1)}s (clone path unavailable; API fallback scanned ${historyScanned} commits).`);
  if (historyNote) limits.push(historyNote);
  // Phase 5: no result list is capped, so there is no truncation line
  // any more. What the time budgets could not cover is stated plainly
  // instead: advisories are all listed, but some may be ID-only;
  // dependencies are all listed, but some may not have been checked.
  if (depsChecked < depsQueryable) limits.push(`Dependency flaw check: ${depsChecked} of ${depsQueryable} pinned dependencies were checked against the flaw database (OSV.dev) within the scan's time budget — the rest were not checked for flaws in this scan. All ${deps.length} dependencies are still listed in this report.`);
  if (detailCapped > 0) limits.push(`Full advisory detail (a plain summary, a severity score, and the version that fixes it) fetched for ${vulnerabilities.length - detailCapped} of ${vulnerabilities.length} listed advisories; ${detailCapped} listed with advisory ID only (detail fetch ran past its time budget).`);
  if (tree.truncated) limits.push("GitHub returned a truncated file tree — some files were not scanned. The tree was too large for GitHub to return in one response.");
  if (tarballFallback) limits.push("Tarball download was unavailable, so files were fetched one by one instead — same files, just slower.");
  if (files.size < allFiles.length) limits.push(`Fetched ${files.size} of ${allFiles.length} files in the tree — ${allFiles.length - files.size} could not be fetched from GitHub, so they were not scanned.`);
  else limits.push(`Scanned all ${allFiles.length} files in the tree (binary, dist, node_modules and .next skipped — generated/vendored paths, not source files).`);

  const base = {
    repo,
    owner,
    branch,
    commit: headSha,
    score,
    grade,
    counts: {
      secrets: dedupedSecrets.length,
      vulnerabilities: vulnerabilities.length,
      frameworks: frameworks.length,
      dependencies: deps.length,
      postureIssues: posture.length,
      filesScanned: files.size,
      historyCommitsScanned: historyScanned,
    },
    summary: plainSummary({ secrets: dedupedSecrets.length, vulnerabilities: vulnerabilities.length, postureIssues: posture.length, frameworks: frameworks.length }),
    scannedAt: new Date().toISOString(),
    historyDepth: HISTORY_DEPTH,
    limits,
  };

  // Phase 4: every caller gets the full report — the repo is public, so
  // the detail is information already public in the repo. Secrets are
  // still redacted fragments only (see secrets.ts / redact.ts).
  // Phase 5: the full report lists EVERYTHING — all secrets, all
  // dependencies, all advisories. No slice, no cap.
  const full: FullReport = { kind: "full", ...base, secrets: dedupedSecrets, frameworks, dependencies: deps, vulnerabilities, posture };
  return full;
}
