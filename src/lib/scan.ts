// GitSecure scanner — public repos only, no auth required (optional
// GITHUB_TOKEN env raises the GitHub API rate limit; it is never logged).
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
// HEAD LIMITS: recursive tree, at most 250 files, 200 KB per file,
// 3 MB total. Binary / generated / vendored paths are skipped.
// No secret values are stored or logged — findings carry redacted
// fragments only (see secrets.ts / redact.ts).

import { checkDependencies } from "./osv";
import { scanFullHistory, MAX_HISTORY_COMMITS, MAX_HISTORY_PATCH_BYTES, HISTORY_TIMEOUT_MS } from "./history";
import { isSkippablePath } from "./paths";
import { computeScore, plainSummary } from "./score";
import { envFileFinding, scanTextForSecrets, type ScannedFile } from "./secrets";
import { fingerprintFrameworks, parseCargoLock, parseCargoToml, parseComposerJson, parseComposerLock, parseCsproj, parseGemfile, parseGemfileLock, parseGoMod, parseGradle, parsePackagesConfig, parsePackageJson, parsePackageLock, parsePomXml, parseRequirements, parseYamlLock, viteFindings } from "./frameworks";
import type { Dependency, Framework, FullReport, PostureIssue, PublicReport, SecretFinding, Vulnerability } from "./types";

export const HISTORY_DEPTH = `Full history (newest-first) via ephemeral git clone: up to ${MAX_HISTORY_COMMITS} commits / ${MAX_HISTORY_PATCH_BYTES / 1_000_000} MB of patches, ${HISTORY_TIMEOUT_MS / 1000}s cap. Falls back to API patches of the 5 most recent commits when git/clone is unavailable.`;
export const HEAD_LIMITS = "HEAD: max 250 files, 200 KB per file, 3 MB total; binary, dist, node_modules and .next skipped.";

const GH_API = "https://api.github.com";
const MAX_FILES = 250;
const MAX_FILE_BYTES = 200_000;
const MAX_TOTAL_BYTES = 3_000_000;
const HISTORY_COMMITS = 5;

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
 *  with a generic error. The underlying scan keeps running in the
 *  background; nothing is stored either way. */
export const SCAN_TIMEOUT_MS = 55_000;
export async function scanRepoWithTimeout(owner: string, repo: string): Promise<FullReport> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      scanRepo(owner, repo),
      new Promise<FullReport>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new ScanError(504, "timeout", "The scan took too long (over 55 seconds) and was stopped. Very large repos can take a while — try again, or try a smaller repo.")),
          SCAN_TIMEOUT_MS,
        );
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

/** Fetch HEAD files with a bounded worker pool (10 concurrent). Files are
 *  claimed in priority order; the 3 MB total cap is enforced on completion
 *  (declared blob size is used as the pre-fetch estimate). Sequential
 *  fetching took ~33 s for 250 files on TechDirect; the pool takes ~11 s,
 *  which is what keeps a full scan (HEAD + history clone) inside the
 *  60 s serverless route limit. */
const HEAD_FETCH_CONCURRENCY = 10;
async function fetchHeadFiles(
  owner: string,
  repo: string,
  branch: string,
  chosen: { path: string; size?: number }[],
): Promise<Map<string, string>> {
  const files = new Map<string, string>();
  let totalBytes = 0;
  let next = 0;
  const workers = Array.from({ length: HEAD_FETCH_CONCURRENCY }, async () => {
    while (next < chosen.length) {
      const entry = chosen[next++];
      if (entry.size && entry.size > MAX_FILE_BYTES) continue;
      if (totalBytes + (entry.size ?? 0) > MAX_TOTAL_BYTES) continue;
      const content = await fetchRaw(owner, repo, branch, entry.path);
      if (content == null) continue;
      if (totalBytes + content.length > MAX_TOTAL_BYTES) continue;
      totalBytes += content.length;
      files.set(entry.path, content);
    }
  });
  await Promise.all(workers);
  return files;
}

export async function scanRepo(owner: string, repo: string, options: ScanOptions = {}): Promise<FullReport> {
  validateOwnerRepo(owner, repo);
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
  const chosen = sorted.slice(0, MAX_FILES);

  const files = await fetchHeadFiles(owner, repo, branch, chosen);

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
  const seenSecrets = new Set<string>();
  const dedupedAll = secrets.filter((s) => {
    const key = `${s.type}:${s.file}:${s.line}:${s.fragment}:${s.commit}`;
    if (seenSecrets.has(key)) return false;
    seenSecrets.add(key);
    return true;
  });
  const secretOverflow = Math.max(0, dedupedAll.length - 100);
  const dedupedSecrets = dedupedAll.slice(0, 100);

  // Frameworks + dependencies (Tier 1 + Tier 2) — priority order, so the
  // OSV 60-dep cap always covers the same manifests run to run.
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

  const { vulnerabilities, unavailable: osvUnavailable, advisoriesFound, detailCapped } = await checkDependencies(deps);

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
  if (secretOverflow > 0) limits.push(`Secret findings capped at 100 in this report — ${secretOverflow} more were found.`);
  if (advisoriesFound > vulnerabilities.length) limits.push(`The flaw database (OSV.dev) returned ${advisoriesFound} advisories; ${vulnerabilities.length} listed (cap 100 per scan).`);
  if (detailCapped > 0) limits.push(`Full advisory detail (a plain summary, a severity score, and the version that fixes it) fetched for ${vulnerabilities.length - detailCapped} of ${vulnerabilities.length} listed advisories; ${detailCapped} listed with advisory ID only (detail cap 50 per scan).`);
  if (tree.truncated) limits.push("GitHub returned a truncated file tree — some files were not scanned.");
  if (allFiles.length > MAX_FILES) limits.push(`File cap reached: scanned ${files.size} of ${allFiles.length} files (manifests and configs first).`);

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

  const full: FullReport = { kind: "full", ...base, secrets: dedupedSecrets, frameworks, dependencies: deps.slice(0, 200), vulnerabilities, posture };
  return full;
}

export function toPublicReport(full: FullReport): PublicReport {
  const { kind: _kind, secrets: _s, frameworks: _f, dependencies: _d, vulnerabilities: _v, posture: _p, ...rest } = full;
  void _kind; void _s; void _f; void _d; void _v; void _p;
  return { kind: "public", ...rest };
}
