// GitSecure scanner — public repos only, no auth required (optional
// GITHUB_TOKEN env raises the GitHub API rate limit; it is never logged).
//
// HISTORY DEPTH (MVP, documented honestly): HEAD tree scan + the patches of
// the 5 most recent commits. The commits list itself covers the last 50
// commits (SHAs/messages only). Full-history scanning (every commit, e.g.
// via a local clone) is NOT done in the MVP — a secret deleted long ago
// in an old commit will not be caught. That is a known MVP limit, listed
// in every report's `limits` and in the README.
//
// HEAD LIMITS: recursive tree, at most 250 files, 200 KB per file,
// 3 MB total. Binary / generated / vendored paths are skipped.
// No secret values are stored or logged — findings carry redacted
// fragments only (see secrets.ts / redact.ts).

import { checkDependencies } from "./osv";
import { computeScore, plainSummary } from "./score";
import { envFileFinding, scanTextForSecrets, type ScannedFile } from "./secrets";
import { fingerprintFrameworks, parseCargoLock, parseCargoToml, parsePackageJson, parsePackageLock, parseRequirements, parseYamlLock, viteFindings } from "./frameworks";
import type { Dependency, Framework, FullReport, PostureIssue, PublicReport, SecretFinding, Vulnerability } from "./types";

export const HISTORY_DEPTH = "HEAD tree + patches of the 5 most recent commits (commits list: last 50). Full-history clone scanning is not in the MVP.";
export const HEAD_LIMITS = "HEAD: max 250 files, 200 KB per file, 3 MB total; binary, dist, node_modules and .next skipped.";

const GH_API = "https://api.github.com";
const MAX_FILES = 250;
const MAX_FILE_BYTES = 200_000;
const MAX_TOTAL_BYTES = 3_000_000;
const HISTORY_COMMITS = 5;

const SKIP_DIRS = ["node_modules", ".git", "dist", "build", ".next", "vendor", "target", ".venv", "__pycache__"];
const SKIP_EXTS = [".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".mp3", ".mp4", ".wav", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".exe", ".dll", ".so", ".dylib", ".bin", ".lockb"];

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
    if (res.status === 404) throw new Error("Repository not found (or it is private). GitSecure scans public repos only.");
    if (res.status === 403) throw new Error("GitHub API rate limit reached. Try again later — a GITHUB_TOKEN raises the limit.");
    if (!res.ok) throw new Error(`GitHub API error (${res.status}).`);
    return (await res.json()) as T;
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
  if (SKIP_DIRS.some((d) => path.split("/").includes(d))) return true;
  const lower = path.toLowerCase();
  if (SKIP_EXTS.some((e) => lower.endsWith(e))) return true;
  return false;
}

/** Priority: manifests, configs, workflows and source first — so the file
 *  cap still covers the files that matter on a big repo like TechDirect. */
function priority(path: string): number {
  const base = path.split("/").pop() ?? "";
  if (["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.toml", "Cargo.lock", "requirements.txt", "pyproject.toml", "Pipfile", "go.mod"].includes(base)) return 0;
  if (path.startsWith(".github/")) return 1;
  if (/\.(env|config\.(js|ts|mjs))$/.test(path) || base === ".gitignore" || base === "SECURITY.md") return 2;
  if (/\.(ts|tsx|js|jsx|py|rs|json|yaml|yml|toml|sh)$/.test(path)) return 3;
  if (/\.(md|txt)$/.test(path)) return 4;
  return 5;
}

export interface ScanOptions {
  historyCommits?: number;
}

export async function scanRepo(owner: string, repo: string, options: ScanOptions = {}): Promise<FullReport> {
  const historyCount = options.historyCommits ?? HISTORY_COMMITS;
  const repoInfo = await ghJson<{ default_branch: string; description: string | null; private: boolean }>(`${GH_API}/repos/${owner}/${repo}`);
  if (repoInfo.private) throw new Error("This repository is private. GitSecure scans public repos only.");
  const branch = repoInfo.default_branch || "main";

  const tree = await ghJson<{ tree: { path: string; type: string; size?: number }[]; truncated?: boolean }>(
    `${GH_API}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
  );
  const allFiles = tree.tree.filter((t) => t.type === "blob" && !isSkippable(t.path));
  const sorted = [...allFiles].sort((a, b) => priority(a.path) - priority(b.path) || a.path.localeCompare(b.path));
  const chosen = sorted.slice(0, MAX_FILES);

  const files = new Map<string, string>();
  let totalBytes = 0;
  for (const entry of chosen) {
    if (entry.size && entry.size > MAX_FILE_BYTES) continue;
    const content = await fetchRaw(owner, repo, branch, entry.path);
    if (content == null) continue;
    if (totalBytes + content.length > MAX_TOTAL_BYTES) break;
    totalBytes += content.length;
    files.set(entry.path, content);
  }

  // Secrets: HEAD files.
  const secrets: SecretFinding[] = [];
  for (const [path, content] of files) {
    if (/(^|\/)\.env(\.|$)/.test(path) && !path.endsWith(".env.example")) {
      secrets.push(envFileFinding(path, "HEAD"));
    }
    secrets.push(...scanTextForSecrets({ path, content, commit: "HEAD" }));
  }

  // Secrets: recent history (patches of the most recent commits).
  const commits = await ghJson<{ sha: string; commit: { message: string } }[]>(
    `${GH_API}/repos/${owner}/${repo}/commits?per_page=50&sha=${encodeURIComponent(branch)}`,
  ).catch(() => []);
  const headSha = commits[0]?.sha ?? "HEAD";
  let historyScanned = 0;
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
  // Dedupe secrets (same type/file/line/fragment, HEAD vs history).
  const seenSecrets = new Set<string>();
  const dedupedSecrets = secrets.filter((s) => {
    const key = `${s.type}:${s.file}:${s.line}:${s.fragment}:${s.commit}`;
    if (seenSecrets.has(key)) return false;
    seenSecrets.add(key);
    return true;
  }).slice(0, 100);

  // Frameworks + dependencies (Tier 1).
  const deps: Dependency[] = [];
  for (const [path, content] of files) {
    const base = path.split("/").pop() ?? "";
    if (base === "package.json") deps.push(...parsePackageJson(content, path));
    else if (base === "package-lock.json") deps.push(...parsePackageLock(content, path));
    else if (base === "pnpm-lock.yaml" || base === "yarn.lock") deps.push(...parseYamlLock(content, path, "npm"));
    else if (base === "requirements.txt" || base === "Pipfile") deps.push(...parseRequirements(content, path));
    else if (base === "Cargo.toml") deps.push(...parseCargoToml(content, path));
    else if (base === "Cargo.lock") deps.push(...parseCargoLock(content, path));
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

  const { vulnerabilities, unavailable: osvUnavailable } = await checkDependencies(deps);

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
    posture.push({ id: "osv-unavailable", title: "Dependency check unavailable", severity: "info", detail: "OSV.dev could not be reached, so dependency vulnerabilities could not be checked in this scan.", fix: "Re-run the scan later." });
  }

  const { score, grade } = computeScore({ secrets: dedupedSecrets, vulnerabilities, posture, unpinnedCount });
  const limits = [HISTORY_DEPTH, HEAD_LIMITS, "Public repos only. No secret is ever stored, logged, or shown in full."];
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
