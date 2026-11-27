// Tier 3 infrastructure fingerprinting - Docker, Kubernetes, Terraform,
// GitHub Actions, Vercel, Supabase (Phase 6).
// Pluggable like Tier 1/2: new detectors + parsers live here; the scan
// core only calls detectInfraFrameworks / infraFindings /
// parseWorkflowActions and merges the results. Version rule (same as
// frameworks.ts): a version is reported only when it can be read honestly
// from the file; otherwise it is null and versionSource is "unknown" -
// never guessed. A range ("~> 5.0", ">= 1.5") is NOT a version.

import type { Dependency, Framework, Severity } from "./types";

/** OSV.dev ecosystem name for GitHub Actions. The coordinator must add
 *  `actions: "GitHub Actions"` to the ecosystemMap in src/lib/osv.ts so
 *  action dependencies are queried under this ecosystem. */
export const ACTIONS_OSV_ECOSYSTEM = "GitHub Actions";

export interface InfraFinding {
  title: string;
  /** Plain English: what the risk is, then "Fix: <exact fix>". */
  detail: string;
  severity: Severity;
  /** Repo-relative file the finding comes from, when known. */
  file?: string;
  /** Posture category for the report map. */
  category?: "actions" | "container";
}

const VERSION_TAG = /^v?\d+(\.\d+){0,2}$/;
const FULL_SHA = /^[0-9a-f]{40}$/i;
/** An exact pinned version: "5.0.0", "1.6.0", "= 5.0.0", "v1.2.3".
 *  Ranges ("~> 5.0", ">= 5.0", ">= 4.0, < 6.0") do NOT match. */
const EXACT_VERSION = /^=?\s*v?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)$/;

/** "5.0.0" -> "5.0.0"; "~> 5.0" / ">= 1.5" / undefined -> null. */
function exactVersion(raw: string | undefined | null): string | null {
  if (!raw) return null;
  const m = EXACT_VERSION.exec(raw.trim());
  return m ? m[1] : null;
}

// --- Docker images (shared by Dockerfile, compose, k8s manifests) ---

export interface ParsedDockerImage {
  /** Image name without registry/namespace, e.g. "node". */
  name: string;
  /** Tag, or null when there is no tag, the tag is "latest", or the
   *  image is pinned by digest only (a digest is not a version). */
  version: string | null;
  unpinned: boolean;
}

export function parseDockerImage(ref: string): ParsedDockerImage | null {
  if (!ref || ref.includes("$")) return null; // ${VAR} - not resolvable, never guessed
  let image = ref;
  let digestPinned = false;
  const at = image.indexOf("@");
  if (at >= 0) {
    digestPinned = true;
    image = image.slice(0, at);
  }
  const lastSlash = image.lastIndexOf("/");
  const last = lastSlash >= 0 ? image.slice(lastSlash + 1) : image;
  const colon = last.lastIndexOf(":");
  let name = last;
  let tag: string | null = null;
  if (colon >= 0) {
    name = last.slice(0, colon);
    tag = last.slice(colon + 1);
  }
  if (!name) return null;
  if (tag === null || tag === "latest") {
    return { name, version: null, unpinned: !digestPinned };
  }
  return { name, version: tag, unpinned: false };
}

function dockerImageFramework(ref: string, sourceFile: string): Framework | null {
  const parsed = parseDockerImage(ref);
  if (!parsed) return null;
  return {
    name: `Docker image ${parsed.name}`,
    ecosystem: "docker",
    version: parsed.version,
    versionSource: parsed.version ? "config" : "unknown",
    unpinned: parsed.unpinned,
    sourceFile,
  };
}

/** Parse a Dockerfile: one entry per FROM (multi-stage builds included).
 *  No dedupe here - detectInfraFrameworks dedupes by name, preferring a
 *  known version. */
export function parseDockerfile(content: string, sourceFile: string): Framework[] {
  const out: Framework[] = [];
  for (const line of content.split("\n")) {
    const m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i.exec(line);
    if (!m) continue;
    const fw = dockerImageFramework(m[1], sourceFile);
    if (fw) out.push(fw);
  }
  return out;
}

/** Parse `image:` lines - the service images in a compose file and the
 *  container images in a Kubernetes manifest. */
function parseImageLines(content: string, sourceFile: string): Framework[] {
  const out: Framework[] = [];
  for (const line of content.split("\n")) {
    const m = /^\s*image:\s*["']?([^\s"'#]+)["']?/.exec(line);
    if (!m) continue;
    const fw = dockerImageFramework(m[1], sourceFile);
    if (fw) out.push(fw);
  }
  return out;
}

/** Parse a docker-compose.yml / compose.yaml: each service's `image:`. */
export function parseCompose(content: string, sourceFile: string): Framework[] {
  return parseImageLines(content, sourceFile);
}

// --- Kubernetes ---

const K8S_KINDS = new Set(["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"]);

export function isK8sManifest(content: string): boolean {
  if (!/^\s*apiVersion:\s*\S+/m.test(content)) return false;
  const kind = /^\s*kind:\s*([A-Za-z]+)\s*$/m.exec(content)?.[1];
  return !!kind && K8S_KINDS.has(kind);
}

/** Parse a Kubernetes manifest: the "Kubernetes" framework itself
 *  (manifests carry no Kubernetes version, so version is null) plus any
 *  container images as Docker image frameworks. */
export function parseK8sManifest(content: string, sourceFile: string): Framework[] {
  if (!isK8sManifest(content)) return [];
  const out: Framework[] = [
    { name: "Kubernetes", ecosystem: "kubernetes", version: null, versionSource: "unknown", unpinned: false, sourceFile },
  ];
  out.push(...parseImageLines(content, sourceFile));
  return out;
}

// --- Terraform ---

interface TerraformBlocks {
  /** required_providers entries: name -> { source, version constraint (null = missing) } */
  required: Map<string, { source: string | null; version: string | null }>;
  /** Names from `provider "name" {}` blocks. */
  declared: Set<string>;
  /** Raw required_version constraints (usually one). */
  requiredVersions: string[];
}

/** Return the text inside the braces starting at openIndex (which points
 *  at the "{" itself). Brace-counted; HCL strings holding braces inside
 *  these blocks are not expected. */
function extractBraced(content: string, openIndex: number): string | null {
  let depth = 0;
  for (let i = openIndex; i < content.length; i++) {
    const ch = content[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return content.slice(openIndex + 1, i);
    }
  }
  return null;
}

function parseTerraformBlocks(content: string): TerraformBlocks {
  const required = new Map<string, { source: string | null; version: string | null }>();
  for (const m of content.matchAll(/required_providers\s*\{/g)) {
    const open = content.indexOf("{", m.index);
    const body = open >= 0 ? extractBraced(content, open) : null;
    if (!body) continue;
    for (const entry of body.matchAll(/([A-Za-z0-9_-]+)\s*=\s*\{/g)) {
      const entryOpen = body.indexOf("{", entry.index);
      const entryBody = entryOpen >= 0 ? extractBraced(body, entryOpen) : null;
      const source = entryBody ? (/source\s*=\s*"([^"]*)"/.exec(entryBody)?.[1] ?? null) : null;
      const version = entryBody ? (/version\s*=\s*"([^"]*)"/.exec(entryBody)?.[1] ?? null) : null;
      required.set(entry[1], { source, version });
    }
  }
  const declared = new Set<string>();
  for (const m of content.matchAll(/provider\s+"([^"]+)"\s*\{/g)) declared.add(m[1]);
  const requiredVersions = [...content.matchAll(/required_version\s*=\s*"([^"]*)"/g)].map((m) => m[1]);
  return { required, declared, requiredVersions };
}

/** Parse a *.tf file: one "Terraform provider <name>" framework per
 *  provider (version = exact constraint only, ranges -> null), plus
 *  "Terraform" itself when required_version pins an exact version. */
export function parseTerraform(content: string, sourceFile: string): Framework[] {
  const { required, declared, requiredVersions } = parseTerraformBlocks(content);
  const out: Framework[] = [];
  for (const name of new Set([...required.keys(), ...declared])) {
    const raw = required.get(name)?.version ?? null;
    const version = exactVersion(raw);
    out.push({
      name: `Terraform provider ${name}`,
      ecosystem: "terraform",
      version,
      versionSource: version ? "config" : "unknown",
      unpinned: version === null,
      sourceFile,
    });
  }
  for (const raw of requiredVersions) {
    const version = exactVersion(raw);
    out.push({
      name: "Terraform",
      ecosystem: "terraform",
      version,
      versionSource: version ? "config" : "unknown",
      unpinned: version === null,
      sourceFile,
    });
  }
  return out;
}

// --- GitHub Actions ---

export interface WorkflowAction {
  name: string; // owner/action
  ref: string | null; // tag, branch, or SHA as written - null when absent
  /** The ref when it looks like a version tag (v4, v4.1.0, 1.2.3), else null. */
  version: string | null;
  unpinned: boolean;
  /** True for first-party actions (actions/*, github/*). */
  firstParty: boolean;
  /** True when the ref is a full 40-hex commit SHA (immutable pin). */
  pinnedSha: boolean;
}

/** First-party actions are published by GitHub itself, so a major
 *  version tag is a trusted pin. Everything else is third-party. */
export function isFirstPartyAction(name: string): boolean {
  return name.startsWith("actions/") || name.startsWith("github/");
}

/** Parse `uses:` steps. Local actions ("./...") and docker:// actions
 *  are skipped - they are not queryable actions. */
export function parseWorkflowUses(content: string): WorkflowAction[] {
  const out: WorkflowAction[] = [];
  for (const line of content.split("\n")) {
    const m = /^\s*-\s*uses:\s*["']?([^\s"'#]+)["']?/.exec(line);
    if (!m) continue;
    const spec = m[1];
    if (spec.startsWith("./") || spec.startsWith("/") || spec.startsWith("docker://")) continue;
    const at = spec.indexOf("@");
    const name = at >= 0 ? spec.slice(0, at) : spec;
    const ref = at >= 0 ? spec.slice(at + 1) : null;
    if (!name.includes("/")) continue; // not owner/action
    const version = ref && VERSION_TAG.test(ref) ? ref : null;
    // Pinned: a version tag, or a full commit SHA (immutable). Unpinned:
    // a branch name (main/master/anything else) or no ref at all.
    const unpinned = !ref || (!VERSION_TAG.test(ref) && !FULL_SHA.test(ref));
    out.push({ name, ref, version, unpinned, firstParty: isFirstPartyAction(name), pinnedSha: !!ref && FULL_SHA.test(ref) });
  }
  return out;
}

/** Workflow actions as OSV-queryable dependencies (ecosystem "actions").
 *  A full 40-char SHA is NOT a queryable version, so version is null -
 *  never guessed. The coordinator must add `actions: "GitHub Actions"`
 *  (ACTIONS_OSV_ECOSYSTEM) to osv.ts's ecosystemMap. */
export function parseWorkflowActions(content: string, sourceFile: string): Dependency[] {
  return parseWorkflowUses(content).map((a) => ({
    name: a.name,
    ecosystem: "actions",
    version: a.version,
    direct: true,
    sourceFile,
  }));
}

/** Workflow actions as frameworks: "GitHub Action owner/action", version
 *  = the ref as written (tag/SHA) or null when the ref is missing. */
export function parseWorkflowFrameworks(content: string, sourceFile: string): Framework[] {
  return parseWorkflowUses(content).map((a) => ({
    name: `GitHub Action ${a.name}`,
    ecosystem: "actions",
    version: a.ref,
    versionSource: a.ref ? "config" : "unknown",
    unpinned: a.unpinned,
    sourceFile,
  }));
}

// --- Vercel / Supabase ---

const VERCEL_FRAMEWORK_MAP: Record<string, string> = {
  nextjs: "Next.js",
  nuxtjs: "Nuxt",
  vite: "Vite",
  "create-react-app": "Create React App",
  gatsby: "Gatsby",
  hugo: "Hugo",
  astro: "Astro",
  sveltekit: "SvelteKit",
  remix: "Remix",
  angular: "Angular",
  vue: "Vue",
};

/** Parse vercel.json: the framework preset, when present. The preset
 *  names a framework but carries no version, so version is null. */
export function parseVercelJson(content: string, sourceFile: string): Framework[] {
  try {
    const json = JSON.parse(content);
    const preset = typeof json.framework === "string" ? json.framework : null;
    if (!preset) return [];
    return [
      {
        name: VERCEL_FRAMEWORK_MAP[preset] ?? preset,
        ecosystem: "config",
        version: null,
        versionSource: "unknown",
        unpinned: false,
        sourceFile,
      },
    ];
  } catch {
    return [];
  }
}

/** Parse supabase/config.toml: Supabase is in use; the config carries no
 *  version, so version is null. Only called for supabase/config.toml. */
export function parseSupabaseConfig(content: string, sourceFile: string): Framework[] {
  void content;
  return [
    { name: "Supabase", ecosystem: "config", version: null, versionSource: "unknown", unpinned: false, sourceFile },
  ];
}

// --- Combined detector ---

/** Detect Tier 3 infra frameworks across all scanned files. One entry
 *  per framework name, preferring a known version (same rule as
 *  fingerprintFrameworks). The coordinator should apply the same dedupe
 *  when merging this list with the Tier 1/2 list. */
export function detectInfraFrameworks(files: Map<string, string>): Framework[] {
  const out: Framework[] = [];
  for (const [path, content] of files) {
    const base = path.split("/").pop() ?? "";
    if (base === "Dockerfile" || base.startsWith("Dockerfile.")) {
      out.push(...parseDockerfile(content, path));
    } else if (base === "docker-compose.yml" || base === "docker-compose.yaml" || base === "compose.yml" || base === "compose.yaml") {
      out.push(...parseCompose(content, path));
    } else if (path.startsWith(".github/workflows/") && /\.ya?ml$/.test(path)) {
      out.push(...parseWorkflowFrameworks(content, path));
    } else if (/\.tf$/.test(path)) {
      out.push(...parseTerraform(content, path));
    } else if (base === "vercel.json") {
      out.push(...parseVercelJson(content, path));
    } else if (path.endsWith("supabase/config.toml")) {
      out.push(...parseSupabaseConfig(content, path));
    } else if (/\.ya?ml$/.test(path)) {
      // Oddly named YAML: a Kubernetes manifest or a compose file.
      if (isK8sManifest(content)) out.push(...parseK8sManifest(content, path));
      else if (/^\s*services:/m.test(content)) out.push(...parseCompose(content, path));
    }
  }
  const byName = new Map<string, Framework>();
  for (const f of out) {
    const existing = byName.get(f.name);
    if (!existing) byName.set(f.name, f);
    else if (!existing.version && f.version) byName.set(f.name, f);
  }
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

// --- Findings (posture) ---

function dockerfileFindings(path: string, content: string): InfraFinding[] {
  const out: InfraFinding[] = [];
  let hasUser = false;
  let hasHealthcheck = false;
  let hasCmdOrEntrypoint = false;
  for (const line of content.split("\n")) {
    if (/^\s*HEALTHCHECK\b/i.test(line)) hasHealthcheck = true;
    if (/^\s*(CMD|ENTRYPOINT)\b/i.test(line)) hasCmdOrEntrypoint = true;
    const user = /^\s*USER\s+(\S+)/i.exec(line)?.[1];
    if (user) {
      hasUser = true;
      if (user === "root" || user === "0") {
        out.push({
          title: "Dockerfile runs as root",
          detail: `${path} sets USER ${user}, so the container runs as root. If the application is compromised, the attacker has root inside the container. Fix: create a dedicated non-root user in the Dockerfile (for example with a RUN step that adds the user) and switch to it with USER <username> before the final CMD.`,
          severity: "medium",
          file: path,
          category: "container",
        });
      }
    }
    const from = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i.exec(line);
    if (from) {
      const parsed = parseDockerImage(from[1]);
      if (parsed && parsed.unpinned) {
        out.push({
          title: "Docker base image is not pinned to a version",
          detail: `${path} uses ${from[1]} as a base image with no pinned version (tag "latest" or no tag), so a rebuild can silently pull a different image. Fix: pin the base image to a specific versioned tag, e.g. FROM node:20-alpine, and bump it deliberately.`,
          severity: "medium",
          file: path,
          category: "container",
        });
      }
    }
    const arg = /^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(line);
    if (arg && /password|passwd|secret|token|private[_-]?key|api[_-]?key|access[_-]?key/i.test(arg[1])) {
      out.push({
        title: "Possible secret passed as a Docker build argument",
        detail: `${path} declares ARG ${arg[1]}, a name that looks like a secret. Build arguments are stored in the image history and can be read back with docker history, so the value can leak to anyone who has the image. Fix: pass the value with a BuildKit secret mount (RUN --mount=type=secret ...) instead, and never put it in an ARG or ENV.`,
        severity: "high",
        file: path,
        category: "container",
      });
    }
    // ENV is worse than ARG in one way: the value is baked into the
    // image config itself, visible to anyone with the image via
    // `docker inspect`. Only secret-looking names are flagged - a
    // plain ENV NODE_ENV never fires. One finding per line.
    if (/^\s*ENV\s+/.test(line)) {
      for (const m of line.matchAll(/([A-Za-z_][A-Za-z0-9_]*)\s*=/g)) {
        if (/password|passwd|secret|token|private[_-]?key|api[_-]?key|access[_-]?key/i.test(m[1])) {
          out.push({
            title: "Possible secret baked into the image with ENV",
            detail: `${path} sets ENV ${m[1]}, a name that looks like a secret. ENV values are stored in the image config and can be read back with docker inspect, so the value leaks to anyone who has the image. Fix: pass the value at run time instead (docker run -e ${m[1]}=... or a secrets manager), and never put it in an ENV.`,
            severity: "high",
            file: path,
            category: "container",
          });
          break;
        }
      }
    }
    const add = /^\s*ADD\s+(https?:\/\/\S+)/i.exec(line);
    if (add) {
      out.push({
        title: "Dockerfile downloads a file with ADD",
        detail: `${path} uses ADD to fetch ${add[1]}. ADD downloads the file without verifying a checksum, and its caching can silently reuse a stale copy. Fix: use COPY for files from the build context, or download the file in a RUN step with curl and verify its checksum before using it.`,
        severity: "low",
        file: path,
        category: "container",
      });
    }
  }
  if (!hasUser) {
    out.push({
      title: "Dockerfile has no USER instruction",
      detail: `${path} never sets a USER, so the container runs as root by default. If the application is compromised, the attacker has root inside the container. Fix: create a dedicated non-root user in the Dockerfile and switch to it with USER <username> before the final CMD.`,
      severity: "medium",
      file: path,
      category: "container",
    });
  }
  if (hasCmdOrEntrypoint && !hasHealthcheck) {
    out.push({
      title: "Dockerfile has no HEALTHCHECK",
      detail: `${path} runs a service (it has a CMD or ENTRYPOINT) but sets no HEALTHCHECK, so a container that stops responding keeps running and keeps receiving traffic. Fix: add a HEALTHCHECK instruction that probes the service, e.g. HEALTHCHECK CMD curl -f http://localhost/health || exit 1.`,
      severity: "low",
      file: path,
      category: "container",
    });
  }
  return out;
}

function k8sFindings(path: string, content: string): InfraFinding[] {
  const out: InfraFinding[] = [];
  if (!isK8sManifest(content)) return out;
  if (/^\s*hostNetwork:\s*true\s*$/im.test(content)) {
    out.push({
      title: "Kubernetes pod uses the host network",
      detail: `${path} sets hostNetwork: true, so the pod shares the host's network namespace and can see host network traffic and ports. Fix: remove hostNetwork: true and expose the pod through a Service instead.`,
      severity: "high",
      file: path,
      category: "container",
    });
  }
  if (/^\s*hostPID:\s*true\s*$/im.test(content)) {
    out.push({
      title: "Kubernetes pod uses the host PID namespace",
      detail: `${path} sets hostPID: true, so the pod can see and signal processes on the host. Fix: remove hostPID: true.`,
      severity: "high",
      file: path,
      category: "container",
    });
  }
  if (/^\s*hostIPC:\s*true\s*$/im.test(content)) {
    out.push({
      title: "Kubernetes pod uses the host IPC namespace",
      detail: `${path} sets hostIPC: true, so the pod shares the host's inter-process communication namespace and can see host IPC objects. Fix: remove hostIPC: true.`,
      severity: "high",
      file: path,
      category: "container",
    });
  }
  if (/^\s*allowPrivilegeEscalation:\s*true\s*$/im.test(content)) {
    out.push({
      title: "Kubernetes container allows privilege escalation",
      detail: `${path} sets allowPrivilegeEscalation: true, so a process in the container can gain more privileges than the container started with. Fix: set allowPrivilegeEscalation: false.`,
      severity: "high",
      file: path,
      category: "container",
    });
  }
  if (/^\s*privileged:\s*true\s*$/im.test(content)) {
    out.push({
      title: "Kubernetes container runs privileged",
      detail: `${path} sets privileged: true, giving the container full access to the host - effectively root on the node. Fix: remove privileged: true and grant only the specific Linux capabilities the container needs.`,
      severity: "high",
      file: path,
      category: "container",
    });
  }
  if (/^\s*runAsUser:\s*0\s*$/m.test(content)) {
    out.push({
      title: "Kubernetes container runs as root (UID 0)",
      detail: `${path} sets runAsUser: 0, so the container runs as root. Fix: set runAsUser to a non-zero UID, e.g. runAsUser: 1000, and make sure the image supports running as that user.`,
      severity: "medium",
      file: path,
      category: "container",
    });
  }
  if (/^\s*runAsNonRoot:\s*false\s*$/m.test(content)) {
    out.push({
      title: "Kubernetes container allows running as root",
      detail: `${path} sets runAsNonRoot: false, so the container is allowed to run as root. Fix: set runAsNonRoot: true and set runAsUser to a non-zero UID.`,
      severity: "medium",
      file: path,
      category: "container",
    });
  }
  for (const line of content.split("\n")) {
    const m = /^\s*image:\s*["']?([^\s"'#]+)["']?/.exec(line);
    if (!m) continue;
    const parsed = parseDockerImage(m[1]);
    if (parsed && parsed.unpinned) {
      out.push({
        title: "Kubernetes container image is not pinned to a version",
        detail: `${path} runs container image ${m[1]} with no pinned version (tag "latest" or no tag), so a redeploy can silently pull a different image. Fix: pin the image to a specific versioned tag or a digest, e.g. image: myapp:1.2.3.`,
        severity: "medium",
        file: path,
        category: "container",
      });
    }
  }
  return out;
}

function workflowFindings(path: string, content: string): InfraFinding[] {
  // NOTE: pull_request_target is already flagged by scan.ts posture -
  // deliberately not repeated here. persist-credentials is default
  // behaviour and is also skipped.
  const out: InfraFinding[] = [];
  for (const a of parseWorkflowUses(content)) {
    // A full commit SHA is an immutable pin for any party.
    if (a.pinnedSha) continue;
    if (a.firstParty) {
      // A major version tag is a trusted pin for first-party actions.
      if (a.version) continue;
      // No ref (or a branch ref) keeps the existing medium finding.
      out.push({
        title: "GitHub Action is not pinned",
        detail: `${path} uses ${a.name}@${a.ref ?? "(no ref)"}. An unpinned action can change under you - a compromised or rewritten action runs with your workflow's permissions. Fix: pin the action to a full commit SHA (uses: ${a.name}@<40-character SHA>) or at least to a versioned tag such as @v4.`,
        severity: "medium",
        file: path,
        category: "actions",
      });
      continue;
    }
    // Third-party action, not pinned to a commit SHA: a version tag,
    // a branch, or no ref at all is a high finding.
    out.push({
      title: "GitHub Action is not pinned",
      detail: `${path} uses ${a.name}@${a.ref ?? "(no ref)"}. This is a third-party action, not one published by GitHub, and it is not pinned to a commit, so a new release or a compromised version can run with your workflow's permissions. Fix: pin the action to a full commit SHA (uses: ${a.name}@<40-character SHA>).`,
      severity: "high",
      file: path,
      category: "actions",
    });
  }
  return out;
}

function composeFindings(path: string, content: string): InfraFinding[] {
  const out: InfraFinding[] = [];
  if (/^\s*privileged:\s*true\s*$/im.test(content)) {
    out.push({
      title: "Compose service runs privileged",
      detail: `${path} sets privileged: true, giving the container full access to the host - effectively root on the machine. Fix: remove privileged: true and grant only the specific Linux capabilities the container needs.`,
      severity: "high",
      file: path,
      category: "container",
    });
  }
  if (/^\s*network_mode:\s*["']?host["']?\s*$/im.test(content)) {
    out.push({
      title: "Compose service uses the host network",
      detail: `${path} sets network_mode: host, so the container shares the host's network namespace and can see host network traffic and ports. Fix: remove network_mode: host and publish only the ports the service needs.`,
      severity: "high",
      file: path,
      category: "container",
    });
  }
  // cap_add: a block list or an inline list. One finding per block
  // that grants SYS_ADMIN or ALL.
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const capLine = /^(\s*)cap_add:\s*(.*)$/.exec(lines[i]);
    if (!capLine) continue;
    const indent = capLine[1].length;
    const bad: string[] = [];
    const collect = (text: string) => {
      for (const cap of text.split(",")) {
        const c = cap.replace(/[\[\]"']/g, "").trim();
        if ((c === "SYS_ADMIN" || c === "ALL") && !bad.includes(c)) bad.push(c);
      }
    };
    collect(capLine[2]);
    for (let j = i + 1; j < lines.length; j++) {
      const item = /^(\s*)-\s*(\S+)/.exec(lines[j]);
      if (!item || item[1].length <= indent) break;
      collect(item[2]);
    }
    if (bad.length > 0) {
      out.push({
        title: "Compose service adds a dangerous Linux capability",
        detail: `${path} grants ${bad.join(" and ")} with cap_add, giving the container broad powers over the host. Fix: remove ${bad.join(" and ")} from cap_add and grant only the specific capability the service needs.`,
        severity: "medium",
        file: path,
        category: "container",
      });
    }
  }
  for (const line of lines) {
    const m = /^\s*image:\s*["']?([^\s"'#]+)["']?/.exec(line);
    if (!m) continue;
    const parsed = parseDockerImage(m[1]);
    if (parsed && parsed.unpinned) {
      out.push({
        title: "Compose service image is not pinned to a version",
        detail: `${path} runs container image ${m[1]} with no pinned version (tag "latest" or no tag), so a redeploy can silently pull a different image. Fix: pin the image to a specific versioned tag or a digest, e.g. image: myapp:1.2.3.`,
        severity: "low",
        file: path,
        category: "container",
      });
    }
  }
  return out;
}

function terraformFindings(path: string, content: string): InfraFinding[] {
  const out: InfraFinding[] = [];
  const { required, declared } = parseTerraformBlocks(content);
  for (const name of new Set([...required.keys(), ...declared])) {
    // Only a MISSING constraint is flagged. A range ("~> 5.0") is a
    // constraint, just not an exact version - not a finding.
    const hasConstraint = required.has(name) && required.get(name)?.version !== null;
    if (hasConstraint) continue;
    const source = required.get(name)?.source;
    out.push({
      title: `Terraform provider ${name} has no version constraint`,
      detail: `${path} uses provider ${name} with no version constraint, so a future release of the provider can change your infrastructure on the next apply. Fix: add a version constraint in the required_providers block, e.g. ${name} = { source = "${source ?? `hashicorp/${name}`}", version = "5.0.0" }.`,
      severity: "medium",
      file: path,
    });
  }
  return out;
}

/** Risky infra patterns as posture findings (same shape as viteFindings
 *  in frameworks.ts). Each detail is plain English and ends with an
 *  exact "Fix: ..." - the coordinator splits the fix out when building
 *  PostureIssues. Only real, specific patterns are flagged; there is no
 *  generic "uses Docker" finding, and exposed ports are deliberately not
 *  flagged (too noisy). */
export function infraFindings(files: Map<string, string>): InfraFinding[] {
  const out: InfraFinding[] = [];
  for (const [path, content] of files) {
    const base = path.split("/").pop() ?? "";
    if (base === "Dockerfile" || base.startsWith("Dockerfile.")) {
      out.push(...dockerfileFindings(path, content));
    } else if (path.startsWith(".github/workflows/") && /\.ya?ml$/.test(path)) {
      out.push(...workflowFindings(path, content));
    } else if (/\.tf$/.test(path)) {
      out.push(...terraformFindings(path, content));
    } else if (base === "docker-compose.yml" || base === "docker-compose.yaml" || base === "compose.yml" || base === "compose.yaml") {
      out.push(...composeFindings(path, content));
    } else if (/\.ya?ml$/.test(path)) {
      // Oddly named YAML: a Kubernetes manifest or a compose file.
      if (isK8sManifest(content)) out.push(...k8sFindings(path, content));
      else if (/^\s*services:/m.test(content)) out.push(...composeFindings(path, content));
    }
  }
  return out;
}
