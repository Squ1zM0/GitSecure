// Framework fingerprinting, Tier 1 only (JS/TS, Python, Rust).
// Pluggable by design: a framework is an entry in FRAMEWORK_MAP —
// dep name -> framework name + ecosystem. Adding an ecosystem means
// adding a manifest parser + map entries, not rebuilding the scanner.
// Version rule: lockfile-pinned wins; manifest range second; if no version
// can be found, version is null and versionSource is "unknown" — never guessed.

import type { Dependency, Framework } from "./types";

export const FRAMEWORK_MAP: Record<string, { name: string; ecosystem: string }> = {
  next: { name: "Next.js", ecosystem: "js" },
  react: { name: "React", ecosystem: "js" },
  vue: { name: "Vue", ecosystem: "js" },
  "@angular/core": { name: "Angular", ecosystem: "js" },
  svelte: { name: "Svelte", ecosystem: "js" },
  vite: { name: "Vite", ecosystem: "js" },
  express: { name: "Express", ecosystem: "js" },
  "@nestjs/core": { name: "NestJS", ecosystem: "js" },
  nuxt: { name: "Nuxt", ecosystem: "js" },
  astro: { name: "Astro", ecosystem: "js" },
  "react-dom": { name: "React DOM", ecosystem: "js" },
  django: { name: "Django", ecosystem: "python" },
  Django: { name: "Django", ecosystem: "python" },
  flask: { name: "Flask", ecosystem: "python" },
  Flask: { name: "Flask", ecosystem: "python" },
  fastapi: { name: "FastAPI", ecosystem: "python" },
  axum: { name: "Axum", ecosystem: "rust" },
  actix_web: { name: "Actix Web", ecosystem: "rust" },
  "actix-web": { name: "Actix Web", ecosystem: "rust" },
  rocket: { name: "Rocket", ecosystem: "rust" },
  warp: { name: "Warp", ecosystem: "rust" },
  tokio: { name: "Tokio", ecosystem: "rust" },
  serde: { name: "Serde", ecosystem: "rust" },
};

export function isUnpinned(spec: string | null): boolean {
  if (!spec) return true;
  const s = spec.trim();
  return s === "*" || s.toLowerCase() === "latest" || s.startsWith("git+") || s.startsWith("http");
}

/** Parse package.json dependencies/devDependencies. */
export function parsePackageJson(content: string, sourceFile: string): Dependency[] {
  try {
    const json = JSON.parse(content);
    const out: Dependency[] = [];
    for (const section of ["dependencies", "devDependencies"]) {
      const deps = json[section] as Record<string, string> | undefined;
      if (!deps) continue;
      for (const [name, spec] of Object.entries(deps)) {
        out.push({ name, ecosystem: "npm", version: typeof spec === "string" ? spec : null, direct: section === "dependencies", sourceFile });
      }
    }
    return out;
  } catch {
    return [];
  }
}

/** Parse package-lock.json (v2/v3): packages[""].dependencies + packages["node_modules/<name>"].version */
export function parsePackageLock(content: string, sourceFile: string): Dependency[] {
  try {
    const json = JSON.parse(content);
    const out: Dependency[] = [];
    const pkgs = (json.packages ?? {}) as Record<string, { version?: string; dev?: boolean }>;
    for (const [key, info] of Object.entries(pkgs)) {
      if (!key.startsWith("node_modules/")) continue;
      const name = key.replace("node_modules/", "");
      if (name.includes("node_modules/")) continue; // nested, skip for MVP (still counted as transitive via top level)
      if (info.version) out.push({ name, ecosystem: "npm", version: info.version, direct: false, sourceFile });
    }
    // Fallback for lock v1 shape.
    const deps = (json.dependencies ?? {}) as Record<string, { version?: string }>;
    for (const [name, info] of Object.entries(deps)) {
      if (info.version && !out.some((d) => d.name === name)) {
        out.push({ name, ecosystem: "npm", version: info.version, direct: false, sourceFile });
      }
    }
    return out;
  } catch {
    return [];
  }
}

/** Parse pnpm-lock.yaml / yarn.lock loosely: "name@version:" lines. */
export function parseYamlLock(content: string, sourceFile: string, ecosystem: "npm"): Dependency[] {
  const out: Dependency[] = [];
  const seen = new Set<string>();
  const re = /^['"]?([^@\s/'"][^@\s'"]*)@[^:\s]+:\s*$/gm;
  // pnpm style: "  next@14.2.5:" — also try a simpler line scan.
  for (const line of content.split("\n")) {
    const m = /^\s*['"]?([A-Za-z0-9@/_.-]+)@(\d+\.\d+\.\d+[^:\s'"]*):/.exec(line.trim());
    if (!m) continue;
    const name = m[1].replace(/^['"]/, "");
    const version = m[2];
    if (seen.has(name)) continue;
    seen.add(name);
    out.push({ name, ecosystem, version, direct: false, sourceFile });
  }
  void re;
  return out;
}

/** Parse requirements.txt / Pipfile-ish lines: name==1.2.3, name>=1.0 */
export function parseRequirements(content: string, sourceFile: string): Dependency[] {
  const out: Dependency[] = [];
  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const m = /^([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|>|<)?\s*([0-9][A-Za-z0-9.+-]*)?/.exec(line);
    if (!m) continue;
    out.push({ name: m[1], ecosystem: "pypi", version: m[2] ?? null, direct: true, sourceFile });
  }
  return out;
}

/** Parse Cargo.toml [dependencies] (simple form) and Cargo.lock [[package]]. */
export function parseCargoToml(content: string, sourceFile: string): Dependency[] {
  const out: Dependency[] = [];
  const inDeps = /\[dependencies\]([\s\S]*?)(?:\n\[|\n$)/.exec(content);
  if (!inDeps) return out;
  for (const line of inDeps[1].split("\n")) {
    const m = /^\s*([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]+)"|\{\s*version\s*=\s*"([^"]+)")/.exec(line);
    if (!m) continue;
    out.push({ name: m[1], ecosystem: "crates", version: m[2] ?? m[3] ?? null, direct: true, sourceFile });
  }
  return out;
}

export function parseCargoLock(content: string, sourceFile: string): Dependency[] {
  const out: Dependency[] = [];
  for (const block of content.split("[[package]]")) {
    const name = /name\s*=\s*"([^"]+)"/.exec(block)?.[1];
    const version = /version\s*=\s*"([^"]+)"/.exec(block)?.[1];
    if (name && version) out.push({ name, ecosystem: "crates", version, direct: false, sourceFile });
  }
  return out;
}

export interface FingerprintInput {
  files: Map<string, string>; // path -> content (manifests, configs, lockfiles)
}

/** Fingerprint frameworks from parsed dependencies + config files. */
export function fingerprintFrameworks(deps: Dependency[], files: Map<string, string>): Framework[] {
  const byName = new Map<string, Dependency>();
  // Lockfile (transitive, pinned) wins over manifest for version.
  for (const d of deps) {
    const existing = byName.get(d.name);
    if (!existing) byName.set(d.name, d);
    else if (!d.direct && existing.direct) byName.set(d.name, d);
    else if (existing.version && /[\^~><*]/.test(existing.version) && d.version && !/[\^~><*]/.test(d.version)) byName.set(d.name, d);
  }
  const out: Framework[] = [];
  for (const [name, dep] of byName) {
    const fw = FRAMEWORK_MAP[name];
    if (!fw) continue;
    const pinned = dep.version && !/[\^~><*]/.test(dep.version);
    out.push({
      name: fw.name,
      ecosystem: fw.ecosystem,
      version: dep.version ?? null,
      versionSource: !dep.direct && pinned ? "lockfile" : dep.direct ? "manifest" : "lockfile",
      unpinned: isUnpinned(dep.version),
      sourceFile: dep.sourceFile,
    });
  }
  // Vite via config file even if only a devDependency / not in the map hit.
  for (const path of files.keys()) {
    if (/vite\.config\.(js|ts|mjs|mts)$/.test(path) && !out.some((f) => f.name === "Vite")) {
      const dep = byName.get("vite");
      out.push({ name: "Vite", ecosystem: "js", version: dep?.version ?? null, versionSource: dep ? "manifest" : "unknown", unpinned: isUnpinned(dep?.version ?? null), sourceFile: path });
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

/** Vite-specific checks: dev-server exposure, SSR, VITE_ env leaks. */
export function viteFindings(files: Map<string, string>): { title: string; detail: string; severity: "medium" | "low" | "info" }[] {
  const out: { title: string; detail: string; severity: "medium" | "low" | "info" }[] = [];
  for (const [path, content] of files) {
    if (!/vite\.config\.(js|ts|mjs|mts)$/.test(path)) continue;
    if (/host\s*:\s*['"]0\.0\.0\.0['"]/.test(content)) {
      out.push({ title: "Vite dev server bound to 0.0.0.0", detail: `${path} sets server.host to 0.0.0.0, exposing the dev server on the local network.`, severity: "medium" });
    }
    const plugins = [...content.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((m) => m[1]).filter((p) => p.includes("vite"));
    if (plugins.length > 0) {
      out.push({ title: "Vite plugins in use", detail: `${path} imports: ${plugins.join(", ")}. Review each plugin — a compromised or unmaintained plugin runs in your build.`, severity: "info" });
    }
  }
  // VITE_-prefixed vars in .env files / code: they are baked into the client bundle.
  for (const [path, content] of files) {
    if (!/\.env/.test(path) && !/\.(ts|tsx|js|jsx)$/.test(path)) continue;
    const vars = [...content.matchAll(/\bVITE_[A-Z0-9_]+/g)].map((m) => m[0]);
    const unique = [...new Set(vars)];
    if (unique.length > 0) {
      out.push({ title: "VITE_ variables are public by design", detail: `${path} references ${unique.slice(0, 5).join(", ")}${unique.length > 5 ? ` (+${unique.length - 5} more)` : ""}. Anything prefixed VITE_ is baked into the client bundle — never put a secret behind that prefix.`, severity: "info" });
      break;
    }
  }
  return out;
}
