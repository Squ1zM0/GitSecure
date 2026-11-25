// Framework fingerprinting, Tier 1 (JS/TS, Python, Rust) + Tier 2 (Go, Ruby,
// PHP, Java/Kotlin, .NET) — Phase 2.
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
  // --- Tier 2: Go ---
  "github.com/gin-gonic/gin": { name: "Gin", ecosystem: "go" },
  "github.com/labstack/echo": { name: "Echo", ecosystem: "go" },
  "github.com/labstack/echo/v4": { name: "Echo", ecosystem: "go" },
  "github.com/gofiber/fiber": { name: "Fiber", ecosystem: "go" },
  "github.com/gofiber/fiber/v2": { name: "Fiber", ecosystem: "go" },
  "github.com/go-chi/chi/v5": { name: "Chi", ecosystem: "go" },
  // --- Tier 2: Ruby ---
  rails: { name: "Rails", ecosystem: "ruby" },
  sinatra: { name: "Sinatra", ecosystem: "ruby" },
  // --- Tier 2: PHP ---
  "laravel/framework": { name: "Laravel", ecosystem: "php" },
  "symfony/http-kernel": { name: "Symfony", ecosystem: "php" },
  "symfony/symfony": { name: "Symfony", ecosystem: "php" },
  "johnpbloch/wordpress": { name: "WordPress", ecosystem: "php" },
  "roots/wordpress": { name: "WordPress", ecosystem: "php" },
  // --- Tier 2: Java / Kotlin ---
  "org.springframework.boot:spring-boot-starter-parent": { name: "Spring Boot", ecosystem: "java" },
  "org.springframework.boot:spring-boot-starter-web": { name: "Spring Boot", ecosystem: "java" },
  "org.springframework.boot:spring-boot-starter": { name: "Spring Boot", ecosystem: "java" },
  "org.springframework:spring-core": { name: "Spring Framework", ecosystem: "java" },
  "org.springframework:spring-webmvc": { name: "Spring Framework", ecosystem: "java" },
  "org.jetbrains.kotlin:kotlin-stdlib": { name: "Kotlin", ecosystem: "java" },
  // --- Tier 2: .NET ---
  "Microsoft.AspNetCore.App": { name: "ASP.NET Core", ecosystem: "dotnet" },
  "Microsoft.AspNetCore.Mvc": { name: "ASP.NET Core", ecosystem: "dotnet" },
  "Microsoft.NET.Sdk.Web": { name: "ASP.NET Core", ecosystem: "dotnet" },
  "Microsoft.AspNetCore.Identity.EntityFrameworkCore": { name: "ASP.NET Core Identity", ecosystem: "dotnet" },
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

// --- Tier 2 parsers (Phase 2) ---

/** Parse go.mod: `require x v1.2.3` lines, single or in a require block. */
export function parseGoMod(content: string, sourceFile: string): Dependency[] {
  const out: Dependency[] = [];
  const seen = new Set<string>();
  for (const line of content.split("\n")) {
    const m = /^\s*(?:require\s+)?([A-Za-z0-9._\/-]+)\s+(v[0-9][A-Za-z0-9.+-]*)/.exec(line.trim());
    if (!m || m[1] === "go" || line.trim().startsWith("//")) continue;
    if (seen.has(m[1])) continue;
    seen.add(m[1]);
    out.push({ name: m[1], ecosystem: "go", version: m[2], direct: true, sourceFile });
  }
  return out;
}

/** Parse Gemfile: `gem 'rails', '~> 7.1.0'` — version may be a range or absent. */
export function parseGemfile(content: string, sourceFile: string): Dependency[] {
  const out: Dependency[] = [];
  for (const line of content.split("\n")) {
    const m = /^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/.exec(line);
    if (!m) continue;
    out.push({ name: m[1], ecosystem: "ruby", version: m[2] ?? null, direct: true, sourceFile });
  }
  return out;
}

/** Parse Gemfile.lock GEM specs: `    rails (7.1.3)` — pinned versions win
 *  over the Gemfile range. DEPENDENCIES entries (`rails (~> 7.1)`) are not
 *  versions and are skipped (their parens hold operators, not versions). */
export function parseGemfileLock(content: string, sourceFile: string): Dependency[] {
  const out: Dependency[] = [];
  const lines = content.split("\n");
  const specsIdx = lines.findIndex((l) => l.trim() === "specs:");
  if (specsIdx < 0) return out;
  for (let i = specsIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (/^\S/.test(line)) break; // next top-level section
    const m = /^    ([A-Za-z0-9_.\/-]+) \((\d[0-9A-Za-z.+-]*)\)/.exec(line);
    if (!m) continue;
    out.push({ name: m[1], ecosystem: "ruby", version: m[2], direct: false, sourceFile });
  }
  return out;
}

/** Parse composer.json require / require-dev. */
export function parseComposerJson(content: string, sourceFile: string): Dependency[] {
  try {
    const json = JSON.parse(content);
    const out: Dependency[] = [];
    for (const section of ["require", "require-dev"]) {
      const deps = json[section] as Record<string, string> | undefined;
      if (!deps) continue;
      for (const [name, spec] of Object.entries(deps)) {
        if (name === "php" || name.startsWith("ext-")) continue;
        out.push({ name, ecosystem: "php", version: typeof spec === "string" ? spec : null, direct: section === "require", sourceFile });
      }
    }
    return out;
  } catch {
    return [];
  }
}

/** Parse composer.lock packages / packages-dev (pinned versions). */
export function parseComposerLock(content: string, sourceFile: string): Dependency[] {
  try {
    const json = JSON.parse(content);
    const out: Dependency[] = [];
    for (const section of ["packages", "packages-dev"]) {
      const pkgs = (json[section] ?? []) as { name?: string; version?: string }[];
      for (const p of pkgs) {
        if (p.name && p.version) out.push({ name: p.name, ecosystem: "php", version: p.version, direct: false, sourceFile });
      }
    }
    return out;
  } catch {
    return [];
  }
}

/** Parse pom.xml <dependency> blocks. `${prop}` versions resolve from
 *  <properties> when present; otherwise version is null (never guessed). */
export function parsePomXml(content: string, sourceFile: string): Dependency[] {
  const out: Dependency[] = [];
  const props = new Map<string, string>();
  const propsBlock = /<properties>([\s\S]*?)<\/properties>/.exec(content)?.[1] ?? "";
  for (const m of propsBlock.matchAll(/<([A-Za-z0-9_.-]+)>([^<]+)<\/\1>/g)) props.set(m[1], m[2].trim());
  const resolve = (v: string | undefined): string | null => {
    if (!v) return null;
    const prop = /^\$\{([^}]+)\}$/.exec(v.trim());
    if (prop) return props.get(prop[1]) ?? null;
    return v.trim();
  };
  // Parent (e.g. spring-boot-starter-parent) carries the framework version.
  const parent = /<parent>([\s\S]*?)<\/parent>/.exec(content)?.[1];
  if (parent) {
    const g = /<groupId>([^<]+)<\/groupId>/.exec(parent)?.[1]?.trim();
    const a = /<artifactId>([^<]+)<\/artifactId>/.exec(parent)?.[1]?.trim();
    const v = resolve(/<version>([^<]+)<\/version>/.exec(parent)?.[1]);
    if (g && a) out.push({ name: `${g}:${a}`, ecosystem: "java", version: v, direct: true, sourceFile });
  }
  for (const block of content.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const body = block[1];
    const g = /<groupId>([^<]+)<\/groupId>/.exec(body)?.[1]?.trim();
    const a = /<artifactId>([^<]+)<\/artifactId>/.exec(body)?.[1]?.trim();
    const v = resolve(/<version>([^<]+)<\/version>/.exec(body)?.[1]);
    if (g && a) out.push({ name: `${g}:${a}`, ecosystem: "java", version: v, direct: true, sourceFile });
  }
  return out;
}

/** Parse build.gradle / build.gradle.kts: `implementation 'group:name:version'`
 *  (Groovy and Kotlin DSL string forms). */
export function parseGradle(content: string, sourceFile: string): Dependency[] {
  const out: Dependency[] = [];
  const seen = new Set<string>();
  for (const m of content.matchAll(/['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([0-9][A-Za-z0-9.+-]*)['"]/g)) {
    const name = `${m[1]}:${m[2]}`;
    if (seen.has(name)) continue;
    seen.add(name);
    out.push({ name, ecosystem: "java", version: m[3], direct: true, sourceFile });
  }
  return out;
}

/** Parse .csproj: PackageReference versions, plus the project SDK — an
 *  SDK of Microsoft.NET.Sdk.Web means ASP.NET Core, but its version is
 *  NOT the TargetFramework (net8.0 is a runtime target, not a framework
 *  version), so version stays null. */
export function parseCsproj(content: string, sourceFile: string): Dependency[] {
  const out: Dependency[] = [];
  const sdk = /<Project\s+Sdk="([^"]+)"/.exec(content)?.[1];
  if (sdk) out.push({ name: sdk, ecosystem: "dotnet", version: null, direct: true, sourceFile });
  for (const m of content.matchAll(/<PackageReference\s+Include="([^"]+)"[^>]*?Version="([^"]+)"/g)) {
    out.push({ name: m[1], ecosystem: "dotnet", version: m[2], direct: true, sourceFile });
  }
  return out;
}

/** Parse legacy NuGet packages.config: `<package id="X" version="Y" />`. */
export function parsePackagesConfig(content: string, sourceFile: string): Dependency[] {
  const out: Dependency[] = [];
  for (const m of content.matchAll(/<package\s+id="([^"]+)"\s+version="([^"]+)"/g)) {
    out.push({ name: m[1], ecosystem: "dotnet", version: m[2], direct: false, sourceFile });
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
    else if (!existing.version && d.version) byName.set(d.name, d);
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
  // WordPress via wp-config.php when no composer package names it: the
  // install is real, the version is not in the config, so it stays null.
  for (const path of files.keys()) {
    if (/(^|\/)wp-config\.php$/.test(path) && !out.some((f) => f.name === "WordPress")) {
      out.push({ name: "WordPress", ecosystem: "php", version: null, versionSource: "unknown", unpinned: false, sourceFile: path });
    }
  }
  // One entry per framework name: a framework named by two deps (e.g.
  // spring-boot-starter-parent + spring-boot-starter-web, or the .NET SDK
  // + an ASP.NET package) appears once, preferring a known version.
  const byFramework = new Map<string, Framework>();
  for (const f of out) {
    const existing = byFramework.get(f.name);
    if (!existing) byFramework.set(f.name, f);
    else if (!existing.version && f.version) byFramework.set(f.name, f);
  }
  return [...byFramework.values()].sort((a, b) => a.name.localeCompare(b.name));
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
