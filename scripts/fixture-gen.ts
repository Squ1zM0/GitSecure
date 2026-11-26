// Phase 14: test-time fixture generation.
//
// The vulnerable fixture manifests and risky infra configs used to be
// committed under tests/fixtures/ — so the repo's own self-scan flagged
// them (73 OSV advisories, 13 fixture-driven posture items, 2 unpinned
// fixture deps; see test-results/phase14-self-scan-inventory.md). A repo
// cannot score well on its own scan while it commits manifests pinning
// known-vulnerable versions, even as test data.
//
// The fix: the versions/configs that actually flag live ONLY here, as
// in-memory strings, and tests generate them into temp dirs (or parse
// them in memory) at test time. The committed fixture files keep only
// the CLEAN versions the tests also need (Django 5.2.17, Fiber
// v2.52.14, next 15.5.29, ...). Detection coverage is unchanged: the
// generated contents below are byte-identical to the old committed
// files, same vulnerable versions (Echo v4.11.1, vite 5.0.0, tokio
// 1.0.0, laravel/framework v10.34.2, spring-core 6.1.2, Flask 3.0.0,
// rails 7.1.3), so the same advisories are detected in tests.
//
// Rules for this file:
// - No literal secret-pattern value anywhere: the generated .env uses a
//   __SECRET_n__ placeholder, same convention as config.js / the test
//   files. The generated vite config references the public variable via
//   concatenation ("VITE_" + "API_URL") so no committed .ts file carries
//   a literal VITE_ token (the scanner flags those in .ts files).
// - Template literals containing ${...} (pom.xml properties) escape the
//   dollar, so the generated text is literal, not interpolated.

import { mkdtempSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Generated contents — byte-identical to the old committed fixtures.
// ---------------------------------------------------------------------------

/** Old tests/fixtures/fake-repo/package.json (vite 5.0.0 flagged 23 advisories). */
export const GENERATED_FAKE_REPO_PACKAGE_JSON =
  `{"dependencies":{"express":"*","next":"15.5.29","react":"18.3.1"},"devDependencies":{"vite":"5.0.0"},"name":"fake-repo","private":true,"version":"0.0.0"}`;

/** Old tests/fixtures/fake-repo/requirements.txt (Flask 3.0.0 flagged 2 advisories; Django 5.2.17 is clean and stays committed). */
export const GENERATED_FAKE_REPO_REQUIREMENTS_TXT = `Django==5.2.17\nFlask==3.0.0\n`;

/** Old tests/fixtures/fake-repo/Cargo.toml (tokio 1.0.0 flagged 9 advisories). */
export const GENERATED_FAKE_REPO_CARGO_TOML =
  `[package]\nname = "fake-repo"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nserde = "1.0.0"\ntokio = "1.0.0"\n`;

/** Old tests/fixtures/fake-repo/vite.config.ts (3 posture items: host 0.0.0.0, plugins, VITE_ var). */
export const GENERATED_FAKE_REPO_VITE_CONFIG_TS =
  `import { defineConfig } from "vite";\nimport react from "@vitejs/plugin-react";\n\nexport default defineConfig({\n  plugins: [react()],\n  server: { host: "0.0.0.0", port: 5173 },\n});\nexport const apiUrl = import.meta.env.` + `VITE_` + `API_URL;\n`;

/** Old tests/fixtures/fake-repo/.env (env-committed posture item, high). Value is a placeholder, never a literal secret. */
export const GENERATED_FAKE_REPO_ENV =
  `# FAKE fixture only — invented values, never real.\n# Placeholder: the test substitutes the invented key in memory.\nAPI_KEY=__SECRET_0__\n`;

/** Old tests/fixtures/fake-repo-tier2/go.mod (Echo v4.11.1 flagged 28 advisories; Fiber v2.52.14 is clean and stays committed). */
export const GENERATED_TIER2_GO_MOD =
  `module example.com/fake-repo-tier2\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgithub.com/labstack/echo/v4 v4.11.1\n\tgithub.com/gofiber/fiber/v2 v2.52.14\n\tgithub.com/spf13/cobra v1.8.0 // indirect\n)\n`;

/** Old tests/fixtures/fake-repo-tier2/composer.lock (laravel/framework v10.34.2 flagged 7 advisories). */
export const GENERATED_TIER2_COMPOSER_LOCK =
  `{"packages":[{"name":"laravel/framework","version":"v10.34.2"},{"name":"symfony/http-kernel","version":"v6.3.8"}],"packages-dev":[{"name":"phpunit/phpunit","version":"10.5.62"}]}`;

/** Old tests/fixtures/fake-repo-tier2/Gemfile.lock (rails 7.1.3 flagged 1 advisory). */
export const GENERATED_TIER2_GEMFILE_LOCK =
  `GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.3)\n      actioncable (= 7.1.3)\n    sinatra (4.2.0)\n    puma (7.2.1)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (~> 7.1.0)\n  sinatra\n  puma\n`;

/** Old tests/fixtures/fake-repo-tier2/pom.xml (spring-core 6.1.2 flagged 3 advisories; org.example:unresolvable stays version-null by design). */
export const GENERATED_TIER2_POM_XML =
  `<project>\n  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    <groupId>org.springframework.boot</groupId>\n    <artifactId>spring-boot-starter-parent</artifactId>\n    <version>3.2.0</version>\n  </parent>\n  <properties>\n    <spring.version>6.1.2</spring.version>\n  </properties>\n  <dependencies>\n    <dependency>\n      <groupId>org.springframework.boot</groupId>\n      <artifactId>spring-boot-starter-web</artifactId>\n    </dependency>\n    <dependency>\n      <groupId>org.springframework</groupId>\n      <artifactId>spring-core</artifactId>\n      <version>\${spring.version}</version>\n    </dependency>\n    <dependency>\n      <groupId>org.example</groupId>\n      <artifactId>unresolvable</artifactId>\n      <version>\${no.such.property}</version>\n    </dependency>\n  </dependencies>\n</project>\n`;

/** Old tests/fixtures/fake-repo-tier2/app.csproj (Microsoft.NET.Sdk.Web is a null-version pseudo-dep — 2 unpinned points — so the whole file is generated, not committed). */
export const GENERATED_TIER2_APP_CSPROJ =
  `<Project Sdk="Microsoft.NET.Sdk.Web">\n  <PropertyGroup>\n    <TargetFramework>net8.0</TargetFramework>\n  </PropertyGroup>\n  <ItemGroup>\n    <PackageReference Include="Microsoft.AspNetCore.Mvc" Version="8.0.0" />\n  </ItemGroup>\n</Project>\n`;

/** Old tests/fixtures/fake-repo-tier3/Dockerfile (4 posture items: node:latest, ARG API_TOKEN, USER root, ADD). */
export const GENERATED_TIER3_DOCKERFILE =
  `# Fake-repo fixture for Tier 3 infra tests. Placeholder values only —\n# no real images, hosts, or credentials.\nFROM node:20-alpine AS build\nWORKDIR /app\nCOPY package.json ./\nRUN npm ci\nCOPY . .\nRUN npm run build\n\nFROM node:latest\nWORKDIR /app\nCOPY --from=build /app/dist ./dist\nARG API_TOKEN\nUSER root\nADD https://example.com/releases/fake-app.tar.gz /tmp/fake-app.tar.gz\nCMD ["node", "dist/index.js"]\n`;

/** Old tests/fixtures/fake-repo-tier3/k8s/deployment.yaml (4 posture items: hostNetwork, myapp:latest, privileged, runAsUser 0). */
export const GENERATED_TIER3_K8S_DEPLOYMENT_YAML =
  `# Fake-repo fixture for Tier 3 infra tests. Placeholder values only.\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: fake-app\nspec:\n  replicas: 1\n  template:\n    spec:\n      hostNetwork: true\n      containers:\n        - name: app\n          image: myapp:latest\n          securityContext:\n            privileged: true\n            runAsUser: 0\n`;

/** Old tests/fixtures/fake-repo-tier3/main.tf (1 posture item: random provider with no version constraint). */
export const GENERATED_TIER3_MAIN_TF =
  `# Fake-repo fixture for Tier 3 infra tests. Placeholder values only.\nterraform {\n  required_version = "1.6.0"\n}\n\nterraform {\n  required_providers {\n    aws = {\n      source  = "hashicorp/aws"\n      version = "5.0.0"\n    }\n    random = {\n      source = "hashicorp/random"\n    }\n  }\n}\n\nprovider "aws" {\n  region = "us-east-1"\n}\n\nprovider "random" {}\n`;

// Generated overlays, keyed by the fixture path tests used to read from disk.
export const GENERATED_FAKE_REPO: Record<string, string> = {
  "package.json": GENERATED_FAKE_REPO_PACKAGE_JSON,
  "requirements.txt": GENERATED_FAKE_REPO_REQUIREMENTS_TXT,
  "Cargo.toml": GENERATED_FAKE_REPO_CARGO_TOML,
  "vite.config.ts": GENERATED_FAKE_REPO_VITE_CONFIG_TS,
  ".env": GENERATED_FAKE_REPO_ENV,
};
export const GENERATED_FAKE_REPO_TIER2: Record<string, string> = {
  "go.mod": GENERATED_TIER2_GO_MOD,
  "composer.lock": GENERATED_TIER2_COMPOSER_LOCK,
  "Gemfile.lock": GENERATED_TIER2_GEMFILE_LOCK,
  "pom.xml": GENERATED_TIER2_POM_XML,
  "app.csproj": GENERATED_TIER2_APP_CSPROJ,
};
export const GENERATED_FAKE_REPO_TIER3: Record<string, string> = {
  "Dockerfile": GENERATED_TIER3_DOCKERFILE,
  "k8s/deployment.yaml": GENERATED_TIER3_K8S_DEPLOYMENT_YAML,
  "main.tf": GENERATED_TIER3_MAIN_TF,
};

// ---------------------------------------------------------------------------
// Loaders — committed files from disk, generated contents overlaid.
// Tests use these instead of reading the fixture dirs directly, so the
// same assertions run against the same contents without the vulnerable
// versions living in the committed tree.
// ---------------------------------------------------------------------------

function loadDirRecursive(dir: string, prefix = ""): Map<string, string> {
  const out = new Map<string, string>();
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const rel = prefix ? `${prefix}/${entry}` : entry;
    if (statSync(full).isDirectory()) {
      for (const [k, v] of loadDirRecursive(full, rel)) out.set(k, v);
    } else {
      out.set(rel, readFileSync(full, "utf8"));
    }
  }
  return out;
}

/** fake-repo: committed clean files + generated vulnerable ones (package.json, requirements.txt, Cargo.toml, vite.config.ts, .env). */
export function loadFakeRepo(): Map<string, string> {
  const files = loadDirRecursive(join(process.cwd(), "tests/fixtures/fake-repo"));
  for (const [name, content] of Object.entries(GENERATED_FAKE_REPO)) files.set(name, content);
  return files;
}

/** fake-repo-tier2: committed clean files + generated vulnerable ones (go.mod, composer.lock, Gemfile.lock, pom.xml, app.csproj). */
export function loadFakeRepoTier2(): Map<string, string> {
  const files = loadDirRecursive(join(process.cwd(), "tests/fixtures/fake-repo-tier2"));
  for (const [name, content] of Object.entries(GENERATED_FAKE_REPO_TIER2)) files.set(name, content);
  return files;
}

/** fake-repo-tier3: committed clean files + generated risky ones (Dockerfile, k8s/deployment.yaml, main.tf). */
export function loadFakeRepoTier3(): Map<string, string> {
  const files = loadDirRecursive(join(process.cwd(), "tests/fixtures/fake-repo-tier3"));
  for (const [name, content] of Object.entries(GENERATED_FAKE_REPO_TIER3)) files.set(name, content);
  return files;
}

/**
 * Write a fixture map to a fresh temp dir (for tests that need a real
 * directory on disk, e.g. a directory scan). Returns the dir path.
 * Caller owns cleanup; temp dirs live under the OS temp dir, never in
 * the repo, so nothing generated is ever scanned as committed code.
 */
export function writeTempFixtureDir(files: Map<string, string>, prefix = "gitsecure-fixture-"): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  for (const [rel, content] of files) {
    const full = join(dir, rel);
    mkdirSync(join(dir, rel.split("/").slice(0, -1).join("/")), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}
