// Phase 14: prove the fixture migration is honest.
// The vulnerable fixture manifests and risky infra configs moved from
// committed files under tests/fixtures/ to test-time generation
// (scripts/fixture-gen.ts). This suite proves three things:
//   (a) the generated fixtures detect exactly what the old committed
//       fixtures detected (same advisory IDs, same posture items);
//   (b) no vulnerable pinned version remains in any committed manifest
//       or lockfile in the repo, and no fixture-driven posture item
//       remains in the committed tree — excluding nothing;
//   (c) the scanner contains no owner/repo special-casing: it treats
//       our repo exactly like any other public repo.
// Run: npm run test:fixtures-phase14 (needs network, queries api.osv.dev).
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import {
  GENERATED_FAKE_REPO,
  loadFakeRepo,
  loadFakeRepoTier2,
  loadFakeRepoTier3,
  writeTempFixtureDir,
} from "./fixture-gen";
import {
  parseCargoToml,
  parseComposerJson,
  parseComposerLock,
  parseCsproj,
  parseGemfile,
  parseGemfileLock,
  parseGoMod,
  parseGradle,
  parsePackageJson,
  parsePackageLock,
  parsePomXml,
  parseRequirements,
  viteFindings,
} from "../src/lib/frameworks";
import { checkDependencies } from "../src/lib/osv";
import { buildPosture } from "../src/lib/scan";
import { envFileFinding } from "../src/lib/secrets";
import { detectInfraFrameworks, infraFindings } from "../src/lib/infra";
import type { Dependency } from "../src/lib/types";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

const ROOT = process.cwd();

// ---------------------------------------------------------------------------
// (a) Equivalence: generated fixtures detect the same advisories.
// Advisory ID sets measured 2026-11-26, copied from
// test-results/phase14-self-scan-inventory.md §1b (the installed
// versions are unchanged since Phase 13). OSV data drifts over time:
// if a kept package gains an advisory, the exact-set check fails
// honestly and the inventory needs re-measuring — same convention as
// test-deps-phase13.ts.
// ---------------------------------------------------------------------------
const EXPECTED_ADVISORIES: Record<string, string[]> = {
  "github.com/labstack/echo/v4": [
    "GHSA-23wf-92cp-8pcj", "GHSA-246p-cpwv-v3jq", "GHSA-2ffq-g2xg-c22p",
    "GHSA-375p-5qhx-8wq4", "GHSA-3pmx-cf9f-34xr", "GHSA-99jh-6h7p-pp36",
    "GHSA-cxf3-9h37-7rr8", "GHSA-f48p-c9v4-h7xv", "GHSA-h7wr-284f-5qvc",
    "GHSA-h9g5-28mm-hx3g", "GHSA-r7w9-592q-9vg4", "GHSA-v753-g4cw-jm48",
    "GHSA-vfp3-v2gw-7wfq", "GHSA-xwq5-6cqp-vx96",
    "GO-2026-6293", "GO-2026-6839", "GO-2026-6840", "GO-2026-6842",
    "GO-2026-6872", "GO-2026-6873", "GO-2026-6875", "GO-2026-6876",
    "GO-2026-6877", "GO-2026-6878", "GO-2026-6879", "GO-2026-6881",
    "GO-2026-6883", "GO-2026-6885",
  ],
  vite: [
    "GHSA-356w-63v5-8wf4", "GHSA-4r4m-qw57-chr8", "GHSA-4w7w-66w2-5vf9",
    "GHSA-587h-7wmj-h5pm", "GHSA-64vr-g452-qvp3", "GHSA-698v-4r3x-3vcv",
    "GHSA-859w-5945-r5v3", "GHSA-8jhw-289h-jh2g", "GHSA-92r3-m2mg-pj97",
    "GHSA-93m4-6634-74q7", "GHSA-9cwx-2883-4wfx", "GHSA-9jrq-w75r-8gcw",
    "GHSA-c24v-8rfc-w8vw", "GHSA-c27g-q93r-2cwf", "GHSA-fx2h-pf6j-xcff",
    "GHSA-g4jq-h2w9-997c", "GHSA-jqfw-vq24-v9c3", "GHSA-r825-w8mm-5pxw",
    "GHSA-rq7h-c2jc-7f22", "GHSA-v6wh-96g9-6wx3", "GHSA-vg6x-rcgg-rjx6",
    "GHSA-x574-m823-4x7w", "GHSA-xcj6-pq6g-qj4x",
  ],
  tokio: [
    "GHSA-2grh-hm3w-w7hv", "GHSA-4q83-7cq4-p6wg", "GHSA-fg7r-2g4j-5cgr",
    "GHSA-rr8g-9fpq-6wmg", "RUSTSEC-2021-0072", "RUSTSEC-2021-0124",
    "RUSTSEC-2023-0005", "RUSTSEC-2025-0023", "RUSTSEC-2026-0386",
  ],
  "laravel/framework": [
    "GHSA-5vg9-5847-vvmq", "GHSA-63hm-g96r-2m2q", "GHSA-78fx-h6xr-vch4",
    "GHSA-crmm-hgp2-wgrp", "GHSA-f9x3-7vq9-cph6", "GHSA-gv7v-rgg6-548h",
    "GHSA-jh5r-qr3c-85q8",
  ],
  "org.springframework:spring-core": [
    "GHSA-659m-px2c-25wj", "GHSA-jmp9-x22r-554x", "GHSA-r4q3-7g4q-x89m",
  ],
  Flask: ["GHSA-68rp-wp8r-4726", "PYSEC-2026-2151"],
  rails: ["GHSA-9822-6m93-xqf4"],
};

function parseGeneratedDeps(): Dependency[] {
  const t2 = loadFakeRepoTier2();
  return [
    ...parsePackageJson(GENERATED_FAKE_REPO["package.json"], "package.json"),
    ...parseRequirements(GENERATED_FAKE_REPO["requirements.txt"], "requirements.txt"),
    ...parseCargoToml(GENERATED_FAKE_REPO["Cargo.toml"], "Cargo.toml"),
    ...parseGoMod(t2.get("go.mod") ?? "", "go.mod"),
    ...parseComposerLock(t2.get("composer.lock") ?? "", "composer.lock"),
    ...parseGemfileLock(t2.get("Gemfile.lock") ?? "", "Gemfile.lock"),
    ...parsePomXml(t2.get("pom.xml") ?? "", "pom.xml"),
  ];
}

// Same dedupe as scanRepo: by ecosystem:name, keep the pinned version.
function dedupeDeps(deps: Dependency[]): Dependency[] {
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
  return [...depByKey.values()];
}

async function main() {
  // --- (a1) OSV equivalence over the generated fixtures ---
  const genDeps = dedupeDeps(parseGeneratedDeps());
  const genResult = await checkDependencies(genDeps);
  check("generated fixtures: OSV reachable", !genResult.unavailable);
  const genVulns = genResult.vulnerabilities;
  const byPkg = (name: string) => genVulns.filter((v) => v.packageName === name);
  let expectedTotal = 0;
  for (const [name, ids] of Object.entries(EXPECTED_ADVISORIES)) {
    expectedTotal += ids.length;
    const found = byPkg(name).map((v) => v.id).sort();
    const want = [...ids].sort();
    check(
      `generated ${name} detects the same ${ids.length} advisories as the old committed fixture`,
      found.length === want.length && found.every((id, i) => id === want[i]),
      `got ${found.length}: ${found.filter((id) => !want.includes(id)).join(", ") || "same set"}`,
    );
  }
  check("generated fixtures: total is 73, the old committed-fixture total", genVulns.length === 73, `got ${genVulns.length}`);
  check("generated fixtures: total matches the expected ID sets", genVulns.length === expectedTotal, `${genVulns.length} vs ${expectedTotal}`);

  // --- (a2) Posture equivalence: generated vite config + infra + .env ---
  const viteMap = new Map([["vite.config.ts", GENERATED_FAKE_REPO["vite.config.ts"]]]);
  const viteTitles = viteFindings(viteMap).map((f) => f.title).sort();
  check(
    "generated vite.config.ts yields the same 3 posture items (host, plugins, public vars)",
    viteTitles.length === 3 &&
      viteTitles.includes("Vite dev server bound to 0.0.0.0") &&
      viteTitles.includes("Vite plugins in use") &&
      viteTitles.includes("VITE_ variables are public by design"),
    viteTitles.join("; "),
  );
  const t3gen = loadFakeRepoTier3();
  // Key the map with repo-prefixed paths, exactly as the real scan sees
  // them: infraFindings only runs workflow checks on paths starting
  // ".github/workflows/", so the unprefixed fixture-relative key would
  // surface an extra unpinned-action finding the real scan never
  // reports (test-tier3.ts asserts that finding separately, via the
  // relative map). The 10 items below are the inventory's Tier 3 set.
  const t3prefixed = new Map([...t3gen].map(([k, v]) => [`tests/fixtures/fake-repo-tier3/${k}`, v] as [string, string]));
  const infraTitles = infraFindings(t3prefixed).map((f) => f.title).sort();
  const expectedInfra = [
    "Docker base image is not pinned to a version",
    "Dockerfile downloads a file with ADD",
    "Dockerfile has no HEALTHCHECK",
    "Dockerfile runs as root",
    "Kubernetes container image is not pinned to a version",
    "Kubernetes container runs as root (UID 0)",
    "Kubernetes container runs privileged",
    "Kubernetes pod uses the host network",
    "Possible secret passed as a Docker build argument",
    "Terraform provider random has no version constraint",
  ].sort();
  check(
    "generated Tier 3 fixtures yield the same 10 infra posture items",
    infraTitles.length === expectedInfra.length && infraTitles.every((t, i) => t === expectedInfra[i]),
    infraTitles.join("; "),
  );
  // The relative-key map (as test-tier3.ts uses it) additionally
  // surfaces the unpinned-action finding — real detector behaviour,
  // just path-gated out of the repo scan. Recorded here so the
  // 10-vs-11 difference is never mistaken for drift.
  check(
    "generated Tier 3 (relative keys): unpinned setup-node action finding also present",
    infraFindings(t3gen).some((f) => f.title === "GitHub Action is not pinned"),
  );
  check("generated .env still trips the env-file finding", envFileFinding(".env", "HEAD").type === "env-file");
  // The whole generated set through buildPosture, with the real repo
  // files that clear the non-fixture items present, and fixture maps
  // keyed with repo-prefixed paths exactly as the real scan sees them:
  // exactly the 14 fixture-driven posture items from the inventory,
  // nothing else.
  const prefixMap = (m: Map<string, string>, prefix: string) =>
    new Map([...m].map(([k, v]) => [`${prefix}${k}`, v] as [string, string]));
  const combined = new Map<string, string>([
    ...prefixMap(loadFakeRepo(), "tests/fixtures/fake-repo/"),
    ...prefixMap(loadFakeRepoTier2(), "tests/fixtures/fake-repo-tier2/"),
    ...prefixMap(loadFakeRepoTier3(), "tests/fixtures/fake-repo-tier3/"),
    ["SECURITY.md", "x"],
    [".github/dependabot.yml", "x"],
    [".gitignore", ".env\nnode_modules\n*.pem\n"],
  ]);
  const postureIds = buildPosture(combined).map((p) => p.id).sort();
  const expectedPostureIds = [
    "env-committed",
    "infra-docker-base-image-is-not-pinned-to-a-version",
    "infra-dockerfile-downloads-a-file-with-add",
    "infra-dockerfile-has-no-healthcheck",
    "infra-dockerfile-runs-as-root",
    "infra-kubernetes-container-image-is-not-pinned-to-a-version",
    "infra-kubernetes-container-runs-as-root-uid-0-",
    "infra-kubernetes-container-runs-privileged",
    "infra-kubernetes-pod-uses-the-host-network",
    "infra-possible-secret-passed-as-a-docker-build-argument",
    "infra-terraform-provider-random-has-no-version-constraint",
    "vite-vite-dev-server-bound-to-0-0-0-0",
    "vite-vite-plugins-in-use",
    "vite-vite-variables-are-public-by-design",
  ].sort();
  check(
    "generated fixtures through buildPosture give exactly the 14 fixture-driven posture items",
    postureIds.length === expectedPostureIds.length && postureIds.every((id, i) => id === expectedPostureIds[i]),
    postureIds.join(", "),
  );

  // --- (a3) Temp-dir generation works: a real directory on disk ---
  const tmpTier2 = writeTempFixtureDir(loadFakeRepoTier2());
  const tmpGoMod = readFileSync(join(tmpTier2, "go.mod"), "utf8");
  const tmpEcho = parseGoMod(tmpGoMod, "go.mod").find((d) => d.name === "github.com/labstack/echo/v4");
  check("temp-dir fixture: go.mod on disk still pins Echo v4.11.1", tmpEcho?.version === "v4.11.1", String(tmpEcho?.version));
  const tmpCsproj = readFileSync(join(tmpTier2, "app.csproj"), "utf8");
  check("temp-dir fixture: app.csproj generated on disk (not committed)", tmpCsproj.includes("Microsoft.NET.Sdk.Web"));
  const tmpTier3 = writeTempFixtureDir(loadFakeRepoTier3());
  check("temp-dir fixture: Dockerfile generated on disk (not committed)", existsSync(join(tmpTier3, "Dockerfile")));
  check("temp-dir fixture: k8s manifest generated on disk (not committed)", existsSync(join(tmpTier3, "k8s/deployment.yaml")));

  // --- (a4) Fingerprints still resolve from generated fixtures ---
  // (The framework assertions themselves live in test-scanner.ts /
  // test-tier3.ts; here we prove the generated maps still carry the
  // frameworks the self-scan counted, e.g. Vite 5.0.0 and Echo.)
  const t3Frameworks = detectInfraFrameworks(t3gen);
  check("generated Tier 3: Docker node image 20-alpine still detected", t3Frameworks.some((f) => f.name === "Docker image node" && f.version === "20-alpine"));

  // -------------------------------------------------------------------------
  // (b) The committed tree is clean — excluding nothing.
  // -------------------------------------------------------------------------
  const MANIFEST_BASES = new Set([
    "package.json", "package-lock.json", "requirements.txt", "Cargo.toml",
    "go.mod", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
    "pom.xml", "build.gradle",
  ]);
  const isCsproj = (p: string) => p.endsWith(".csproj");
  function walkCommittedManifests(dir: string, out: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
      if (entry === "node_modules" || entry === ".next" || entry === ".git") continue;
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walkCommittedManifests(full, out);
      else if (MANIFEST_BASES.has(entry) || isCsproj(entry)) out.push(full);
    }
    return out;
  }
  const committedManifests = walkCommittedManifests(ROOT);
  const committedDeps: Dependency[] = [];
  for (const path of committedManifests) {
    const content = readFileSync(path, "utf8");
    const base = path.split("/").pop() ?? "";
    const rel = path.slice(ROOT.length + 1);
    if (base === "package.json") committedDeps.push(...parsePackageJson(content, rel));
    else if (base === "package-lock.json") committedDeps.push(...parsePackageLock(content, rel));
    else if (base === "requirements.txt") committedDeps.push(...parseRequirements(content, rel));
    else if (base === "Cargo.toml") committedDeps.push(...parseCargoToml(content, rel));
    else if (base === "go.mod") committedDeps.push(...parseGoMod(content, rel));
    else if (base === "Gemfile") committedDeps.push(...parseGemfile(content, rel));
    else if (base === "Gemfile.lock") committedDeps.push(...parseGemfileLock(content, rel));
    else if (base === "composer.json") committedDeps.push(...parseComposerJson(content, rel));
    else if (base === "composer.lock") committedDeps.push(...parseComposerLock(content, rel));
    else if (base === "pom.xml") committedDeps.push(...parsePomXml(content, rel));
    else if (base === "build.gradle") committedDeps.push(...parseGradle(content, rel));
    else if (isCsproj(base)) committedDeps.push(...parseCsproj(content, rel));
  }
  const committedResult = await checkDependencies(dedupeDeps(committedDeps));
  check("committed manifests: OSV reachable", !committedResult.unavailable);
  check(
    "committed manifests: ZERO OSV advisories (was 73 before the migration)",
    committedResult.vulnerabilities.length === 0,
    committedResult.vulnerabilities.map((v) => `${v.packageName}@${v.installedVersion}:${v.id}`).join("; "),
  );
  // No unpinned direct dep left in the committed tree (the two fixture
  // ones — Microsoft.NET.Sdk.Web and org.example:unresolvable — are
  // generated now, not committed).
  const unpinnedDirect = dedupeDeps(committedDeps).filter((d) => d.direct && !d.version);
  check("committed manifests: zero unpinned direct dependencies (was 2)", unpinnedDirect.length === 0, unpinnedDirect.map((d) => d.name).join(", "));

  // The vulnerable versions are gone from the committed fixture files.
  const readCommitted = (p: string) => (existsSync(join(ROOT, p)) ? readFileSync(join(ROOT, p), "utf8") : null);
  const gone: [string, string, string][] = [
    ["tests/fixtures/fake-repo/package.json", "vite", "vite 5.0.0"],
    ["tests/fixtures/fake-repo/requirements.txt", "Flask", "Flask 3.0.0"],
    ["tests/fixtures/fake-repo/Cargo.toml", "tokio", "tokio 1.0.0"],
    ["tests/fixtures/fake-repo-tier2/go.mod", "labstack/echo", "Echo v4.11.1"],
    ["tests/fixtures/fake-repo-tier2/composer.lock", "laravel/framework", "laravel v10.34.2"],
    ["tests/fixtures/fake-repo-tier2/Gemfile.lock", "rails (", "rails 7.1.3"],
    ["tests/fixtures/fake-repo-tier2/pom.xml", "spring-core", "spring-core 6.1.2"],
    ["tests/fixtures/fake-repo-tier2/pom.xml", "no.such.property", "org.example:unresolvable"],
  ];
  for (const [path, needle, label] of gone) {
    const content = readCommitted(path);
    check(`committed ${path} no longer contains ${label}`, content !== null && !content.includes(needle), content === null ? "file missing" : "");
  }
  // Files that cannot be clean are gone from the committed tree entirely.
  for (const path of [
    "tests/fixtures/fake-repo/.env",
    "tests/fixtures/fake-repo-tier2/app.csproj",
    "tests/fixtures/fake-repo-tier3/Dockerfile",
    "tests/fixtures/fake-repo-tier3/k8s/deployment.yaml",
    "tests/fixtures/fake-repo-tier3/main.tf",
  ]) {
    check(`committed ${path} no longer exists (generated at test time)`, !existsSync(join(ROOT, path)));
  }
  // The committed vite.config.ts is clean: no host, no plugins, no
  // public-variable reference.
  const committedVite = readCommitted("tests/fixtures/fake-repo/vite.config.ts") ?? "";
  check("committed vite.config.ts yields zero vite findings", viteFindings(new Map([["vite.config.ts", committedVite]])).length === 0);

  // No fixture-driven posture item remains in the committed fixture maps.
  function loadCommittedDir(dir: string, prefix = ""): Map<string, string> {
    const out = new Map<string, string>();
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const rel = prefix ? `${prefix}/${entry}` : entry;
      if (statSync(full).isDirectory()) {
        for (const [k, v] of loadCommittedDir(full, rel)) out.set(k, v);
      } else out.set(rel, readFileSync(full, "utf8"));
    }
    return out;
  }
  // Keyed with repo-prefixed paths, exactly as the real scan sees
  // them (see the note in (a2): relative keys would surface a
  // path-gated workflow finding the real scan never reports).
  const committedFixtures = new Map<string, string>([
    ...[...loadCommittedDir(join(ROOT, "tests/fixtures/fake-repo"))].map(([k, v]) => [`tests/fixtures/fake-repo/${k}`, v] as [string, string]),
    ...[...loadCommittedDir(join(ROOT, "tests/fixtures/fake-repo-tier2"))].map(([k, v]) => [`tests/fixtures/fake-repo-tier2/${k}`, v] as [string, string]),
    ...[...loadCommittedDir(join(ROOT, "tests/fixtures/fake-repo-tier3"))].map(([k, v]) => [`tests/fixtures/fake-repo-tier3/${k}`, v] as [string, string]),
  ]);
  const committedFixturePosture = buildPosture(
    new Map([...committedFixtures, ["SECURITY.md", "x"], [".github/dependabot.yml", "x"], [".gitignore", ".env\nnode_modules\n*.pem\n"]]),
  );
  const fixtureDrivenLeft = committedFixturePosture.filter(
    (p) => p.id === "env-committed" || p.id.startsWith("vite-") || p.id.startsWith("infra-"),
  );
  check(
    "committed fixture maps: zero fixture-driven posture items left (was 13)",
    fixtureDrivenLeft.length === 0,
    fixtureDrivenLeft.map((p) => p.id).join(", "),
  );
  check("committed fixture maps: no infra findings left", infraFindings(committedFixtures).length === 0);

  // -------------------------------------------------------------------------
  // (c) No owner/repo special-casing in the scanner.
  // -------------------------------------------------------------------------
  function walkTs(dir: string, out: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walkTs(full, out);
      else if (/\.tsx?$/.test(entry)) out.push(full);
    }
    return out;
  }
  const libFiles = walkTs(join(ROOT, "src/lib"));
  // (c1) No owner/repo equality or membership test against OUR literal
  // name. Generic guards are fine and must not trip this: `owner.includes("..")`
  // (path-traversal guard) and `typeof parsed.owner === "string"` (type
  // check) compare against generic tokens, not a repo name — the regex
  // below only fires when the literal IS our owner/repo name.
  const specialCaseRe =
    /(owner|repo)\s*(===?|!==?)\s*["'](Squ1zM0|GitSecure)|["'](Squ1zM0|GitSecure)["']\s*(===?|!==?)|(owner|repo)\s*\.\s*(includes|startsWith|endsWith)\s*\(\s*["'](Squ1zM0|GitSecure)/;
  const specialCaseHits: string[] = [];
  for (const f of libFiles) {
    const content = readFileSync(f, "utf8");
    if (specialCaseRe.test(content)) specialCaseHits.push(f);
  }
  check("scanner lib: no owner/repo literal comparison anywhere", specialCaseHits.length === 0, specialCaseHits.join(", "));
  // (c2) Every "Squ1zM0" mention in src/lib is documentation or a tool
  // description example — never a branch condition. (The product name
  // "GitSecure" legitimately appears in src/lib as User-Agent, error
  // copy and comments; what must never appear is a conditional keyed
  // on it.)
  const squ1zHits: string[] = [];
  for (const f of libFiles) {
    const lines = readFileSync(f, "utf8").split("\n");
    lines.forEach((line, i) => {
      if (line.includes("Squ1zM0")) {
        const docOrExample = /\/\/|\bexample\b|for example/i.test(line);
        if (!docOrExample) squ1zHits.push(`${f}:${i + 1}`);
      }
    });
  }
  check("scanner lib: 'Squ1zM0' appears only in doc comments / tool examples", squ1zHits.length === 0, squ1zHits.join(", "));
  const conditionalOnProduct: string[] = [];
  for (const f of libFiles) {
    const lines = readFileSync(f, "utf8").split("\n");
    lines.forEach((line, i) => {
      // Strip string literals first: error copy like "GitSecure scans
      // public repos only" sits on the same line as an `if`, but the
      // product name is in the message, not in the condition.
      const code = line.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, '""');
      if (/if\s*\(.*(GitSecure|Squ1zM0)|switch\s*\(.*(owner|repo)/.test(code)) conditionalOnProduct.push(`${f}:${i + 1}`);
    });
  }
  check("scanner lib: no conditional keyed on the product/repo name", conditionalOnProduct.length === 0, conditionalOnProduct.join(", "));

  console.log(failures === 0 ? "\nAll Phase 14 fixture checks passed." : `\n${failures} Phase 14 fixture check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
