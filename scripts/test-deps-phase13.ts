// Phase 13: prove the dependency-flaw fixes with live OSV data.
// Upgraded fixture + real-dep versions must return ZERO advisories;
// the deliberately kept-vulnerable fixtures must still flag (at least
// one advisory each), so detection coverage is preserved.
// Counts measured 2026-11-26 (see test-results/phase13-vuln-inventory.md
// and the Phase 13 section in GITSECURE.md). OSV data drifts over time:
// if a NEW advisory is published for a fixed version, the zero-advisory
// checks fail honestly and the version needs another bump; if a kept
// package gains advisories, only the exact-count checks move.
// Phase 14: the kept-vulnerable fixtures are no longer committed — they
// are generated at test time by scripts/fixture-gen.ts (same versions,
// same contents), so this suite parses the GENERATED contents. The
// committed tree itself now carries zero advisories; that is proven
// separately by scripts/test-fixtures-phase14.ts, not here.
// Run: npm run test:deps-phase13 (needs network, queries api.osv.dev).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  GENERATED_FAKE_REPO,
  loadFakeRepoTier2,
} from "./fixture-gen";
import {
  parsePackageJson, parsePackageLock, parseRequirements, parseCargoToml,
  parseGoMod, parseGemfile, parseGemfileLock, parseComposerJson,
  parseComposerLock, parsePomXml, parseGradle, parseCsproj,
} from "../src/lib/frameworks";
import { checkDependencies } from "../src/lib/osv";
import type { Dependency } from "../src/lib/types";

let failures = 0;
function check(name: string, ok: boolean, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

const ROOT = process.cwd();
const read = (p: string) => readFileSync(join(ROOT, p), "utf8");

// All manifest files the scanner reads from this repo, in the same
// priority order scanRepo uses (manifests first, alphabetical by path).
// Phase 14: the kept-vulnerable manifests come from the GENERATED
// test-time fixtures (scripts/fixture-gen.ts); the committed clean
// manifests come from disk. The committed fixture files that the
// generated ones replace (fake-repo package.json / requirements.txt /
// Cargo.toml, tier2 go.mod / Gemfile.lock / composer.lock / pom.xml /
// app.csproj) are NOT read from disk here — their clean committed
// versions would undercount the kept advisories.
const manifestPaths = [
  "package.json",
  "package-lock.json",
  "tests/fixtures/fake-repo-tier2/Gemfile",
  "tests/fixtures/fake-repo-tier2/composer.json",
  "tests/fixtures/fake-repo-tier2/build.gradle",
];
const deps: Dependency[] = [];
for (const path of manifestPaths) {
  const content = read(path);
  const base = path.split("/").pop() ?? "";
  if (base === "package.json") deps.push(...parsePackageJson(content, path));
  else if (base === "package-lock.json") deps.push(...parsePackageLock(content, path));
  else if (base === "Gemfile") deps.push(...parseGemfile(content, path));
  else if (base === "composer.json") deps.push(...parseComposerJson(content, path));
  else if (base === "build.gradle") deps.push(...parseGradle(content, path));
}
// Generated kept-vulnerable fixtures (same contents as the old committed
// files, Phase 14): fake-repo package.json (vite 5.0.0),
// requirements.txt (Flask 3.0.0), Cargo.toml (tokio 1.0.0), tier2
// go.mod (Echo v4.11.1), composer.lock (laravel v10.34.2), Gemfile.lock
// (rails 7.1.3), pom.xml (spring-core 6.1.2 + unresolvable), app.csproj
// (.NET SDK pseudo-dep).
deps.push(...parsePackageJson(GENERATED_FAKE_REPO["package.json"], "tests/fixtures/fake-repo/package.json"));
deps.push(...parseRequirements(GENERATED_FAKE_REPO["requirements.txt"], "tests/fixtures/fake-repo/requirements.txt"));
deps.push(...parseCargoToml(GENERATED_FAKE_REPO["Cargo.toml"], "tests/fixtures/fake-repo/Cargo.toml"));
const t2gen = loadFakeRepoTier2();
deps.push(...parseGoMod(t2gen.get("go.mod") ?? "", "tests/fixtures/fake-repo-tier2/go.mod"));
deps.push(...parseGemfileLock(t2gen.get("Gemfile.lock") ?? "", "tests/fixtures/fake-repo-tier2/Gemfile.lock"));
deps.push(...parseComposerLock(t2gen.get("composer.lock") ?? "", "tests/fixtures/fake-repo-tier2/composer.lock"));
deps.push(...parsePomXml(t2gen.get("pom.xml") ?? "", "tests/fixtures/fake-repo-tier2/pom.xml"));
deps.push(...parseCsproj(t2gen.get("app.csproj") ?? "", "tests/fixtures/fake-repo-tier2/app.csproj"));
// Same dedupe as scanRepo: by ecosystem:name, keep the pinned version.
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
const deduped = [...depByKey.values()];
async function main() {
const result = await checkDependencies(deduped);
const vulns = result.vulnerabilities;
const byPkg = (name: string) => vulns.filter((v) => v.packageName === name);

// --- Upgraded versions must return zero advisories ---
const upgraded: [string, string][] = [
  ["Django", "5.2.17"],
  ["next", "15.5.29"],
  ["github.com/gofiber/fiber/v2", "v2.52.14"],
  ["sinatra", "4.2.0"],
  ["puma", "7.2.1"],
  ["phpunit/phpunit", "10.5.62"],
  ["diff", "9.0.0"],
  ["zod", "4.6.7"],
];
for (const [name, version] of upgraded) {
  const found = byPkg(name);
  check(`Phase 13: upgraded ${name} ${version} has zero advisories`, found.length === 0, found.length ? found.map((v) => v.id).join(", ") : "");
}
// The upgraded versions are the ones actually pinned in the repo.
const pinned = new Map(deduped.map((d) => [`${d.ecosystem}:${d.name}`, d.version]));
check("Phase 13: Django pinned at 5.2.17", pinned.get("pypi:Django") === "5.2.17", String(pinned.get("pypi:Django")));
const fixtureNext = parsePackageJson(GENERATED_FAKE_REPO["package.json"], "tests/fixtures/fake-repo/package.json").find((d) => d.name === "next");
check("Phase 13: fixture next pinned at 15.5.29 (root next 16.4.6 shadows it in-scan)", fixtureNext?.version === "15.5.29", String(fixtureNext?.version));
check("Phase 13: diff pinned at 9.0.0", pinned.get("npm:diff") === "9.0.0", String(pinned.get("npm:diff")));
check("Phase 13: zod pinned at 4.6.7", pinned.get("npm:zod") === "4.6.7", String(pinned.get("npm:zod")));

// --- Kept-vulnerable fixtures must still flag (detection coverage) ---
const kept: [string, number][] = [
  ["github.com/labstack/echo/v4", 28],
  ["laravel/framework", 7],
  ["org.springframework:spring-core", 3],
  ["vite", 23],
  ["tokio", 9],
  ["Flask", 2],
  ["rails", 1],
];
for (const [name, measured] of kept) {
  const found = byPkg(name);
  check(`Phase 13: kept-vulnerable ${name} still flags (>=1 advisory, measured ${measured})`, found.length >= 1, `got ${found.length}, measured ${measured} on 2026-11-26`);
}

// --- Generated-fixture total (Phase 14: the 73 live in the generated
// test-time fixtures now, not in the committed tree — the committed
// tree total is 0, proven by scripts/test-fixtures-phase14.ts) ---
const sevCount: Record<string, number> = {};
for (const v of vulns) sevCount[v.severity] = (sevCount[v.severity] ?? 0) + 1;
const weights: Record<string, number> = { critical: 15, high: 10, medium: 5, low: 2, info: 0 };
let deduction = 0;
for (const v of vulns) deduction += weights[v.severity] ?? 0;
check("Phase 13: generated kept-vulnerable fixtures flag 73 total (was 197)", vulns.length === 73, `got ${vulns.length} (${JSON.stringify(sevCount)})`);
check("Phase 13: vuln deduction is 206 (was 547)", deduction === 206, `got ${deduction}`);
check("Phase 13: no critical or high vulns remain", (sevCount.critical ?? 0) === 0 && (sevCount.high ?? 0) === 0, JSON.stringify(sevCount));

console.log(failures === 0 ? "\nAll Phase 13 dep checks passed." : `\n${failures} Phase 13 dep check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
}

main();
