// Phase 13: prove the dependency-flaw fixes with live OSV data.
// Upgraded fixture + real-dep versions must return ZERO advisories;
// the deliberately kept-vulnerable fixtures must still flag (at least
// one advisory each), so detection coverage is preserved.
// Counts measured 2026-11-26 (see test-results/phase13-vuln-inventory.md
// and the Phase 13 section in GITSECURE.md). OSV data drifts over time:
// if a NEW advisory is published for a fixed version, the zero-advisory
// checks fail honestly and the version needs another bump; if a kept
// package gains advisories, only the exact-count checks move.
// Run: npm run test:deps-phase13 (needs network, queries api.osv.dev).
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
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
const manifestPaths = [
  "package.json",
  "package-lock.json",
  "tests/fixtures/fake-repo/package.json",
  "tests/fixtures/fake-repo/requirements.txt",
  "tests/fixtures/fake-repo/Cargo.toml",
  "tests/fixtures/fake-repo-tier2/go.mod",
  "tests/fixtures/fake-repo-tier2/Gemfile",
  "tests/fixtures/fake-repo-tier2/Gemfile.lock",
  "tests/fixtures/fake-repo-tier2/composer.json",
  "tests/fixtures/fake-repo-tier2/composer.lock",
  "tests/fixtures/fake-repo-tier2/pom.xml",
  "tests/fixtures/fake-repo-tier2/build.gradle",
  "tests/fixtures/fake-repo-tier2/app.csproj",
];
const deps: Dependency[] = [];
for (const path of manifestPaths) {
  const content = read(path);
  const base = path.split("/").pop() ?? "";
  if (base === "package.json") deps.push(...parsePackageJson(content, path));
  else if (base === "package-lock.json") deps.push(...parsePackageLock(content, path));
  else if (base === "requirements.txt") deps.push(...parseRequirements(content, path));
  else if (base === "Cargo.toml") deps.push(...parseCargoToml(content, path));
  else if (base === "go.mod") deps.push(...parseGoMod(content, path));
  else if (base === "Gemfile") deps.push(...parseGemfile(content, path));
  else if (base === "Gemfile.lock") deps.push(...parseGemfileLock(content, path));
  else if (base === "composer.json") deps.push(...parseComposerJson(content, path));
  else if (base === "composer.lock") deps.push(...parseComposerLock(content, path));
  else if (base === "pom.xml") deps.push(...parsePomXml(content, path));
  else if (base === "build.gradle") deps.push(...parseGradle(content, path));
  else if (base.endsWith(".csproj")) deps.push(...parseCsproj(content, path));
}
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
  ["diff", "8.0.4"],
  ["zod", "4.6.7"],
];
for (const [name, version] of upgraded) {
  const found = byPkg(name);
  check(`Phase 13: upgraded ${name} ${version} has zero advisories`, found.length === 0, found.length ? found.map((v) => v.id).join(", ") : "");
}
// The upgraded versions are the ones actually pinned in the repo.
const pinned = new Map(deduped.map((d) => [`${d.ecosystem}:${d.name}`, d.version]));
check("Phase 13: Django pinned at 5.2.17", pinned.get("pypi:Django") === "5.2.17", String(pinned.get("pypi:Django")));
const fixtureNext = parsePackageJson(read("tests/fixtures/fake-repo/package.json"), "tests/fixtures/fake-repo/package.json").find((d) => d.name === "next");
check("Phase 13: fixture next pinned at 15.5.29 (root next 16.4.6 shadows it in-scan)", fixtureNext?.version === "15.5.29", String(fixtureNext?.version));
check("Phase 13: diff pinned at 8.0.4", pinned.get("npm:diff") === "8.0.4", String(pinned.get("npm:diff")));
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

// --- Repo-wide total after the fix ---
const sevCount: Record<string, number> = {};
for (const v of vulns) sevCount[v.severity] = (sevCount[v.severity] ?? 0) + 1;
const weights: Record<string, number> = { critical: 15, high: 10, medium: 5, low: 2, info: 0 };
let deduction = 0;
for (const v of vulns) deduction += weights[v.severity] ?? 0;
check("Phase 13: repo-wide vuln total is 73 (was 197)", vulns.length === 73, `got ${vulns.length} (${JSON.stringify(sevCount)})`);
check("Phase 13: vuln deduction is 206 (was 547)", deduction === 206, `got ${deduction}`);
check("Phase 13: no critical or high vulns remain", (sevCount.critical ?? 0) === 0 && (sevCount.high ?? 0) === 0, JSON.stringify(sevCount));

console.log(failures === 0 ? "\nAll Phase 13 dep checks passed." : `\n${failures} Phase 13 dep check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
}

main();
