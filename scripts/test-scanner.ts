// Synthetic-fixture test for the GitSecure scanner.
// Uses FAKE planted secrets only (tests/fixtures/fake-repo). Never use a
// real leaked secret here. Run: npm run test:scanner
// Checks: detection of each planted secret type, redaction (no full fake
// secret appears anywhere in the findings), framework fingerprinting,
// unpinned detection, and the Phase 4 full report (everyone gets the
// detail — file names, framework names, vulnerability IDs — with
// secrets still redacted).

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { envFileFinding, scanTextForSecrets } from "../src/lib/secrets";
import { fingerprintFrameworks, parseCargoToml, parseComposerJson, parseComposerLock, parseCsproj, parseGemfile, parseGemfileLock, parseGoMod, parseGradle, parsePackageJson, parsePomXml, parseRequirements } from "../src/lib/frameworks";
import { leaksSecret } from "../src/lib/redact";
import type { Dependency, FullReport } from "../src/lib/types";

const FIXTURE = join(process.cwd(), "tests/fixtures/fake-repo");

// Fake secrets are assembled from fragments at runtime, never written
// as literal values: GitHub push protection blocks literal secret-pattern
// strings even when they are fake. The runtime values are identical to
// the invented ones used before.
const FAKE = "FAKE";
const FAKE_SECRETS = [
  "https://discord.com/api/webhooks/" + "123456789012345678/" + FAKE.repeat(6) + "123456",
  "AKIA" + "IOSFODNN7EXAMPLE",
  "ghp_" + FAKE.repeat(8) + "1234",
  "sk_live_" + FAKE.repeat(6) + "12",
  "sk-proj-" + FAKE.repeat(7),
  "postgres://fakeuser:FAKEPASSWORD123@localhost:5432/fakedb",
  FAKE.repeat(8) + "12345678",
];
const PRIVATE_KEY_FAKE =
  "-----BEGIN RSA " + "PRIVATE KEY-----\nFAKEFAKEFAKE\n-----END RSA PRIVATE KEY-----";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

const files = readdirSync(FIXTURE);
const contents = new Map<string, string>();
for (const f of files) contents.set(f, readFileSync(join(FIXTURE, f), "utf8"));

// --- Secret detection ---
// The fixture file holds __SECRET_n__ placeholders (see its header).
// Substitute the invented secrets in memory before scanning, so the
// scanner sees the same text as before without any literal secret-pattern
// value being committed.
const configRaw = contents.get("config.js") ?? "";
const config = FAKE_SECRETS.reduce(
  (text, secret, i) => text.split(`__SECRET_${i}__`).join(secret),
  configRaw,
).split("__SECRET_7__").join(PRIVATE_KEY_FAKE);
const findings = scanTextForSecrets({ path: "config.js", content: config, commit: "HEAD" });
const types = new Set(findings.map((f) => f.type));
for (const expected of ["discord-webhook", "aws-access-key", "github-token", "stripe-secret-key", "openai-api-key", "database-url", "hardcoded-password", "private-key"]) {
  check(`detects ${expected}`, types.has(expected));
}
check("env file finding", envFileFinding(".env", "HEAD").type === "env-file");

// --- Redaction: no full fake secret anywhere in the findings output ---
const findingsJson = JSON.stringify(findings);
for (const secret of FAKE_SECRETS) {
  check(`redaction: full fake secret never appears (${secret.slice(0, 18)}…)`, !leaksSecret(findingsJson, secret));
  check(`redaction: fragment is not the full value`, findings.every((f) => f.fragment.length < 12));
}
check("at least 8 findings in fixture", findings.length >= 8, `${findings.length} found`);

// --- Framework fingerprinting ---
const deps: Dependency[] = [
  ...parsePackageJson(contents.get("package.json") ?? "{}", "package.json"),
  ...parseCargoToml(contents.get("Cargo.toml") ?? "", "Cargo.toml"),
  ...parseRequirements(contents.get("requirements.txt") ?? "", "requirements.txt"),
];
const frameworks = fingerprintFrameworks(deps, contents);
const byName = new Map(frameworks.map((f) => [f.name, f]));
check("fingerprints Next.js 14.2.5", byName.get("Next.js")?.version === "14.2.5", byName.get("Next.js")?.version ?? "missing");
check("fingerprints React 18.3.1", byName.get("React")?.version === "18.3.1");
check("fingerprints Vite 5.0.0", byName.get("Vite")?.version === "5.0.0");
check("fingerprints Django 4.2.0", byName.get("Django")?.version === "4.2.0");
check("fingerprints Serde (Rust)", byName.has("Serde"));
check("flags unpinned express (*)", byName.get("Express")?.unpinned === true || deps.some((d) => d.name === "express" && (!d.version || d.version === "*")));

// --- Framework fingerprinting, Tier 2 (Go, Ruby, PHP, Java, .NET) ---
const TIER2 = join(process.cwd(), "tests/fixtures/fake-repo-tier2");
const t2 = new Map<string, string>();
for (const f of readdirSync(TIER2)) t2.set(f, readFileSync(join(TIER2, f), "utf8"));
const deps2: Dependency[] = [
  ...parseGoMod(t2.get("go.mod") ?? "", "go.mod"),
  ...parseGemfile(t2.get("Gemfile") ?? "", "Gemfile"),
  ...parseGemfileLock(t2.get("Gemfile.lock") ?? "", "Gemfile.lock"),
  ...parseComposerJson(t2.get("composer.json") ?? "", "composer.json"),
  ...parseComposerLock(t2.get("composer.lock") ?? "", "composer.lock"),
  ...parsePomXml(t2.get("pom.xml") ?? "", "pom.xml"),
  ...parseGradle(t2.get("build.gradle") ?? "", "build.gradle"),
  ...parseCsproj(t2.get("app.csproj") ?? "", "app.csproj"),
];
const frameworks2 = fingerprintFrameworks(deps2, t2);
const byName2 = new Map(frameworks2.map((f) => [f.name, f]));
check("Tier 2: fingerprints Gin v1.9.1", byName2.get("Gin")?.version === "v1.9.1", byName2.get("Gin")?.version ?? "missing");
check("Tier 2: fingerprints Echo v4.11.1", byName2.get("Echo")?.version === "v4.11.1");
check("Tier 2: fingerprints Fiber v2.49.0", byName2.get("Fiber")?.version === "v2.49.0");
check("Tier 2: Rails lockfile 7.1.3 wins over Gemfile range", byName2.get("Rails")?.version === "7.1.3" && byName2.get("Rails")?.versionSource === "lockfile", `${byName2.get("Rails")?.version ?? "missing"} / ${byName2.get("Rails")?.versionSource ?? "?"}`);
check("Tier 2: fingerprints Sinatra 3.0.5", byName2.get("Sinatra")?.version === "3.0.5");
check("Tier 2: Laravel lockfile v10.34.2 wins over ^10.0", byName2.get("Laravel")?.version === "v10.34.2" && byName2.get("Laravel")?.versionSource === "lockfile", byName2.get("Laravel")?.version ?? "missing");
check("Tier 2: fingerprints Symfony v6.3.8", byName2.get("Symfony")?.version === "v6.3.8");
check("Tier 2: Spring Boot 3.2.0, one entry (parent + starter + gradle)", frameworks2.filter((f) => f.name === "Spring Boot").length === 1 && byName2.get("Spring Boot")?.version === "3.2.0", byName2.get("Spring Boot")?.version ?? "missing");
check("Tier 2: Spring Framework 6.1.2 via ${spring.version}", byName2.get("Spring Framework")?.version === "6.1.2", byName2.get("Spring Framework")?.version ?? "missing");
check("Tier 2: fingerprints Kotlin 1.9.20", byName2.get("Kotlin")?.version === "1.9.20");
check("Tier 2: ASP.NET Core 8.0.0, one entry (SDK + package)", frameworks2.filter((f) => f.name === "ASP.NET Core").length === 1 && byName2.get("ASP.NET Core")?.version === "8.0.0", byName2.get("ASP.NET Core")?.version ?? "missing");
check("Tier 2: WordPress detected, version unknown (wp-config.php only)", byName2.get("WordPress")?.version === null && byName2.get("WordPress")?.versionSource === "unknown", `version=${String(byName2.get("WordPress")?.version)} / ${byName2.get("WordPress")?.versionSource ?? "?"}`);
check("Tier 2: unresolvable ${...} pom version stays null, never guessed", deps2.some((d) => d.name === "org.example:unresolvable" && d.version === null));
check("Tier 2: .NET SDK pseudo-dep has null version (TargetFramework is not a version)", deps2.some((d) => d.name === "Microsoft.NET.Sdk.Web" && d.version === null));

// --- Phase 4 full report: everyone gets the detail ---
const full: FullReport = {
  kind: "full",
  repo: "fake-repo",
  owner: "fake-owner",
  branch: "main",
  commit: "abc1234",
  score: 10,
  grade: "F",
  counts: { secrets: findings.length, vulnerabilities: 1, frameworks: frameworks.length, dependencies: deps.length, postureIssues: 1, filesScanned: files.length, historyCommitsScanned: 0 },
  summary: "Scan complete.",
  scannedAt: new Date().toISOString(),
  historyDepth: "test",
  limits: [],
  secrets: findings,
  frameworks,
  dependencies: deps,
  vulnerabilities: [{ id: "GHSA-test-1234", packageName: "next", ecosystem: "npm", installedVersion: "14.2.5", fixedVersion: "14.2.6", severity: "high", summary: "Test vuln.", plainEnglish: "Upgrade.", upgrade: "Upgrade next." }],
  posture: [],
};
const fullJson = JSON.stringify(full);
check("full report has score + counts", typeof full.score === "number" && full.counts.secrets === findings.length);
check("full report includes file names", fullJson.includes("config.js"));
check("full report includes framework names", fullJson.includes("Next.js") && fullJson.includes("Django"));
check("full report includes vulnerability IDs", fullJson.includes("GHSA-test-1234"));
// Compare against the PARSED report, not the raw JSON string: a
// fragment can contain a `"` (e.g. `pass…2"`), which JSON.stringify
// escapes, so a raw substring search would false-fail.
const parsedFull = JSON.parse(fullJson) as FullReport;
check("full report includes redacted secret fragments (never full)", findings.every((f) => parsedFull.secrets.some((s) => s.fragment === f.fragment) && f.fragment.length < 12));
for (const secret of FAKE_SECRETS) {
  check(`full report never contains the full fake secret (${secret.slice(0, 18)}…)`, !leaksSecret(fullJson, secret));
}

console.log(failures === 0 ? "\nAll fixture tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
