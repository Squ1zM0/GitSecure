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
import { envFileFinding, scanLinesForSecrets, scanTextForSecrets } from "../src/lib/secrets";
import { dedupeSecrets } from "../src/lib/scan";
import { computeScore } from "../src/lib/score";
import { findingAnchorId, githubBlobUrl, osvAdvisoryUrl } from "../src/lib/links";
import { fingerprintFrameworks, parseCargoToml, parseComposerJson, parseComposerLock, parseCsproj, parseGemfile, parseGemfileLock, parseGoMod, parseGradle, parsePackageJson, parsePomXml, parseRequirements } from "../src/lib/frameworks";
import { leaksSecret } from "../src/lib/redact";
import type { Dependency, FullReport, SecretFinding } from "../src/lib/types";

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

// --- Whole-content scan equivalence (Phase 9 detector rewrite) ---
// scanTextForSecrets runs each detector once over the whole content
// instead of once per line. These cases prove it reports exactly what
// the old per-line scan reports — including the tricky ones.
const FAKEPW = FAKE.repeat(4); // 16 chars, inside quotes
// A value split across lines is NOT a finding (no closing quote on
// the assignment's own line).
const split = scanTextForSecrets({ path: "split.js", content: `const a = 1;\npassword = "${FAKE.repeat(2)}\n${FAKE.repeat(3)}";\nconst b = 2;`, commit: "HEAD" });
check("split-across-lines password is not flagged", !split.some((f) => f.type === "hardcoded-password"), `${split.length} findings`);
// A real match hiding inside a cross-line span IS still found.
const hidden = scanTextForSecrets({ path: "hidden.js", content: `password = "${FAKE.repeat(2)}\nFAKE"; password = "${FAKEPW}";\nconst b = 2;`, commit: "HEAD" });
check("match inside a cross-line span is still found", hidden.filter((f) => f.type === "hardcoded-password").length === 1 && hidden[0].line === 2, `${hidden.length} findings, lines ${hidden.map((f) => f.line)}`);
// Line numbers point at the right line.
const lined = scanTextForSecrets({ path: "lined.js", content: `// one\n// two\nconst token = "ghp_${FAKE.repeat(8)}1234";\n// four\n`, commit: "HEAD" });
check("finding lands on the right line", lined.some((f) => f.type === "github-token" && f.line === 3), lined.map((f) => `${f.type}:${f.line}`).join(","));
// Two different assignments on one line are two findings (the dedup
// key is the redacted fragment, so the values must differ in their
// first/last chars to count as distinct — same as the old per-line
// scan; identical values on one line dedupe to one).
const twoOnLine = scanTextForSecrets({ path: "two.js", content: `password = "${FAKE.repeat(4)}A"; password = "${FAKE.repeat(4)}B";`, commit: "HEAD" });
check("two assignments on one line are two findings", twoOnLine.filter((f) => f.type === "hardcoded-password").length === 2, `${twoOnLine.length}`);
// Direct equivalence: whole-content vs per-line over a mixed doc.
const mixedLines = [
  `// plain code, nothing here`,
  `const x = "${"AKIA" + "IOSFODNN7EXAMPLE"}";`,
  `password = "${FAKE.repeat(2)}`,
  `${FAKE.repeat(3)}"; // closes the split value, no finding on either line`,
  `const token = "ghp_${FAKE.repeat(8)}1234";`,
  `// https://discord.com/api/webhooks/123456789012345678/${FAKE.repeat(6)}123456`,
  `const jwt = "eyJ${FAKE.repeat(3)}.eyJ${FAKE.repeat(3)}.eyJ${FAKE.repeat(3)}";`,
  `api_key = "${FAKEPW}"; api_key = "${FAKEPW}";`,
  ``,
  "-----BEGIN RSA " + "PRIVATE KEY-----",
  `postgres://fakeuser:FAKEPASSWORD123@localhost:5432/fakedb`,
  `// trailing plain line`,
];
const mixedContent = mixedLines.join("\n");
const wholeFindings = scanTextForSecrets({ path: "mixed.js", content: mixedContent, commit: "HEAD" });
const lineFindings = scanLinesForSecrets({ path: "mixed.js" }, mixedLines.map((text, i) => ({ line: i + 1, text })), "HEAD");
const norm = (fs: SecretFinding[]) => JSON.stringify(fs.map((f) => [f.type, f.file, f.line, f.fragment]).sort());
check("whole-content scan equals per-line scan", norm(wholeFindings) === norm(lineFindings), `whole ${wholeFindings.length} vs per-line ${lineFindings.length}`);

// --- Framework fingerprinting ---
const deps: Dependency[] = [
  ...parsePackageJson(contents.get("package.json") ?? "{}", "package.json"),
  ...parseCargoToml(contents.get("Cargo.toml") ?? "", "Cargo.toml"),
  ...parseRequirements(contents.get("requirements.txt") ?? "", "requirements.txt"),
];
const frameworks = fingerprintFrameworks(deps, contents);
const byName = new Map(frameworks.map((f) => [f.name, f]));
check("fingerprints Next.js 15.5.29", byName.get("Next.js")?.version === "15.5.29", byName.get("Next.js")?.version ?? "missing"); // Phase 13: next 14.2.5 -> 15.5.29 (26 advisories had no 14.2 fix)
check("fingerprints React 18.3.1", byName.get("React")?.version === "18.3.1");
check("fingerprints Vite 5.0.0", byName.get("Vite")?.version === "5.0.0");
check("fingerprints Django 5.2.17", byName.get("Django")?.version === "5.2.17"); // Phase 13: Django 4.2.0 -> 5.2.17 (10 advisories had no 4.2 fix)
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
check("Tier 2: fingerprints Fiber v2.52.14", byName2.get("Fiber")?.version === "v2.52.14"); // Phase 13: fiber v2.49.0 -> v2.52.14 (19 advisories fixed)
check("Tier 2: Rails lockfile 7.1.3 wins over Gemfile range", byName2.get("Rails")?.version === "7.1.3" && byName2.get("Rails")?.versionSource === "lockfile", `${byName2.get("Rails")?.version ?? "missing"} / ${byName2.get("Rails")?.versionSource ?? "?"}`);
check("Tier 2: fingerprints Sinatra 4.2.0", byName2.get("Sinatra")?.version === "4.2.0"); // Phase 13: sinatra 3.0.5 -> 4.2.0 (no 3.x fix exists)
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
  scoreDetail: { score: 10, grade: "F", secretsDeduction: 90, secretsFullWeight: findings.length, secretsHalfWeight: 0, secretsExcluded: 0, wouldBeScore: 10, vulnDeduction: 0, postureDeduction: 0, unpinnedDeduction: 0 },
  counts: { secrets: findings.length, testKeySecrets: 0, vulnerabilities: 1, frameworks: frameworks.length, dependencies: deps.length, postureIssues: 1, filesScanned: files.length, historyCommitsScanned: 0 },
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

// --- Phase 5: no result-count caps ---
// 150 fake findings generated in memory (distinct lines, distinct
// redacted fragments) — the old code truncated at 100. The dedupe step
// is the exact code path scanRepo runs on HEAD + history findings, so
// this proves a >100-finding report comes back whole, not sampled.
const manyFindings: SecretFinding[] = Array.from({ length: 150 }, (_, i) => ({
  id: `test-secret-${i}`,
  type: "discord-webhook",
  title: "Discord webhook URL",
  severity: "high",
  confidence: "high",
  file: "config.js",
  line: i + 1,
  commit: "HEAD",
  fragment: `FAKE…${String(i).padStart(2, "0")}`,
  fix: "Rotate the webhook URL and remove it from the repo.",
  plainEnglish: "A test finding.",
}));
const dedupedMany = dedupeSecrets(manyFindings);
check("Phase 5: 150 findings stay 150 through dedupe (no 100 cap)", dedupedMany.length === 150, `${dedupedMany.length} kept`);
const manyReport: FullReport = {
  ...full,
  secrets: dedupedMany,
  counts: { ...full.counts, secrets: dedupedMany.length },
  limits: [],
};
const manyJson = JSON.stringify(manyReport);
const parsedMany = JSON.parse(manyJson) as FullReport;
check("Phase 5: report lists all 150 secret findings", parsedMany.secrets.length === 150, `${parsedMany.secrets.length} listed`);
check("Phase 5: count is the true total (150, not 100)", parsedMany.counts.secrets === 150, `${parsedMany.counts.secrets}`);
check("Phase 5: no truncation message in the report", !parsedMany.limits.some((l) => /capped at 100|more were found/i.test(l)));
check("Phase 5: every fragment in the 150 is still redacted", parsedMany.secrets.every((s) => s.fragment.length < 12));
// Score with a very large secret count: floors at 0, grade F, never
// negative, never NaN — DefinitelyTyped stays 0/F with everything listed.
const bigScore = computeScore({
  secrets: manyFindings.map((s) => ({ ...s, severity: "critical" as const })),
  vulnerabilities: [],
  posture: [],
  unpinnedCount: 0,
});
check("Phase 5: score floors at 0 with 150 critical secrets", bigScore.score === 0 && bigScore.grade === "F", `${bigScore.score}/${bigScore.grade}`);
check("Phase 5: score is never NaN with a huge finding count", Number.isFinite(bigScore.score));

// --- Phase 5 navigation: direct links + anchors (pure helpers) ---
check(
  "nav: HEAD finding links to branch blob + line",
  githubBlobUrl("Squ1zM0", "TechDirect", "main", "src/index.js", 42, "HEAD") ===
    "https://github.com/Squ1zM0/TechDirect/blob/main/src/index.js#L42",
  githubBlobUrl("Squ1zM0", "TechDirect", "main", "src/index.js", 42, "HEAD"),
);
check(
  "nav: history finding links to its commit, not the branch",
  githubBlobUrl("Squ1zM0", "TechDirect", "main", "src/index.js", 42, "abc1234") ===
    "https://github.com/Squ1zM0/TechDirect/blob/abc1234/src/index.js#L42",
  githubBlobUrl("Squ1zM0", "TechDirect", "main", "src/index.js", 42, "abc1234"),
);
check(
  "nav: file path segments are URL-encoded",
  githubBlobUrl("o", "r", "main", "my folder/a b.js", 1, "HEAD") ===
    "https://github.com/o/r/blob/main/my%20folder/a%20b.js#L1",
  githubBlobUrl("o", "r", "main", "my folder/a b.js", 1, "HEAD"),
);
check("nav: anchor ids are stable per kind + index", findingAnchorId("secret", 12) === "secret-12" && findingAnchorId("vuln", 3) === "vuln-3");
check("nav: advisory links go to OSV.dev", osvAdvisoryUrl("GHSA-test-1234") === "https://osv.dev/vulnerability/GHSA-test-1234");

console.log(failures === 0 ? "\nAll fixture tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
