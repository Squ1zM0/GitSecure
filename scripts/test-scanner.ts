// Synthetic-fixture test for the GitSecure scanner.
// Uses FAKE planted secrets only (tests/fixtures/fake-repo). Never use a
// real leaked secret here. Run: npm run test:scanner
// Checks: detection of each planted secret type, redaction (no full fake
// secret appears anywhere in the findings), framework fingerprinting,
// unpinned detection, and the public-vs-full split (public leaks no detail).

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { envFileFinding, scanTextForSecrets } from "../src/lib/secrets";
import { fingerprintFrameworks, parseCargoToml, parsePackageJson, parseRequirements } from "../src/lib/frameworks";
import { toPublicReport } from "../src/lib/scan";
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

// --- Public vs full split ---
const full: FullReport = {
  kind: "full",
  repo: "fake-repo",
  owner: "fake-owner",
  branch: "main",
  commit: "abc1234",
  score: 10,
  grade: "F",
  counts: { secrets: findings.length, vulnerabilities: 0, frameworks: frameworks.length, dependencies: deps.length, postureIssues: 1, filesScanned: files.length, historyCommitsScanned: 0 },
  summary: "Scan complete.",
  scannedAt: new Date().toISOString(),
  historyDepth: "test",
  limits: [],
  secrets: findings,
  frameworks,
  dependencies: deps,
  vulnerabilities: [],
  posture: [],
};
const pub = toPublicReport(full);
const pubJson = JSON.stringify(pub);
check("public report has score + counts", typeof pub.score === "number" && pub.counts.secrets === findings.length);
check("public report has no file names", !pubJson.includes("config.js"));
check("public report has no secret fragments", !pubJson.includes("FAKE"));
check("public report has no framework names", !pubJson.includes("Next.js") && !pubJson.includes("Django"));

console.log(failures === 0 ? "\nAll fixture tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
