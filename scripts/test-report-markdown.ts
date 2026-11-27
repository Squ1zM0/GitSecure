// "Roll all into report" test (Freddy, 2026-11-26). Run: npm run test:report-markdown
//
// The Markdown builder (src/lib/report-markdown.ts) is pure: it takes
// the FullReport the page already has and returns the whole scan as
// one document. This script proves, with no network and no browser:
//   1. The file contains EVERY finding from a fixture report -
//      secrets (including the likely-test-key one the page hides in a
//      collapsed section), vulnerabilities, posture issues, frameworks,
//      dependencies - plus score, summary, explanation, and metadata.
//   2. Secrets stay fragment-only: the output contains each redacted
//      fragment and no full secret value (a decoy full value planted
//      on a finding via an extra property must not leak in).
//   3. The filename is gitsecure-report-{owner}-{repo}-{short-sha}.md.
//   4. A provisional report is labelled provisional, with what is
//      still scanning (or paused); a finished report is not.
//   5. The vulnerability Fix lines are reconciled the same way the
//      page reconciles them (one version per package).
//
// Fixtures use redacted fragments ("abcd…yz") and hand-built
// findings - NO literal secret-pattern values anywhere in this file
// (grep-verified; see the check at the end).

import { buildReportMarkdown, reportMarkdownFilename } from "../src/lib/report-markdown";
import type { FullReport, SecretFinding, Vulnerability } from "../src/lib/types";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` - ${extra}` : ""}`);
  if (!ok) failures++;
}

// --- Fixture: a small report whose arithmetic is pinned -----------
// Secrets: S1 low genuine (3 pts full), S2 low test key (0), S3
// medium uncertain (8 x 0.5 = 4) -> secrets deduction 7, would-be
// (full weight) 14. Vulns: 4 low js-yaml + 1 low lodash -> 10.
// Posture: medium + 3 low -> 11. Score 100-7-10-11 = 72/C; driver
// posture, runner-up vulns (10 points).
const mkSecret = (overrides: Partial<SecretFinding> & { file: string; line: number }): SecretFinding => ({
  id: `md-${overrides.file.replace(/[^A-Za-z0-9]/g, "-")}-${overrides.line}`,
  type: overrides.type ?? "hardcoded-password",
  title: overrides.title ?? "Test finding",
  severity: overrides.severity ?? "low",
  confidence: "high",
  file: overrides.file,
  line: overrides.line,
  commit: "HEAD",
  fragment: "abcd…yz",
  fix: "Rotate it.",
  plainEnglish: "Test finding.",
  ...overrides,
});

const fixtureSecrets: SecretFinding[] = [
  mkSecret({
    file: "src/config/prod.key", line: 1, type: "private-key", title: "Private key committed",
    severity: "low", fragment: "----…--",
    plainEnglish: "A private key is in the repo - anyone with it can pretend to be you.",
    fix: "Treat this key as compromised: generate a new key pair, replace it everywhere it was used, and remove the old one from git history.",
    triage: {
      verdict: "likely-genuine-leak", signals: ["prod-filename:prod"],
      explanation: "This looks like a genuine leak: its file name looks production (prod.key) with no test signals.",
      adjustedSeverity: "low", adjustedConfidence: "high",
      fix: "Treat this key as compromised: generate a new key pair, replace it everywhere it was used, and remove the old one from git history.",
    },
    usage: {
      referencedBy: [{ file: "src/server.ts", line: 42 }], referencedByTotal: 1,
      referencedByTests: [], referencedByTestsTotal: 0, deadEnd: false,
    },
  }),
  // The collapsed-section case: a likely test key. The page hides
  // these behind a collapsed "Likely test keys" section; the file
  // must still contain it.
  mkSecret({
    file: "tools/testing/selftests/sgx/sign_key.pem", line: 1, type: "private-key", title: "Private key in tests",
    severity: "low", fragment: "----…--",
    plainEnglish: "A private key in a public repo is no longer private.",
    triage: {
      verdict: "likely-test-key", signals: ["test-path:testing"],
      explanation: "This looks like an intentional test key: it lives in a test path (tools/testing/selftests).",
      adjustedSeverity: "low", adjustedConfidence: "low",
      fix: "Confirm this key is only used by tests and never signs real artifacts; if it does, rotate it.",
    },
    usage: {
      referencedBy: [], referencedByTotal: 0,
      referencedByTests: [{ file: "tests/sgx.test.ts", line: 5 }], referencedByTestsTotal: 1, deadEnd: false,
    },
  }),
  // The long-path case (Phase 15 finding 2): the DefinitelyTyped
  // path that overflowed a 360 px report.
  mkSecret({
    file: "types/nginstack__datasource/lib/DataSourceDataType.d.ts", line: 1,
    type: "hardcoded-password", title: "Hardcoded password in a type definition",
    severity: "medium", fragment: "efgh…ij",
    plainEnglish: "A password is written in a file anyone can read.",
    triage: {
      verdict: "uncertain", signals: [],
      explanation: "No test signals and no production signals either, so a human has to decide.",
      adjustedSeverity: "medium", adjustedConfidence: "low",
      fix: "Rotate the password and move it to an environment variable.",
    },
    usage: {
      referencedBy: [], referencedByTotal: 0,
      referencedByTests: [], referencedByTestsTotal: 0, deadEnd: true,
    },
  }),
];

const mkVuln = (id: string, fixed: string | null): Vulnerability => ({
  id, packageName: "js-yaml", ecosystem: "npm", installedVersion: "4.1.1",
  fixedVersion: fixed, severity: "low",
  summary: "js-yaml flaw.",
  plainEnglish: `js-yaml 4.1.1 has a known security flaw (${id}). Upgrade to ${fixed} or later to fix it.`,
  upgrade: `Upgrade js-yaml to ${fixed} or later.`,
});

const fixture: FullReport = {
  kind: "full", repo: "FixtureRepo", owner: "Squ1zM0", branch: "main", commit: "abc1234def5678",
  score: 72, grade: "C",
  scoreDetail: {
    score: 72, grade: "C", secretsDeduction: 7, secretsFullWeight: 1,
    secretsHalfWeight: 1, secretsExcluded: 1, wouldBeScore: 65,
    vulnDeduction: 10, postureDeduction: 11, unpinnedDeduction: 0,
  },
  counts: { secrets: 3, testKeySecrets: 1, vulnerabilities: 5, frameworks: 2, dependencies: 3, postureIssues: 4, filesScanned: 10, historyCommitsScanned: 3 },
  summary: "Scan complete. 3 possible leaked secrets found - 1 look like test keys and 1 needs a human check; 5 known vulnerabilities in dependencies; 4 security hygiene issues to fix; 2 frameworks fingerprinted. The full detail is in this report - no sign-in needed.",
  scannedAt: "2026-11-26T00:00:00.000Z", historyDepth: "Full history, newest first.",
  limits: ["Scanned all 10 files in the tree."],
  secrets: fixtureSecrets,
  frameworks: [
    { name: "Next.js", ecosystem: "js", version: "15.0.0", versionSource: "lockfile", unpinned: false, sourceFile: "package.json" },
    { name: "React", ecosystem: "js", version: null, versionSource: "unknown", unpinned: true, sourceFile: "package.json" },
  ],
  dependencies: [
    { name: "js-yaml", ecosystem: "npm", version: "4.1.1", direct: true, sourceFile: "package.json" },
    { name: "lodash", ecosystem: "npm", version: "4.17.20", direct: true, sourceFile: "package.json" },
    { name: "zod", ecosystem: "npm", version: "4.6.7", direct: false, sourceFile: "package-lock.json" },
  ],
  vulnerabilities: [
    mkVuln("GHSA-js-yaml-1", "4.3.2"),
    mkVuln("GHSA-js-yaml-2", "3.15.0"),
    mkVuln("GHSA-js-yaml-3", "4.3.1"),
    mkVuln("GHSA-js-yaml-4", "4.2.0"),
    { id: "GHSA-lodash-1", packageName: "lodash", ecosystem: "npm", installedVersion: "4.17.20", fixedVersion: "4.17.21", severity: "low", summary: "lodash flaw.", plainEnglish: "lodash 4.17.20 has a known security flaw (GHSA-lodash-1). Upgrade to 4.17.21 or later to fix it.", upgrade: "Upgrade lodash to 4.17.21 or later." },
  ],
  posture: [
    { id: "p1", title: "No SECURITY.md", severity: "medium", detail: "No SECURITY.md file was found.", fix: "Add a SECURITY.md file." },
    { id: "p2", title: "No Dependabot config", severity: "low", detail: "No Dependabot config was found.", fix: "Add a dependabot.yml file." },
    { id: "p3", title: ".gitignore gaps", severity: "low", detail: "The .gitignore file does not cover .env files.", fix: "Add .env to .gitignore." },
    { id: "p4", title: "Workflow permissions too broad", severity: "low", detail: "A workflow grants write access it does not need.", fix: "Narrow the workflow permissions." },
  ],
};

const md = buildReportMarkdown(fixture);

// --- 1. Filename ----------------------------------------------------
check("filename is gitsecure-report-{owner}-{repo}-{short-sha}.md", reportMarkdownFilename(fixture) === "gitsecure-report-Squ1zM0-FixtureRepo-abc1234.md", reportMarkdownFilename(fixture));

// --- 2. Score, summary, explanation ---------------------------------
check("md has the report title", md.includes("# GitSecure report: Squ1zM0/FixtureRepo"));
check("md has score and grade", md.includes("72 out of 100 (grade C - fair)"));
check("md has the verdict naming the real driver", md.includes("Biggest problem: 4 small security-hygiene issues to fix."));
check("md has the summary", md.includes(fixture.summary));
check("md names the runner-up deduction (Phase 15 finding 13)", md.includes("Plus 5 known flaws in dependencies, which cost 10 points"));
check("md explains the test-key adjustment with both scores", md.includes("1 looks like a test key and is excluded") && md.includes("the score would be 65 instead of 72"));
check("md carries the scan metadata", md.includes("Branch: main") && md.includes("Commit: abc1234def5678") && md.includes("Files scanned: 10") && md.includes("History commits scanned: 3"));

// --- 3. Every secret, including the collapsed-section one ------------
check("md lists the genuine leak with its fragment", md.includes("Private key committed") && md.includes("----…--"));
check("md lists the test-key secret the page collapses by default", md.includes("Private key in tests") && md.includes("Likely test key") && md.includes("Confirm this key is only used by tests"));
check("md lists the long-path secret with its full path", md.includes("types/nginstack__datasource/lib/DataSourceDataType.d.ts:1"));
check("md lists the dead-end finding as a dead end", md.includes("a true dead end"));
check("md lists the test-only usage with its test reference", md.includes("tests/sgx.test.ts:5 (test)"));
check("md has one ### heading per finding (3 secrets + 5 vulns + 4 posture)", (md.match(/^### \d+\. /gm) ?? []).length === 3 + 5 + 4, `${(md.match(/^### \d+\. /gm) ?? []).length}`);

// --- 4. Vulnerabilities: reconciled Fix lines ------------------------
check("md reconciles js-yaml to one version (4.3.2, all 4 advisories)", md.includes("Upgrade js-yaml to 4.3.2 or later - this covers all 4 advisories for this version."));
const fixLines = md.match(/^Fix: .*$/gm) ?? [];
check("md Fix lines never name the losing versions", fixLines.filter((l) => l.includes("3.15.0") || l.includes("4.3.1") || l.includes("4.2.0")).length === 0, fixLines.filter((l) => l.includes("js-yaml")).join(" | "));
check("md keeps the single-version lodash Fix unchanged", md.includes("Fix: Upgrade lodash to 4.17.21 or later."));
check("md lists every advisory id", ["GHSA-js-yaml-1", "GHSA-js-yaml-2", "GHSA-js-yaml-3", "GHSA-js-yaml-4", "GHSA-lodash-1"].every((id) => md.includes(id)));

// --- 5. Posture, frameworks, dependencies ---------------------------
check("md lists every posture issue", ["No SECURITY.md", "No Dependabot config", ".gitignore gaps", "Workflow permissions too broad"].every((t) => md.includes(t)));
check("md lists every framework, unpinned flagged", md.includes("Next.js") && md.includes("React") && md.includes("unpinned version"));
check("md lists every dependency with direct/transitive", md.includes("js-yaml") && md.includes("lodash") && md.includes("zod") && md.includes("transitive"));
check("md carries the About-this-scan lines", md.includes("Scanned all 10 files in the tree."));
check("md has no undefined/NaN placeholders", !md.includes("undefined") && !md.includes("NaN"));

// --- 6. Secrets stay fragment-only ----------------------------------
// A decoy full value planted on a finding via an extra property must
// never leak into the file: the builder only reads known-safe fields.
const decoy = { ...fixtureSecrets[0], secretValue: "SENTINEL_FULL_SECRET_9f8e7d" } as unknown as SecretFinding;
const mdDecoy = buildReportMarkdown({ ...fixture, secrets: [decoy, ...fixtureSecrets.slice(1)] });
check("md never emits an unknown field holding a full secret (decoy)", !mdDecoy.includes("SENTINEL_FULL_SECRET_9f8e7d"));
const leaked = /(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/.test(md);
check("md contains no secret-pattern values (fragments only)", !leaked);

// --- 7. Provisional reports -----------------------------------------
const mdProv = buildReportMarkdown({ ...fixture, provisional: true });
check("provisional md is labelled provisional with what is still running", mdProv.includes("Provisional report") && mdProv.includes("still running"));
const mdPaused = buildReportMarkdown({ ...fixture, provisional: true }, { paused: true });
check("paused provisional md says paused, not still running", mdPaused.includes("paused - history and dependency checks stopped here"));
check("finished md is not labelled provisional", !md.includes("Provisional report"));
const mdProvEmpty = buildReportMarkdown({ ...fixture, provisional: true, vulnerabilities: [], counts: { ...fixture.counts, vulnerabilities: 0 } });
check("provisional md says vulns are not checked yet, not 'none found'", mdProvEmpty.includes("Dependency checks are still running - no vulnerabilities listed yet."));

// --- 8. No literal secret-pattern values in this file ---------------
import { readFileSync } from "node:fs";
const self = readFileSync(new URL(import.meta.url).pathname, "utf8");
const selfLeaked = ["AKIA" + "IOSFODNN7EXAMPLE", "ghp_" + "FAKE".repeat(8) + "1234", "sk_test_" + "FAKE".repeat(6) + "12", "discord.com/api/webhooks/" + "123456789012345678/"].some((s) => self.includes(s));
check("No literal secret-pattern values in this file", !selfLeaked);

console.log(failures === 0 ? "\nAll report-markdown tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
