// Phase 12 scoring test — triage-weighted secrets deduction.
// Run: npm run test:score-phase12
//
// Phase 12 (Freddy, 2026-11-26) overturns the Phase 10 rule "triage
// never changes the score": an F for 34 test fixtures is a false alarm,
// so the score must reflect real risk. New rule (src/lib/score.ts):
//   likely-test-key  -> weight 0 (deducts nothing)
//   uncertain        -> weight 0.5 (deducts half)
//   likely-genuine-leak / no triage annotation -> weight 1 (full)
// Secrets deduction is the weighted sum rounded to the nearest integer
// (Math.round, summed first, then rounded — not per-finding rounding).
// Vulns, posture, and unpinned are unchanged. wouldBeScore is the score
// the old full-weight rule would have given the same input.
//
// Fixtures use `__SECRET_n__` placeholders and hand-built findings —
// NO literal secret-pattern values anywhere in this file
// (grep-verified; see the check at the end).

import { computeScore } from "../src/lib/score";
import { computeUsageForFindings } from "../src/lib/usage";
import { triageFinding } from "../src/lib/triage";
import { buildProvisionalReport } from "../src/lib/provisional";
import type { HeadPartial, SecretFinding, Severity, TriageVerdict } from "../src/lib/types";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

function mkFinding(overrides: Partial<SecretFinding> & { severity: Severity }): SecretFinding {
  return {
    id: `s12-${overrides.type ?? "x"}-${overrides.file?.replace(/[^A-Za-z0-9]/g, "-") ?? "x"}-${overrides.line ?? 1}`,
    type: overrides.type ?? "hardcoded-password",
    title: "Test finding",
    confidence: "high",
    file: overrides.file ?? "src/a.ts",
    line: overrides.line ?? 1,
    commit: "HEAD",
    fragment: "____…__",
    fix: "Rotate it.",
    plainEnglish: "Test finding.",
    ...overrides,
  };
}

/** A triage annotation with the given verdict (signals/explanation
 *  are filler — the score only reads the verdict). */
function triaged(severity: Severity, verdict: TriageVerdict, type = "hardcoded-password", file = "tests/fixture.txt"): SecretFinding {
  return mkFinding({
    severity,
    type,
    file,
    triage: {
      verdict,
      signals: [`test-${verdict}`],
      explanation: `Test ${verdict}.`,
      adjustedSeverity: "low",
      adjustedConfidence: "low",
      fix: "Test fix.",
    },
  });
}

const EMPTY = { secrets: [], vulnerabilities: [], posture: [], unpinnedCount: 0 };

// --- 1. All test keys score as if there were no secrets ---
const allTest = computeScore({
  ...EMPTY,
  secrets: [
    triaged("critical", "likely-test-key", "private-key"),
    triaged("high", "likely-test-key", "github-token"),
    triaged("medium", "likely-test-key"),
  ],
});
const control = computeScore(EMPTY);
check("All-test-key: secrets deduction is 0", allTest.secretsDeduction === 0, `${allTest.secretsDeduction}`);
check("All-test-key: score equals the zero-secrets control (100/A)", allTest.score === control.score && allTest.score === 100 && allTest.grade === "A", `${allTest.score}/${allTest.grade} vs control ${control.score}/${control.grade}`);
check("All-test-key: 3 excluded, 0 full, 0 half", allTest.secretsExcluded === 3 && allTest.secretsFullWeight === 0 && allTest.secretsHalfWeight === 0, `full=${allTest.secretsFullWeight} half=${allTest.secretsHalfWeight} excluded=${allTest.secretsExcluded}`);
check("All-test-key: wouldBeScore is the old-rule score (100-48=52/D)", allTest.wouldBeScore === 52, `${allTest.wouldBeScore}`);

// --- 2. Mixed verdicts at the stated weights, exact numbers ---
const mixed = computeScore({
  ...EMPTY,
  secrets: [
    triaged("critical", "likely-genuine-leak", "private-key"), // 25 x 1 = 25
    triaged("high", "uncertain", "github-token"), // 15 x 0.5 = 7.5
    triaged("medium", "likely-test-key"), // 8 x 0 = 0
    triaged("low", "likely-genuine-leak", "generic-high-entropy-secret"), // 3 x 1 = 3
  ],
});
// Weighted sum 35.5 -> Math.round -> 36; score 100-36 = 64/C.
check("Mixed: secrets deduction is 36 (25 + 7.5 + 0 + 3, rounded)", mixed.secretsDeduction === 36, `${mixed.secretsDeduction}`);
check("Mixed: score 64/C", mixed.score === 64 && mixed.grade === "C", `${mixed.score}/${mixed.grade}`);
check("Mixed: counts full=2 half=1 excluded=1", mixed.secretsFullWeight === 2 && mixed.secretsHalfWeight === 1 && mixed.secretsExcluded === 1, `full=${mixed.secretsFullWeight} half=${mixed.secretsHalfWeight} excluded=${mixed.secretsExcluded}`);
check("Mixed: wouldBeScore is the old-rule score (100-51=49/D)", mixed.wouldBeScore === 49, `${mixed.wouldBeScore}`);

// --- 2b. Rounding is sum-then-round, not per-finding ---
// One critical uncertain (25 x 0.5 = 12.5) + one low uncertain
// (3 x 0.5 = 1.5) = 14.0 exactly. Per-finding rounding would give
// 13 + 2 = 15 — this check pins the sum-first behaviour.
const rounding = computeScore({
  ...EMPTY,
  secrets: [triaged("critical", "uncertain", "private-key"), triaged("low", "uncertain", "generic-high-entropy-secret")],
});
check("Rounding: 12.5 + 1.5 sums to 14 (not 13 + 2 = 15)", rounding.secretsDeduction === 14, `${rounding.secretsDeduction}`);
check("Rounding: score 86/B", rounding.score === 86 && rounding.grade === "B", `${rounding.score}/${rounding.grade}`);
// A single low uncertain: 3 x 0.5 = 1.5 -> Math.round -> 2.
const roundingSingle = computeScore({ ...EMPTY, secrets: [triaged("low", "uncertain", "generic-high-entropy-secret")] });
check("Rounding: single low uncertain 1.5 rounds to 2", roundingSingle.secretsDeduction === 2, `${roundingSingle.secretsDeduction}`);

// --- 3. No-triage findings score at full weight ---
const noTriage = computeScore({
  ...EMPTY,
  secrets: [mkFinding({ severity: "critical", type: "private-key" }), mkFinding({ severity: "high", type: "github-token" })],
});
check("No-triage: full weight (25 + 15 = 40)", noTriage.secretsDeduction === 40, `${noTriage.secretsDeduction}`);
check("No-triage: score 60/C", noTriage.score === 60 && noTriage.grade === "C", `${noTriage.score}/${noTriage.grade}`);
check("No-triage: counted as full weight (never assumed a test key)", noTriage.secretsFullWeight === 2 && noTriage.secretsHalfWeight === 0 && noTriage.secretsExcluded === 0, `full=${noTriage.secretsFullWeight}`);
check("No-triage: wouldBeScore equals the score (nothing to discount)", noTriage.wouldBeScore === noTriage.score, `wouldBe=${noTriage.wouldBeScore} score=${noTriage.score}`);

// --- 4. A likely-test finding upgraded to likely-genuine-leak
// (Phase 11 triage feed-back: production usage) scores full again ---
// Same setup as Phase 11 (vi-a): an AWS key fixture referenced from
// src/ code. Without usage it triages likely-test-key (score 100);
// with the production reference it upgrades to likely-genuine-leak
// (full 25-point deduction, score 75/B).
const awsContents = new Map<string, string>([
  ["tests/fixtures/keys.txt", `TEST_AWS_KEY = "__SECRET_3__"\n`],
  ["src/service.ts", `import { client } from "./client";\nconst k = TEST_AWS_KEY;\n`],
]);
const awsFinding = mkFinding({ severity: "critical", type: "aws-access-key", file: "tests/fixtures/keys.txt", line: 1 });
const awsTriageNoUsage = triageFinding(awsFinding, { content: awsContents.get(awsFinding.file) });
check("Upgrade: fixture AWS key triages likely-test-key without usage", awsTriageNoUsage.triage.verdict === "likely-test-key", awsTriageNoUsage.triage.verdict);
const awsScoreBefore = computeScore({ ...EMPTY, secrets: [{ ...awsFinding, triage: awsTriageNoUsage.triage }] });
check("Upgrade: before upgrade it deducts 0 (score 100/A)", awsScoreBefore.secretsDeduction === 0 && awsScoreBefore.score === 100, `${awsScoreBefore.secretsDeduction} / ${awsScoreBefore.score}`);
computeUsageForFindings([awsFinding], awsContents, (f) => {
  const content = awsContents.get(f.file);
  return { content, lineText: content !== undefined ? (content.split("\n")[f.line - 1] ?? null) : null };
});
const awsTriageUpgraded = triageFinding(awsFinding, { usage: awsFinding.usage });
check("Upgrade: production usage upgrades it to likely-genuine-leak", awsTriageUpgraded.triage.verdict === "likely-genuine-leak", awsTriageUpgraded.triage.verdict);
const awsScoreAfter = computeScore({ ...EMPTY, secrets: [{ ...awsFinding, triage: awsTriageUpgraded.triage }] });
check("Upgrade: after upgrade it deducts full 25 (score 75/B)", awsScoreAfter.secretsDeduction === 25 && awsScoreAfter.score === 75 && awsScoreAfter.grade === "B", `${awsScoreAfter.secretsDeduction} / ${awsScoreAfter.score}/${awsScoreAfter.grade}`);
check("Upgrade: counted as full weight after upgrade", awsScoreAfter.secretsFullWeight === 1 && awsScoreAfter.secretsExcluded === 0, `full=${awsScoreAfter.secretsFullWeight} excluded=${awsScoreAfter.secretsExcluded}`);

// --- 5. TechDirect fixture scores unchanged at 83/B ---
// Measured TechDirect: 0 secrets, 4 low vulns (js-yaml), posture
// low + low + medium (.gitignore gaps), 0 unpinned:
// 100 - (4x2) - (2+2+5) - 0 = 83/B.
const techdirect = computeScore({
  secrets: [],
  vulnerabilities: [1, 2, 3, 4].map((i) => ({
    id: `GHSA-test-${i}`, packageName: "js-yaml", ecosystem: "npm",
    installedVersion: "3.13.1", fixedVersion: "3.14.0", severity: "low" as Severity,
    summary: "Test vuln.", plainEnglish: "Upgrade.", upgrade: "Upgrade js-yaml.",
  })),
  posture: [
    { id: "p1", title: "No SECURITY.md", severity: "low" as Severity, detail: "d", fix: "f" },
    { id: "p2", title: "No Dependabot config", severity: "low" as Severity, detail: "d", fix: "f" },
    { id: "p3", title: ".gitignore gaps", severity: "medium" as Severity, detail: "d", fix: "f" },
  ],
  unpinnedCount: 0,
});
check("TechDirect fixture: score 83/B unchanged", techdirect.score === 83 && techdirect.grade === "B", `${techdirect.score}/${techdirect.grade}`);
check("TechDirect fixture: vuln 8, posture 9, unpinned 0", techdirect.vulnDeduction === 8 && techdirect.postureDeduction === 9 && techdirect.unpinnedDeduction === 0, `v=${techdirect.vulnDeduction} p=${techdirect.postureDeduction} u=${techdirect.unpinnedDeduction}`);
check("TechDirect fixture: wouldBeScore equals score (no secrets)", techdirect.wouldBeScore === 83, `${techdirect.wouldBeScore}`);

// --- 6. Self-scan reproduction (measured 2026-11-26, see
// test-results/phase12-score-breakdown.md): 34 secrets (32 test, 2
// uncertain), 197 vulns (51 medium, 146 low), 15 posture (5 high,
// 6 medium, 2 low, 2 info), 2 unpinned direct deps. New rule: secrets 8, total
// 643 -> still 0/F; wouldBe 0/F. The vulns alone (547) floor it.
const selfSecrets: SecretFinding[] = [];
for (let i = 0; i < 16; i++) selfSecrets.push(triaged("high", "likely-test-key", "github-token", `tests/fixture-${i}.txt`));
for (let i = 0; i < 16; i++) selfSecrets.push(triaged("medium", "likely-test-key", "hardcoded-password", `tests/fixture-${16 + i}.txt`));
for (let i = 0; i < 2; i++) selfSecrets.push(triaged("medium", "uncertain", "hardcoded-password", `scripts/test-scanner-${i}.ts`));
const selfVulns = [
  ...Array.from({ length: 51 }, (_, i) => ({ id: `GHSA-m-${i}`, packageName: "pkg-m", ecosystem: "npm", installedVersion: "1.0.0", fixedVersion: "1.0.1", severity: "medium" as Severity, summary: "m", plainEnglish: "m", upgrade: "u" })),
  ...Array.from({ length: 146 }, (_, i) => ({ id: `GHSA-l-${i}`, packageName: "pkg-l", ecosystem: "npm", installedVersion: "1.0.0", fixedVersion: "1.0.1", severity: "low" as Severity, summary: "l", plainEnglish: "l", upgrade: "u" })),
];
const selfPosture = [
  ...Array.from({ length: 5 }, (_, i) => ({ id: `ph-${i}`, title: "high", severity: "high" as Severity, detail: "d", fix: "f" })),
  ...Array.from({ length: 6 }, (_, i) => ({ id: `pm-${i}`, title: "medium", severity: "medium" as Severity, detail: "d", fix: "f" })),
  ...Array.from({ length: 2 }, (_, i) => ({ id: `pl-${i}`, title: "low", severity: "low" as Severity, detail: "d", fix: "f" })),
  ...Array.from({ length: 2 }, (_, i) => ({ id: `pi-${i}`, title: "info", severity: "info" as Severity, detail: "d", fix: "f" })),
];
const selfScan = computeScore({ secrets: selfSecrets, vulnerabilities: selfVulns, posture: selfPosture, unpinnedCount: 2 });
check("Self-scan repro: secrets deduction 8 (32 test at 0, 2 uncertain at half)", selfScan.secretsDeduction === 8, `${selfScan.secretsDeduction}`);
check("Self-scan repro: vuln 547, posture 84, unpinned 4", selfScan.vulnDeduction === 547 && selfScan.postureDeduction === 84 && selfScan.unpinnedDeduction === 4, `v=${selfScan.vulnDeduction} p=${selfScan.postureDeduction} u=${selfScan.unpinnedDeduction}`);
check("Self-scan repro: new score still 0/F (vulns alone floor it)", selfScan.score === 0 && selfScan.grade === "F", `${selfScan.score}/${selfScan.grade}`);
check("Self-scan repro: wouldBeScore 0/F (old rule)", selfScan.wouldBeScore === 0, `${selfScan.wouldBeScore}`);
check("Self-scan repro: counts full=0 half=2 excluded=32", selfScan.secretsFullWeight === 0 && selfScan.secretsHalfWeight === 2 && selfScan.secretsExcluded === 32, `full=${selfScan.secretsFullWeight} half=${selfScan.secretsHalfWeight} excluded=${selfScan.secretsExcluded}`);

// --- 7. The provisional report carries the same ScoreDetail ---
// (score and sections computed from the same annotations).
const head: HeadPartial = {
  owner: "fake-owner", repo: "fake-repo", branch: "main", headSha: "abc1234",
  filesScanned: 3, filesTotal: 3, treeTruncated: false, tarballFallback: false,
  secrets: [
    triaged("critical", "likely-test-key", "private-key"),
    triaged("high", "likely-genuine-leak", "github-token"),
  ],
  frameworks: [], dependencies: [], posture: [], unpinnedCount: 0,
  repoSizeKb: 1, historyMethod: "git", retainedIncomplete: false,
};
const provisional = buildProvisionalReport(head, [], 0, true);
check("Provisional: carries scoreDetail", provisional.scoreDetail !== undefined, String(provisional.scoreDetail));
check("Provisional: scoreDetail matches computeScore (15 deducted, 85/B)", provisional.scoreDetail?.secretsDeduction === 15 && provisional.score === 85 && provisional.grade === "B", `ded=${provisional.scoreDetail?.secretsDeduction} ${provisional.score}/${provisional.grade}`);
check("Provisional: counts full=1 excluded=1", provisional.scoreDetail?.secretsFullWeight === 1 && provisional.scoreDetail?.secretsExcluded === 1, `full=${provisional.scoreDetail?.secretsFullWeight} excluded=${provisional.scoreDetail?.secretsExcluded}`);

// --- 8. No literal secret-pattern values in this file ---
import { readFileSync } from "node:fs";
const self = readFileSync(new URL(import.meta.url).pathname, "utf8");
const leaked = ["AKIA" + "IOSFODNN7EXAMPLE", "ghp_" + "FAKE".repeat(8) + "1234", "sk_test_" + "FAKE".repeat(6) + "12", "discord.com/api/webhooks/" + "123456789012345678/"].some((s) => self.includes(s));
check("No literal secret-pattern values in this file", !leaked);

console.log(failures === 0 ? "\nAll Phase 12 score tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
