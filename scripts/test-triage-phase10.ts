// Phase 10 triage test — the layered pipeline that tells intentional
// test keys apart from genuine credential leaks, without ever hiding a
// real leak. Run: npm run test:triage-phase10
//
// Keys are generated at runtime with node:crypto (real RSA/EC keys,
// exported as PEM) — no literal key is ever committed. Fake tokens are
// assembled from fragments at runtime, never written as literal
// secret-pattern values (GitHub push protection blocks those).
//
// The two screenshot cases:
//   - tools/testing/selftests/sgx/sign_key.pem (Linux SGX self-test
//     signing key) must triage likely-test-key with the test-key Fix.
//     The REAL key's fingerprint is a built-in constant (verified
//     2026-11-25 by fetching the file from torvalds/linux and hashing
//     its DER); this test proves the same code path with the exact
//     Linux path and a real RSA 3072 key, and proves the fingerprint
//     mechanism separately with a generated key. The live proof (the
//     actual torvalds/linux scan) closes the loop on the real key.
//   - drivers/of/unittest-data/tests-phandle.dtsi line 9
//     (security-password device-tree test data) must triage on its own
//     signals: unittest path + tests filename + testcase content.
// And the control: a private key in a production path stays CRITICAL
// and likely-genuine-leak.

import { generateKeyPairSync, createHash } from "node:crypto";
import { scanTextForSecrets } from "../src/lib/secrets";
import {
  KNOWN_TEST_KEY_FINGERPRINTS,
  collectPublicKeyIdentities,
  ensureTriage,
  parsePrivateKeyInContent,
  triageFinding,
  triageFindings,
  triageHistoryFindings,
} from "../src/lib/triage";
import { computeScore } from "../src/lib/score";
import { buildProvisionalReport } from "../src/lib/provisional";
import type { HeadPartial, SecretFinding } from "../src/lib/types";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

// --- Key generation helpers (runtime only, never committed) ---
function rsaPem(bits: 1024 | 2048 | 3072 | 4096): string {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: bits,
    publicExponent: 0x10001,
  });
  return privateKey.export({ type: "pkcs1", format: "pem" }).toString();
}
function ecPem(curve: "prime256v1" | "secp384r1"): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: curve });
  return {
    privatePem: privateKey.export({ type: "sec1", format: "pem" }).toString(),
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}
function rsaPair(bits: 2048): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: bits });
  return {
    privatePem: privateKey.export({ type: "pkcs1", format: "pem" }).toString(),
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

const TEST_KEY_FIX = "Confirm this key is only used by tests and never signs real artifacts; if it does, rotate it.";

// --- Layer 2: DER parsing ---
const rsa3072 = rsaPem(3072);
const parsed3072 = parsePrivateKeyInContent(rsa3072, 1);
check("Layer 2: RSA 3072 parses (kind + bits)", parsed3072?.kind === "rsa" && parsed3072?.bits === 3072, parsed3072?.label ?? "null");
const ec = ecPem("prime256v1");
const parsedEc = parsePrivateKeyInContent(ec.privatePem, 1);
check("Layer 2: EC P-256 parses (kind + bits)", parsedEc?.kind === "ec" && parsedEc?.bits === 256, parsedEc?.label ?? "null");
const parsedEc384 = parsePrivateKeyInContent(ecPem("secp384r1").privatePem, 1);
check("Layer 2: EC P-384 parses", parsedEc384?.kind === "ec" && parsedEc384?.bits === 384, parsedEc384?.label ?? "null");
check("Layer 2: unparseable content is null, not a crash", parsePrivateKeyInContent("not a key at all", 1) === null);
check("Layer 2: fingerprint is a 64-hex SHA-256", !!parsed3072 && /^[0-9a-f]{64}$/.test(parsed3072.fingerprint));

// --- Case 1: the Linux SGX self-test signing key ---
const sgxKey = rsaPem(3072);
const sgxFindings = scanTextForSecrets({ path: "tools/testing/selftests/sgx/sign_key.pem", content: sgxKey, commit: "HEAD" });
check("Linux case: private-key detector fires on sign_key.pem", sgxFindings.some((f) => f.type === "private-key"), `${sgxFindings.length} findings`);
const sgxFinding = sgxFindings.find((f) => f.type === "private-key")!;
const sgxTriage = triageFinding(sgxFinding, { content: sgxKey });
check("Linux case: sign_key.pem triages likely-test-key", sgxTriage.triage.verdict === "likely-test-key", sgxTriage.triage.verdict);
check("Linux case: test-key Fix (not 'rotate it')", sgxTriage.triage.fix === TEST_KEY_FIX, sgxTriage.triage.fix);
check("Linux case: detector severity stays critical", sgxFinding.severity === "critical");
check("Linux case: adjusted severity is low", sgxTriage.triage.adjustedSeverity === "low");
check("Linux case: explanation names the test path", /tools\/testing\/selftests/.test(sgxTriage.triage.explanation), sgxTriage.triage.explanation);
check("Linux case: test-path signal recorded", sgxTriage.triage.signals.some((s) => s.startsWith("test-path:")));

// The real fingerprint constant: the built-in list carries the Linux
// SGX key's DER SHA-256, verified 2026-11-25 from the fetched file.
check(
  "Linux case: built-in list carries the SGX key fingerprint",
  KNOWN_TEST_KEY_FINGERPRINTS.some((k) => k.sha256 === "739756e08012f17a899b05995ed88295c68e434b8680d7d8a1219347a07cb7b1" && /SGX/.test(k.name)),
);
// Fingerprint mechanism: a generated key whose fingerprint is passed
// in matches decisively, even in a production-looking path.
const fpKey = rsaPem(2048);
const fpParsed = parsePrivateKeyInContent(fpKey, 1)!;
const fpFindings = scanTextForSecrets({ path: "src/config/prod.key", content: fpKey, commit: "HEAD" });
const fpFinding = fpFindings.find((f) => f.type === "private-key")!;
const fpTriage = triageFinding(fpFinding, {
  content: fpKey,
  extraKnownFingerprints: [{ sha256: fpParsed.fingerprint, name: "Test-only planted key" }],
});
check("Fingerprint match: known test key is decisive even in a prod path", fpTriage.triage.verdict === "likely-test-key", fpTriage.triage.verdict);
check("Fingerprint match: explanation names the fingerprint", /fingerprint matches a published test key/.test(fpTriage.triage.explanation));
check("Fingerprint match: the decisive match is recorded in the signals list", fpTriage.triage.signals.includes("known-test-key"), fpTriage.triage.signals.join(","));
const fpTriageNoList = triageFinding(fpFinding, { content: fpKey });
check("Fingerprint match: same key WITHOUT the fingerprint stays genuine in a prod path", fpTriageNoList.triage.verdict === "likely-genuine-leak", fpTriageNoList.triage.verdict);

// --- Case 2: the tests-phandle.dtsi device-tree test data ---
// The real line 9 is `security-password="<8-char value>"` (a device
// tree property, not a password). The value below is assembled from
// fragments and is clearly fake.
const dtsiContent = [
  "// SPDX-License-Identifier: GPL-2.0",
  "",
  "/ {",
  "\taliases {",
  "\t\ttestcase-alias = &testcase;",
  "\t};",
  "",
  "\ttestcase: testcase-data {",
  `\t\tsecurity-password="${"TEST" + "PASS12"}";`,
  "\t\tduplicate-name = \"duplicate\";",
  "",
  "\t\tduplicate-name { };",
  "",
  "\t\tphandle-tests {",
  "\t\t\tprovider0: provider0 {",
  "\t\t\t\t#phandle-cells = <0>;",
  "\t\t\t};",
  "",
  "\t\t\tprovider1: provider1 {",
  "\t\t\t\t#phandle-cells = <1>;",
  "\t\t\t};",
  "\t\t};",
  "\t};",
  "};",
].join("\n");
const dtsiFindings = scanTextForSecrets({ path: "drivers/of/unittest-data/tests-phandle.dtsi", content: dtsiContent, commit: "HEAD" });
check("dtsi case: hardcoded-password detector fires on line 9", dtsiFindings.some((f) => f.type === "hardcoded-password" && f.line === 9), dtsiFindings.map((f) => `${f.type}:${f.line}`).join(","));
const dtsiFinding = dtsiFindings.find((f) => f.type === "hardcoded-password")!;
const dtsiTriage = triageFinding(dtsiFinding, { content: dtsiContent });
check("dtsi case: triages likely-test-key on its own signals", dtsiTriage.triage.verdict === "likely-test-key", dtsiTriage.triage.verdict);
check("dtsi case: unittest path signal recorded", dtsiTriage.triage.signals.some((s) => s.startsWith("test-path:unittest-data")));
check("dtsi case: tests filename signal recorded", dtsiTriage.triage.signals.some((s) => s.startsWith("filename-test:tests")));
check("dtsi case: testcase content signal recorded", dtsiTriage.triage.signals.some((s) => s.startsWith("content-test:testcase")));
check("dtsi case: test-value Fix (not the detector rotate fix)", /Confirm this value is only used by tests/.test(dtsiTriage.triage.fix), dtsiTriage.triage.fix);

// --- Case 3: control — a production-path private key stays CRITICAL ---
const prodKey = rsaPem(2048);
const prodFindings = scanTextForSecrets({ path: "src/config/prod.key", content: prodKey, commit: "HEAD" });
const prodFinding = prodFindings.find((f) => f.type === "private-key")!;
const prodTriage = triageFinding(prodFinding, { content: prodKey });
check("Control: prod.key stays likely-genuine-leak", prodTriage.triage.verdict === "likely-genuine-leak", prodTriage.triage.verdict);
check("Control: detector severity stays critical", prodFinding.severity === "critical" && prodTriage.triage.adjustedSeverity === "critical");
check("Control: detector Fix kept (rotate it)", /Treat this key as compromised/.test(prodTriage.triage.fix));
const awsKey = "AKIA" + "IOSFODNN7EXAMPLE";
// A different fake AWS key for the deploy/ control: the example key
// above is a published example value, so it MUST triage test wherever
// it sits (decisive) — it cannot also be the genuine control.
const awsProdKey = "AKIA" + "FAKEFAKEFAKEFAKE";
const awsFindings = scanTextForSecrets({ path: "deploy/settings.js", content: `const key = "${awsProdKey}";`, commit: "HEAD" });
const awsFinding = awsFindings.find((f) => f.type === "aws-access-key");
check("Control: AWS key in deploy/ is found", !!awsFinding);
if (awsFinding) {
  const awsTriage = triageFinding(awsFinding, { content: `const key = "${awsProdKey}";` });
  check("Control: AWS key in deploy/ stays likely-genuine-leak", awsTriage.triage.verdict === "likely-genuine-leak", awsTriage.triage.verdict);
  check("Control: deploy/ prod-path signal recorded", awsTriage.triage.signals.some((s) => s.startsWith("prod-path:deploy")));
}
// The example key is decisive wherever it sits — even in deploy/.
const awsExampleDeployFindings = scanTextForSecrets({ path: "deploy/settings.js", content: `const key = "${awsKey}";`, commit: "HEAD" });
const awsExampleDeployFinding = awsExampleDeployFindings.find((f) => f.type === "aws-access-key")!;
check("Example value: AWS example key is test even in deploy/", triageFinding(awsExampleDeployFinding, { content: `const key = "${awsKey}";` }).triage.verdict === "likely-test-key");

// --- Case 4: same token, fixture file vs src/ — different verdicts ---
const fakeToken = "ghp_" + "FAKE".repeat(8) + "1234";
const tokenFixture = scanTextForSecrets({ path: "tests/fixtures/token.txt", content: `token=${fakeToken}`, commit: "HEAD" }).find((f) => f.type === "github-token")!;
const tokenSrc = scanTextForSecrets({ path: "src/config.ts", content: `export const token = "${fakeToken}";`, commit: "HEAD" }).find((f) => f.type === "github-token")!;
check("Token case: same token detected in both files", !!tokenFixture && !!tokenSrc);
const tokenFixtureTriage = triageFinding(tokenFixture, { content: `token=${fakeToken}` });
const tokenSrcTriage = triageFinding(tokenSrc, { content: `export const token = "${fakeToken}";` });
check("Token case: fixture file triages likely-test-key", tokenFixtureTriage.triage.verdict === "likely-test-key", tokenFixtureTriage.triage.verdict);
check("Token case: src/ triages likely-genuine-leak", tokenSrcTriage.triage.verdict === "likely-genuine-leak", tokenSrcTriage.triage.verdict);
check("Token case: the two verdicts differ", tokenFixtureTriage.triage.verdict !== tokenSrcTriage.triage.verdict);

// --- Case 5: AWS documentation example key (hash match) ---
const awsExampleFindings = scanTextForSecrets({ path: "src/config.js", content: `const key = "${awsKey}";`, commit: "HEAD" });
const awsExampleFinding = awsExampleFindings.find((f) => f.type === "aws-access-key")!;
const awsExampleTriage = triageFinding(awsExampleFinding, { content: `const key = "${awsKey}";` });
check("Example value: AWS docs example key triages likely-test-key", awsExampleTriage.triage.verdict === "likely-test-key", awsExampleTriage.triage.verdict);
check("Example value: explanation names the AWS example", /AWS documentation example/.test(awsExampleTriage.triage.explanation));
check("Example value: the decisive match is recorded in the signals list", awsExampleTriage.triage.signals.includes("known-example-value"), awsExampleTriage.triage.signals.join(","));
check("Example value: baked hash matches the assembled string", createHash("sha256").update(awsKey).digest("hex") === "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3");

// --- Case 6: uncertain — test path, production-looking key, nothing else ---
const strongKey = rsaPem(4096);
const uncertainFindings = scanTextForSecrets({ path: "tests/key.pem", content: strongKey, commit: "HEAD" });
const uncertainFinding = uncertainFindings.find((f) => f.type === "private-key")!;
const uncertainTriage = triageFinding(uncertainFinding, { content: strongKey });
check("Uncertain case: test path + RSA 4096 is uncertain", uncertainTriage.triage.verdict === "uncertain", `${uncertainTriage.triage.verdict} (signals: ${uncertainTriage.triage.signals.join(",")})`);
check("Uncertain case: keeps detector severity", uncertainTriage.triage.adjustedSeverity === "critical");
check("Uncertain case: explanation says a human should check", /human should check/.test(uncertainTriage.triage.explanation));

// --- Layer 2 extras: weak key, public counterpart, Stripe test mode ---
const weakKey = rsaPem(1024);
const weakFindings = scanTextForSecrets({ path: "src/keys/weak.pem", content: weakKey, commit: "HEAD" });
const weakFinding = weakFindings.find((f) => f.type === "private-key")!;
const weakTriage = triageFinding(weakFinding, { content: weakKey });
check("Weak key: RSA 1024 signal recorded", weakTriage.triage.signals.some((s) => s.startsWith("weak-key:RSA 1024")), weakTriage.triage.signals.join(","));
check("Weak key: weak key alone in src/ is uncertain, not auto-test", weakTriage.triage.verdict === "uncertain", weakTriage.triage.verdict);

const pair = rsaPair(2048);
const pairIdentities = collectPublicKeyIdentities(pair.publicPem);
const pairParsed = parsePrivateKeyInContent(pair.privatePem, 1)!;
check("Counterpart: public key identity matches the private key's", pairParsed.identity !== null && pairIdentities.has(pairParsed.identity));
const pairFindings = scanTextForSecrets({ path: "tests/fixtures/app.key", content: pair.privatePem, commit: "HEAD" });
const pairFinding = pairFindings.find((f) => f.type === "private-key")!;
const pairTriage = triageFinding(pairFinding, { content: pair.privatePem, repoPublicKeyIdentities: pairIdentities });
check("Counterpart: public-counterpart signal recorded", pairTriage.triage.signals.includes("public-counterpart-in-repo"), pairTriage.triage.signals.join(","));
check("Counterpart: test path + counterpart triages likely-test-key", pairTriage.triage.verdict === "likely-test-key", pairTriage.triage.verdict);

const stripeTest = "sk_test_" + "FAKE".repeat(6) + "12";
const stripeFindings = scanTextForSecrets({ path: "src/payments.ts", content: `const k = "${stripeTest}";`, commit: "HEAD" });
const stripeFinding = stripeFindings.find((f) => f.type === "stripe-secret-key")!;
const stripeTriage = triageFinding(stripeFinding, { content: `const k = "${stripeTest}";` });
check("Stripe: test-mode signal recorded", stripeTriage.triage.signals.includes("stripe-test-mode"), stripeTriage.triage.signals.join(","));
const stripeLive = "sk_live_" + "FAKE".repeat(6) + "12";
const stripeLiveFindings = scanTextForSecrets({ path: "src/payments.ts", content: `const k = "${stripeLive}";`, commit: "HEAD" });
const stripeLiveFinding = stripeLiveFindings.find((f) => f.type === "stripe-secret-key")!;
const stripeLiveTriage = triageFinding(stripeLiveFinding, { content: `const k = "${stripeLive}";` });
check("Stripe: live key in src/ is NOT test-mode and stays genuine", stripeLiveTriage.triage.verdict === "likely-genuine-leak" && !stripeLiveTriage.triage.signals.includes("stripe-test-mode"), stripeLiveTriage.triage.verdict);

// --- History path: triage from added diff lines ---
const histKey = rsaPem(2048);
const histLines = histKey.split("\n").map((text, i) => ({ line: i + 1, text }));
const histFindings = scanTextForSecrets({ path: "tools/testing/selftests/sgx/sign_key.pem", content: histKey, commit: "abc1234" });
triageHistoryFindings(histFindings, "tools/testing/selftests/sgx/sign_key.pem", histLines);
const histFinding = histFindings.find((f) => f.type === "private-key")!;
check("History: added-lines triage works (selftest path)", histFinding.triage?.verdict === "likely-test-key", histFinding.triage?.verdict ?? "none");
const histProdLines = histKey.split("\n").map((text, i) => ({ line: i + 1, text }));
const histProdFindings = scanTextForSecrets({ path: "src/config/prod.key", content: histKey, commit: "abc1234" });
triageHistoryFindings(histProdFindings, "src/config/prod.key", histProdLines);
check("History: prod-path key added in a commit stays genuine", histProdFindings.find((f) => f.type === "private-key")?.triage?.verdict === "likely-genuine-leak");

// --- Regression: triage never drops a finding ---
const mixed: SecretFinding[] = [];
for (let i = 0; i < 25; i++) {
  const inTest = i % 3 === 0;
  mixed.push({
    id: `mixed-${i}`,
    type: i % 2 === 0 ? "github-token" : "hardcoded-password",
    title: "Mixed",
    severity: i % 2 === 0 ? "critical" : "medium",
    confidence: i % 2 === 0 ? "high" : "medium",
    file: inTest ? `tests/f${i}.txt` : `src/f${i}.txt`,
    line: i + 1,
    commit: "HEAD",
    fragment: `FAKE…${String(i).padStart(2, "0")}`,
    fix: "Rotate it.",
    plainEnglish: "Mixed finding.",
  });
}
const triagedMixed = triageFindings(mixed, () => ({}));
check("Regression: triage keeps all 25 findings", triagedMixed.length === 25, `${triagedMixed.length}`);
check("Regression: every input id is still present", mixed.every((f) => triagedMixed.some((t) => t.id === f.id)));
check("Regression: every finding got an annotation", triagedMixed.every((f) => !!f.triage && ["likely-test-key", "likely-genuine-leak", "uncertain"].includes(f.triage.verdict)));
check("Regression: ensureTriage fills a missing annotation, keeps an existing one", (() => {
  const bare: SecretFinding = { ...mixed[1], triage: undefined };
  const kept: SecretFinding = { ...mixed[0], triage: { verdict: "likely-test-key", signals: ["x"], explanation: "kept", adjustedSeverity: "low", adjustedConfidence: "low", fix: "kept fix" } };
  ensureTriage([bare, kept]);
  return !!bare.triage && kept.triage?.fix === "kept fix";
})());

// --- Scoring rule (Phase 12): triage DOES change the score ---
// Phase 10 said "triage never changes the score". That rule is
// OVERTURNED in Phase 12 (Freddy, 2026-11-26): an F for 34 test
// fixtures is a false alarm, so the score must reflect real risk.
// Likely-test-key findings deduct nothing, uncertain deduct half,
// likely-genuine-leak / untriaged deduct full weight.
// Here: sgx critical test (25 -> 0) + prod critical genuine (25) +
// dtsi medium test (8 -> 0). Before triage (no annotations, full
// weight): 58 deducted, 42/D — and wouldBeScore stays 42 after
// triage. After triage: 25 deducted, 75/B.
const before = computeScore({
  secrets: [sgxFinding, prodFinding, dtsiFinding],
  vulnerabilities: [],
  posture: [],
  unpinnedCount: 0,
});
const triagedForScore = [sgxFinding, prodFinding, dtsiFinding].map((f) => ({ ...f }));
triageFindings(triagedForScore, (f) => ({ content: f.file.includes("sign_key") ? sgxKey : f.file.includes("prod.key") ? prodKey : dtsiContent }));
const after = computeScore({
  secrets: triagedForScore,
  vulnerabilities: [],
  posture: [],
  unpinnedCount: 0,
});
check("Scoring rule (Phase 12): untriaged findings score at full weight (42/D)", before.score === 42 && before.grade === "D", `${before.score}/${before.grade}`);
check("Scoring rule (Phase 12): after triage the test keys deduct nothing (75/B)", after.score === 75 && after.grade === "B", `${after.score}/${after.grade}`);
check("Scoring rule (Phase 12): secrets deduction is 25 (only the genuine key)", after.secretsDeduction === 25, `${after.secretsDeduction}`);
check("Scoring rule (Phase 12): counts are full=1, excluded=2", after.secretsFullWeight === 1 && after.secretsExcluded === 2 && after.secretsHalfWeight === 0, `full=${after.secretsFullWeight} half=${after.secretsHalfWeight} excluded=${after.secretsExcluded}`);
check("Scoring rule (Phase 12): wouldBeScore is the old-rule score (42)", after.wouldBeScore === 42 && after.wouldBeScore === before.score, `wouldBe=${after.wouldBeScore} before=${before.score}`);
check("Scoring rule: detector severity untouched by triage", triagedForScore.every((f, i) => f.severity === [sgxFinding, prodFinding, dtsiFinding][i].severity));

// --- Counts plumbing: likely-test findings still counted, shown separately ---
const head: HeadPartial = {
  owner: "fake-owner",
  repo: "fake-repo",
  branch: "main",
  headSha: "abc1234",
  filesScanned: 3,
  filesTotal: 3,
  treeTruncated: false,
  tarballFallback: false,
  secrets: triagedForScore,
  frameworks: [],
  dependencies: [],
  posture: [],
  unpinnedCount: 0,

  historyMethod: "git",
  retainedIncomplete: false,
};
const provisional = buildProvisionalReport(head, [], 0, true);
check("Counts: secrets total still includes the test keys", provisional.counts.secrets === 3, `${provisional.counts.secrets}`);
check("Counts: testKeySecrets is the honest split (2 of 3)", provisional.counts.testKeySecrets === 2, `${provisional.counts.testKeySecrets}`);
check("Counts: provisional carries the triage annotations", provisional.secrets.every((s) => !!s.triage));

console.log(failures === 0 ? "\nAll triage tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
