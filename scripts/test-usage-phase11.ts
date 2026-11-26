// Phase 11 usage test — whether anything in the repo still
// references a secret finding's identifier, and the triage
// feed-back that follows. Run: npm run test:usage-phase11
//
// Fixtures use `__SECRET_n__` placeholders and assemble fakes in
// memory — NO literal secret-pattern values anywhere in this file
// (grep-verified; see the check at the end). Findings are built by
// hand (no detector run), so no real credential pattern is needed:
// usage works on identifiers (names), never on values.
//
// Cases:
//   (i)   key file referenced by src/ code -> in use, triage upgraded
//   (ii)  key referenced only by tests -> still likely-test-key
//   (iii) key referenced by nothing -> deadEnd, dead-end signal
//   (iv)  identifier in many files -> referencedBy capped at 10,
//         true total kept
//   (v)   REGRESSION: the secret VALUE in another file (identifier
//         absent) must NOT produce a reference
//   (vi)  triage-upgrade rule cases (prod usage -> genuine, docs-only
//         usage on a decisive key -> stays test, dead end reinforces)
//   (ix)  LIVE REGRESSION (2026-11-26): a comment mention is not
//         usage — `api_key` named in usage.ts's own doc comments
//         wrongly upgraded the test-scanner fixture to
//         likely-genuine-leak; comments are stripped before matching

import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { computeUsageForFindings, extractIdentifiers, stripComments } from "../src/lib/usage";
import { isDocsPath, isProductionPath, parsePrivateKeyInContent, triageFinding } from "../src/lib/triage";
import { buildLimits } from "../src/lib/scan";
import { buildProvisionalReport } from "../src/lib/provisional";
import { computeScore } from "../src/lib/score";
import type { HeadPartial, SecretFinding } from "../src/lib/types";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

function finding(overrides: Partial<SecretFinding> & { type: string; file: string }): SecretFinding {
  return {
    id: `u-${overrides.type}-${overrides.file.replace(/[^A-Za-z0-9]/g, "-")}`,
    title: "Test finding",
    severity: "critical",
    confidence: "high",
    line: 1,
    commit: "HEAD",
    fragment: "____…__",
    fix: "Rotate it.",
    plainEnglish: "Test finding.",
    ...overrides,
  };
}

function filesMap(entries: [string, string][]): Map<string, string> {
  return new Map(entries);
}

/** getContext for computeUsageForFindings: line text + content come
 *  from the same in-memory map the corpus is built from. */
function ctxFrom(contents: Map<string, string>) {
  return (f: SecretFinding) => {
    const content = contents.get(f.file);
    return {
      content,
      lineText: content !== undefined ? (content.split("\n")[f.line - 1] ?? null) : null,
    };
  };
}

const DEAD_END_SENTENCE = "Nothing in this repo references this key — a true dead end.";

// --- (i) key file referenced by src/ code: in use, triage upgraded ---
const keyContents = filesMap([
  ["tests/fixtures/app.key", "fake key file content\n"],
  ["src/config.ts", `const keyPath = "keys/app.key";\nconst other = 1;\nimport { load } from "./loader";\nload(keyPath);\n`],
  ["tests/load_key.test.ts", `import { readFileSync } from "fs";\nconst p = "tests/fixtures/app.key";\n`],
]);
const keyFinding = finding({ type: "private-key", file: "tests/fixtures/app.key", line: 1 });
computeUsageForFindings([keyFinding], keyContents, ctxFrom(keyContents));
check(
  "(i) in-use: referencedBy lists the src/ reference with its line",
  keyFinding.usage?.referencedBy.some((r) => r.file === "src/config.ts" && r.line === 1) ?? false,
  JSON.stringify(keyFinding.usage?.referencedBy),
);
check("(i) in-use: referencedByTotal is 1", keyFinding.usage?.referencedByTotal === 1, `${keyFinding.usage?.referencedByTotal}`);
check(
  "(i) in-use: test reference recorded separately in referencedByTests",
  keyFinding.usage?.referencedByTests.some((r) => r.file === "tests/load_key.test.ts") ?? false,
  JSON.stringify(keyFinding.usage?.referencedByTests),
);
check("(i) in-use: not a dead end", keyFinding.usage?.deadEnd === false);
const keyTriage = triageFinding(keyFinding, { usage: keyFinding.usage });
check("(i) in-use: test-key + production usage upgrades to likely-genuine-leak", keyTriage.triage.verdict === "likely-genuine-leak", keyTriage.triage.verdict);
check("(i) in-use: explanation names the referencing file", /src\/config\.ts/.test(keyTriage.triage.explanation), keyTriage.triage.explanation);
check("(i) in-use: usage-prod-ref signal recorded", keyTriage.triage.signals.includes("usage-prod-ref"), keyTriage.triage.signals.join(","));
check("(i) in-use: adjusted severity stays critical (detector severity)", keyTriage.triage.adjustedSeverity === "critical");
check("(i) in-use: detector Fix kept (rotate it)", /Rotate it/.test(keyTriage.triage.fix));

// --- (ii) key referenced only by tests: still likely-test-key ---
const testOnlyContents = filesMap([
  ["tests/fixtures/app.key", "fake key file content\n"],
  ["tests/load_key.test.ts", `import { readFileSync } from "fs";\nconst p = "tests/fixtures/app.key";\nconst q = "tests/fixtures/app.key";\n`],
  ["src/unrelated.ts", "export const x = 1;\n"],
]);
const testOnlyFinding = finding({ type: "private-key", file: "tests/fixtures/app.key", line: 1 });
computeUsageForFindings([testOnlyFinding], testOnlyContents, ctxFrom(testOnlyContents));
check("(ii) test-only: referencedBy is empty", (testOnlyFinding.usage?.referencedBy.length ?? -1) === 0, JSON.stringify(testOnlyFinding.usage?.referencedBy));
check("(ii) test-only: referencedByTotal is 0", testOnlyFinding.usage?.referencedByTotal === 0);
check(
  "(ii) test-only: test references recorded in referencedByTests",
  testOnlyFinding.usage?.referencedByTestsTotal === 2 && (testOnlyFinding.usage?.referencedByTests.length ?? 0) === 2,
  JSON.stringify(testOnlyFinding.usage?.referencedByTests),
);
check("(ii) test-only: not a dead end (tests reference it)", testOnlyFinding.usage?.deadEnd === false);
const testOnlyTriage = triageFinding(testOnlyFinding, { usage: testOnlyFinding.usage });
check("(ii) test-only: still likely-test-key", testOnlyTriage.triage.verdict === "likely-test-key", testOnlyTriage.triage.verdict);
check("(ii) test-only: usage-test-only signal recorded", testOnlyTriage.triage.signals.includes("usage-test-only"), testOnlyTriage.triage.signals.join(","));

// --- (iii) key referenced by nothing: dead end ---
const deadContents = filesMap([
  ["tests/fixtures/app.key", "fake key file content\n"],
  ["src/unrelated.ts", "export const x = 1;\n"],
  ["README.md", "# Project\nNothing to see here.\n"],
]);
const deadFinding = finding({ type: "private-key", file: "tests/fixtures/app.key", line: 1 });
computeUsageForFindings([deadFinding], deadContents, ctxFrom(deadContents));
check("(iii) dead end: deadEnd is true", deadFinding.usage?.deadEnd === true);
check("(iii) dead end: both totals are 0", deadFinding.usage?.referencedByTotal === 0 && deadFinding.usage?.referencedByTestsTotal === 0);
const deadTriage = triageFinding(deadFinding, { usage: deadFinding.usage });
check("(iii) dead end: usage-dead-end signal recorded", deadTriage.triage.signals.includes("usage-dead-end"), deadTriage.triage.signals.join(","));
check("(iii) dead end: explanation says so plainly", deadTriage.triage.explanation.includes(DEAD_END_SENTENCE), deadTriage.triage.explanation);
check("(iii) dead end: still likely-test-key", deadTriage.triage.verdict === "likely-test-key", deadTriage.triage.verdict);

// --- (iv) identifier in many files: capped at 10, true total kept ---
const manyEntries: [string, string][] = [["src/config.js", `const SHARED_KEY_NAME = "__SECRET_1__";\n`]];
for (let i = 1; i <= 12; i++) {
  manyEntries.push([`src/a${String(i).padStart(2, "0")}.ts`, `// header\nexport const x = SHARED_KEY_NAME;\n`]);
}
for (let i = 1; i <= 3; i++) {
  manyEntries.push([`lib/b0${i}.ts`, `// header\nexport const y = SHARED_KEY_NAME;\n`]);
}
for (let i = 1; i <= 12; i++) {
  manyEntries.push([`tests/t${String(i).padStart(2, "0")}.test.ts`, `// header\nconst z = SHARED_KEY_NAME;\n`]);
}
const manyContents = filesMap(manyEntries);
const manyFinding = finding({ type: "aws-access-key", file: "src/config.js", line: 1 });
computeUsageForFindings([manyFinding], manyContents, ctxFrom(manyContents));
check("(iv) cap: referencedBy capped at 10", (manyFinding.usage?.referencedBy.length ?? -1) === 10, `${manyFinding.usage?.referencedBy.length}`);
check("(iv) cap: referencedByTotal is the true total (15)", manyFinding.usage?.referencedByTotal === 15, `${manyFinding.usage?.referencedByTotal}`);
check("(iv) cap: referencedByTests capped at 10", (manyFinding.usage?.referencedByTests.length ?? -1) === 10, `${manyFinding.usage?.referencedByTests.length}`);
check("(iv) cap: referencedByTestsTotal is the true total (12)", manyFinding.usage?.referencedByTestsTotal === 12, `${manyFinding.usage?.referencedByTestsTotal}`);
check("(iv) cap: not a dead end", manyFinding.usage?.deadEnd === false);
check("(iv) cap: own-file definition line does not count as a reference", !(manyFinding.usage?.referencedBy.some((r) => r.file === "src/config.js") ?? true));

// --- (v) REGRESSION: secret VALUE in another file, identifier absent ---
const valueContents = filesMap([
  [".env", "MY_API_KEY=__SECRET_2__\n"],
  ["src/other.ts", `const leaked = "__SECRET_2__";\nconst other = "__SECRET_2__";\n`],
  ["src/clean.ts", "export const ok = 1;\n"],
]);
const valueFinding = finding({ type: "aws-access-key", file: ".env", line: 1 });
computeUsageForFindings([valueFinding], valueContents, ctxFrom(valueContents));
check(
  "(v) value-regression: value present in src/other.ts, identifier absent -> no reference",
  (valueFinding.usage?.referencedByTotal ?? -1) === 0 && (valueFinding.usage?.referencedByTestsTotal ?? -1) === 0,
  JSON.stringify(valueFinding.usage),
);
check("(v) value-regression: deadEnd is true (identifier searched, nothing references it)", valueFinding.usage?.deadEnd === true);
check(
  "(v) value-regression: identifier extracted from the line, not the value",
  extractIdentifiers(valueFinding, { lineText: "MY_API_KEY=__SECRET_2__" }).includes("MY_API_KEY") &&
    !extractIdentifiers(valueFinding, { lineText: "MY_API_KEY=__SECRET_2__" }).some((id) => id.includes("__SECRET")),
  extractIdentifiers(valueFinding, { lineText: "MY_API_KEY=__SECRET_2__" }).join(","),
);

// --- (vi) triage-upgrade rule cases ---
// (vi-a) test-key + production usage -> likely-genuine-leak (AWS key).
const awsContents = filesMap([
  ["tests/fixtures/keys.txt", `TEST_AWS_KEY = "__SECRET_3__"\n`],
  ["src/service.ts", `import { client } from "./client";\nconst k = TEST_AWS_KEY;\n`],
]);
const awsFinding = finding({ type: "aws-access-key", file: "tests/fixtures/keys.txt", line: 1 });
computeUsageForFindings([awsFinding], awsContents, ctxFrom(awsContents));
const awsTriage = triageFinding(awsFinding, { usage: awsFinding.usage });
check("(vi-a) prod usage: test-key + src/ reference upgrades to likely-genuine-leak", awsTriage.triage.verdict === "likely-genuine-leak", awsTriage.triage.verdict);
check("(vi-a) prod usage: explanation names src/service.ts", /src\/service\.ts/.test(awsTriage.triage.explanation), awsTriage.triage.explanation);

// (vi-b) decisive fingerprint + docs-only usage -> stays likely-test-key.
//
// PHASE 14 BEHAVIOUR CHANGE (Bug 2 fix): a docs/prose mention is
// not usage at all — it is not recorded in referencedBy, so a
// finding mentioned only in docs is a dead end, not "referenced
// from documentation". Before the fix this case asserted the
// docs/guide.md reference was recorded in referencedBy with a
// `usage-docs-ref` signal; the usage layer now skips docs files
// entirely (see computeUsageForFindings), so that signal can no
// longer fire from real usage data. The verdict is unchanged
// (decisive fingerprint -> likely-test-key); the dead-end signal
// now reinforces it instead.
const { privateKey: decisivePem } = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 0x10001 });
const decisivePemText = decisivePem.export({ type: "pkcs1", format: "pem" }).toString();
const decisiveParsed = parsePrivateKeyInContent(decisivePemText, 1)!;
const docsContents = filesMap([
  ["tests/fixtures/sign_key.pem", decisivePemText],
  ["docs/guide.md", `# Guide\n\nSee "sign_key.pem" for the test key.\n`],
]);
const docsFinding = finding({ type: "private-key", file: "tests/fixtures/sign_key.pem", line: 1 });
computeUsageForFindings([docsFinding], docsContents, ctxFrom(docsContents));
check(
  "(vi-b) docs-only: a docs mention is NOT a non-test reference",
  docsFinding.usage?.referencedByTotal === 0 && (docsFinding.usage?.referencedBy.length ?? -1) === 0,
  JSON.stringify(docsFinding.usage?.referencedBy),
);
check("(vi-b) docs-only: docs mention leaves it a dead end", docsFinding.usage?.deadEnd === true);
check("(vi-b) docs-only: docs/ is a docs path, not a production path", isDocsPath("docs/guide.md") && !isProductionPath("docs/guide.md"));
const docsTriage = triageFinding(docsFinding, {
  content: decisivePemText,
  extraKnownFingerprints: [{ sha256: decisiveParsed.fingerprint, name: "Test-only planted key" }],
  usage: docsFinding.usage,
});
check("(vi-b) docs-only: decisive key + docs mention stays likely-test-key", docsTriage.triage.verdict === "likely-test-key", docsTriage.triage.verdict);
check("(vi-b) docs-only: usage-dead-end signal recorded (no usage-docs-ref any more)", docsTriage.triage.signals.includes("usage-dead-end") && !docsTriage.triage.signals.includes("usage-docs-ref"), docsTriage.triage.signals.join(","));
check("(vi-b) docs-only: explanation says it is a dead end", docsTriage.triage.explanation.includes(DEAD_END_SENTENCE), docsTriage.triage.explanation);

// (vi-c) dead end reinforces likely-test-key (uncertain -> test-key).
const { privateKey: strongPem } = generateKeyPairSync("rsa", { modulusLength: 4096, publicExponent: 0x10001 });
const strongPemText = strongPem.export({ type: "pkcs1", format: "pem" }).toString();
const strongFinding = finding({ type: "private-key", file: "tests/key.pem", line: 1 });
const strongNoUsage = triageFinding(strongFinding, { content: strongPemText });
check("(vi-c) dead end: test path + RSA 4096 without usage is uncertain", strongNoUsage.triage.verdict === "uncertain", `${strongNoUsage.triage.verdict} (${strongNoUsage.triage.signals.join(",")})`);
const strongContents = filesMap([["tests/key.pem", strongPemText]]);
computeUsageForFindings([strongFinding], strongContents, ctxFrom(strongContents));
check("(vi-c) dead end: usage says deadEnd", strongFinding.usage?.deadEnd === true);
const strongWithUsage = triageFinding(strongFinding, { content: strongPemText, usage: strongFinding.usage });
check("(vi-c) dead end: dead end reinforces to likely-test-key", strongWithUsage.triage.verdict === "likely-test-key", strongWithUsage.triage.verdict);
check("(vi-c) dead end: explanation says so plainly", strongWithUsage.triage.explanation.includes(DEAD_END_SENTENCE));

// (vi-d) non-decisive test-key + non-prod, non-test reference -> uncertain.
const toolsContents = filesMap([
  ["tests/fixtures/keys.txt", `OTHER_KEY = "__SECRET_5__"\n`],
  ["tools/run.sh", `#!/bin/sh\necho "$OTHER_KEY"\n`],
]);
const toolsFinding = finding({ type: "aws-access-key", file: "tests/fixtures/keys.txt", line: 1 });
computeUsageForFindings([toolsFinding], toolsContents, ctxFrom(toolsContents));
check("(vi-d) other usage: tools/ is neither production nor docs", !isProductionPath("tools/run.sh") && !isDocsPath("tools/run.sh"));
const toolsTriage = triageFinding(toolsFinding, { usage: toolsFinding.usage });
check("(vi-d) other usage: upgrades to uncertain (not genuine)", toolsTriage.triage.verdict === "uncertain", toolsTriage.triage.verdict);
check("(vi-d) other usage: explanation names tools/run.sh", /tools\/run\.sh/.test(toolsTriage.triage.explanation), toolsTriage.triage.explanation);

// --- .env file identifiers: variable names only, never the bare basename ---
// A bare ".env" basename is not an identifier: every repo mentions
// ".env" in prose ("committed .env files", "add .env to
// .gitignore"), and none of those mentions loads the file. An .env
// file's identifiers are the variable names it defines.
const envContents = filesMap([
  [".env", "MY_DB_URL=__SECRET_4__\nMY_OTHER_VAR=hello\n"],
  ["src/db.ts", `import { connect } from "./pg";\nconnect(MY_DB_URL);\n`],
  ["src/app.ts", `import "dotenv/config";\nconst path = ".env";\n`],
]);
const envFinding = finding({ type: "env-file", file: ".env", line: 1, severity: "high" });
computeUsageForFindings([envFinding], envContents, ctxFrom(envContents));
check(
  "(env) env-file: the variable name is found",
  (envFinding.usage?.referencedByTotal ?? -1) === 1 &&
    envFinding.usage?.referencedBy.some((r) => r.file === "src/db.ts") === true,
  JSON.stringify(envFinding.usage?.referencedBy),
);
check(
  "(env) env-file: a prose/code mention of the bare \".env\" name is NOT a reference",
  !(envFinding.usage?.referencedBy.some((r) => r.file === "src/app.ts") ?? true),
  JSON.stringify(envFinding.usage?.referencedBy),
);
check(
  "(env) env-file: identifiers are the var names, never the basename",
  extractIdentifiers(envFinding, { content: "MY_DB_URL=__SECRET_4__\nMY_OTHER_VAR=hello\n" }).includes("MY_DB_URL") &&
    !extractIdentifiers(envFinding, { content: "MY_DB_URL=__SECRET_4__\nMY_OTHER_VAR=hello\n" }).includes(".env"),
  extractIdentifiers(envFinding, { content: "MY_DB_URL=__SECRET_4__\nMY_OTHER_VAR=hello\n" }).join(","),
);

// --- (vii) dogfood regression: a bare URL line has no identifier ---
// The fixture line is just a URL in an array — its scheme
// (`postgres`) is not a variable name, and no assignment precedes
// it. Before the match-anchored fix it yielded `postgres`, which
// matched the detector's own prefilter line in src/lib/secrets.ts
// and wrongly upgraded the fixture to likely-genuine-leak.
const bareUrlFinding = finding({ type: "database-url", file: "scripts/test-scanner.ts", line: 33 });
check(
  "(vii) bare URL: no identifier extracted from a bare URL line",
  extractIdentifiers(bareUrlFinding, { lineText: `"postgres://fakeuser:FAKEPASSWORD123@localhost:5432/fakedb",` }).length === 0,
  extractIdentifiers(bareUrlFinding, { lineText: `"postgres://fakeuser:FAKEPASSWORD123@localhost:5432/fakedb",` }).join(","),
);
computeUsageForFindings(
  [bareUrlFinding],
  filesMap([
    ["scripts/test-scanner.ts", `${"// filler\n".repeat(32)}"postgres://fakeuser:FAKEPASSWORD123@localhost:5432/fakedb",\n`],
    ["src/lib/secrets.ts", `prefilter: ["postgres://", "postgresql://", "mysql://", "mongodb", "redis://"],\n`],
  ]),
  ctxFrom(filesMap([["scripts/test-scanner.ts", `${"// filler\n".repeat(32)}"postgres://fakeuser:FAKEPASSWORD123@localhost:5432/fakedb",\n`]])),
);
check("(vii) bare URL: usage undetermined, never a false dead end", bareUrlFinding.usage?.deadEnd === false && bareUrlFinding.usage?.referencedByTotal === 0);
check(
  "(vii) bare URL: stays likely-test-key (no production-usage upgrade)",
  triageFinding(bareUrlFinding, { usage: bareUrlFinding.usage }).triage.verdict === "likely-test-key",
);

// --- (viii) dogfood regression: a match inside a string yields the name in the string ---
// The finding's value sits inside a test's string literal; the
// line's own assignment (`const hidden = …`) is the test's variable,
// not the credential's name. The name attached to the match is
// `password` — generic — so there is no identifier at all. Before
// the match-anchored fix the line-start fallback yielded `hidden`,
// which matched `hidden` attributes across the UI and wrongly
// upgraded the fixture to likely-genuine-leak.
const hiddenFinding = finding({ type: "hardcoded-password", file: "scripts/test-scanner.ts", line: 84 });
const hiddenLine = `const hidden = scanTextForSecrets({ path: "hidden.js", content: \`password = "FAKEFAKEFAKEFAKE";\`, commit: "HEAD" });`;
check(
  "(viii) string match: no identifier (test variable is not the credential name)",
  extractIdentifiers(hiddenFinding, { lineText: hiddenLine }).length === 0,
  extractIdentifiers(hiddenFinding, { lineText: hiddenLine }).join(","),
);
computeUsageForFindings(
  [hiddenFinding],
  filesMap([
    ["scripts/test-scanner.ts", `${"// filler\n".repeat(83)}${hiddenLine}\n`],
    ["src/app/page.tsx", `<div hidden={true}>x</div>\n`],
    ["src/components/ScanProgress.tsx", `const hidden = true;\n`],
  ]),
  ctxFrom(filesMap([["scripts/test-scanner.ts", `${"// filler\n".repeat(83)}${hiddenLine}\n`]])),
);
check("(viii) string match: usage undetermined, never a false dead end", hiddenFinding.usage?.deadEnd === false && hiddenFinding.usage?.referencedByTotal === 0);
check(
  "(viii) string match: stays likely-test-key (no production-usage upgrade)",
  triageFinding(hiddenFinding, { usage: hiddenFinding.usage }).triage.verdict === "likely-test-key",
);

// --- (ix) LIVE REGRESSION: a comment mention is not usage ---
// Live self-scan 2026-11-26: the test-scanner fixture
// `api_key = "FAKEPW"` (identifier `api_key`) was upgraded to
// likely-genuine-leak because `api_key` appears in the doc comments
// of src/lib/usage.ts itself (`api_key` from `"api_key": "…"`).
// A mention in prose is not a use of the value.
const commentFinding = finding({ type: "hardcoded-password", file: "scripts/test-scanner.ts", line: 104 });
const commentLine = `api_key = "__SECRET_9__"; api_key = "__SECRET_9__";`;
check(
  "(ix) comment: identifier is api_key",
  extractIdentifiers(commentFinding, { lineText: commentLine }).join(",") === "api_key",
  extractIdentifiers(commentFinding, { lineText: commentLine }).join(","),
);
computeUsageForFindings(
  [commentFinding],
  filesMap([
    ["scripts/test-scanner.ts", `${"// filler\n".repeat(103)}${commentLine}\n`],
    // Doc comments naming the identifier — the exact live false flip.
    ["src/lib/usage.ts", `/** The name inside a detector match: \`api_key\` from \`"api_key": "…"\`. */\n// set api_key in config before running\nconst x = 1;\n`],
    // A # full-line comment in a Python file naming it too.
    ["src/app.py", `# configure api_key before deploying\nprint("ok")\n`],
  ]),
  ctxFrom(filesMap([["scripts/test-scanner.ts", `${"// filler\n".repeat(103)}${commentLine}\n`]])),
);
check("(ix) comment: no production reference from comments", commentFinding.usage?.referencedByTotal === 0, JSON.stringify(commentFinding.usage?.referencedBy));
check("(ix) comment: true dead end", commentFinding.usage?.deadEnd === true);
check(
  "(ix) comment: stays likely-test-key (no production-usage upgrade)",
  triageFinding(commentFinding, { usage: commentFinding.usage }).triage.verdict === "likely-test-key",
  triageFinding(commentFinding, { usage: commentFinding.usage }).triage.verdict,
);
check(
  "(ix) comment: dead-end signal recorded",
  triageFinding(commentFinding, { usage: commentFinding.usage }).triage.signals.includes("usage-dead-end"),
);
// …but the same identifier inside a string literal in real code IS a reference.
const stringRefFinding = finding({ type: "hardcoded-password", file: "scripts/test-scanner.ts", line: 104 });
computeUsageForFindings(
  [stringRefFinding],
  filesMap([
    ["scripts/test-scanner.ts", `${"// filler\n".repeat(103)}${commentLine}\n`],
    ["src/config.ts", `const key = process.env["api_key"];\n`],
  ]),
  ctxFrom(filesMap([["scripts/test-scanner.ts", `${"// filler\n".repeat(103)}${commentLine}\n`]])),
);
check("(ix) string: identifier in a string literal in code counts", stringRefFinding.usage?.referencedByTotal === 1, `${stringRefFinding.usage?.referencedByTotal}`);
// stripComments unit checks: `//` inside a URL string must not eat
// the rest of the line, and line numbers must survive stripping.
const stripped = stripComments(`const u = "https://x/api_key";\nconst y = api_key;\n// api_key in a comment\n`);
check("(ix) stripComments: URL string survives", stripped.includes(`"https://x/api_key"`), JSON.stringify(stripped));
check("(ix) stripComments: real reference after the URL survives", stripped.split("\n")[1].includes("api_key"));
check("(ix) stripComments: comment line blanked, line count kept", stripped.split("\n").length === 4 && !stripped.split("\n")[2].includes("api_key"), JSON.stringify(stripped));
// A regex literal full of quotes must not trap the tracker in quote
// state across lines: /^[\"']?…[\"']?/ ends the line in sq state, and
// without the newline reset the NEXT line's block comment never opens,
// so a comment mention past it counted as a reference (live flip,
// usage.ts:140 in the pre-fix code).
const regexTrap = stripComments(
  `const m = /^\\s*["']?([A-Za-z_][A-Za-z0-9_.\\-]*)["']?\\s*[:=]/.exec(match);\n` +
  `/** The assignment name: ("api_key": "ghp_…"). */\nconst y = api_key;\n`,
);
check("(ix) stripComments: regex-quote trap — block comment after a regex is stripped", !regexTrap.split("\n")[1].includes("api_key"), JSON.stringify(regexTrap));
check("(ix) stripComments: regex-quote trap — real reference on the next line survives", regexTrap.split("\n")[2].includes("api_key"), JSON.stringify(regexTrap));

// --- (x) LIVE REGRESSION (Phase 14, Bug 2): a docs/prose mention is not usage ---
// The two uncertain self-scan findings (scripts/test-scanner.ts:104
// and scripts/test-usage-phase11.ts:333, both `api_key` fixtures)
// were kept uncertain by one signal, `usage-referenced`, whose only
// non-test references were prose mentions in GITSECURE.md:1294/1301
// and README.md:1228 — the Phase 11.1 write-up itself describing
// the comment-strip fix. Those lines quote the identifier while
// explaining a fix; they never use the value. A `.md` mention is
// not code using a credential.
const proseFinding = finding({ type: "hardcoded-password", file: "scripts/test-scanner.ts", line: 104 });
computeUsageForFindings(
  [proseFinding],
  filesMap([
    ["scripts/test-scanner.ts", `${"// filler\n".repeat(103)}${commentLine}\n`],
    // The exact live shape: prose in the repo docs naming the identifier.
    ["GITSECURE.md", `# Phase 11.1\n\nThe fixture \`api_key = "FAKEPW"\` was flipped.\nSee \`api_key\` in the write-up.\n`],
    ["README.md", `# Project\n\nSet \`api_key\` in config before running.\n`],
    ["docs/guide.md", `# Guide\n\nThe \`api_key\` example above is only a test value.\n`],
  ]),
  ctxFrom(filesMap([["scripts/test-scanner.ts", `${"// filler\n".repeat(103)}${commentLine}\n`]])),
);
check("(x) prose: identifier is api_key", extractIdentifiers(proseFinding, { lineText: commentLine }).join(",") === "api_key");
check("(x) prose: no non-test reference from .md / docs prose", proseFinding.usage?.referencedByTotal === 0, JSON.stringify(proseFinding.usage?.referencedBy));
check("(x) prose: no test reference either", proseFinding.usage?.referencedByTestsTotal === 0);
check("(x) prose: true dead end", proseFinding.usage?.deadEnd === true);
const proseTriage = triageFinding(proseFinding, { usage: proseFinding.usage });
check("(x) prose: stays likely-test-key (no production-usage upgrade)", proseTriage.triage.verdict === "likely-test-key", proseTriage.triage.verdict);
check("(x) prose: usage-dead-end signal recorded, no usage-referenced", proseTriage.triage.signals.includes("usage-dead-end") && !proseTriage.triage.signals.includes("usage-referenced"), proseTriage.triage.signals.join(","));
// …but the same identifier referenced from real code still counts.
const proseCodeFinding = finding({ type: "hardcoded-password", file: "scripts/test-scanner.ts", line: 104 });
computeUsageForFindings(
  [proseCodeFinding],
  filesMap([
    ["scripts/test-scanner.ts", `${"// filler\n".repeat(103)}${commentLine}\n`],
    ["README.md", `# Project\n\nSet \`api_key\` in config before running.\n`],
    ["src/config.ts", `const key = process.env["api_key"];\n`],
  ]),
  ctxFrom(filesMap([["scripts/test-scanner.ts", `${"// filler\n".repeat(103)}${commentLine}\n`]])),
);
check(
  "(x) code: real code reference counts, docs mention does not",
  proseCodeFinding.usage?.referencedByTotal === 1 &&
    proseCodeFinding.usage?.referencedBy.some((r) => r.file === "src/config.ts" && r.line === 1) === true &&
    !(proseCodeFinding.usage?.referencedBy.some((r) => r.file === "README.md") ?? true),
  JSON.stringify(proseCodeFinding.usage?.referencedBy),
);
check("(x) code: not a dead end", proseCodeFinding.usage?.deadEnd === false);
check(
  "(x) code: test-key + production code reference upgrades to likely-genuine-leak",
  triageFinding(proseCodeFinding, { usage: proseCodeFinding.usage }).triage.verdict === "likely-genuine-leak",
  triageFinding(proseCodeFinding, { usage: proseCodeFinding.usage }).triage.verdict,
);
// …and a test-file reference is still recorded in referencedByTests.
const proseTestFinding = finding({ type: "hardcoded-password", file: "scripts/test-scanner.ts", line: 104 });
computeUsageForFindings(
  [proseTestFinding],
  filesMap([
    ["scripts/test-scanner.ts", `${"// filler\n".repeat(103)}${commentLine}\n`],
    ["README.md", `# Project\n\nSet \`api_key\` in config before running.\n`],
    ["tests/other.test.ts", `const k = api_key;\n`],
  ]),
  ctxFrom(filesMap([["scripts/test-scanner.ts", `${"// filler\n".repeat(103)}${commentLine}\n`]])),
);
check(
  "(x) test: test-file reference still recorded in referencedByTests",
  proseTestFinding.usage?.referencedByTestsTotal === 1 &&
    proseTestFinding.usage?.referencedByTests.some((r) => r.file === "tests/other.test.ts") === true,
  JSON.stringify(proseTestFinding.usage?.referencedByTests),
);
check("(x) test: no non-test reference (docs + tests only)", proseTestFinding.usage?.referencedByTotal === 0);
check("(x) test: not a dead end (tests reference it)", proseTestFinding.usage?.deadEnd === false);
check(
  "(x) test: still likely-test-key (test-only references do not upgrade)",
  triageFinding(proseTestFinding, { usage: proseTestFinding.usage }).triage.verdict === "likely-test-key",
  triageFinding(proseTestFinding, { usage: proseTestFinding.usage }).triage.verdict,
);

// --- Generic names yield no identifier: liveness undetermined, never a false dead end ---
const genericFinding = finding({ type: "github-token", file: "src/config.ts", line: 5 });
check(
  "(generic) generic name: `token = ...` yields no identifier",
  extractIdentifiers(genericFinding, { lineText: `const token = "__SECRET_6__";` }).length === 0,
  extractIdentifiers(genericFinding, { lineText: `const token = "__SECRET_6__";` }).join(","),
);
computeUsageForFindings([genericFinding], filesMap([["src/config.ts", `const token = "__SECRET_6__";\n`]]), ctxFrom(filesMap([["src/config.ts", `const token = "__SECRET_6__";\n`]])));
check("(generic) generic name: usage present but deadEnd false (undetermined)", genericFinding.usage?.deadEnd === false && genericFinding.usage?.referencedByTotal === 0);
const genericTriage = triageFinding(genericFinding, { usage: genericFinding.usage });
check("(generic) generic name: no usage-dead-end signal without an identifier", !genericTriage.triage.signals.includes("usage-dead-end"), genericTriage.triage.signals.join(","));

// --- Regression: usage never drops a finding; score DOES change with usage (Phase 12) ---
// Phase 11 said "score never changes with usage" — that was the Phase 10
// rule, OVERTURNED in Phase 12 (Freddy, 2026-11-26): the score must
// reflect real risk. Before triage all 5 criticals deduct full (125,
// 0/F). After usage-aware triage the 3 fixture findings deduct nothing
// (likely-test-key), the src/ github-token deducts full 25
// (likely-genuine-leak), and the src/ private-key deducts half 12.5
// (uncertain) — weighted 38, score 62/C. wouldBeScore stays 0/F.
// Usage still never drops a finding and never changes detector severity.
// Fresh findings (the cases above keep their own usage; this section
// must not recompute it).
const regFindings: SecretFinding[] = [
  finding({ type: "private-key", file: "tests/fixtures/a.key", line: 1 }),
  finding({ type: "aws-access-key", file: "tests/fixtures/b.txt", line: 1 }),
  finding({ type: "github-token", file: "src/c.ts", line: 1 }),
  finding({ type: "private-key", file: "src/d.key", line: 1 }),
  finding({ type: "hardcoded-password", file: "tests/e.txt", line: 1 }),
];
const regBack = computeUsageForFindings(regFindings, new Map(), undefined);
check("Regression: usage keeps all 5 findings", regBack.length === 5, `${regBack.length}`);
check("Regression: every input id is still present", regFindings.every((f) => regBack.some((t) => t.id === f.id)));
const mixed = regFindings;
const scoreBefore = computeScore({ secrets: mixed, vulnerabilities: [], posture: [], unpinnedCount: 0 });
const triagedMixed = mixed.map((f) => ({ ...f }));
for (const f of triagedMixed) f.triage = triageFinding(f, { usage: f.usage }).triage;
const scoreAfter = computeScore({ secrets: triagedMixed, vulnerabilities: [], posture: [], unpinnedCount: 0 });
check("Scoring rule (Phase 12): usage-aware triage changes the score — test keys drop out (62/C, was 0/F untriaged)", scoreAfter.score === 62 && scoreAfter.grade === "C" && scoreBefore.score === 0, `${scoreBefore.score}/${scoreBefore.grade} vs ${scoreAfter.score}/${scoreAfter.grade}`);
check("Scoring rule (Phase 12): deduction 38 = genuine 25 + uncertain 12.5, 3 test keys at 0", scoreAfter.secretsDeduction === 38 && scoreAfter.secretsFullWeight === 1 && scoreAfter.secretsHalfWeight === 1 && scoreAfter.secretsExcluded === 3, `ded=${scoreAfter.secretsDeduction} full=${scoreAfter.secretsFullWeight} half=${scoreAfter.secretsHalfWeight} excluded=${scoreAfter.secretsExcluded}`);
check("Scoring rule (Phase 12): wouldBeScore is the old-rule score (0/F)", scoreAfter.wouldBeScore === 0 && scoreAfter.wouldBeScore === scoreBefore.score, `wouldBe=${scoreAfter.wouldBeScore}`);
check("Scoring rule: detector severity untouched by usage", triagedMixed.every((f, i) => f.severity === mixed[i].severity));

// --- Report plumbing: limits line + provisional carry-through ---
const limitsOn = buildLimits({
  filesScanned: 3, filesTotal: 3, historyOk: true, historyMethod: "git", historyCommitsScanned: 2,
  historyMs: 0, historyNote: null, depsChecked: 0, depsQueryable: 0, depsTotal: 0,
  advisoriesTotal: 0, detailCapped: 0, treeTruncated: false, tarballFallback: false,
  historyUsageFromHead: true,
});
check("Limits: history-usage line present when history findings carry HEAD-only usage", limitsOn.some((l) => /checked against the current files only/.test(l)), limitsOn.join(" | "));
const limitsOff = buildLimits({
  filesScanned: 3, filesTotal: 3, historyOk: true, historyMethod: "git", historyCommitsScanned: 2,
  historyMs: 0, historyNote: null, depsChecked: 0, depsQueryable: 0, depsTotal: 0,
  advisoriesTotal: 0, detailCapped: 0, treeTruncated: false, tarballFallback: false,
});
check("Limits: history-usage line absent when no history usage exists", !limitsOff.some((l) => /checked against the current files only/.test(l)));
const histFinding: SecretFinding = { ...deadFinding, commit: "abc1234", usage: { ...deadFinding.usage!, historyOnly: true } };
const head: HeadPartial = {
  owner: "fake-owner", repo: "fake-repo", branch: "main", headSha: "abc1234",
  filesScanned: 3, filesTotal: 3, treeTruncated: false, tarballFallback: false,
  secrets: [keyFinding], frameworks: [], dependencies: [], posture: [],
  unpinnedCount: 0, historyMethod: "git", retainedIncomplete: false,
};
const provisional = buildProvisionalReport(head, [histFinding], 1, true);
check("Provisional: carries the usage annotation through", provisional.secrets.some((s) => !!s.usage));
check("Provisional: history-usage limits line present for historyOnly findings", provisional.limits.some((l) => /checked against the current files only/.test(l)), provisional.limits.join(" | "));
const provisionalSrc = readFileSync(new URL("../src/lib/provisional.ts", import.meta.url), "utf8");
check(
  "Provisional: does not import the triage module (client-safe)",
  !/from\s+["']\.\/triage["']/.test(provisionalSrc) && !/from\s+["']node:crypto["']/.test(provisionalSrc) && !/^import\s+.*triage/m.test(provisionalSrc),
  "provisional.ts must stay client-safe",
);

console.log(failures === 0 ? "\nAll usage tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
