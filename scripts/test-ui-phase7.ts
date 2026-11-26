// Phase 7 UI test. Run: npm run test:ui-phase7
//
// Design phase only — no scanner logic, scores, caps, redaction, or
// API/MCP contracts changed. This script proves, with no network:
//   1. The score dial renders (SVG arc, band class, score + grade,
//      accessible label) and gradeBand maps A/B -> good, C -> fair,
//      D/F -> poor; biggestProblem picks the biggest problem.
//   2. The findings lists render with GitHub blob links, in-page
//      anchors (#secret-0 …), copy-link buttons, filters, the List/Map
//      toggle, and aria-live result counts.
//   3. The file map renders with its legend and keyboard-reachable
//      file chips.
//   4. The stylesheet carries a real dark mode (prefers-color-scheme),
//      reduced-motion support, focus-visible rings, and >=44px tap
//      targets — and the human pages carry no "Honest limits" or
//      sign-in copy.
//   5. No literal secret-pattern values in the UI files.
//
//   6. (Phase 12) The triage-weighted score explanation renders with
//      the three counts and both scores; an all-test-key report never
//      presents secrets as the biggest problem; the explanation falls
//      back gracefully (renders nothing, old wording kept) when the
//      report carries no scoreDetail; MCP prose states the new rule.
//
//   7. (Phase 15) The UX-audit fixes: score-0 dial butt cap, the
//      runner-up deduction in the score explanation, the short GitHub
//      link label, the never-empty "Used by" line, middle-truncated
//      map labels with counts inside their nodes, 44 px tap targets,
//      one recommended version per package — plus the "Roll all into
//      report" button in the score hero (the Markdown itself is
//      covered by scripts/test-report-markdown.ts).
//
// Fragments below are redacted placeholders ("abcd…yz"), never a
// real secret value or a real provider prefix.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { renderToString } from "react-dom/server";
import React from "react";
import ScoreDial, { adjustedExplainScore, adjustedVerdict, ScoreExplanation, type ScoreDetail } from "../src/components/ScoreDial";
import ReportView from "../src/components/ReportView";
import { compareVersions, recommendedFixVersions } from "../src/lib/versions";
import { FileMap, SecretsList, trackDetailSegments, usageRefText, shortLabel, UsageMap, VulnerabilitiesList, FrameworksList, getUsage, type SecretUsage } from "../src/components/ReportLists";
import { biggestProblem, gradeBand } from "../src/lib/score";
import type { FullReport, SecretFinding, Vulnerability } from "../src/lib/types";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

const ROOT = process.cwd();
const src = (p: string) => readFileSync(join(ROOT, p), "utf8");

// --- 1. Score dial + grade bands + verdict --------------------------
check("gradeBand A is good", gradeBand("A") === "good");
check("gradeBand B is good", gradeBand("B") === "good");
check("gradeBand C is fair", gradeBand("C") === "fair");
check("gradeBand D is poor", gradeBand("D") === "poor");
check("gradeBand F is poor", gradeBand("F") === "poor");
check(
  "biggestProblem names leaked secrets first",
  biggestProblem({ secrets: 2, vulnerabilities: 4, postureIssues: 1 }).startsWith("Biggest problem: 2 possible leaked secrets"),
);
check(
  "biggestProblem falls back to vulnerabilities",
  biggestProblem({ secrets: 0, vulnerabilities: 4, postureIssues: 1 }).startsWith("Biggest problem: 4 known flaws"),
);
check(
  "biggestProblem says clean when nothing found",
  biggestProblem({ secrets: 0, vulnerabilities: 0, postureIssues: 0 }).includes("looks clean"),
);

const dial = renderToString(React.createElement(ScoreDial, { score: 83, grade: "B" })).replace(/<!-- -->/g, "");
check("dial renders an SVG", dial.includes("<svg"));
check("dial carries the good band class", dial.includes("dial-good"));
check("dial shows the score number", dial.includes(">83<"));
check("dial shows the grade", dial.includes("Grade B"));
check("dial has an accessible label", dial.includes('aria-label="Security score 83 out of 100, grade B, good"'));
check("dial arc uses a dasharray (0–100 gauge)", /stroke-dasharray="[\d.]+ [\d.]+"/.test(dial));
const dialF = renderToString(React.createElement(ScoreDial, { score: 0, grade: "F" }));
check("dial F carries the poor band class", dialF.includes("dial-poor"));

// --- 2. Secrets list: links, anchors, filters, live counts ----------
const fakeSecrets: SecretFinding[] = [
  {
    id: "s1", type: "database-url", title: "Database URL in a config file",
    severity: "critical", confidence: "high", file: "config/settings.py", line: 12,
    commit: "HEAD", fragment: "abcd…yz", fix: "Move it to an environment variable and rotate it.",
    plainEnglish: "A database password is written in a config file anyone can read.",
  },
  {
    id: "s2", type: "private-key", title: "Private key committed",
    severity: "high", confidence: "high", file: "keys/id_rsa", line: 1,
    commit: "abc1234", fragment: "wxyz…ab", fix: "Delete the key and generate a new one.",
    plainEnglish: "A private key is in the repo — anyone with it can pretend to be you.",
  },
];
const list = renderToString(
  React.createElement(SecretsList, { secrets: fakeSecrets, owner: "Squ1zM0", repo: "TechDirect", branch: "main" }),
).replace(/<!-- -->/g, "");
check("list has a GitHub blob link to the exact file and line", list.includes("https://github.com/Squ1zM0/TechDirect/blob/main/config/settings.py#L12"));
check("history finding links to its commit, not the branch", list.includes("https://github.com/Squ1zM0/TechDirect/blob/abc1234/keys/id_rsa#L1"));
check("list renders the secret-0 anchor", list.includes('id="secret-0"'));
check("list renders the secret-1 anchor", list.includes('id="secret-1"'));
check("list has copy-link buttons", list.includes("Copy link"));
check("list has a severity filter", list.includes("Filter by severity"));
check("list has a file-name search", list.includes("Filter by file name"));
check("list has List/Map toggle", list.includes(">List<") && list.includes(">Map<"));
check("list count line is aria-live", list.includes('aria-live="polite"'));
check("list shows the true filtered count", list.includes("Showing 2 of 2 secrets"));
check("list shows the severity pill with its label", list.includes("critical") && list.includes("high"));
check("list never renders a full secret (fragments only)", list.includes("abcd…yz") && !/postgres:\/\/[^<]{8,}/.test(list));

// --- 2b. Phase 10 triage: pills, explanations, test-key fix, filter ---
const triagedSecrets: SecretFinding[] = [
  {
    id: "t1", type: "private-key", title: "Private key",
    severity: "critical", confidence: "high", file: "tools/testing/selftests/sgx/sign_key.pem", line: 1,
    commit: "HEAD", fragment: "----…--", fix: "Treat this key as compromised: generate a new key pair, replace it everywhere it was used, and remove the old one from git history.",
    plainEnglish: "A private key in a public repo is no longer private. Anyone can impersonate whatever it unlocks.",
    triage: {
      verdict: "likely-test-key",
      signals: ["test-path:testing"],
      explanation: "This looks like an intentional test key: it lives in a test path (tools/testing/selftests). It is still listed and still counted — if it ever signs real artifacts or grants real access, treat it as compromised and rotate it.",
      adjustedSeverity: "low",
      adjustedConfidence: "low",
      fix: "Confirm this key is only used by tests and never signs real artifacts; if it does, rotate it.",
    },
  },
  {
    id: "t2", type: "private-key", title: "Private key",
    severity: "critical", confidence: "high", file: "src/config/prod.key", line: 1,
    commit: "HEAD", fragment: "----…--", fix: "Treat this key as compromised: generate a new key pair, replace it everywhere it was used, and remove the old one from git history.",
    plainEnglish: "A private key in a public repo is no longer private. Anyone can impersonate whatever it unlocks.",
    triage: {
      verdict: "likely-genuine-leak",
      signals: ["prod-filename:prod"],
      explanation: "This looks like a genuine leak: its file name looks production (prod.key) with no test signals.",
      adjustedSeverity: "critical",
      adjustedConfidence: "high",
      fix: "Treat this key as compromised: generate a new key pair, replace it everywhere it was used, and remove the old one from git history.",
    },
  },
];
const triageList = renderToString(
  React.createElement(SecretsList, { secrets: triagedSecrets, owner: "Squ1zM0", repo: "TechDirect", branch: "main" }),
).replace(/<!-- -->/g, "");
check("triage: likely-test-key pill renders with its label", triageList.includes("Likely test key"));
check("triage: likely-genuine-leak pill renders with its label", triageList.includes("Likely genuine leak"));
check("triage: test-key explanation renders", triageList.includes("This looks like an intentional test key"));
check("triage: test-key Fix replaces the rotate fix", triageList.includes("Confirm this key is only used by tests and never signs real artifacts"));
check("triage: genuine leak keeps the detector Fix", triageList.includes("Treat this key as compromised"));
check("triage: filter dropdown offers the three verdicts", triageList.includes("Filter by triage verdict") && triageList.includes("Likely test keys") && triageList.includes("Likely genuine leaks") && triageList.includes("Uncertain"));
check("triage: count line names the test-key split", triageList.includes("Of the 2 secrets, 1 looks like test keys"));
check("triage: adjusted severity shown", triageList.includes("Triage assessed severity: low"));

// --- 3. File map -----------------------------------------------------
const map = renderToString(
  React.createElement(FileMap, {
    byFile: [
      { file: "config/settings.py", count: 5 },
      { file: "keys/id_rsa", count: 1 },
    ],
    onSelectFile: () => {},
  }),
).replace(/<!-- -->/g, "");
check("map renders an SVG spider", map.includes("<svg") && map.includes("This repo"));
check("map carries its legend", map.includes("Bigger node — more findings"));
check("map nodes are keyboard reachable (role=button, tabIndex)", map.includes('role="button"') && map.includes("tabindex=\"0\""));
check("map file chips are real buttons", map.includes("<button") && map.includes("settings.py (5)"));

// --- 4. Stylesheet: dark mode, motion, focus, tap targets -----------
const css = src("src/app/globals.css");
check("CSS has a real dark mode (prefers-color-scheme: dark)", /@media \(prefers-color-scheme: dark\)/.test(css));
check("CSS dark mode redefines surfaces and text", css.includes("--bg: #141514") && css.includes("--text: #f0f0ec"));
check("CSS respects prefers-reduced-motion", /@media \(prefers-reduced-motion: reduce\)/.test(css));
check("CSS has focus-visible rings", /:focus-visible\s*\{[^}]*outline: 3px solid var\(--focus\)/.test(css));
check("CSS tap targets are >= 44px", css.includes("min-height: 44px"));
check("CSS styles the score dial", css.includes(".score-dial") && css.includes(".dial-good"));
check("CSS styles the stat grid", css.includes(".stat-grid"));
check("CSS styles grade chips per band", css.includes(".grade-chip.good") && css.includes(".grade-chip.poor"));
check("CSS styles the loading spinner", css.includes(".spinner"));
check("CSS buttons use an on-accent text colour (dark-mode contrast)", css.includes("--on-accent: #052e1e") && /button[^{]*\{[^}]*color: var\(--on-accent\)/.test(css));
// Phase 15 finding 2 (real-DT follow-up): break-word does NOT break a
// long path token when the line has other break points — the live DT
// provisional report at 360 px kept the audit's exact path 454 px
// wide. code.inline now uses anywhere, which still only breaks a token
// when it would overflow, never gratuitously. The "no mid-word breaks"
// intent is the ban on word-break: break-all, which still holds.
check("CSS inline code wraps only when it must (no mid-word breaks)", !css.includes("word-break: break-all") && /code\.inline, \.finding code \{[^}]*overflow-wrap: anywhere/.test(css));
check("triage: pills have their own styles", css.includes(".pill.triage-test") && css.includes(".pill.triage-genuine") && css.includes(".pill.triage-uncertain"));

const home = src("src/app/page.tsx");
const reportPage = src("src/app/[owner]/[repo]/page.tsx");
// Phase 9: the report rendering moved from the page into ReportView
// (so the chunk driver can swap a provisional report for the finished
// one without a reload) — the rendering checks read that file now.
const reportView = src("src/components/ReportView.tsx");
check("home has no 'Honest limits' copy", !/Honest limits/i.test(home));
check("home has no sign-in copy", !/sign in/i.test(home));
check("report page has no sign-in copy", !/sign in/i.test(reportPage));
check("home keeps the designed URL example", home.includes("url-example") && home.includes("git-secure.com/Squ1zM0/GitSecure"));
check("home error is styled and role=alert", home.includes('className="form-error"') && home.includes('role="alert"'));
check("home scanning state is role=status with a spinner", home.includes('role="status"') && home.includes("spinner"));
check("report page renders the score dial", reportView.includes("ScoreDial"));
check("report page renders the stat grid", reportView.includes("stat-grid"));
check("report page renders the verdict", reportView.includes("adjustedVerdict"));
check("report view labels a provisional score as provisional", reportView.includes("Provisional score"));

// --- 2c. Phase 11: verdict sections + usage map --------------------
// Fixtures carry `usage` via the shared contract (SecretUsage on the
// finding). The type field is not in src/lib/types.ts yet — the engine
// worker is adding it — so the fixtures are typed with the local
// mirror from ReportLists and passed structurally.
type SecretWithUsage = SecretFinding & { usage?: SecretUsage };
const phase11Secrets: SecretWithUsage[] = [
  {
    id: "p1", type: "private-key", title: "Private key",
    severity: "critical", confidence: "high", file: "tools/testing/selftests/sgx/sign_key.pem", line: 1,
    commit: "HEAD", fragment: "----…--", fix: "Treat this key as compromised: generate a new key pair, replace it everywhere it was used, and remove the old one from git history.",
    plainEnglish: "A private key in a public repo is no longer private. Anyone can impersonate whatever it unlocks.",
    triage: {
      verdict: "likely-test-key",
      signals: ["test-path:testing"],
      explanation: "This looks like an intentional test key: it lives in a test path (tools/testing/selftests). It is still listed and still counted — if it ever signs real artifacts or grants real access, treat it as compromised and rotate it.",
      adjustedSeverity: "low",
      adjustedConfidence: "low",
      fix: "Confirm this key is only used by tests and never signs real artifacts; if it does, rotate it.",
    },
    usage: {
      referencedBy: [{ file: "src/app.ts", line: 10 }],
      referencedByTotal: 1,
      referencedByTests: [{ file: "tests/app.test.ts", line: 5 }],
      referencedByTestsTotal: 1,
      deadEnd: false,
    },
  },
  {
    id: "p2", type: "private-key", title: "Private key",
    severity: "critical", confidence: "high", file: "src/config/prod.key", line: 1,
    commit: "HEAD", fragment: "----…--", fix: "Treat this key as compromised: generate a new key pair, replace it everywhere it was used, and remove the old one from git history.",
    plainEnglish: "A private key in a public repo is no longer private. Anyone can impersonate whatever it unlocks.",
    triage: {
      verdict: "likely-genuine-leak",
      signals: ["prod-filename:prod"],
      explanation: "This looks like a genuine leak: its file name looks production (prod.key) with no test signals.",
      adjustedSeverity: "critical",
      adjustedConfidence: "high",
      fix: "Treat this key as compromised: generate a new key pair, replace it everywhere it was used, and remove the old one from git history.",
    },
    usage: {
      referencedBy: [{ file: "src/server.ts", line: 42 }],
      referencedByTotal: 1,
      referencedByTests: [],
      referencedByTestsTotal: 0,
      deadEnd: false,
    },
  },
  {
    id: "p3", type: "api-key", title: "API key",
    severity: "high", confidence: "medium", file: "lib/old_client.py", line: 7,
    commit: "HEAD", fragment: "abcd…yz", fix: "Rotate the key and move it to an environment variable.",
    plainEnglish: "An API key is written in a source file anyone can read.",
    triage: {
      verdict: "uncertain",
      signals: [],
      explanation: "Nothing in this repo references this key — a true dead end. No test signals and no production signals either, so a human has to decide.",
      adjustedSeverity: "high",
      adjustedConfidence: "low",
      fix: "Rotate the key and move it to an environment variable.",
    },
    usage: {
      referencedBy: [],
      referencedByTotal: 0,
      referencedByTests: [],
      referencedByTestsTotal: 0,
      deadEnd: true,
    },
  },
  {
    id: "p4", type: "api-key", title: "API key",
    severity: "medium", confidence: "low", file: "docs/example.md", line: 3,
    commit: "HEAD", fragment: "efgh…ij", fix: "Remove it from the docs.",
    plainEnglish: "An API key appears in a documentation example.",
    // No triage, no usage: an older report's finding renders as
    // uncertain and without usage info, never crashes.
  },
];
const p11List = renderToString(
  React.createElement(SecretsList, { secrets: phase11Secrets, owner: "Squ1zM0", repo: "TechDirect", branch: "main" }),
).replace(/<!-- -->/g, "");
// The opening <details …> tag of one verdict section.
const sectionTag = (html: string, cls: string) => {
  const i = html.indexOf(cls);
  if (i < 0) return "";
  const start = html.lastIndexOf("<details", i);
  return html.slice(start, html.indexOf(">", start) + 1);
};
const testSection = p11List.slice(p11List.indexOf("verdict-test"));
check("phase11: likely-test-keys section exists with its own count", p11List.includes("Likely test keys") && p11List.includes("(1 finding)"));
check("phase11: genuine-leaks section exists with its own count", p11List.includes("Likely genuine leaks") && p11List.includes("(1 finding)"));
check("phase11: uncertain section exists with its own count", p11List.includes("Uncertain — needs a human check") && p11List.includes("(2 findings)"));
check("phase11: test-keys section is collapsed by default", !sectionTag(p11List, "verdict-test").includes("open"));
check("phase11: genuine-leaks section is open by default", sectionTag(p11List, "verdict-genuine").includes("open"));
check("phase11: uncertain section is open by default", sectionTag(p11List, "verdict-uncertain").includes("open"));
const p11ListOpen = renderToString(
  React.createElement(SecretsList, { secrets: phase11Secrets, owner: "Squ1zM0", repo: "TechDirect", branch: "main", defaultTestSectionOpen: true }),
).replace(/<!-- -->/g, "");
check("phase11: test-keys section expands (open when asked)", sectionTag(p11ListOpen, "verdict-test").includes("open"));
check("phase11: genuine leak is not in the test-keys section", !testSection.includes("src/config/prod.key") && !testSection.includes("src/server.ts"));
check("phase11: test key is in the test-keys section, with its test-key Fix", testSection.includes("tools/testing/selftests/sgx/sign_key.pem") && testSection.includes("Confirm this key is only used by tests"));
check("phase11: counts line shows the honest split", p11List.includes("Of the 4 secrets, 1 looks like test keys") && p11List.includes("1 looks like genuine leaks, 2 uncertain."));
check("phase11: dead-end finding carries the Dead end label", p11List.includes("Dead end"));
check("phase11: dead-end explanation renders", p11List.includes("Nothing in this repo references this key — a true dead end"));
check("phase11: in-use finding shows its references", p11List.includes("Used by: src/app.ts:10, tests/app.test.ts:5 (test)"));
check("phase11: every finding keeps its GitHub link and anchor", p11List.includes("https://github.com/Squ1zM0/TechDirect/blob/main/src/config/prod.key#L1") && p11List.includes('id="secret-3"'));
check("phase11: getUsage is defensive (absent -> undefined)", getUsage(phase11Secrets[3]) === undefined);
check("phase11: getUsage is defensive (malformed -> undefined)", getUsage({ ...phase11Secrets[3], usage: { deadEnd: "yes" } } as unknown as SecretFinding) === undefined);

// --- 2d. Phase 11 usage map ------------------------------------------
const p11ByFile = [
  { file: "tools/testing/selftests/sgx/sign_key.pem", count: 1 },
  { file: "src/config/prod.key", count: 1 },
  { file: "lib/old_client.py", count: 1 },
  { file: "docs/example.md", count: 1 },
  { file: "src/app.ts", count: 0 },
  { file: "tests/app.test.ts", count: 0 },
  { file: "src/server.ts", count: 0 },
];
const p11Findings = phase11Secrets.map((item, idx) => ({ item, idx }));
const usageMap = renderToString(
  React.createElement(UsageMap, { findings: p11Findings, byFile: p11ByFile, onSelectFile: () => {} }),
).replace(/<!-- -->/g, "");
check("phase11 map: renders an SVG usage graph", usageMap.includes("<svg") && usageMap.includes("Usage map"));
check("phase11 map: legend names solid vs dashed edges and dead ends", usageMap.includes("Used in non-test code") && usageMap.includes("Used in tests only") && usageMap.includes("dead end"));
check("phase11 map: in-use finding gets code + test edges", usageMap.includes("map-edge-code") && usageMap.includes("map-edge-test"));
check("phase11 map: edges total 5 (test key: own+code+test, genuine: own+code, dead end: none)", (usageMap.match(/<line/g) ?? []).length === 5);
check("phase11 map: dead-end finding is greyed and labelled", usageMap.includes("map-finding-deadend") && usageMap.includes(">dead end<"));
check("phase11 map: finding nodes are keyboard reachable", usageMap.includes('role="button"') && usageMap.includes("tabindex=\"0\""));
check("phase11 map: track hint renders when nothing is selected", usageMap.includes("Click a finding node to follow its track"));
const noUsageMap = renderToString(
  React.createElement(UsageMap, {
    findings: [{ item: fakeSecrets[0], idx: 0 }],
    byFile: [{ file: "config/settings.py", count: 5 }],
    onSelectFile: () => {},
  }),
).replace(/<!-- -->/g, "");
check("phase11 map: degrades gracefully with no usage data (file-count spider)", noUsageMap.includes("Map of files holding secrets") && !noUsageMap.includes("map-edge"));
check("phase11 CSS: verdict sections, dead-end pill, map edges and track detail styled", css.includes(".verdict-test") && css.includes(".pill.dead-end") && css.includes(".map-edge-test") && css.includes(".map-edge-own") && css.includes(".map-finding-deadend") && css.includes(".map-track-detail"));

// --- 5. Phase 12: triage-weighted score explanation ----------------
// Self-scan detail, measured Phase 13 (test-results/phase13-vuln-inventory.md
// + scripts/test-deps-phase13.ts): 34 secrets (32 test keys excluded,
// 2 uncertain at half weight, 0 genuine), secrets deduction 384 -> 8,
// vulns 206 (73 vulns: 20 medium, 53 low — was 547 / 197 in Phase 12),
// posture 84, unpinned 4 — score still 0/F, would-be score also 0/F.
const selfScanDetail: ScoreDetail = {
  score: 0, grade: "F", secretsDeduction: 8, secretsFullWeight: 0,
  secretsHalfWeight: 2, secretsExcluded: 32, wouldBeScore: 0,
  vulnDeduction: 206, postureDeduction: 84, unpinnedDeduction: 4,
};
const selfScanCounts = { secrets: 34, vulnerabilities: 73, postureIssues: 15 };
// A case where the adjustment changes the score: 4 test keys, no
// genuine secrets, vulns 10 + posture 7 -> 83/B; at full weight the 4
// critical test keys (4 x 25) would floor it to 0.
const adjustedDetail: ScoreDetail = {
  score: 83, grade: "B", secretsDeduction: 0, secretsFullWeight: 0,
  secretsHalfWeight: 0, secretsExcluded: 4, wouldBeScore: 0,
  vulnDeduction: 10, postureDeduction: 7, unpinnedDeduction: 0,
};
const adjustedCounts = { secrets: 4, vulnerabilities: 1, postureIssues: 1 };
// A genuine-leak case: secrets are still the driver.
const genuineDetail: ScoreDetail = {
  score: 40, grade: "D", secretsDeduction: 50, secretsFullWeight: 2,
  secretsHalfWeight: 0, secretsExcluded: 1, wouldBeScore: 15,
  vulnDeduction: 10, postureDeduction: 0, unpinnedDeduction: 0,
};
const genuineCounts = { secrets: 3, vulnerabilities: 1, postureIssues: 0 };

const stripTags = (html: string) => html.replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/<!-- -->/g, "");

const selfExplain = stripTags(renderToString(React.createElement(ScoreExplanation, { detail: selfScanDetail })));
check("phase12: explanation names the excluded test keys", selfExplain.includes("32 look like test keys and are excluded"));
check("phase12: explanation names the half-weight count", selfExplain.includes("2 are uncertain and count at half weight"));
check("phase12: explanation names the full-weight count", selfExplain.includes("0 count at full weight"));
check("phase12: explanation shows both scores (self-scan: would-be equals score)", selfExplain.includes("the score would still be 0"));
const adjExplain = stripTags(renderToString(React.createElement(ScoreExplanation, { detail: adjustedDetail })));
check("phase12: explanation shows the would-be score when it differs", adjExplain.includes("the score would be 0 instead of 83"));
check("phase12: explanation states the rule in plain English", adjExplain.includes("does not count toward the score at all") && adjExplain.includes("counts at half weight") && adjExplain.includes("counts in full"));
check("phase12: explanation renders nothing with no scoreDetail", renderToString(React.createElement(ScoreExplanation, { detail: undefined })) === "");
const zeroDetail: ScoreDetail = { ...adjustedDetail, secretsExcluded: 0, wouldBeScore: 83 };
const zeroExplain = stripTags(renderToString(React.createElement(ScoreExplanation, { detail: zeroDetail })));
check("phase12: explanation handles zero secrets", zeroExplain.includes("No secrets were found") && zeroExplain.includes("no test-key adjustment"));

const selfVerdict = adjustedVerdict(selfScanDetail, selfScanCounts);
check("phase12: all-test-key verdict does not present secrets as the biggest problem", !selfVerdict.includes("possible leaked secrets — rotate") && !selfVerdict.startsWith("Biggest problem: 34"));
check("phase12: all-test-key verdict names the real driver (vulnerabilities)", selfVerdict.includes("Biggest problem: 73 known flaws in dependencies"));
check("phase12: all-test-key verdict says the test keys are excluded", selfVerdict.includes("The 32 look like test keys and do not count toward the score; the 2 uncertain ones count at half weight"));
check("phase12: all-excluded verdict (no uncertain) says all are excluded", adjustedVerdict(adjustedDetail, adjustedCounts).includes("The 4 possible leaked secrets all look like test keys, so they do not count toward the score"));
check("phase12: verdict falls back to the old wording with no scoreDetail", adjustedVerdict(undefined, { secrets: 2, vulnerabilities: 4, postureIssues: 1 }) === biggestProblem({ secrets: 2, vulnerabilities: 4, postureIssues: 1 }));
const genuineVerdict = adjustedVerdict(genuineDetail, genuineCounts);
check("phase12: genuine-leak verdict still names the secrets", genuineVerdict.includes("Biggest problem: 2 genuine leaked secrets"));

const selfExplainScore = adjustedExplainScore(0, "F", selfScanDetail, selfScanCounts);
check("phase12: explainScore names the real driver, not the test keys", selfExplainScore.includes("73 known flaws") && !selfExplainScore.includes("possible leaked secrets — rotating"));
check("phase12: explainScore says the test keys are excluded", selfExplainScore.includes("do not count toward the score"));
check("phase12: genuine-leak explainScore still names the secrets", adjustedExplainScore(40, "D", genuineDetail, genuineCounts).includes("2 genuine leaked secrets"));
check("phase12: explainScore falls back with no scoreDetail", adjustedExplainScore(83, "B", undefined, { secrets: 2, vulnerabilities: 4, postureIssues: 1 }).includes("2 possible leaked secrets"));

// Report hero wiring: the explanation renders in the real ReportView,
// and an older report without scoreDetail renders the old wording.
const fakeReport = (detail: ScoreDetail | undefined): FullReport =>
  ({
    kind: "full", repo: "TechDirect", owner: "Squ1zM0", branch: "main", commit: "abc1234",
    score: detail ? detail.score : 83, grade: detail ? detail.grade : "B",
    ...(detail ? { scoreDetail: detail } : {}),
    counts: { secrets: 4, testKeySecrets: 4, vulnerabilities: 1, frameworks: 2, dependencies: 5, postureIssues: 1, filesScanned: 10, historyCommitsScanned: 3 },
    summary: "Scan complete. 4 possible leaked secrets found — rotate and remove these first; 1 known vulnerability in dependencies; 1 security hygiene issue to fix; 2 frameworks fingerprinted. The full detail is in this report — no sign-in needed.",
    scannedAt: "2026-11-26T00:00:00.000Z", historyDepth: "Full history, newest first.",
    limits: ["Scanned all 10 files in the tree."], secrets: [], frameworks: [], dependencies: [], vulnerabilities: [], posture: [],
  }) as unknown as FullReport;
const reportWithDetail = stripTags(renderToString(React.createElement(ReportView, { report: fakeReport(adjustedDetail) })));
check("phase12: report hero renders the explanation with both scores", reportWithDetail.includes("the score would be 0 instead of 83"));
check("phase12: report hero verdict names the real driver, not test keys", reportWithDetail.includes("Biggest problem: 1 known flaw in dependencies") && !reportWithDetail.includes("Biggest problem: 4 possible leaked secrets"));
const reportNoDetail = stripTags(renderToString(React.createElement(ReportView, { report: fakeReport(undefined) })));
check("phase12: report hero falls back gracefully with no scoreDetail", reportNoDetail.includes("Biggest problem: 4 possible leaked secrets") && !reportNoDetail.includes("How this score works"));
check("phase12: report view wires the explanation to scoreDetail", reportView.includes("ScoreExplanation") && reportView.includes("scoreDetail") && reportView.includes("adjustedVerdict") && reportView.includes("adjustedExplainScore"));

// MCP prose states the new rule.
const mcp = src("src/lib/mcp.ts");
check("phase12: MCP prose states the new weights, not the old rule", mcp.includes("deducts nothing") && mcp.includes("half weight") && mcp.includes("full weight") && !/never changes the score/.test(mcp));

// --- 7. Phase 15: UX audit fixes + "Roll all into report" ---------
// Findings are numbered as in test-results/phase15-ux-audit.md, and
// the reason for each behaviour change is recorded on the check.

// Finding 8: a score-0 dial must not render a stray red dot — the arc
// uses a butt cap at 0 (round cap otherwise).
const dialZero = renderToString(React.createElement(ScoreDial, { score: 0, grade: "F" }));
check("phase15 finding 8: score-0 dial uses a butt cap (no stray dot)", dialZero.includes('stroke-linecap="butt"'));
const dialNormal = renderToString(React.createElement(ScoreDial, { score: 83, grade: "B" }));
check("phase15 finding 8: a normal score keeps the round cap", dialNormal.includes('stroke-linecap="round"'));

// Finding 13: the score explanation names the runner-up deduction,
// not just the top driver. TechDirect's hero said the points lost
// came from "3 small security-hygiene issues" and never mentioned
// its 4 dependency vulnerabilities.
const tdDetail: ScoreDetail = {
  score: 83, grade: "B", secretsDeduction: 0, secretsFullWeight: 0,
  secretsHalfWeight: 0, secretsExcluded: 0, wouldBeScore: 83,
  vulnDeduction: 8, postureDeduction: 9, unpinnedDeduction: 0,
};
const tdCounts = { secrets: 0, vulnerabilities: 4, postureIssues: 3 };
const tdExplain = adjustedExplainScore(83, "B", tdDetail, tdCounts);
check("phase15 finding 13: TechDirect explanation still names the top driver", tdExplain.includes("3 small security-hygiene issues"));
check("phase15 finding 13: TechDirect explanation appends the runner-up vulns with their points", tdExplain.includes("Plus 4 known flaws in dependencies, which cost 8 points"));
const singleDriver = adjustedExplainScore(91, "B", { ...tdDetail, vulnDeduction: 0 }, { secrets: 0, vulnerabilities: 0, postureIssues: 3 });
check("phase15 finding 13: no runner-up is appended when nothing else deducts", !singleDriver.includes("Plus"));
const secretsRunnerUp = adjustedExplainScore(70, "C",
  { score: 70, grade: "C", secretsDeduction: 25, secretsFullWeight: 1, secretsHalfWeight: 0, secretsExcluded: 0, wouldBeScore: 70, vulnDeduction: 30, postureDeduction: 0, unpinnedDeduction: 0 },
  { secrets: 1, vulnerabilities: 3, postureIssues: 0 });
check("phase15 finding 13: a secrets runner-up names the genuine leaks", secretsRunnerUp.includes("Plus 1 genuine leaked secret, which cost 25 points"));

// Finding 2: the GitHub link label is short ("View on GitHub") — the
// long path used to be part of the label and pushed a 360 px DT
// report 66 px wide. The path is already shown in the line above.
const longPathSecret: SecretFinding = {
  id: "lp1", type: "hardcoded-password", title: "Hardcoded password",
  severity: "medium", confidence: "high", file: "types/nginstack__datasource/lib/DataSourceDataType.d.ts", line: 1,
  commit: "HEAD", fragment: "efgh…ij", fix: "Rotate it.",
  plainEnglish: "A password is written in a file anyone can read.",
};
const longPathList = renderToString(
  React.createElement(SecretsList, { secrets: [longPathSecret], owner: "DefinitelyTyped", repo: "DefinitelyTyped", branch: "master" }),
).replace(/<!-- -->/g, "");
check("phase15 finding 2: GitHub link label is short", longPathList.includes(">View on GitHub<"));
check("phase15 finding 2: the long path is not in the link label", !longPathList.includes("View on GitHub — types/"));
check("phase15 finding 2: the blob link still points at the exact file and line", longPathList.includes("https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/nginstack__datasource/lib/DataSourceDataType.d.ts#L1"));
check("phase15 finding 2: the path is still shown in the row above the link", longPathList.includes("types/nginstack__datasource/lib/DataSourceDataType.d.ts:1"));

// Finding 9: the "Used by" line and the track detail never print an
// empty label when one reference list is empty.
const testsOnlyUsage: SecretUsage = {
  referencedBy: [], referencedByTotal: 0,
  referencedByTests: [{ file: "tests/app.test.ts", line: 5 }], referencedByTestsTotal: 1,
  deadEnd: false,
};
check("phase15 finding 9: tests-only usage renders without an empty Used by", usageRefText(testsOnlyUsage) === "Used by: tests/app.test.ts:5 (test)");
check("phase15 finding 9: track detail omits the Used by segment when only tests exist", JSON.stringify(trackDetailSegments(testsOnlyUsage)) === JSON.stringify(["in tests: tests/app.test.ts:5"]));
const bothUsage: SecretUsage = {
  referencedBy: [{ file: "src/app.ts", line: 10 }], referencedByTotal: 1,
  referencedByTests: [{ file: "tests/app.test.ts", line: 5 }], referencedByTestsTotal: 1,
  deadEnd: false,
};
check("phase15 finding 9: both lists render as two segments", JSON.stringify(trackDetailSegments(bothUsage)) === JSON.stringify(["Used by: src/app.ts:10", "in tests: tests/app.test.ts:5"]));
check("phase15 finding 9: no references renders null", usageRefText({ referencedBy: [], referencedByTotal: 0, referencedByTests: [], referencedByTestsTotal: 0, deadEnd: false }) === null);
check("phase15 finding 9: totals without a list fall back to a count sentence", usageRefText({ referencedBy: [], referencedByTotal: 3, referencedByTests: [], referencedByTestsTotal: 0, deadEnd: false }) === "Used by: 3 references (file list not shown)");

// Finding 4: file labels truncate middle-out with an ellipsis, never
// a silent mid-word clip; the dense usage map stays legible.
check("phase15 finding 4: long basenames truncate middle-out with an ellipsis", shortLabel("test-usage-phase11.ts") === "test-usa…11.ts");
check("phase15 finding 4: test-history.ts keeps head and tail", shortLabel("test-history.ts") === "test-his…ry.ts");
check("phase15 finding 4: short basenames render whole", shortLabel("README.md") === "README.md" && shortLabel("config.js") === "config.js");
const denseFiles = [
  "scripts/test-history.ts", "scripts/test-usage-phase11.ts", "scripts/test-scanner.ts",
  "scripts/test-triage-phase10.ts", "scripts/test-public-full.ts", "scripts/test-fixtures-phase14.ts",
  "README.md", "config.js",
];
const mkDense = (idx: number, file: string, refs: number, dead = false): SecretWithUsage => ({
  id: `d${idx}`, type: "hardcoded-password", title: "Hardcoded password",
  severity: "medium", confidence: "high", file, line: idx + 1,
  commit: "HEAD", fragment: "abcd…yz", fix: "Rotate it.",
  plainEnglish: "A password is written in a file anyone can read.",
  usage: {
    referencedBy: Array.from({ length: Math.min(refs, 10) }, (_, j) => ({ file: denseFiles[(idx + j) % denseFiles.length], line: 10 + j })),
    referencedByTotal: refs,
    referencedByTests: [], referencedByTestsTotal: 0,
    deadEnd: dead,
  },
});
const denseFindings: SecretWithUsage[] = [
  mkDense(0, "scripts/test-history.ts", 35),
  mkDense(1, "scripts/test-usage-phase11.ts", 35),
  mkDense(2, "scripts/test-scanner.ts", 27),
  mkDense(3, "scripts/test-triage-phase10.ts", 27),
  mkDense(4, "scripts/test-public-full.ts", 27),
  mkDense(5, "scripts/test-fixtures-phase14.ts", 15),
  mkDense(6, "README.md", 15),
  mkDense(7, "config.js", 0),
  mkDense(8, "scripts/test-history.ts", 0),
  mkDense(9, "scripts/test-usage-phase11.ts", 0),
  mkDense(10, "scripts/test-scanner.ts", 0, true),
  mkDense(11, "scripts/test-fixtures-phase14.ts", 0, true),
];
const denseByFile = [
  { file: "scripts/test-history.ts", count: 2 },
  { file: "scripts/test-usage-phase11.ts", count: 2 },
  { file: "scripts/test-scanner.ts", count: 2 },
  { file: "scripts/test-triage-phase10.ts", count: 1 },
  { file: "scripts/test-public-full.ts", count: 1 },
  { file: "scripts/test-fixtures-phase14.ts", count: 2 },
  { file: "README.md", count: 1 },
  { file: "config.js", count: 1 },
];
const denseMap = renderToString(
  React.createElement(UsageMap, { findings: denseFindings.map((item, idx) => ({ item, idx })), byFile: denseByFile, onSelectFile: () => {} }),
).replace(/<!-- -->/g, "");
check("phase15 finding 4: dense map truncates file labels with an ellipsis, never a silent clip", denseMap.includes(">test-usa…11.ts<") && denseMap.includes(">test-his…ry.ts<") && !denseMap.includes(">test-usage-pha<") && !denseMap.includes(">test-history.t<"));
check("phase15 finding 4: dense map shows the uses captions", denseMap.includes("35 uses") && denseMap.includes("27 uses") && denseMap.includes("15 uses"));
check("phase15 finding 4: dense map labels carry the halo class", denseMap.includes('class="map-label"'));
check("phase15 finding 4: dense map file counts sit inside their nodes", denseMap.includes('font-size="11"'));
check("phase15 finding 4: dense map still draws the dead ends", denseMap.includes("map-finding-deadend") && denseMap.includes(">dead end<"));
check("phase15 finding 4: dense map keeps keyboard-reachable nodes", denseMap.includes('role="button"') && denseMap.includes('tabindex="0"'));

// Finding 12: the ≥44 px tap-target rule has no 36 px exceptions
// left; inline text links stay as-is (ordinary inline text).
check("phase15 finding 12: no 36 px tap-target exception remains in the CSS", !css.includes("min-height: 36px"));
check("phase15 finding 12: copy-btn is 44 px", /button\.copy-btn \{[^}]*min-height: 44px/.test(css));
check("phase15 finding 12: file-chip is 44 px", /button\.file-chip \{[^}]*min-height: 44px/.test(css));

// Finding 2 (CSS half) + finding 4 (CSS half): wrap + halo rules.
check("phase15 finding 2: .github-link wraps anywhere", /\.github-link \{[^}]*overflow-wrap: anywhere/.test(css));
// Finding 2 (real-DT follow-up): break-word does NOT break a long
// file-path token when the line has other break points — the live DT
// provisional report at 360 px kept the audit's exact path
// (types/nginstack__datasource/.../DataSourceDataType.d.ts:14) 454 px
// wide. code.inline must use anywhere so the token itself breaks.
check("phase15 finding 2: code.inline wraps anywhere (long file paths break)", /code\.inline, \.finding code \{[^}]*overflow-wrap: anywhere/.test(css));
check("phase15 finding 2: no break-word left on code.inline", !/code\.inline, \.finding code \{[^}]*overflow-wrap: break-word/.test(css));
// Finding 2 (real-DT follow-up, second contributor): the Frameworks list
// on the live DT provisional report carried 40-char SHA versions as plain
// text — no break opportunity — and the report measured 411 px wide at a
// 360 px viewport even after the code.inline fix. The list items and the
// finding rows wrap anywhere so a token that would overflow breaks.
check("phase15 finding 2: report-list items wrap anywhere", /\.report-list li \{[^}]*overflow-wrap: anywhere/.test(css));
check("phase15 finding 2: finding rows wrap anywhere", /\.finding \{[^}]*overflow-wrap: anywhere/.test(css));
const longShaFrameworks = [
  { name: "GitHub Action actions/cache", ecosystem: "actions", version: "55cc8345863c7cc4c66a329aec7e43d4f5a6b7c8", versionSource: "lockfile" as const, unpinned: false, sourceFile: ".github/workflows/test.yml" },
];
const frameworksHtml = renderToString(React.createElement(FrameworksList, { frameworks: longShaFrameworks }));
check("phase15 finding 2: FrameworksList renders the wrapping report-list", frameworksHtml.includes('class="report-list"') && frameworksHtml.includes("55cc8345863c7cc4c66a329aec7e43d4f5a6b7c8"));
check("phase15 finding 4: map labels carry a halo so edges cannot strike them through", /\.map-node text\.map-label \{[^}]*paint-order: stroke/.test(css));

// Finding 15: one recommended version per package in the Fix line.
const jsYamlVulns: Vulnerability[] = [
  { id: "GHSA-a", packageName: "js-yaml", ecosystem: "npm", installedVersion: "4.1.1", fixedVersion: "4.3.2", severity: "low", summary: "a", plainEnglish: "js-yaml 4.1.1 has a flaw (GHSA-a). Upgrade to 4.3.2 or later to fix it.", upgrade: "Upgrade js-yaml to 4.3.2 or later." },
  { id: "GHSA-b", packageName: "js-yaml", ecosystem: "npm", installedVersion: "4.1.1", fixedVersion: "3.15.0", severity: "low", summary: "b", plainEnglish: "js-yaml 4.1.1 has a flaw (GHSA-b). Upgrade to 3.15.0 or later to fix it.", upgrade: "Upgrade js-yaml to 3.15.0 or later." },
  { id: "GHSA-c", packageName: "js-yaml", ecosystem: "npm", installedVersion: "4.1.1", fixedVersion: "4.3.1", severity: "low", summary: "c", plainEnglish: "js-yaml 4.1.1 has a flaw (GHSA-c). Upgrade to 4.3.1 or later to fix it.", upgrade: "Upgrade js-yaml to 4.3.1 or later." },
  { id: "GHSA-d", packageName: "js-yaml", ecosystem: "npm", installedVersion: "4.1.1", fixedVersion: "4.2.0", severity: "low", summary: "d", plainEnglish: "js-yaml 4.1.1 has a flaw (GHSA-d). Upgrade to 4.2.0 or later to fix it.", upgrade: "Upgrade js-yaml to 4.2.0 or later." },
  { id: "GHSA-lodash", packageName: "lodash", ecosystem: "npm", installedVersion: "4.17.20", fixedVersion: "4.17.21", severity: "low", summary: "l", plainEnglish: "lodash 4.17.20 has a flaw (GHSA-lodash). Upgrade to 4.17.21 or later to fix it.", upgrade: "Upgrade lodash to 4.17.21 or later." },
];
const vulnList = renderToString(React.createElement(VulnerabilitiesList, { vulnerabilities: jsYamlVulns })).replace(/<!-- -->/g, "");
const vulnFixLines = vulnList.match(/<p class="fix">.*?<\/p>/g) ?? [];
check("phase15 finding 15: every js-yaml Fix line names the single recommended version", vulnFixLines.filter((l) => l.includes("js-yaml")).length === 4 && vulnFixLines.filter((l) => l.includes("js-yaml")).every((l) => l.includes("Upgrade js-yaml to 4.3.2 or later — this covers all 4 advisories for this version.")));
check("phase15 finding 15: no Fix line names a losing version", vulnFixLines.filter((l) => l.includes("3.15.0") || l.includes("4.3.1") || l.includes("4.2.0")).length === 0);
check("phase15 finding 15: the single-version lodash Fix is unchanged", vulnList.includes("Fix:</b> Upgrade lodash to 4.17.21 or later."));
check("phase15 finding 15: recommendedFixVersions picks the max (4.3.2 of 4.3.2/3.15.0/4.3.1/4.2.0)", recommendedFixVersions(jsYamlVulns).get("js-yaml@4.1.1")?.recommended === "4.3.2");
check("phase15 finding 15: a single-version package has no reconciliation entry", !recommendedFixVersions(jsYamlVulns).has("lodash@4.17.20"));
check("phase15 finding 15: compareVersions is semver-aware (4.3.2 > 3.15.0)", compareVersions("4.3.2", "3.15.0") > 0 && compareVersions("3.15.0", "4.3.2") < 0 && compareVersions("4.3.1", "4.3.2") < 0 && compareVersions("4.3.2", "4.3.2") === 0);
check("phase15 finding 15: a pre-release sorts below its release", compareVersions("1.0.0-alpha", "1.0.0") < 0);

// "Roll all into report" (Freddy, 2026-11-26): the button renders in
// the score hero, next to the dial and above the stat grid, and says
// what it downloads.
const heroHtml = renderToString(React.createElement(ReportView, { report: fakeReport(adjustedDetail) }));
check("roll-all: the button renders in the report hero", heroHtml.includes("Roll all into report"));
check("roll-all: the button sits in the score hero, above the stat grid", heroHtml.indexOf("Roll all into report") > heroHtml.indexOf("score-hero") && heroHtml.indexOf("Roll all into report") < heroHtml.indexOf("stat-grid"));
check("roll-all: the button explains what it downloads", heroHtml.includes("One Markdown file — score, summary, and every finding."));
check("roll-all: the hero CSS puts the button top-right and full-width on phones", /\.roll-all \{[^}]*margin-left: auto/.test(css) && css.includes(".roll-all button { width: 100%; }"));

// --- 6. No literal secret-pattern values in the UI files ------------
const uiFiles = [
  "src/app/globals.css", "src/app/page.tsx", "src/app/layout.tsx",
  "src/app/[owner]/[repo]/page.tsx", "src/app/[owner]/[repo]/loading.tsx",
  "src/components/ScoreDial.tsx", "src/components/ReportLists.tsx",
  "src/components/ReportView.tsx", "src/components/RollAllButton.tsx",
  "src/components/McpSection.tsx", "src/components/ScanProgress.tsx",
  "src/lib/score.ts", "src/lib/report-markdown.ts", "src/lib/versions.ts",
];
const bad = uiFiles.filter((f) => /(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/.test(src(f)));
check("no literal secret-pattern values in UI files", bad.length === 0, bad.join(", "));

console.log(failures === 0 ? "\nAll Phase 7 UI checks passed." : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
