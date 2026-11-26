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
// Fragments below are redacted placeholders ("abcd…yz"), never a
// real secret value or a real provider prefix.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { renderToString } from "react-dom/server";
import React from "react";
import ScoreDial from "../src/components/ScoreDial";
import { FileMap, SecretsList } from "../src/components/ReportLists";
import { biggestProblem, gradeBand } from "../src/lib/score";
import type { SecretFinding } from "../src/lib/types";

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
check("CSS inline code wraps only when it must (no mid-word breaks)", !css.includes("word-break: break-all") && css.includes("overflow-wrap: break-word"));
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
check("report page renders the verdict", reportView.includes("biggestProblem"));
check("report view labels a provisional score as provisional", reportView.includes("Provisional score"));

// --- 5. No literal secret-pattern values in the UI files ------------
const uiFiles = [
  "src/app/globals.css", "src/app/page.tsx", "src/app/layout.tsx",
  "src/app/[owner]/[repo]/page.tsx", "src/app/[owner]/[repo]/loading.tsx",
  "src/components/ScoreDial.tsx", "src/components/ReportLists.tsx",
  "src/components/ReportView.tsx",
  "src/components/McpSection.tsx", "src/components/ScanProgress.tsx",
  "src/lib/score.ts",
];
const bad = uiFiles.filter((f) => /(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/.test(src(f)));
check("no literal secret-pattern values in UI files", bad.length === 0, bad.join(", "));

console.log(failures === 0 ? "\nAll Phase 7 UI checks passed." : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
