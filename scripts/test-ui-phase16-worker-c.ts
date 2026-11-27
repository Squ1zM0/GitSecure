// Phase 16 worker C tests. Run: npm run test:ui-phase16c
//
// Covers the three Phase 16 worker-C fixes - no network:
//   1. Honest timing copy: the "15–30 seconds" claim is scoped to
//      small repos on the home scan-status line and the loading
//      screen, and the live progress card shows a history pace
//      measured from real chunk progress (historyRatePerMin) or the
//      no-number "large repos take longer" wording - never an
//      invented estimate. Live evidence: vinta/awesome-python took
//      16 minutes for 3,350 history commits while the page claimed
//      "usually takes 15–30 seconds".
//   2. Footer contradiction: a provisional report must not show a 0
//      vulnerability count for a check that has not run yet (the OSV
//      check runs at assemble time). The vulnerabilities section, the
//      stat tile, and the Markdown report all say "not checked yet"
//      while provisional, and the finished report shows the real
//      count - so the section and the "Dependencies not checked yet"
//      progress line agree.
//   3. Typo: "91 out of 100 (grade A) is a excellent score" -
//      "an excellent score" (gradeWordWithArticle, shared by both
//      score-explanation templates).
//
// Fixtures use `__SECRET_n__` placeholders only where a finding is
// needed - this file needs none: the live-case fixture has 0 secrets.
// NO literal secret-pattern values anywhere in this file
// (grep-verified; see the check at the end).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { renderToString } from "react-dom/server";
import React from "react";
import Loading from "../src/app/[owner]/[repo]/loading";
import ReportView from "../src/components/ReportView";
import ScanProgress from "../src/components/ScanProgress";
import { adjustedExplainScore } from "../src/components/ScoreDial";
import { explainScore, gradeWordWithArticle } from "../src/lib/score";
import { historyRatePerMin } from "../src/lib/progress";
import { buildProvisionalReport } from "../src/lib/provisional";
import { buildReportMarkdown } from "../src/lib/report-markdown";
import type { HeadPartial, Severity } from "../src/lib/types";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` - ${extra}` : ""}`);
  if (!ok) failures++;
}

const ROOT = process.cwd();
const src = (p: string) => readFileSync(join(ROOT, p), "utf8");
const render = (el: React.ReactElement) => renderToString(el).replace(/<!-- -->/g, "");

// --- Live-case fixture: vinta/awesome-python as the iPhone showed it ---
// 91/A, 0 secrets, 0 vulns, 3 posture issues (low + low + medium = 9
// points lost), 126 files, 3,350 history commits.
const head: HeadPartial = {
  owner: "vinta", repo: "awesome-python", branch: "master", headSha: "4c3cb15",
  filesScanned: 126, filesTotal: 126, treeTruncated: false, tarballFallback: false,
  secrets: [], frameworks: [], dependencies: [],
  posture: [
    { id: "p1", title: "No SECURITY.md", severity: "low" as Severity, detail: "d", fix: "f" },
    { id: "p2", title: "No Dependabot config", severity: "low" as Severity, detail: "d", fix: "f" },
    { id: "p3", title: ".gitignore gaps", severity: "medium" as Severity, detail: "d", fix: "f" },
  ],
  unpinnedCount: 0, historyMethod: "git", retainedIncomplete: false,
};
const prov = buildProvisionalReport(head, [], 3350, true);
check("live-case fixture scores 91/A like the iPhone report", prov.score === 91 && prov.grade === "A", `${prov.score}/${prov.grade}`);
check("live-case fixture is provisional", prov.provisional === true);

// --- 3. Typo: "an excellent score", every grade ----------------------
check("explainScore A says 'an excellent score'", explainScore({ score: 91, grade: "A", secrets: 0, vulnerabilities: 0, postureIssues: 3 }).includes("91 out of 100 (grade A) is an excellent score"));
check("explainScore A never says 'a excellent score'", !explainScore({ score: 91, grade: "A", secrets: 0, vulnerabilities: 0, postureIssues: 3 }).includes("a excellent"));
check("explainScore B says 'a good score'", explainScore({ score: 80, grade: "B", secrets: 0, vulnerabilities: 0, postureIssues: 3 }).includes("is a good score"));
check("explainScore C says 'a fair score'", explainScore({ score: 65, grade: "C", secrets: 0, vulnerabilities: 0, postureIssues: 3 }).includes("is a fair score"));
check("explainScore D says 'a poor score'", explainScore({ score: 50, grade: "D", secrets: 0, vulnerabilities: 0, postureIssues: 3 }).includes("is a poor score"));
check("explainScore F says 'a needs urgent attention score'", explainScore({ score: 20, grade: "F", secrets: 0, vulnerabilities: 0, postureIssues: 3 }).includes("is a needs urgent attention score"));
check("explainScore 100 keeps the perfect-score line", explainScore({ score: 100, grade: "A", secrets: 0, vulnerabilities: 0, postureIssues: 0 }).includes("is a perfect score"));
check("gradeWordWithArticle A is 'an excellent'", gradeWordWithArticle("A") === "an excellent");
check("gradeWordWithArticle B is 'a good'", gradeWordWithArticle("B") === "a good");
check("gradeWordWithArticle F is 'a needs urgent attention'", gradeWordWithArticle("F") === "a needs urgent attention");
check(
  "adjustedExplainScore A says 'an excellent score'",
  prov.scoreDetail !== undefined &&
    adjustedExplainScore(91, "A", prov.scoreDetail, { secrets: 0, vulnerabilities: 0, postureIssues: 3 }).includes("91 out of 100 (grade A) is an excellent score"),
  prov.scoreDetail === undefined ? "no scoreDetail" : adjustedExplainScore(91, "A", prov.scoreDetail, { secrets: 0, vulnerabilities: 0, postureIssues: 3 }),
);
check("both score templates use the article helper, not a hard-coded 'a'", src("src/lib/score.ts").includes("is ${gradeWordWithArticle(grade)} score") && src("src/components/ScoreDial.tsx").includes("is ${gradeWordWithArticle(grade)} score"));

// --- 1. Honest timing copy -------------------------------------------
const loading = render(React.createElement(Loading));
check("loading screen scopes 15–30 seconds to small repos", loading.includes("A small repo usually takes 15–30 seconds"));
check("loading screen says large repos take several minutes", loading.includes("A large repo with a long history takes several minutes"));
check("loading screen never makes the unscoped 15–30 second claim", !loading.includes("A full scan usually takes 15–30 seconds"));
const home = src("src/app/page.tsx");
check("home scan-status scopes 15–30 seconds to small repos", home.includes("Small repos usually take 15–30 seconds; a large repo with a long history takes several minutes."));
check("home scan-status never makes the unscoped 15–30 second claim", !home.includes("This usually takes 15–30 seconds."));
check("no unscoped 15–30 second claim anywhere in src", !src("src/app/page.tsx").includes("This usually takes 15–30 seconds") && !src("src/app/[owner]/[repo]/loading.tsx").includes("A full scan usually takes 15–30 seconds") && !src("src/components/ScanProgress.tsx").includes("usually takes 15–30 seconds"));

// --- 1b. Measured history pace (pure function) -----------------------
check("historyRatePerMin: 400 commits in 60 s is 400/min (the observed iPhone pace)", historyRatePerMin(400, 60) === 400);
check("historyRatePerMin: 100 commits in 20 s is 300/min", historyRatePerMin(100, 20) === 300);
check("historyRatePerMin: under 100 commits is null (too little to mean anything)", historyRatePerMin(99, 60) === null);
check("historyRatePerMin: under 20 s is null (early chunks include HEAD setup)", historyRatePerMin(500, 10) === null);
check("historyRatePerMin: zero commits is null", historyRatePerMin(0, 60) === null);
check("ScanProgress wires the measured rate (no invented ETA)", src("src/components/ScanProgress.tsx").includes("historyRatePerMin("));

// --- 2. Footer contradiction: provisional vs finished ----------------
const provHtml = render(React.createElement(ReportView, { report: prov }));
check("provisional report: vuln heading says not checked yet", provHtml.includes("Dependency vulnerabilities (not checked yet)"));
check("provisional report: vuln body says the check has not run", provHtml.includes("been checked for known flaws yet"));
check("provisional report: stat tile says not checked yet", provHtml.includes("dependency vulnerabilities - not checked yet"));
check("provisional report: no 0 vulnerability count anywhere", !provHtml.includes("Dependency vulnerabilities (0)") && !provHtml.includes("No known vulnerabilities were found in the dependencies checked"));

const done = { ...prov, provisional: false };
const doneHtml = render(React.createElement(ReportView, { report: done }));
check("finished report: vuln heading shows the real 0", doneHtml.includes("Dependency vulnerabilities (0)"));
check("finished report: vuln body says none found in the dependencies checked", doneHtml.includes("No known vulnerabilities were found in the dependencies checked."));
check("finished report: no 'not checked yet' anywhere", !doneHtml.includes("not checked yet"));
check("finished report: hero says 'an excellent score'", doneHtml.includes("is an excellent score"));
check("finished report: hero never says 'a excellent score'", !doneHtml.includes("a excellent"));

// The combined live view: provisional report above the progress card.
// Both must say the same thing about dependencies.
const scanHtml = render(
  React.createElement(ScanProgress, {
    owner: "vinta", repo: "awesome-python", cursor: "", head, historyFindings: [], historyScanned: 1016,
    initial: { step: "history", filesScanned: 126, filesTotal: 126, commitsScanned: 1016, depsChecked: 0, depsTotal: 0, advisoriesDetailed: 0, advisoriesTotal: 0 },
    provisional: prov,
  }),
);
check("live progress view: report section and footer agree (both 'not checked yet')", scanHtml.includes("Dependency vulnerabilities (not checked yet)") && scanHtml.includes("Dependencies not checked yet"));
check("live progress view: no 0 vulnerability count while the check is pending", !scanHtml.includes("Dependency vulnerabilities (0)"));
check("live progress view: history timing says large repos take several minutes", scanHtml.includes("History is the slow part on a big repo - a repo with thousands of commits takes several minutes."));
check("live progress view: no invented per-minute rate on first paint", !scanHtml.includes(" a minute"));

// Markdown carries the same agreement.
const mdProv = buildReportMarkdown(prov);
check("provisional markdown: vuln heading says not checked yet", mdProv.includes("## Dependency vulnerabilities (not checked yet)"));
check("provisional markdown: summary bullet says not checked yet", mdProv.includes("- Dependency vulnerabilities: not checked yet"));
check("provisional markdown: no 0 vulnerability count", !mdProv.includes("## Dependency vulnerabilities (0)") && !mdProv.includes("- Dependency vulnerabilities: 0"));
const mdDone = buildReportMarkdown(done);
check("finished markdown: vuln heading shows the real 0", mdDone.includes("## Dependency vulnerabilities (0)"));
check("finished markdown: summary bullet shows 0", mdDone.includes("- Dependency vulnerabilities: 0"));

// --- No literal secret-pattern values in this file --------------------
const self = readFileSync(new URL(import.meta.url).pathname, "utf8");
const leaked = ["AKIA" + "IOSFODNN7EXAMPLE", "ghp_" + "FAKE".repeat(8) + "1234", "sk_test_" + "FAKE".repeat(6) + "12", "discord.com/api/webhooks/" + "123456789012345678/"].some((s) => self.includes(s));
check("No literal secret-pattern values in this file", !leaked);

console.log(failures === 0 ? "\nAll Phase 16 worker-C checks passed." : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
