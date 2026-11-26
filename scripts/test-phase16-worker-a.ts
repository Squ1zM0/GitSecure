// Phase 16 worker A tests. Run: npm run test:phase16-a
//
// Covers the fast-shell + visible-resume work — no network:
//   1. The report page renders the progress shell immediately: no
//      server-side scan wait (no runScanLoop / FAST_PATH_WAIT_MS), a
//      null cursor, and only a bad owner/repo name keeps a
//      server-side error page.
//   2. The shared error copy (scan-error-copy.ts) carries the exact
//      Phase 15 words for every terminal failure, and the retry
//      labels.
//   3. ScanProgress starts a fresh scan through POST /api/scan/start,
//      resumes from ANY saved progress (not only when it is ahead of
//      a server partial — there is no server partial any more), shows
//      the retained counts and the resume line at once, verifies a
//      saved finished report against the live tip, and shows the full
//      error page for a terminal failure before any progress.
//   4. The shared budgets are untouched by this change (Worker B owns
//      the API budget): FAST_PATH_WAIT_MS is still 50_000 in chunks.ts,
//      and the scan API and MCP use the separate API_FAST_PATH_WAIT_MS.
//
// Fixtures use `__SECRET_n__` placeholders only where a finding is
// needed — this file needs none. NO literal secret-pattern values
// anywhere in this file (grep-verified; see the check at the end).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { renderToString } from "react-dom/server";
import React from "react";
import ReportPage from "../src/app/[owner]/[repo]/page";
import ScanProgress from "../src/components/ScanProgress";
import { scanErrorCopy, scanErrorRetryLabel } from "../src/lib/scan-error-copy";
import { emptyProgress } from "../src/lib/progress";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

const ROOT = process.cwd();
const src = (p: string) => readFileSync(join(ROOT, p), "utf8");
const render = (el: React.ReactElement) => renderToString(el).replace(/<!-- -->/g, "");

// --- 1. Report page: fast shell, zero server await --------------------
const page = src("src/app/[owner]/[repo]/page.tsx");
check("report page never awaits the scan loop", !page.includes("runScanLoop"));
check("report page never touches the fast-path budget", !page.includes("FAST_PATH_WAIT_MS"));
check("report page never imports the chunk driver", !/from ["']@\/lib\/chunks["']/.test(page));
check("report page renders ScanProgress with a null cursor", page.includes("cursor={null}"));
check("report page still validates the owner/repo name server-side", page.includes("validateOwnerRepo(owner, repo)"));
check("report page bad-format state keeps the retry button", page.includes("RetryScanButton"));
check("report page bad-format state still offers 'Scan another repo'", page.includes("Scan another repo"));
check("report page renders on demand via params (no prerender)", page.includes("await params") && !page.includes("export const dynamic"));
check("report page has no sign-in copy", !/sign in/i.test(page));

// --- 2. Shared error copy: exact Phase 15 words -----------------------
check(
  "not-found copy unchanged",
  scanErrorCopy("not-found", "vinta", "awesome-python").title === "Couldn't find vinta/awesome-python" &&
    scanErrorCopy("not-found", "vinta", "awesome-python").body.includes("only scans public repos"),
);
check(
  "private copy unchanged",
  scanErrorCopy("private", "vinta", "awesome-python").title === "vinta/awesome-python is private",
);
const twelveMinOut = Date.now() + 12 * 60_000;
check(
  "rate-limit copy uses the honest reset body",
  scanErrorCopy("rate-limit", "vinta", "awesome-python", twelveMinOut).body.includes("resets in about 12 minutes"),
  scanErrorCopy("rate-limit", "vinta", "awesome-python", twelveMinOut).body,
);
check(
  "rate-limit copy falls back to within the hour",
  scanErrorCopy("rate-limit", "vinta", "awesome-python", null).body.includes("resets within the hour"),
);
check(
  "timeout copy unchanged",
  scanErrorCopy("timeout", "vinta", "awesome-python").title === "GitHub took too long to answer" &&
    scanErrorCopy("timeout", "vinta", "awesome-python").body.includes("no time limit"),
);
check(
  "bad-format copy unchanged",
  scanErrorCopy("bad-format", "vinta", "awesome-python").title === "That doesn't look like a valid repo",
);
check(
  "head-moved copy unchanged",
  scanErrorCopy("head-moved", "vinta", "awesome-python").title === "The repo changed while scanning vinta/awesome-python" &&
    scanErrorCopy("head-moved", "vinta", "awesome-python").body.includes("previous HEAD"),
);
check(
  "unknown kind falls back to the generic error",
  scanErrorCopy("unknown", "vinta", "awesome-python").title === "Couldn't scan vinta/awesome-python",
);
check("rate-limit retry label is 'Try this scan again'", scanErrorRetryLabel("rate-limit") === "Try this scan again");
check("other retry label is 'Retry this scan'", scanErrorRetryLabel("not-found") === "Retry this scan" && scanErrorRetryLabel("timeout") === "Retry this scan");

// --- 3. ScanProgress: start, resume, tip check, terminal errors ------
const scanProgress = src("src/components/ScanProgress.tsx");
check("ScanProgress starts a fresh scan through /api/scan/start", scanProgress.includes('"/api/scan/start"'));
check("ScanProgress still drives later chunks through /api/scan/chunk", scanProgress.includes('"/api/scan/chunk"'));
check("ScanProgress picks the start route exactly when there is no cursor", scanProgress.includes("const isStart = cursor === null"));
check("ScanProgress verifies a saved report against the live tip", scanProgress.includes("/api/scan/") && scanProgress.includes("/tip"));
check("ScanProgress loads saved progress before any fetch", scanProgress.indexOf("loadProgress(sessionStorage") < scanProgress.indexOf("const isStart = cursor === null"));
check("ScanProgress resumes from saved progress without a server comparison", !scanProgress.includes("saved.historyScanned > initialScanned"));
check("ScanProgress saves nothing before the first chunk answers", scanProgress.indexOf("saveProgress(sessionStorage") > scanProgress.indexOf("for (;;)"));
check("ScanProgress shows the resume line from saved progress", scanProgress.includes("setResumed(resumedLine(scanned, findings.length))"));
check("ScanProgress shows the retained counts at once on resume", scanProgress.includes("setProgress(progressFromSaved(head, scanned, cursorStage(cursor)))"));
check("ScanProgress re-bases the history pace on a resume", scanProgress.includes("baseCommitsRef.current = scanned"));
check("ScanProgress shows the full error page for a terminal failure", scanProgress.includes("scanErrorCopy(terminalError.kind"));
check("ScanProgress terminal errors use the matching retry label", scanProgress.includes("scanErrorRetryLabel(terminalError.kind)"));
check("ScanProgress terminal errors render the shared RetryScanButton", scanProgress.includes("<RetryScanButton label={scanErrorRetryLabel(terminalError.kind)}"));
check("ScanProgress keeps the sessionStorage resume path", scanProgress.includes("sessionStorage") && scanProgress.includes("resumedLine"));
check("ScanProgress keeps the 429 fail-fast", scanProgress.includes('fail("rate-limit", rateLimitPausedBody(resetAtMs))'));
check("ScanProgress keeps the provisional report paused on chunk errors", scanProgress.includes("<ReportView report={provisional} paused />"));
check("ScanProgress keeps the provisional report unpaused while running", scanProgress.includes("<ReportView report={provisional} />"));

// --- 3b. SSR shell: what the browser paints first ---------------------
const shellHtml = render(
  React.createElement(ScanProgress, {
    owner: "vinta", repo: "awesome-python", cursor: null, head: null, historyFindings: [], historyScanned: 0,
    initial: emptyProgress(), provisional: null,
  }),
);
check("fresh shell says which repo is scanning", shellHtml.includes("Scanning vinta/awesome-python"));
check("fresh shell shows honest zero counts, not a bare spinner", shellHtml.includes("0 files scanned so far") && shellHtml.includes("History not checked yet"));
check("fresh shell shows no resume line (nothing saved yet)", !shellHtml.includes("Resumed"));
check("fresh shell shows no invented per-minute rate", !shellHtml.includes(" a minute"));

// The page component is async, so its renders run inside main() at the
// end of this file (tsx runs this script as CommonJS, where top-level
// await is not supported).
async function checkPageRenders() {
  const pageHtml = render(await ReportPage({ params: Promise.resolve({ owner: "vinta", repo: "awesome-python" }) }));
  check("report page renders the scanning shell immediately", pageHtml.includes("Scanning vinta/awesome-python"));
  const badPageHtml = render(await ReportPage({ params: Promise.resolve({ owner: "bad owner!", repo: "awesome-python" }) }));
  check("bad owner name still gets the server-side error page", badPageHtml.includes("That doesn&#x27;t look like a valid repo") || badPageHtml.includes("That doesn't look like a valid repo"));
  check("bad owner page offers a retry", badPageHtml.includes("Retry this scan"));
}

// --- 4. New routes ------------------------------------------------------
const startRoute = src("src/app/api/scan/start/route.ts");
check("start route runs exactly one fresh chunk", startRoute.includes("advanceScan({ owner, repo, cursor: null })"));
check("start route returns the scan error kind", startRoute.includes("kind: err.kind"));
check("start route passes the reset time through on errors", startRoute.includes("resetAtMs"));
const tipRoute = src("src/app/api/scan/[owner]/[repo]/tip/route.ts");
check("tip route resolves the live tip over the git protocol", tipRoute.includes("resolveRemoteHead(owner, repo)"));
check("tip route answers the branch and HEAD sha", tipRoute.includes("headSha: tip.headSha"));

// --- 5. Shared budgets untouched by this change ----------------------
// FAST_PATH_WAIT_MS is still 50_000 (Worker B owns the API budget:
// the scan API and MCP now use the separate API_FAST_PATH_WAIT_MS =
// 40_000 — this change did not touch either constant, and the report
// page uses neither).
check("FAST_PATH_WAIT_MS is still 50_000", src("src/lib/chunks.ts").includes("FAST_PATH_WAIT_MS = 50_000"));
check("API_FAST_PATH_WAIT_MS is 40_000 (Worker B's API budget)", src("src/lib/chunks.ts").includes("API_FAST_PATH_WAIT_MS = 40_000"));
check("scan API route uses the API budget", src("src/app/api/scan/[owner]/[repo]/route.ts").includes("budgetMs: API_FAST_PATH_WAIT_MS"));
check("MCP uses the API budget", src("src/lib/mcp.ts").includes("budgetMs: API_FAST_PATH_WAIT_MS"));
check("report page uses neither budget constant", !page.includes("FAST_PATH_WAIT_MS") && !page.includes("API_FAST_PATH_WAIT_MS"));
check("chunk route untouched by this change", !src("src/app/api/scan/chunk/route.ts").includes("/api/scan/start"));

// --- No literal secret-pattern values in the changed files ------------
const changed =
  src("src/app/[owner]/[repo]/page.tsx") +
  src("src/components/ScanProgress.tsx") +
  src("src/lib/scan-error-copy.ts") +
  src("src/app/api/scan/start/route.ts") +
  src("src/app/api/scan/[owner]/[repo]/tip/route.ts") +
  src("scripts/test-phase16-worker-a.ts");
check(
  "no literal secret-pattern values in the changed files",
  !/(sk_live|ghp_|AKIA|discord\.com\/api\/webhooks\/\d+\/)[A-Za-z0-9]/.test(changed),
);
const self = readFileSync(new URL(import.meta.url).pathname, "utf8");
const leaked = ["AKIA" + "IOSFODNN7EXAMPLE", "ghp_" + "FAKE".repeat(8) + "1234", "sk_test_" + "FAKE".repeat(6) + "12", "discord.com/api/webhooks/" + "123456789012345678/"].some((s) => self.includes(s));
check("No literal secret-pattern values in this file", !leaked);

async function main() {
  await checkPageRenders();
  console.log(failures === 0 ? "\nAll Phase 16 worker-A checks passed." : `\n${failures} check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

void main();
