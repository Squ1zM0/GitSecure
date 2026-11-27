// Phase 15 worker A - scan resilience and honest progress.
// Run: npm run test:resilience-phase15
//
// Covers the audit findings this worker fixed (see
// test-results/phase15-ux-audit.md):
//   1. Page-level error states offer a "Retry this scan" button that
//      restarts the same repo's scan (not just a link home).
//   3a. When the chunk driver errors, the provisional report below
//       the error card says the checks are PAUSED, never "still
//       running" (ReportView `paused` prop, wired in ScanProgress).
//   3b. The chunk-error card names the failure reason (rate limit vs
//       network vs other) and the progress reached (files / commits /
//       secrets so far) - the driver already holds those numbers.
//   5. Provisional reports say "So far: ", never "Scan complete."
//      (functional check via buildProvisionalReport; the unit checks
//      live in test-score-phase12.ts).
//   7. Zero-secrets summary capitalised ("No leaked secrets…").
//
// The chunk-driver behaviour (HEAD timeout → partial cursor) is
// proved in test-cursor-phase9.ts section 9 with a mocked fetch;
// this script proves the UI wiring around it. Source checks read the
// shipped files; the functional check builds a real provisional
// report from a synthetic HEAD partial (no network).
//
// No literal secret-pattern values anywhere in this file
// (grep-verified; see the check at the end).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { buildProvisionalReport } from "../src/lib/provisional";
import { parseResetAtMs, rateLimitBody, rateLimitPausedBody, resetMinutes, resetPhrase } from "../src/lib/rate-limit";
import type { HeadPartial } from "../src/lib/types";

const ROOT = join(import.meta.dirname, "..");
const src = (rel: string) => readFileSync(join(ROOT, rel), "utf8");

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` - ${extra}` : ""}`);
  if (!ok) failures++;
}

// --- 1. "Retry this scan" on the page-level error states. ---
const page = src("src/app/[owner]/[repo]/page.tsx");
const retryButton = src("src/components/RetryScanButton.tsx");
check("page error state renders a Retry this scan button", page.includes("RetryScanButton"));
check("RetryScanButton is a client component that reloads the same scan", retryButton.includes('"use client"') && retryButton.includes("window.location.reload()"));
check("RetryScanButton says 'Retry this scan'", retryButton.includes("Retry this scan"));
check("page error state still offers 'Scan another repo' alongside", page.includes("Scan another repo"));

// --- 3a. Paused provisional banner. ---
const reportView = src("src/components/ReportView.tsx");
check("ReportView accepts a paused prop", /paused\?: boolean/.test(reportView));
check(
  "paused banner says history and dependency checks stopped here",
  reportView.includes("paused - history and dependency checks stopped here"),
);
check(
  "running banner still says 'still running' when not paused",
  reportView.includes("history and dependency checks are still running"),
);
const scanProgress = src("src/components/ScanProgress.tsx");
check("ScanProgress error state renders the provisional report paused", scanProgress.includes("<ReportView report={provisional} paused />"));
check("ScanProgress running state renders the provisional report unpaused", scanProgress.includes("<ReportView report={provisional} />"));

// --- 3b. Chunk-error card: reason + progress reached. ---
check("chunk-error copy distinguishes the rate-limit reason", scanProgress.includes("GitHub's request limit was hit, so the scan paused here"));
check("chunk-error copy distinguishes the network reason", scanProgress.includes("The scan couldn't be reached - check your connection"));
check("chunk-error copy keeps the generic reason for other failures", scanProgress.includes("GitHub didn't answer as expected. Try again in a bit"));
check("a 429 fails fast instead of burning three retries", scanProgress.includes('fail("rate-limit", rateLimitPausedBody(resetAtMs))'));
check("chunk-error card shows files scanned so far", scanProgress.includes("files scanned") && scanProgress.includes("So far:"));
check("chunk-error card shows history commits checked so far", scanProgress.includes("history commits checked"));
check("chunk-error card shows secrets found so far", scanProgress.includes("found so far"));
check("chunk-error card keeps 'Retry from where it left off'", scanProgress.includes("Retry from where it left off"));

// --- 5 + 7. Provisional report wording (functional). ---
const head: HeadPartial = {
  owner: "fake-owner", repo: "fake-repo", branch: "main", headSha: "abc1234",
  filesScanned: 3, filesTotal: 3, treeTruncated: false, tarballFallback: false,
  secrets: [], frameworks: [], dependencies: [], posture: [], unpinnedCount: 0,
  historyMethod: "git", retainedIncomplete: false,
};
const provisional = buildProvisionalReport(head, [], 0, false);
check(
  "provisional report summary says 'So far: ', never 'Scan complete.'",
  provisional.summary.startsWith("So far: ") && !provisional.summary.includes("Scan complete"),
  provisional.summary,
);
check(
  "provisional zero-secrets summary is capitalised",
  provisional.summary.includes("No leaked secrets were found in the files scanned"),
  provisional.summary,
);
check("provisional report is still flagged provisional", provisional.provisional === true);

// --- Rate-limit recovery (Freddy's live dead-end, Phase 15 add-on). ---
// The page he hit only offered "Scan another repo" and no sense of
// the wait. The fix: a "Try this scan again" button (same reload
// mechanism as "Retry this scan") plus honest reset wording -
// "resets in about N minutes" when GitHub's response said when,
// "resets within the hour" when it did not, never an invented
// countdown. No GITHUB_TOKEN anywhere in this path (standing ruling).
const NOW = 1_800_000_000_000; // fixed clock for the unit checks
const headersOf = (entries: Record<string, string>) => ({
  get: (name: string) => entries[name.toLowerCase()] ?? null,
});
check(
  "reset time parses from x-ratelimit-reset (epoch seconds)",
  parseResetAtMs(headersOf({ "x-ratelimit-reset": String(Math.floor(NOW / 1000) + 600) }), NOW) === NOW + 600_000,
);
check(
  "reset time parses from retry-after (seconds)",
  parseResetAtMs(headersOf({ "retry-after": "120" }), NOW) === NOW + 120_000,
);
check(
  "earliest of retry-after / x-ratelimit-reset wins",
  parseResetAtMs(headersOf({ "retry-after": "120", "x-ratelimit-reset": String(Math.floor(NOW / 1000) + 600) }), NOW) === NOW + 120_000,
);
check("no reset headers → null (unknown, never invented)", parseResetAtMs(headersOf({}), NOW) === null);
check("a reset time in the past → null (clock skew is not a countdown)", parseResetAtMs(headersOf({ "x-ratelimit-reset": String(Math.floor(NOW / 1000) - 60) }), NOW) === null);
check("garbage header values → null", parseResetAtMs(headersOf({ "retry-after": "soon", "x-ratelimit-reset": "yesterday" }), NOW) === null);
check("reset minutes round up (61 s → 2)", resetMinutes(NOW + 61_000, NOW) === 2);
check("reset minutes are at least 1", resetMinutes(NOW + 1_000, NOW) === 1);
check("reset minutes unknown → null", resetMinutes(null, NOW) === null);
check("reset phrase with a known time names the minutes", resetPhrase(NOW + 12 * 60_000, NOW) === "resets in about 12 minutes");
check("reset phrase singular minute", resetPhrase(NOW + 60_000, NOW) === "resets in about 1 minute");
check("reset phrase without a known time is hourly, no countdown", resetPhrase(null, NOW) === "resets within the hour");
check(
  "page rate-limit body names the wait when known",
  rateLimitBody(NOW + 12 * 60_000, NOW).includes("resets in about 12 minutes") && rateLimitBody(NOW + 12 * 60_000, NOW).startsWith("Too many requests went to GitHub at once"),
  rateLimitBody(NOW + 12 * 60_000, NOW),
);
check(
  "page rate-limit body falls back to hourly when unknown",
  rateLimitBody(null, NOW).includes("resets within the hour"),
  rateLimitBody(null, NOW),
);
check(
  "chunk rate-limit body names the wait and the resume point",
  rateLimitPausedBody(NOW + 12 * 60_000, NOW).includes("resets in about 12 minutes") && rateLimitPausedBody(NOW + 12 * 60_000, NOW).includes("picks up from the last finished chunk"),
  rateLimitPausedBody(NOW + 12 * 60_000, NOW),
);
check(
  "rate-limit copy never proposes a token (standing ruling)",
  !/token/i.test(rateLimitBody(NOW + 12 * 60_000, NOW)) && !/token/i.test(rateLimitPausedBody(NOW + 12 * 60_000, NOW)) && !/token/i.test(rateLimitBody(null, NOW)),
);
// Phase 16: the error page moved out of the report page (which renders
// the progress shell immediately now) into the shared error-copy module,
// shown by ScanProgress when a scan fails before any progress. The
// words are unchanged - only their home moved.
const errorCopySrc = src("src/lib/scan-error-copy.ts");
check("scan error copy uses the honest reset body for rate limits", errorCopySrc.includes("rateLimitBody(resetAtMs"));
check("ScanProgress terminal errors use the shared error copy", scanProgress.includes("scanErrorCopy(terminalError.kind"));
check("rate-limit error offers 'Try this scan again'", errorCopySrc.includes('"Try this scan again"'));
check("other errors keep 'Retry this scan'", errorCopySrc.includes('"Retry this scan"'));
check("ScanProgress terminal errors use the matching retry label", scanProgress.includes("scanErrorRetryLabel(terminalError.kind)"));
check("RetryScanButton accepts a label prop", src("src/components/RetryScanButton.tsx").includes("label"));
const chunkRoute = src("src/app/api/scan/chunk/route.ts");
check("chunk route passes the reset time through on errors", chunkRoute.includes("resetAtMs"));
const scanRoute = src("src/app/api/scan/[owner]/[repo]/route.ts");
check("scan API route passes the reset time through on errors", scanRoute.includes("resetAtMs"));
check("scan.ts captures the reset time from GitHub's rate-limit response", src("src/lib/scan.ts").includes("parseResetAtMs(res.headers)"));
check("ScanProgress reads the reset time from a 429 body", scanProgress.includes("resetAtMs") && scanProgress.includes("rateLimitPausedBody(resetAtMs)"));

// --- No literal secret-pattern values in this file ---
const self = readFileSync(new URL(import.meta.url).pathname, "utf8");
const leaked = ["AKIA" + "IOSFODNN7EXAMPLE", "ghp_" + "FAKE".repeat(8) + "1234", "sk_test_" + "FAKE".repeat(6) + "12", "discord.com/api/webhooks/" + "123456789012345678/"].some((s) => self.includes(s));
check("No literal secret-pattern values in this file", !leaked);

console.log(failures === 0 ? "\nAll Phase 15 resilience tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
