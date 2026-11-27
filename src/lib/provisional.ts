// Provisional HEAD report (Phase 9) — client-safe, imports only
// score.ts and types.ts, so the browser can build it from the saved
// HEAD partial while history is still streaming in.
//
// A provisional report is the HEAD chunk rendered as a full report
// shape: HEAD secrets + posture, no dependency vulnerabilities yet
// (the OSV check runs at assemble time), history counted so far.
// Its score WILL change when history findings and vulnerabilities land,
// so it always carries `provisional: true` and the page says so in
// plain English next to it. It is never presented as finished.

import { computeScore, plainSummary } from "./score";
import type { FullReport, HeadPartial, SecretFinding } from "./types";

function dedupe(secrets: SecretFinding[]): SecretFinding[] {
  const seen = new Set<string>();
  return secrets.filter((s) => {
    const key = `${s.type}:${s.file}:${s.line}:${s.fragment}:${s.commit}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function buildProvisionalReport(
  head: HeadPartial,
  historyFindings: SecretFinding[],
  historyScanned: number,
  historyComplete: boolean,
): FullReport {
  const secrets = dedupe([...head.secrets, ...historyFindings]);
  // Phase 10: HEAD findings are triaged in scanHead and history
  // findings at creation, so the provisional report already carries
  // the annotations — no import of the (server-only, node:crypto)
  // triage module here: this file must stay client-safe. The
  // finished report fills in any annotation missing from an older
  // client/cursor in assembleReport.
  const scoreDetail = computeScore({
    secrets,
    vulnerabilities: [],
    posture: head.posture,
    unpinnedCount: head.unpinnedCount,
  });
  const { score, grade } = scoreDetail;
  const limits: string[] = [
    head.filesScanned >= head.filesTotal
      ? `Scanned all ${head.filesTotal} files in the tree (binary, dist, node_modules and .next skipped — generated/vendored paths, not source files).`
      : `Fetched ${head.filesScanned} of ${head.filesTotal} files in the tree — ${head.filesTotal - head.filesScanned} could not be fetched from GitHub, so they were not scanned.`,
    historyComplete
      ? `History checked: ${historyScanned} commit${historyScanned === 1 ? "" : "s"}, newest first.`
      : `History still scanning: ${historyScanned} commit${historyScanned === 1 ? "" : "s"} checked so far, newest first — older commits are still being checked.`,
    "Dependency flaws are still being checked — no vulnerability count yet.",
    "Public repos only. No secret is ever stored after the scan finishes, logged, or shown in full.",
  ];
  // Phase 11: usage is plain data on the finding, so passing it
  // through needs no import — and the history-only note is a pure
  // data check on the rendered findings, so this file stays
  // client-safe (no triage import).
  if (secrets.some((f) => f.usage?.historyOnly === true)) {
    limits.push("For secrets found in history, usage (whether anything still references the key) was checked against the current files only — the old commit's files are gone, so a reference that existed then but not now is not counted.");
  }
  if (head.treeTruncated) {
    limits.push("GitHub returned a truncated file tree — some files were not scanned. The tree was too large for GitHub to return in one response.");
  }
  if (head.tarballFallback) {
    limits.push("Tarball download was unavailable, so files were fetched one by one instead — same files, just slower.");
  }
  return {
    kind: "full",
    repo: head.repo,
    owner: head.owner,
    branch: head.branch,
    commit: head.headSha,
    score,
    grade,
    scoreDetail,
    counts: {
      secrets: secrets.length,
      testKeySecrets: secrets.filter((s) => s.triage?.verdict === "likely-test-key").length,
      vulnerabilities: 0,
      frameworks: head.frameworks.length,
      dependencies: head.dependencies.length,
      postureIssues: head.posture.length,
      filesScanned: head.filesScanned,
      historyCommitsScanned: historyScanned,
    },
    summary: plainSummary({
      secrets: secrets.length,
      vulnerabilities: 0,
      postureIssues: head.posture.length,
      frameworks: head.frameworks.length,
      secretsByVerdict: { genuine: secrets.filter((s) => s.triage?.verdict === "likely-genuine-leak" || !s.triage).length, uncertain: secrets.filter((s) => s.triage?.verdict === "uncertain").length, test: secrets.filter((s) => s.triage?.verdict === "likely-test-key").length },
      // Phase 15 (finding 5): a provisional report must never claim
      // the scan is complete — its summary starts "So far: ".
      provisional: true,
    }),
    scannedAt: new Date().toISOString(),
    historyDepth: "Full history, newest first.",
    limits,
    secrets,
    frameworks: head.frameworks,
    dependencies: head.dependencies,
    vulnerabilities: [],
    posture: head.posture,
    provisional: true,
  };
}
