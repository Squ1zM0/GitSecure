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
  const { score, grade } = computeScore({
    secrets,
    vulnerabilities: [],
    posture: head.posture,
    unpinnedCount: head.unpinnedCount,
  });
  const limits: string[] = [
    head.filesScanned >= head.filesTotal
      ? `Scanned all ${head.filesTotal} files in the tree (binary, dist, node_modules and .next skipped — generated/vendored paths, not source files).`
      : `Fetched ${head.filesScanned} of ${head.filesTotal} files in the tree — ${head.filesTotal - head.filesScanned} could not be fetched from GitHub, so they were not scanned.`,
    historyComplete
      ? `History checked: ${historyScanned} commit${historyScanned === 1 ? "" : "s"}, newest first.`
      : `History still scanning: ${historyScanned} commit${historyScanned === 1 ? "" : "s"} checked so far, newest first — older commits are still being checked.`,
    "Dependency flaws are still being checked — no vulnerability count yet.",
    "Public repos only. No secret is ever stored, logged, or shown in full.",
  ];
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
    counts: {
      secrets: secrets.length,
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
