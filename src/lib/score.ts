// Score 0–100. Starts at 100, deducts per finding. Plain-English summary
// must never name files, lines, or secret fragments (the full report
// shows them; the summary never does).

import type { PostureIssue, SecretFinding, Severity, Vulnerability } from "./types";

const SECRET_DEDUCTION: Record<Severity, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
const VULN_DEDUCTION: Record<Severity, number> = { critical: 15, high: 10, medium: 5, low: 2, info: 0 };
const POSTURE_DEDUCTION: Record<Severity, number> = { critical: 15, high: 10, medium: 5, low: 2, info: 0 };

export function computeScore(args: { secrets: SecretFinding[]; vulnerabilities: Vulnerability[]; posture: PostureIssue[]; unpinnedCount: number }): { score: number; grade: string } {
  let score = 100;
  for (const s of args.secrets) score -= SECRET_DEDUCTION[s.severity] ?? 0;
  for (const v of args.vulnerabilities) score -= VULN_DEDUCTION[v.severity] ?? 0;
  for (const p of args.posture) score -= POSTURE_DEDUCTION[p.severity] ?? 0;
  score -= Math.min(args.unpinnedCount * 2, 10);
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { score, grade };
}

export function plainSummary(args: { secrets: number; vulnerabilities: number; postureIssues: number; frameworks: number }): string {
  const parts: string[] = [];
  if (args.secrets > 0) parts.push(`${args.secrets} possible leaked secret${args.secrets === 1 ? "" : "s"} found — rotate and remove these first`);
  else parts.push("no leaked secrets were found in the files scanned");
  if (args.vulnerabilities > 0) parts.push(`${args.vulnerabilities} known vulnerabilit${args.vulnerabilities === 1 ? "y" : "ies"} in dependencies`);
  if (args.postureIssues > 0) parts.push(`${args.postureIssues} security hygiene issue${args.postureIssues === 1 ? "" : "s"} to fix`);
  if (args.frameworks > 0) parts.push(`${args.frameworks} framework${args.frameworks === 1 ? "" : "s"} fingerprinted`);
  return `Scan complete. ${parts.join("; ")}. The full detail is in this report — no sign-in needed.`;
}

/** One plain line under the score: what the number means, and what
 *  would raise it. Never names files, lines, or secret fragments. */
export function explainScore(args: { score: number; grade: string; secrets: number; vulnerabilities: number; postureIssues: number }): string {
  const { score, grade } = args;
  const gradeWord = grade === "A" ? "excellent" : grade === "B" ? "good" : grade === "C" ? "fair" : grade === "D" ? "poor" : "needs urgent attention";
  if (score >= 100) return "100 out of 100 (grade A) is a perfect score — nothing was found to fix in this scan.";
  let driver: string;
  if (args.secrets > 0) {
    driver = `The biggest problem is ${args.secrets} possible leaked secret${args.secrets === 1 ? "" : "s"} — rotating and removing those would raise the score the most.`;
  } else if (args.vulnerabilities > 0) {
    driver = `Most of the points lost come from ${args.vulnerabilities} known flaw${args.vulnerabilities === 1 ? "" : "s"} in dependencies — upgrading the affected packages would raise the score.`;
  } else if (args.postureIssues > 0) {
    driver = `The points lost come from ${args.postureIssues} small security-hygiene issue${args.postureIssues === 1 ? "" : "s"} — fixing those would raise the score.`;
  } else {
    driver = "Only a few points were lost, from minor issues in the scan.";
  }
  return `${score} out of 100 (grade ${grade}) is a ${gradeWord} score. ${driver}`;
}
