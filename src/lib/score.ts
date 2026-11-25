// Score 0–100. Starts at 100, deducts per finding. Plain-English summary
// must never name files, lines, or secret fragments (public view is
// score + counts only).

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
  return `Scan complete. ${parts.join("; ")}. Full detail is available to the repo owner only.`;
}
