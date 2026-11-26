// Score 0–100. Starts at 100, deducts per finding. Plain-English summary
// must never name files, lines, or secret fragments (the full report
// shows them; the summary never does).

import type { PostureIssue, SecretFinding, Severity, TriageVerdict, Vulnerability } from "./types";

const SECRET_DEDUCTION: Record<Severity, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
const VULN_DEDUCTION: Record<Severity, number> = { critical: 15, high: 10, medium: 5, low: 2, info: 0 };
const POSTURE_DEDUCTION: Record<Severity, number> = { critical: 15, high: 10, medium: 5, low: 2, info: 0 };

/** Phase 12 — triage-weighted secrets deduction (Freddy's direction,
 *  2026-11-26: an F for 34 test fixtures is a false alarm, so the score
 *  must reflect real risk). A likely-test-key finding deducts nothing,
 *  an uncertain finding deducts at half weight, a likely-genuine-leak
 *  finding deducts at full weight, and a finding with no triage
 *  annotation deducts at full weight — a test key is never assumed
 *  without evidence. Phase 10's "triage never changes the score" rule
 *  is overturned by this phase. */
export function triageWeight(verdict: TriageVerdict | undefined): number {
  if (verdict === "likely-test-key") return 0;
  if (verdict === "uncertain") return 0.5;
  return 1;
}

/** The full scoring breakdown. `secretsFullWeight` /
 *  `secretsHalfWeight` / `secretsExcluded` count FINDINGS, not points.
 *  `wouldBeScore` is the score the old (Phase 10) rule would have
 *  given the same input — every secret at full weight, same other
 *  components — clamped 0–100. The score and the sections shown in a
 *  report are always computed from the same triage annotations, so
 *  they can never disagree. */
export interface ScoreDetail {
  score: number;
  grade: string;
  secretsDeduction: number;
  secretsFullWeight: number;
  secretsHalfWeight: number;
  secretsExcluded: number;
  wouldBeScore: number;
  vulnDeduction: number;
  postureDeduction: number;
  unpinnedDeduction: number;
}

export function computeScore(args: { secrets: SecretFinding[]; vulnerabilities: Vulnerability[]; posture: PostureIssue[]; unpinnedCount: number }): ScoreDetail {
  let secretsWeighted = 0;
  let secretsFull = 0;
  let secretsFullWeight = 0;
  let secretsHalfWeight = 0;
  let secretsExcluded = 0;
  for (const s of args.secrets) {
    const deduction = SECRET_DEDUCTION[s.severity] ?? 0;
    secretsFull += deduction;
    const weight = triageWeight(s.triage?.verdict);
    if (weight === 0) secretsExcluded++;
    else if (weight === 0.5) secretsHalfWeight++;
    else secretsFullWeight++;
    secretsWeighted += deduction * weight;
  }
  const secretsDeduction = Math.round(secretsWeighted);
  let vulnDeduction = 0;
  for (const v of args.vulnerabilities) vulnDeduction += VULN_DEDUCTION[v.severity] ?? 0;
  let postureDeduction = 0;
  for (const p of args.posture) postureDeduction += POSTURE_DEDUCTION[p.severity] ?? 0;
  const unpinnedDeduction = Math.min(args.unpinnedCount * 2, 10);
  const clamp = (n: number) => Math.max(0, Math.min(100, n));
  const score = clamp(100 - secretsDeduction - vulnDeduction - postureDeduction - unpinnedDeduction);
  const wouldBeScore = clamp(100 - secretsFull - vulnDeduction - postureDeduction - unpinnedDeduction);
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { score, grade, secretsDeduction, secretsFullWeight, secretsHalfWeight, secretsExcluded, wouldBeScore, vulnDeduction, postureDeduction, unpinnedDeduction };
}

/* Phase 12: triage-aware. When the caller passes secretsByVerdict, the
 * summary names the split instead of presenting test keys as live leaks:
 * a report whose secrets are all test keys must not say "rotate and
 * remove these first". Without the breakdown it falls back to the old
 * wording (older callers / untriaged reports).
 * Phase 15 (finding 5): a provisional report must never claim the scan
 * is complete — pass provisional: true and the summary starts "So far: "
 * instead of "Scan complete. ". Finding 7: the zero-secrets part is
 * capitalised ("No leaked secrets…"), it opens a sentence. */
export function plainSummary(args: { secrets: number; vulnerabilities: number; postureIssues: number; frameworks: number; secretsByVerdict?: { genuine: number; uncertain: number; test: number }; provisional?: boolean }): string {
  const parts: string[] = [];
  const v = args.secretsByVerdict;
  if (args.secrets > 0 && v) {
    if (v.genuine > 0) {
      parts.push(`${v.genuine} possible leaked secret${v.genuine === 1 ? "" : "s"} found — rotate and remove these first`);
      if (v.test > 0) parts.push(`${v.test} look like test keys and do not count toward the score`);
      if (v.uncertain > 0) parts.push(`${v.uncertain} need${v.uncertain === 1 ? "s" : ""} a human check and count at half weight`);
    } else if (v.uncertain > 0) {
      parts.push(`${args.secrets} possible leaked secret${args.secrets === 1 ? "" : "s"} found — ${v.test} look like test keys and ${v.uncertain} need${v.uncertain === 1 ? "s" : ""} a human check; none is a confirmed leak`);
    } else {
      parts.push(`${args.secrets} possible leaked secret${args.secrets === 1 ? "" : "s"} found — all look like test keys, so none count toward the score`);
    }
  } else if (args.secrets > 0) parts.push(`${args.secrets} possible leaked secret${args.secrets === 1 ? "" : "s"} found — rotate and remove these first`);
  else parts.push("No leaked secrets were found in the files scanned");
  if (args.vulnerabilities > 0) parts.push(`${args.vulnerabilities} known vulnerabilit${args.vulnerabilities === 1 ? "y" : "ies"} in dependencies`);
  if (args.postureIssues > 0) parts.push(`${args.postureIssues} security hygiene issue${args.postureIssues === 1 ? "" : "s"} to fix`);
  if (args.frameworks > 0) parts.push(`${args.frameworks} framework${args.frameworks === 1 ? "" : "s"} fingerprinted`);
  return `${args.provisional ? "So far: " : "Scan complete. "}${parts.join("; ")}. The full detail is in this report — no sign-in needed.`;
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
  return `${score} out of 100 (grade ${grade}) is ${gradeWordWithArticle(grade)} score. ${driver}`;
}

/* Phase 7 — presentation helpers only. Scoring is untouched: these
 * map the existing grade to a colour band (colour + label together,
 * never colour alone) and pull the one-sentence verdict — the biggest
 * problem — out of explainScore's driver for the report hero. */
export type GradeBand = "good" | "fair" | "poor";

export function gradeBand(grade: string): GradeBand {
  if (grade === "A" || grade === "B") return "good";
  if (grade === "C") return "fair";
  return "poor";
}

export function gradeWord(grade: string): string {
  return grade === "A" ? "excellent" : grade === "B" ? "good" : grade === "C" ? "fair" : grade === "D" ? "poor" : "needs urgent attention";
}

/** The grade word with its article — "an excellent" for A, "a good"
 *  for B, and so on. Phase 16: both score-explanation templates
 *  hard-coded "a", which rendered "is a excellent score" for grade A. */
export function gradeWordWithArticle(grade: string): string {
  const word = gradeWord(grade);
  return /^[aeiou]/i.test(word) ? `an ${word}` : `a ${word}`;
}

/** The hero verdict: the single biggest problem, in one sentence. */
export function biggestProblem(args: { secrets: number; vulnerabilities: number; postureIssues: number }): string {
  if (args.secrets > 0) {
    return `Biggest problem: ${args.secrets} possible leaked secret${args.secrets === 1 ? "" : "s"} — rotate and remove these first.`;
  }
  if (args.vulnerabilities > 0) {
    return `Biggest problem: ${args.vulnerabilities} known flaw${args.vulnerabilities === 1 ? "" : "s"} in dependencies — upgrade the affected packages.`;
  }
  if (args.postureIssues > 0) {
    return `Biggest problem: ${args.postureIssues} small security-hygiene issue${args.postureIssues === 1 ? "" : "s"} to fix.`;
  }
  return "Nothing found to fix — this repo looks clean in this scan.";
}
