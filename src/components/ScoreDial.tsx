// Phase 7 — the score as a proper gauge, not a bare number.
//
// An SVG arc, 0–100, coloured by grade band (green A/B, amber C, red
// D/F) with the grade word right beside it — colour + label together,
// never colour alone. Pure presentation: score and grade come from
// computeScore unchanged.
//
// Phase 12 — the triage-weighted score explanation (Freddy's
// direction, 2026-11-26: an F for 34 test fixtures is a false alarm,
// so the score must reflect real risk). Test keys deduct nothing,
// uncertain findings deduct at half weight, genuine leaks at full
// weight (see ScoreDetail in src/lib/score.ts). The helpers below are
// pure presentation over that detail: they pick the real driver by
// deduction size, never present test keys as the biggest problem, and
// state the rule with the actual numbers. They take the detail as
// `ScoreDetail | undefined` and fall back to the Phase 7 helpers
// (biggestProblem / explainScore) when it is absent — an older cached
// report without scoreDetail renders exactly as before, never crashes.
import { biggestProblem, explainScore, gradeBand, gradeWord, type ScoreDetail } from "@/lib/score";

export type { ScoreDetail };

export type ScoreCounts = { secrets: number; vulnerabilities: number; postureIssues: number };

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

/** The test-key note: what happened to the secrets that did not count
 *  in full. Only speaks when there are NO genuine (full-weight)
 *  secrets — when a real leak exists, the explanation component states
 *  the full split instead. Empty when there is nothing to say (no
 *  detail, or every secret counted at full weight). */
export function testKeyNote(detail: ScoreDetail | undefined): string {
  if (!detail) return "";
  const { secretsExcluded: ex, secretsHalfWeight: half, secretsFullWeight: full } = detail;
  if (full > 0) return "";
  if (ex > 0 && half === 0) {
    return `The ${ex} possible leaked ${plural(ex, "secret", "secrets")} ${plural(ex, "looks", "all look")} like test ${plural(ex, "key", "keys")}, so ${plural(ex, "it does", "they do")} not count toward the score.`;
  }
  if (ex > 0 && half > 0) {
    return `The ${ex} look like test keys and do not count toward the score; the ${half} uncertain ${plural(half, "one counts", "ones count")} at half weight.`;
  }
  if (half > 0) {
    return `No genuine leaks were found — the ${half} uncertain ${plural(half, "secret counts", "secrets count")} at half weight until a human checks ${plural(half, "it", "them")}.`;
  }
  return "";
}

type DriverKind = "secrets" | "vulns" | "posture" | "unpinned" | "none";

/** The real driver: whichever component deducts the most points.
 *  Ties break in the order secrets, vulnerabilities, posture,
 *  unpinned (first wins). "none" when nothing deducts anything. */
function driverKind(detail: ScoreDetail): DriverKind {
  const ranked: { kind: DriverKind; points: number }[] = [
    { kind: "secrets", points: detail.secretsDeduction },
    { kind: "vulns", points: detail.vulnDeduction },
    { kind: "posture", points: detail.postureDeduction },
    { kind: "unpinned", points: detail.unpinnedDeduction },
  ];
  let best: { kind: DriverKind; points: number } = { kind: "none", points: 0 };
  for (const entry of ranked) {
    if (entry.points > best.points) best = entry;
  }
  return best.kind;
}

/** The driver as a "Biggest problem: …" core sentence (no trailing
 *  period — the caller adds it and the test-key note). With no detail
 *  this is unused; the caller falls back to biggestProblem instead. */
function verdictCore(detail: ScoreDetail, counts: ScoreCounts): string {
  switch (driverKind(detail)) {
    case "secrets":
      if (detail.secretsFullWeight > 0) {
        return `${detail.secretsFullWeight} genuine leaked ${plural(detail.secretsFullWeight, "secret", "secrets")} — rotate and remove these first`;
      }
      return `${detail.secretsHalfWeight} uncertain ${plural(detail.secretsHalfWeight, "secret", "secrets")} — counted at half weight; rotate ${plural(detail.secretsHalfWeight, "it", "them")} if ${plural(detail.secretsHalfWeight, "it turns", "they turn")} out to be real`;
    case "vulns":
      return `${counts.vulnerabilities} known ${plural(counts.vulnerabilities, "flaw", "flaws")} in dependencies — upgrade the affected packages`;
    case "posture":
      return `${counts.postureIssues} small security-hygiene ${plural(counts.postureIssues, "issue", "issues")} to fix`;
    case "unpinned":
      return "unpinned dependency versions — pin them to exact versions";
    case "none":
      return "";
  }
}

/** The hero verdict, Phase 12-aware. With a scoreDetail, the driver
 *  is picked by deduction size, so an all-test-key report never says
 *  "N leaked secrets — rotate and remove these first"; it names the
 *  real driver and says the test keys are excluded. Without one, the
 *  Phase 7 wording is used unchanged. */
export function adjustedVerdict(detail: ScoreDetail | undefined, counts: ScoreCounts): string {
  if (!detail) return biggestProblem(counts);
  const core = verdictCore(detail, counts);
  if (core === "") return "Nothing found to fix — this repo looks clean in this scan.";
  const note = testKeyNote(detail);
  return `Biggest problem: ${core}.${note ? ` ${note}` : ""}`;
}

/** The one-line explanation under the score, Phase 12-aware. Same
 *  driver logic as adjustedVerdict, in explainScore's phrasing. */
export function adjustedExplainScore(score: number, grade: string, detail: ScoreDetail | undefined, counts: ScoreCounts): string {
  if (!detail) return explainScore({ score, grade, ...counts });
  if (score >= 100) return "100 out of 100 (grade A) is a perfect score — nothing was found to fix in this scan.";
  let driver: string;
  switch (driverKind(detail)) {
    case "secrets":
      driver =
        detail.secretsFullWeight > 0
          ? `Most of the points lost come from ${detail.secretsFullWeight} genuine leaked ${plural(detail.secretsFullWeight, "secret", "secrets")} — rotating and removing those would raise the score the most.`
          : `Most of the points lost come from ${detail.secretsHalfWeight} uncertain ${plural(detail.secretsHalfWeight, "secret", "secrets")}, counted at half weight — checking ${plural(detail.secretsHalfWeight, "it", "them")} and rotating any real ${plural(detail.secretsHalfWeight, "one", "ones")} would raise the score.`;
      break;
    case "vulns":
      driver = `Most of the points lost come from ${counts.vulnerabilities} known ${plural(counts.vulnerabilities, "flaw", "flaws")} in dependencies — upgrading the affected packages would raise the score.`;
      break;
    case "posture":
      driver = `The points lost come from ${counts.postureIssues} small security-hygiene ${plural(counts.postureIssues, "issue", "issues")} — fixing those would raise the score.`;
      break;
    case "unpinned":
      driver = "Most of the points lost come from unpinned dependency versions — pinning them to exact versions would raise the score.";
      break;
    case "none":
      driver = "Only a few points were lost, from minor issues in the scan.";
      break;
  }
  const note = testKeyNote(detail);
  return `${score} out of 100 (grade ${grade}) is a ${gradeWord(grade)} score. ${driver}${note ? ` ${note}` : ""}`;
}

/** The score explanation, rendered next to the dial in the report
 *  hero. States the rule in plain English with the actual numbers
 *  from the detail: how many secrets were excluded as test keys, how
 *  many counted at half weight, how many at full weight — and BOTH
 *  scores, the adjusted score and the would-be score under the old
 *  full-weight rule, so the reader can see the test-key adjustment
 *  and verify it. Renders nothing when the detail is absent (older
 *  cached report) — the existing explainScore line is the fallback. */
export function ScoreExplanation({ detail }: { detail: ScoreDetail | undefined }) {
  if (!detail) return null;
  const total = detail.secretsExcluded + detail.secretsHalfWeight + detail.secretsFullWeight;
  const wouldBe = detail.wouldBeScore === detail.score
    ? `If every secret counted at full weight, the score would still be ${detail.score}.`
    : `If every secret counted at full weight, the score would be ${detail.wouldBeScore} instead of ${detail.score}.`;
  return (
    <p className="score-explain">
      How this score works: a secret that looks like an intentional test key does not count toward the score at all, an uncertain one counts at half weight, and a genuine leak counts in full.{" "}
      {total === 0
        ? "No secrets were found in this scan, so there was no test-key adjustment. "
        : `Of the ${total} possible leaked ${plural(total, "secret", "secrets")}, ${detail.secretsExcluded} ${plural(detail.secretsExcluded, "looks like a test key and is", "look like test keys and are")} excluded, ${detail.secretsHalfWeight} ${plural(detail.secretsHalfWeight, "is", "are")} uncertain and ${plural(detail.secretsHalfWeight, "counts", "count")} at half weight, and ${detail.secretsFullWeight} ${plural(detail.secretsFullWeight, "counts", "count")} at full weight. `}
      {wouldBe}
    </p>
  );
}

export default function ScoreDial({ score, grade }: { score: number; grade: string }) {
  const band = gradeBand(grade);
  const size = 168;
  const stroke = 13;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const frac = Math.max(0, Math.min(100, score)) / 100;
  return (
    <div className="score-dial" role="img" aria-label={`Security score ${score} out of 100, grade ${grade}, ${gradeWord(grade)}`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle className="dial-track" cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} />
        <circle
          className={`dial-${band}`}
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${(frac * c).toFixed(1)} ${c.toFixed(1)}`}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
        <text className="dial-value" x="50%" y="47%" textAnchor="middle">{score}</text>
        <text className={`dial-grade dial-${band}-text`} x="50%" y="64%" textAnchor="middle">Grade {grade}</text>
      </svg>
    </div>
  );
}
