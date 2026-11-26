// Phase 7 — the score as a proper gauge, not a bare number.
//
// An SVG arc, 0–100, coloured by grade band (green A/B, amber C, red
// D/F) with the grade word right beside it — colour + label together,
// never colour alone. Pure presentation: score and grade come from
// computeScore unchanged.
import { gradeBand, gradeWord } from "@/lib/score";

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
