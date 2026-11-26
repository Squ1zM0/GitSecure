// Report view (Phase 9) — the finished (or provisional) report,
// rendered the same way whether the server produced it in one request
// or the browser assembled it chunk by chunk.
//
// "use client" so the chunk driver (ScanProgress) can swap the
// provisional HEAD report for the finished report without a page
// reload — a reload would re-run the server fast-path loop from
// scratch and throw away the resumed history progress. The server
// page renders this component too, so the first paint is identical
// either way.
//
// Phase 9: when `report.provisional` is set, the score counts HEAD
// secrets + posture only (no vulnerabilities yet) and the page says
// so in plain English next to the dial — a provisional score is never
// presented as finished.
"use client";

import { gradeBand, gradeWord } from "@/lib/score";
import ScoreDial, { adjustedExplainScore, adjustedVerdict, ScoreExplanation, type ScoreDetail } from "@/components/ScoreDial";
import RollAllButton from "@/components/RollAllButton";
import McpSection from "@/components/McpSection";
import { DependenciesList, FrameworksList, PostureList, SecretsList, VulnerabilitiesList } from "@/components/ReportLists";
import type { FullReport } from "@/lib/types";

function ScoreCard({ report, paused }: { report: FullReport; paused?: boolean }) {
  const band = gradeBand(report.grade);
  // Phase 12: the detail is required on a fresh report, but an older
  // cached report may not carry it — read it defensively so the hero
  // falls back to the Phase 7 wording instead of crashing.
  const detail: ScoreDetail | undefined = (report as { scoreDetail?: ScoreDetail }).scoreDetail;
  const counts = {
    secrets: report.counts.secrets,
    vulnerabilities: report.counts.vulnerabilities,
    postureIssues: report.counts.postureIssues,
  };
  return (
    <div className="card">
      <div className="score-hero">
        <ScoreDial score={report.score} grade={report.grade} />
        <div className="score-copy">
          <p>
            <span className={`grade-chip ${band}`}>Grade {report.grade} — {gradeWord(report.grade)}</span>
          </p>
          <p className="muted small">
            {report.owner}/{report.repo} · branch {report.branch} · commit <code className="inline">{String(report.commit).slice(0, 7)}</code>
          </p>
          <p className="verdict">
            {adjustedVerdict(detail, counts)}
          </p>
          <p className="score-explain">{report.summary}</p>
        </div>
        {/* "Roll all into report" (Freddy, 2026-11-26): the empty
          space at the top right of the hero card, next to the dial —
          one button that downloads the whole scan as Markdown. */}
        <RollAllButton report={report} paused={paused} />
      </div>
      <p className="score-explain">
        {adjustedExplainScore(report.score, report.grade, detail, counts)}
      </p>
      <ScoreExplanation detail={detail} />
      <div className="stat-grid" role="list" aria-label="Scan counts">
        <div className={report.counts.secrets > 0 ? "stat stat-alert" : "stat"} role="listitem"><b>{report.counts.secrets}</b><span>possible leaked secrets{report.counts.testKeySecrets > 0 ? ` — of which ${report.counts.testKeySecrets} look${report.counts.testKeySecrets === 1 ? "s" : ""} like test keys` : ""}</span></div>
        {/* Phase 16: on a provisional report the dependency check has
          not run yet (OSV runs at assemble time), so the tile must not
          present a 0 as a checked result — it says "not checked yet",
          agreeing with the progress card below it. */}
        {report.provisional ? (
          <div className="stat" role="listitem"><b>—</b><span>dependency vulnerabilities — not checked yet</span></div>
        ) : (
          <div className="stat" role="listitem"><b>{report.counts.vulnerabilities}</b><span>dependency vulnerabilities</span></div>
        )}
        <div className="stat" role="listitem"><b>{report.counts.frameworks}</b><span>frameworks detected</span></div>
        <div className="stat" role="listitem"><b>{report.counts.dependencies}</b><span>dependencies checked</span></div>
        <div className="stat" role="listitem"><b>{report.counts.postureIssues}</b><span>posture issues</span></div>
        <div className="stat" role="listitem"><b>{report.counts.filesScanned}</b><span>files scanned</span></div>
      </div>
      <p className="small scan-meta">
        Scanned {new Date(report.scannedAt).toLocaleString()} · History checked: {report.counts.historyCommitsScanned} commit{report.counts.historyCommitsScanned === 1 ? "" : "s"}, newest first.
      </p>
    </div>
  );
}

export default function ReportView({ report, paused }: { report: FullReport; paused?: boolean }) {
  return (
    <div className="report-hero">
      <p className="back-link"><a href="/">← Scan another repo</a></p>
      <h1>{report.owner}/{report.repo}</h1>

      {report.provisional ? (
        <div className="card" role="status" aria-live="polite">
          {paused ? (
            <p>
              <b>Provisional score — the current files are scanned, but history and dependency checks are paused — history and dependency checks stopped here.</b>{" "}
              The score counts what the current files show so far; it will update when the scan resumes and the rest finishes. Nothing below is half-reported — the lists show exactly what has been checked so far.
            </p>
          ) : (
            <p>
              <b>Provisional score — the current files are scanned, but history and dependency checks are still running.</b>{" "}
              The score counts what the current files show so far; it will update when the rest of the scan finishes. Nothing below is half-reported — the lists show exactly what has been checked so far.
            </p>
          )}
        </div>
      ) : null}

      <ScoreCard report={report} paused={paused} />

      <div className="card">
        <h2>Leaked secrets ({report.secrets.length})</h2>
        {report.secrets.length === 0 ? (
          <p>No leaked secrets were found in the files and recent history scanned.</p>
        ) : (
          <SecretsList secrets={report.secrets} owner={report.owner} repo={report.repo} branch={report.branch} />
        )}
      </div>

      <div className="card">
        <h2>Frameworks ({report.frameworks.length})</h2>
        {report.frameworks.length === 0 ? (
          <p>No frameworks were fingerprinted in this repo (Tiers 1–2: JS/TS, Python, Rust, Go, Ruby, PHP, Java/Kotlin, .NET).</p>
        ) : (
          <FrameworksList frameworks={report.frameworks} />
        )}
      </div>

      <div className="card">
        <h2>Dependencies ({report.dependencies.length})</h2>
        {report.dependencies.length === 0 ? (
          <p>No dependencies were found in this repo.</p>
        ) : (
          <DependenciesList dependencies={report.dependencies} />
        )}
      </div>

      <div className="card">
        <h2>Dependency vulnerabilities{report.provisional ? " (not checked yet)" : ` (${report.vulnerabilities.length})`}</h2>
        {report.provisional ? (
          // Phase 16: the OSV check runs at assemble time, so a
          // provisional report has no vulnerability count to show.
          // Saying "0" here while the progress card below said
          // "Dependencies not checked yet" was a contradiction —
          // the count must not render before the check completes.
          <p>Dependencies haven&apos;t been checked for known flaws yet — this section fills in when the scan finishes.</p>
        ) : report.vulnerabilities.length === 0 ? (
          <p>No known vulnerabilities were found in the dependencies checked.</p>
        ) : (
          <VulnerabilitiesList vulnerabilities={report.vulnerabilities} />
        )}
      </div>

      <div className="card">
        <h2>Security posture ({report.posture.length})</h2>
        {report.posture.length === 0 ? (
          <p>No posture issues were found in the basic MVP checks.</p>
        ) : (
          <PostureList posture={report.posture} />
        )}
      </div>

      <div className="card">
        <h2>About this scan</h2>
        <ul>
          {report.limits.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
        <p className="small">
          API: <a href={`/api/scan/${report.owner}/${report.repo}`}>full JSON report for this repo</a> — same detail as this page, no sign-in.
        </p>
      </div>

      <McpSection compact />

      <p><a className="button-link" href="/">Scan another repo</a></p>
    </div>
  );
}
