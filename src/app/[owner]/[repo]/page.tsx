// Phase 4: every caller gets the full report — the site only scans
// public repos, so the detail is information already public in the
// repo. No login flow, no owner gate, no ?full flag.
// Phase 8: the scan runs as an async job. This page waits up to ~50 s
// for it (the fast path — a small repo renders in one request); if the
// job is still running, it renders live progress instead and the
// client polls until the job finishes, then reloads the finished
// report. No scan is ever killed for taking too long.
import { after } from "next/server";
import { FAST_PATH_WAIT_MS, getOrStartJob, waitForJob, type ScanJob } from "@/lib/jobs";
import { ScanError } from "@/lib/scan";
import { biggestProblem, explainScore, gradeBand, gradeWord } from "@/lib/score";
import McpSection from "@/components/McpSection";
import ScanProgress from "@/components/ScanProgress";
import ScoreDial from "@/components/ScoreDial";
import { DependenciesList, FrameworksList, PostureList, SecretsList, VulnerabilitiesList } from "@/components/ReportLists";
import type { FullReport } from "@/lib/types";

// Scan-on-demand page: never prerendered — each visit runs a live scan.
export const instant = false;
export const maxDuration = 60;

function ScoreCard({ report }: { report: FullReport }) {
  const band = gradeBand(report.grade);
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
            {biggestProblem({
              secrets: report.counts.secrets,
              vulnerabilities: report.counts.vulnerabilities,
              postureIssues: report.counts.postureIssues,
            })}
          </p>
          <p className="score-explain">{report.summary}</p>
        </div>
      </div>
      <p className="score-explain">
        {explainScore({
          score: report.score,
          grade: report.grade,
          secrets: report.counts.secrets,
          vulnerabilities: report.counts.vulnerabilities,
          postureIssues: report.counts.postureIssues,
        })}
      </p>
      <div className="stat-grid" role="list" aria-label="Scan counts">
        <div className={report.counts.secrets > 0 ? "stat stat-alert" : "stat"} role="listitem"><b>{report.counts.secrets}</b><span>possible leaked secrets</span></div>
        <div className="stat" role="listitem"><b>{report.counts.vulnerabilities}</b><span>dependency vulnerabilities</span></div>
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

/** Plain-English message for each way a scan can fail. The API carries
 *  the matching HTTP status; this page shows the same words. */
function errorCopy(err: unknown, owner: string, repo: string): { title: string; body: string } {
  if (err instanceof ScanError) {
    switch (err.kind) {
      case "not-found":
        return {
          title: `Couldn't find ${owner}/${repo}`,
          body: "We couldn't find that repo on GitHub, or it is private. GitSecure only scans public repos — check the spelling of the owner and repo names, and make sure the repo is public.",
        };
      case "private":
        return {
          title: `${owner}/${repo} is private`,
          body: "That repo is private, and GitSecure only scans public repos.",
        };
      case "rate-limit":
        return {
          title: "GitHub's request limit was hit",
          body: "Too many requests went to GitHub at once, so this scan couldn't run right now. Please try again in a few minutes.",
        };
      case "timeout":
        return {
          title: "GitHub took too long to answer",
          body: "A request to GitHub timed out, so this scan couldn't run right now. The scan itself has no time limit — try again in a bit.",
        };
      case "bad-format":
        return {
          title: "That doesn't look like a valid repo",
          body: "Owner and repo names can only use letters, numbers, dots, hyphens and underscores — check for typos or extra characters.",
        };
      default:
        return {
          title: `Couldn't scan ${owner}/${repo}`,
          body: "GitHub didn't answer as expected. Try again in a bit.",
        };
    }
  }
  return {
    title: `Couldn't scan ${owner}/${repo}`,
    body: "Something went wrong on our side. Try again in a bit.",
  };
}

export default async function ReportPage({
  params,
}: {
  params: Promise<{ owner: string; repo: string }>;
}) {
  const { owner, repo } = await params;

  let full: FullReport | null = null;
  let runningJob: ScanJob | null = null;
  try {
    const job = getOrStartJob(owner, repo);
    // Keep the job alive past this render on Vercel: after() runs
    // after the response is sent, inside the same invocation.
    after(async () => {
      await job.promise.catch(() => undefined);
    });
    const finished = await waitForJob(job, FAST_PATH_WAIT_MS);
    if (finished.status === "done" && finished.report) {
      full = finished.report;
    } else if (finished.status === "error" && finished.error) {
      throw new ScanError(
        finished.error.status,
        finished.error.kind as ScanError["kind"],
        finished.error.message,
      );
    } else {
      runningJob = finished;
    }
  } catch (err) {
    const { title, body } = errorCopy(err, owner, repo);
    return (
      <div>
        <p className="back-link"><a href="/">← Scan another repo</a></p>
        <h1>{title}</h1>
        <div className="card error-card" role="alert">
          <p>{body}</p>
          <p><a className="button-link" href="/">Scan another repo</a></p>
        </div>
      </div>
    );
  }

  // Still running after the fast-path wait: show honest live progress
  // and poll the job until it finishes, then reload the report.
  if (runningJob) {
    return <ScanProgress jobId={runningJob.id} owner={owner} repo={repo} initial={runningJob.progress} />;
  }
  if (!full) throw new Error("Unreachable: job neither done, errored, nor running.");

  const report: FullReport = full;

  return (
    <div className="report-hero">
      <p className="back-link"><a href="/">← Scan another repo</a></p>
      <h1>{owner}/{repo}</h1>

      <ScoreCard report={report} />

      {(
        <>
          <div className="card">
            <h2>Leaked secrets ({full.secrets.length})</h2>
            {full.secrets.length === 0 ? (
              <p>No leaked secrets were found in the files and recent history scanned.</p>
            ) : (
              <SecretsList secrets={full.secrets} owner={full.owner} repo={full.repo} branch={full.branch} />
            )}
          </div>

          <div className="card">
            <h2>Frameworks ({full.frameworks.length})</h2>
            {full.frameworks.length === 0 ? (
              <p>No frameworks were fingerprinted in this repo (Tiers 1–2: JS/TS, Python, Rust, Go, Ruby, PHP, Java/Kotlin, .NET).</p>
            ) : (
              <FrameworksList frameworks={full.frameworks} />
            )}
          </div>

          <div className="card">
            <h2>Dependencies ({full.dependencies.length})</h2>
            {full.dependencies.length === 0 ? (
              <p>No dependencies were found in this repo.</p>
            ) : (
              <DependenciesList dependencies={full.dependencies} />
            )}
          </div>

          <div className="card">
            <h2>Dependency vulnerabilities ({full.vulnerabilities.length})</h2>
            {full.vulnerabilities.length === 0 ? (
              <p>No known vulnerabilities were found in the dependencies checked.</p>
            ) : (
              <VulnerabilitiesList vulnerabilities={full.vulnerabilities} />
            )}
          </div>

          <div className="card">
            <h2>Security posture ({full.posture.length})</h2>
            {full.posture.length === 0 ? (
              <p>No posture issues were found in the basic MVP checks.</p>
            ) : (
              <PostureList posture={full.posture} />
            )}
          </div>
        </>
      )}

      <div className="card">
        <h2>About this scan</h2>
        <ul>
          {report.limits.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
        <p className="small">
          API: <a href={`/api/scan/${owner}/${repo}`}>full JSON report for this repo</a> — same detail as this page, no sign-in.
        </p>
      </div>

      <McpSection compact />

      <p><a className="button-link" href="/">Scan another repo</a></p>
    </div>
  );
}
