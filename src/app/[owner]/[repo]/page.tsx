import { canViewFull, isOAuthConfigured, isOwnerModeEnabled } from "@/lib/owner";
import { scanRepoWithTimeout, ScanError, toPublicReport } from "@/lib/scan";
import { explainScore } from "@/lib/score";
import McpSection from "@/components/McpSection";
import type { FullReport, PublicReport } from "@/lib/types";

// Scan-on-demand page: never prerendered — each visit runs a live scan.
export const instant = false;
export const maxDuration = 60;

function ScoreCard({ report }: { report: PublicReport | FullReport }) {
  return (
    <div className="card">
      <div className="score-row">
        <div className="score">{report.score}</div>
        <div>
          <span className="grade">Grade {report.grade}</span>
          <p className="muted small">
            {report.owner}/{report.repo} · branch {report.branch} · commit <code className="inline">{String(report.commit).slice(0, 7)}</code>
          </p>
        </div>
      </div>
      <p>{report.summary}</p>
      <p>
        {explainScore({
          score: report.score,
          grade: report.grade,
          secrets: report.counts.secrets,
          vulnerabilities: report.counts.vulnerabilities,
          postureIssues: report.counts.postureIssues,
        })}
      </p>
      <div className="counts">
        <div className="count"><b>{report.counts.secrets}</b><span>possible leaked secrets</span></div>
        <div className="count"><b>{report.counts.vulnerabilities}</b><span>dependency vulnerabilities</span></div>
        <div className="count"><b>{report.counts.frameworks}</b><span>frameworks detected</span></div>
        <div className="count"><b>{report.counts.dependencies}</b><span>dependencies checked</span></div>
        <div className="count"><b>{report.counts.postureIssues}</b><span>posture issues</span></div>
        <div className="count"><b>{report.counts.filesScanned}</b><span>files scanned</span></div>
      </div>
      <p className="small">
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
          title: "The scan took too long",
          body: "The scan was stopped because it ran past the time limit. Very large repos can take a while — try again, or try a smaller repo.",
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
  searchParams,
}: {
  params: Promise<{ owner: string; repo: string }>;
  searchParams: Promise<{ full?: string }>;
}) {
  const { owner, repo } = await params;
  const sp = await searchParams;
  const wantsFull = sp.full === "1";
  const ownerMode = isOwnerModeEnabled();
  const oauthConfigured = isOAuthConfigured();
  const { allowed: isOwner, login: signedInAs } = await canViewFull(owner);

  let full: FullReport;
  try {
    full = await scanRepoWithTimeout(owner, repo);
  } catch (err) {
    const { title, body } = errorCopy(err, owner, repo);
    return (
      <div>
        <p><a href="/">← Scan another repo</a></p>
        <h1>{title}</h1>
        <div className="card">
          <p>{body}</p>
          <p><a className="button-link" href="/">Scan another repo</a></p>
        </div>
      </div>
    );
  }

  const showFull = wantsFull && isOwner;
  const report: PublicReport | FullReport = showFull ? full : toPublicReport(full);

  return (
    <div>
      <p><a href="/">← Scan another repo</a></p>
      <h1>{owner}/{repo}</h1>

      {!showFull && (
        <div className="banner amber" role="note">
          <b>Public view — score and counts only.</b> Full detail (file names, line numbers, redacted
          secret fragments, framework versions, vulnerability IDs) is available to the repo owner only.
          {oauthConfigured ? (
            signedInAs ? (
              <> You are signed in as <b>{signedInAs}</b>, which does not match this repo&apos;s owner. <a href="/api/auth/signout">Sign out</a> to switch accounts.</>
            ) : (
              <> Owners: <a href={`/api/auth/signin?callbackUrl=/${owner}/${repo}?full=1`}>sign in with GitHub</a> to view the full detail for this repo.</>
            )
          ) : (
            <> Owner verification is not live yet on this deployment — the GitHub OAuth App is not configured (see README). The full view is available in local/dev owner mode only.</>
          )}
        </div>
      )}
      {showFull && (
        <div className="banner green" role="note">
          <b>Owner view{signedInAs ? <> — signed in as {signedInAs}</> : " (local/dev owner mode)"}.</b>{" "}
          {ownerMode && !signedInAs
            ? "This deployment has local/dev owner mode enabled. Production owner verification via GitHub OAuth is still to be wired up — do not treat this banner as proof of ownership."
            : "Full detail is shown because the signed-in GitHub account matches this repo's owner."}{" "}
          <a href="/api/auth/signout">Sign out</a>
        </div>
      )}

      <ScoreCard report={report} />

      {showFull && (
        <>
          <div className="card">
            <h2>Leaked secrets ({full.secrets.length})</h2>
            {full.secrets.length === 0 ? (
              <p>No leaked secrets were found in the files and recent history scanned.</p>
            ) : (
              full.secrets.map((s) => (
                <div className="finding" key={s.id}>
                  <p><span className={`pill ${s.severity}`}>{s.severity}</span><b>{s.title}</b> <span className="muted">· {s.confidence} confidence</span></p>
                  <p>{s.plainEnglish}</p>
                  <p className="small"><code className="inline">{s.file}:{s.line}</code> · commit <code className="inline">{s.commit ?? "HEAD"}</code> · fragment <code className="inline">{s.fragment}</code> (redacted — never the full secret)</p>
                  <p><b>Fix:</b> {s.fix}</p>
                </div>
              ))
            )}
          </div>

          <div className="card">
            <h2>Frameworks ({full.frameworks.length})</h2>
            {full.frameworks.length === 0 ? (
              <p>No frameworks were fingerprinted in this repo (Tiers 1–2: JS/TS, Python, Rust, Go, Ruby, PHP, Java/Kotlin, .NET).</p>
            ) : (
              <ul>
                {full.frameworks.map((f) => (
                  <li key={`${f.name}-${f.sourceFile}`}>
                    <b>{f.name}</b> — {f.version ?? "version could not be determined"} ({f.versionSource})
                    {f.unpinned ? " · unpinned version" : ""} · <code className="inline">{f.sourceFile}</code>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="card">
            <h2>Dependency vulnerabilities ({full.vulnerabilities.length})</h2>
            {full.vulnerabilities.length === 0 ? (
              <p>No known vulnerabilities were found in the dependencies checked.</p>
            ) : (
              full.vulnerabilities.map((v) => (
                <div className="finding" key={`${v.id}-${v.packageName}`}>
                  <p><span className={`pill ${v.severity}`}>{v.severity}</span><b>{v.id}</b> — {v.packageName} {v.installedVersion ?? ""}</p>
                  <p>{v.plainEnglish}</p>
                  <p><b>Fix:</b> {v.upgrade}</p>
                </div>
              ))
            )}
          </div>

          <div className="card">
            <h2>Security posture ({full.posture.length})</h2>
            {full.posture.length === 0 ? (
              <p>No posture issues were found in the basic MVP checks.</p>
            ) : (
              full.posture.map((p) => (
                <div className="finding" key={p.id}>
                  <p><span className={`pill ${p.severity}`}>{p.severity}</span><b>{p.title}</b></p>
                  <p>{p.detail}</p>
                  <p><b>Fix:</b> {p.fix}</p>
                </div>
              ))
            )}
          </div>
        </>
      )}

      <div className="card">
        <h2>Scan limits</h2>
        <ul>
          {report.limits.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
        <p className="small">
          API: <a href={`/api/scan/${owner}/${repo}`}>public JSON for this repo</a>
          <> · <a href={`/${owner}/${repo}?full=1`}>owner view (GitHub sign-in)</a></>
        </p>
      </div>

      <McpSection compact />

      <p><a className="button-link" href="/">Scan another repo</a></p>
    </div>
  );
}
