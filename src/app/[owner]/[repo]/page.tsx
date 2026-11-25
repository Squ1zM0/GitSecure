import { isOwnerModeEnabled } from "@/lib/owner";
import { scanRepo, toPublicReport } from "@/lib/scan";
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
      <div className="counts">
        <div className="count"><b>{report.counts.secrets}</b><span>possible leaked secrets</span></div>
        <div className="count"><b>{report.counts.vulnerabilities}</b><span>dependency vulnerabilities</span></div>
        <div className="count"><b>{report.counts.frameworks}</b><span>frameworks detected</span></div>
        <div className="count"><b>{report.counts.dependencies}</b><span>dependencies checked</span></div>
        <div className="count"><b>{report.counts.postureIssues}</b><span>posture issues</span></div>
        <div className="count"><b>{report.counts.filesScanned}</b><span>files scanned</span></div>
      </div>
      <p className="small">Scanned {new Date(report.scannedAt).toLocaleString()} · History: {report.historyDepth}</p>
    </div>
  );
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

  let full: FullReport;
  try {
    full = await scanRepo(owner, repo);
  } catch (err) {
    return (
      <div>
        <h1>Couldn&apos;t scan {owner}/{repo}</h1>
        <div className="card">
          <p>{err instanceof Error ? err.message : "Scan failed."}</p>
          <p className="muted">Check the owner and repo names, and that the repo is public. <a href="/">Try another repo</a></p>
        </div>
      </div>
    );
  }

  const showFull = wantsFull && ownerMode;
  const report: PublicReport | FullReport = showFull ? full : toPublicReport(full);

  return (
    <div>
      <h1>{owner}/{repo}</h1>

      {!showFull && (
        <div className="banner amber" role="note">
          <b>Public view — score and counts only.</b> Full detail (file names, line numbers, redacted
          secret fragments, framework versions, vulnerability IDs) is available to the repo owner only.
          {!wantsFull && " Owners: full detail is not yet wired to GitHub sign-in — see the banner below."}
          {wantsFull && !ownerMode && " Owner verification is coming — the full view is not available yet in this deployment."}
        </div>
      )}
      {showFull && (
        <div className="banner green" role="note">
          <b>Owner view (local/dev owner mode).</b> This deployment has owner mode enabled for local
          testing only. Production owner verification via GitHub OAuth is still to be built — do not
          treat this banner as proof of ownership.
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
              <p>No Tier 1 frameworks were fingerprinted in this repo.</p>
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
                  <p>{v.summary}</p>
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
          {ownerMode ? <> · <a href={`/${owner}/${repo}?full=1`}>owner view (local/dev mode)</a></> : null}
        </p>
      </div>
    </div>
  );
}
