// Live scan progress (Phase 8) — client component.
//
// The report page renders this when a scan job is still running after
// the ~50 s fast path. It polls GET /api/scan/jobs/{jobId} and shows
// honest live progress — the current step, files scanned so far,
// commits checked so far, dependencies checked — never a spinner
// that pretends to know. When the job finishes, the page reloads and
// the finished report renders server-side (the job record is kept in
// memory for 10 minutes, so the reload does not re-scan). If the job
// is gone (404 — cold start, redeploy, or a poll on another instance),
// it says so plainly and offers a retry instead of spinning forever.
"use client";

import { useEffect, useState } from "react";
import { stepLabel, type ScanProgress } from "@/lib/progress";

function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}

export default function ScanProgress({
  jobId,
  owner,
  repo,
  initial,
}: {
  jobId: string;
  owner: string;
  repo: string;
  initial: ScanProgress;
}) {
  const [progress, setProgress] = useState<ScanProgress>(initial);
  const [gone, setGone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let stopped = false;
    const tick = async () => {
      try {
        const res = await fetch(`/api/scan/jobs/${encodeURIComponent(jobId)}`, { cache: "no-store" });
        if (res.status === 404) {
          if (!stopped) setGone(true);
          return;
        }
        if (!res.ok) return; // transient failure: keep polling
        const snap = (await res.json()) as { status: string; progress: ScanProgress; error?: { message: string } };
        if (stopped) return;
        if (snap.status === "done") {
          window.location.reload();
          return;
        }
        if (snap.status === "error") {
          setError(snap.error?.message ?? "The scan failed. Try again in a bit.");
          return;
        }
        setProgress(snap.progress);
      } catch {
        // Network blip: keep polling.
      }
    };
    const timer = setInterval(() => void tick(), 2000);
    void tick();
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [jobId]);

  if (gone) {
    return (
      <div>
        <p className="back-link"><a href="/">← Scan another repo</a></p>
        <h1>That scan is no longer running</h1>
        <div className="card error-card" role="alert">
          <p>The server restarted while the scan of {owner}/{repo} was running, so the scan was interrupted. Nothing was half-reported — start it again and it will run from the beginning.</p>
          <p><a className="button-link" href={`/${owner}/${repo}`}>Run the scan again</a></p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <p className="back-link"><a href="/">← Scan another repo</a></p>
        <h1>Couldn&apos;t scan {owner}/{repo}</h1>
        <div className="card error-card" role="alert">
          <p>{error}</p>
          <p><a className="button-link" href="/">Scan another repo</a></p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <p className="back-link"><a href="/">← Scan another repo</a></p>
      <h1>Scanning {owner}/{repo}…</h1>
      <div className="card" role="status" aria-live="polite">
        <p className="scan-status">
          <span className="spinner" aria-hidden="true" />
          <span><b>{stepLabel(progress.step)}…</b></span>
        </p>
        <ul className="loading-steps">
          <li>
            <span className="step-dot" aria-hidden="true" />
            {progress.filesTotal > 0
              ? `${formatCount(progress.filesScanned)} of ${formatCount(progress.filesTotal)} files scanned`
              : `${formatCount(progress.filesScanned)} files scanned so far`}
          </li>
          <li>
            <span className="step-dot" aria-hidden="true" />
            {progress.commitsScanned > 0
              ? `${formatCount(progress.commitsScanned)} history commits checked`
              : "History not checked yet"}
          </li>
          <li>
            <span className="step-dot" aria-hidden="true" />
            {progress.depsTotal > 0
              ? `${formatCount(progress.depsChecked)} of ${formatCount(progress.depsTotal)} dependencies checked for known flaws`
              : progress.step === "dependencies"
                ? "Checking dependencies for known flaws"
                : "Dependencies not checked yet"}
          </li>
        </ul>
        <p className="muted">
          This is a big repo, so the scan keeps running in the background — the report will appear here as soon as it is done. There is nothing to click.
        </p>
      </div>
    </div>
  );
}
