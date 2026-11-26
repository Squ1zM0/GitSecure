// Shown instantly while a report page runs its live scan (~15 s for a
// typical repo). The scan itself is one server-side job, so this is a
// static progress message describing the steps in order — checking the
// current files, then the full history, then dependencies for known
// flaws — not a live per-step indicator.
export default function Loading() {
  return (
    <div>
      <h1>Scanning the repo…</h1>
      <div className="card" role="status" aria-live="polite">
        <p className="scan-status">
          <span className="spinner" aria-hidden="true" />
          <span><b>Checking files…</b> then the full history, then dependencies for known flaws.</span>
        </p>
        <ol className="loading-steps">
          <li><span className="step-dot" aria-hidden="true" />Checking the current files for leaked secrets</li>
          <li><span className="step-dot" aria-hidden="true" />Checking the full history, newest first</li>
          <li><span className="step-dot" aria-hidden="true" />Checking dependencies for known flaws</li>
        </ol>
        <p className="muted">
          A full scan usually takes about 15 seconds. The page will appear here as soon as
          it is done — there is nothing to click.
        </p>
      </div>
    </div>
  );
}
