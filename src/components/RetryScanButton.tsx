// "Retry this scan" (Phase 15, finding 1) — the page-level error
// states (404, rate limit, timeout, …) only offered "Scan another
// repo", so a failed scan was a dead end for the same repo. This
// button restarts the scan for the repo the user already asked for:
// a full reload re-runs the report page's fast-path scan loop for
// the same owner/repo. A plain link to the same URL would not
// reliably re-run the server component, so this reloads instead.
// The rate-limit case passes its own label ("Try this scan again")
// — same mechanism, its own wording.
"use client";

export default function RetryScanButton({ label = "Retry this scan" }: { label?: string }) {
  return (
    <button
      className="button-link"
      type="button"
      onClick={() => window.location.reload()}
    >
      {label}
    </button>
  );
}
