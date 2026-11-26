// Phase 4: every caller gets the full report — the site only scans
// public repos, so the detail is information already public in the
// repo. No login flow, no owner gate, no ?full flag.
// Phase 9: the scan runs as stateless chunks (see src/lib/chunks.ts).
// Phase 16: this page NO LONGER awaits the scan server-side. It used
// to drive chunks for up to ~50 s (the fast path) before rendering —
// on a big repo the document took 53–64 s and slow runs had their
// stream cut at Vercel's 60 s function ceiling, which Safari/WebKit
// reported as "This page couldn't load" (live: vinta/awesome-python,
// 2026-11-26). The page now renders the progress shell immediately
// and the browser drives the scan chunk by chunk from the start
// (POST /api/scan/start, then POST /api/scan/chunk — see
// ScanProgress), saving progress in sessionStorage so a reload resumes
// instead of restarting. A single HEAD chunk can stall up to ~30 s on
// a huge repo's tarball download, so no short server budget could be
// proven to stay under ~5 s total including cold start — zero server
// await is the only budget that holds for every repo. The shell
// completes in well under a second; the scan itself still takes as
// long as it takes, chunk by chunk, and no scan is ever killed for
// taking too long. The one failure the page can still know
// server-side is a malformed owner/repo name, which keeps its error
// page here; every other failure surfaces in the client driver with
// the same words (see src/lib/scan-error-copy.ts).
import { validateOwnerRepo, ScanError } from "@/lib/scan";
import { scanErrorCopy, scanErrorRetryLabel } from "@/lib/scan-error-copy";
import { emptyProgress } from "@/lib/progress";
import RetryScanButton from "@/components/RetryScanButton";
import ScanProgress from "@/components/ScanProgress";

// Scan-on-demand page: never prerendered — each visit runs a live scan.
// (No `dynamic` export: it is incompatible with cacheComponents, and
// awaiting `params` already makes this page render on demand.)
export const maxDuration = 60;

export default async function ReportPage({
  params,
}: {
  params: Promise<{ owner: string; repo: string }>;
}) {
  const { owner, repo } = await params;

  try {
    validateOwnerRepo(owner, repo);
  } catch (err) {
    if (!(err instanceof ScanError)) throw err;
    const { title, body } = scanErrorCopy(err.kind, owner, repo, err.resetAtMs ?? null);
    return (
      <div>
        <p className="back-link"><a href="/">← Scan another repo</a></p>
        <h1>{title}</h1>
        <div className="card error-card" role="alert">
          <p>{body}</p>
          <p><RetryScanButton label={scanErrorRetryLabel(err.kind)} />{" "}<a className="button-link" href="/">Scan another repo</a></p>
        </div>
      </div>
    );
  }

  // Zero server await: the progress shell renders immediately and the
  // browser starts the scan (no cursor yet — the first chunk runs
  // through POST /api/scan/start). Saved progress from this tab, if
  // any, is picked up by the driver on mount.
  return (
    <ScanProgress
      owner={owner}
      repo={repo}
      cursor={null}
      head={null}
      historyFindings={[]}
      historyScanned={0}
      initial={emptyProgress()}
      provisional={null}
    />
  );
}
