// Phase 4: every caller gets the full report — the site only scans
// public repos, so the detail is information already public in the
// repo. No login flow, no owner gate, no ?full flag.
// Phase 9: the scan runs as stateless chunks (see src/lib/chunks.ts).
// This page drives chunks server-side for up to ~50 s (the fast path
// — a small repo renders in one request). If the scan is still running,
// it renders the HEAD report when the HEAD chunk is done (provisional
// score, clearly labelled) and the client keeps driving chunks from
// the cursor, saving progress in sessionStorage so a reload resumes
// instead of restarting. No scan is ever killed for taking too long,
// and no server restart can lose it — there is no job to lose.
import { FAST_PATH_WAIT_MS, runScanLoop } from "@/lib/chunks";
import { buildProvisionalReport } from "@/lib/provisional";
import { ScanError } from "@/lib/scan";
import ReportView from "@/components/ReportView";
import ScanProgress from "@/components/ScanProgress";
import type { FullReport } from "@/lib/types";

// Scan-on-demand page: never prerendered — each visit runs a live scan.
export const instant = false;
export const maxDuration = 60;

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
      case "head-moved":
        return {
          title: `The repo changed while scanning ${owner}/${repo}`,
          body: "New commits landed while the scan was running, so the saved progress belongs to the previous HEAD. Start a fresh scan for the new HEAD.",
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
  let partial: Awaited<ReturnType<typeof runScanLoop>> | null = null;
  try {
    const result = await runScanLoop(owner, repo, { budgetMs: FAST_PATH_WAIT_MS });
    if (result.status === "done" && result.report) {
      full = result.report;
    } else {
      partial = result;
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

  if (full) {
    return <ReportView report={full} />;
  }
  if (!partial || partial.status !== "partial" || !partial.cursor || !partial.partial) {
    throw new Error("Unreachable: scan neither done nor partial.");
  }

  // Still running after the fast-path wait: the HEAD report renders
  // first when the HEAD chunk is done (provisional score, labelled),
  // and the client drives the remaining history chunks from the
  // cursor, saving progress so a reload resumes where it left off.
  const head = partial.head ?? null;
  const provisional =
    head !== null
      ? buildProvisionalReport(head, partial.historyFindings ?? [], partial.partial.historyScanned, partial.partial.historyComplete)
      : null;
  return (
    <ScanProgress
      owner={owner}
      repo={repo}
      cursor={partial.cursor}
      head={head}
      historyFindings={partial.historyFindings ?? []}
      historyScanned={partial.partial.historyScanned}
      initial={partial.progress ?? partial.partial.progress}
      provisional={provisional}
    />
  );
}
