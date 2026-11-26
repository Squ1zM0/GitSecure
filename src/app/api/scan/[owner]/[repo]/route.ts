// Scan API — returns the FULL report to anyone, no sign-in, no login.
// Phase 4: the site only scans public repos, so the detail is
// information already public in the repo. Secrets are still redacted
// fragments only (see src/lib/scan.ts / redact.ts).
//
// Phase 9: stateless chunked scans (see src/lib/chunks.ts). There is
// NO server-side job any more — GET drives chunks in-process for up to
// ~50 s (the fast path, so a small repo still answers 200 with the
// full report in a single request). If the scan is still running after
// that, the API answers 202 with a CURSOR and the partial results so
// far; the caller resumes by passing the cursor back (?cursor=... on
// this endpoint, or POST /api/scan/chunk). A server restart, cold
// start, or a poll landing on a different instance loses nothing —
// the next request simply continues from the cursor. The old
// the old unknown-job dead-end is gone: there is no job to lose.
import { NextResponse } from "next/server";
import { FAST_PATH_WAIT_MS, runScanLoop } from "@/lib/chunks";
import { ScanError } from "@/lib/scan";

export const maxDuration = 60;

export async function GET(
  req: Request,
  ctx: { params: Promise<{ owner: string; repo: string }> },
) {
  const { owner, repo } = await ctx.params;
  const url = new URL(req.url);
  const cursor = url.searchParams.get("cursor");
  try {
    const result = await runScanLoop(owner, repo, {
      cursor: cursor || null,
      budgetMs: FAST_PATH_WAIT_MS,
    });
    if (result.status === "done" && result.report) {
      return NextResponse.json(result.report);
    }
    // Still running: 202 with the cursor and the partial results so
    // far. Resume with ?cursor=... — nothing is lost by waiting.
    return NextResponse.json(
      {
        cursor: result.cursor,
        partial: result.partial,
        progress: result.progress,
        note: result.note ?? undefined,
        status: "running",
      },
      { status: 202 },
    );
  } catch (err) {
    if (err instanceof ScanError) {
      // Phase 15 (rate-limit recovery): the reset time travels with
      // the error when GitHub said when the limit resets, so API
      // callers can say honestly how long to wait.
      return NextResponse.json({ error: err.message, kind: err.kind, ...(err.resetAtMs !== undefined ? { resetAtMs: err.resetAtMs } : {}) }, { status: err.status });
    }
    return NextResponse.json({ error: "Scan failed. Try again in a bit.", kind: "unknown" }, { status: 500 });
  }
}
