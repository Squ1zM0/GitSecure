// Scan API — returns the FULL report to anyone, no sign-in, no login.
// Phase 4: the site only scans public repos, so the detail is
// information already public in the repo. Secrets are still redacted
// fragments only (see src/lib/scan.ts / redact.ts).
//
// Phase 8: async scan jobs. GET starts (or joins) a scan job and
// waits up to ~50 s for it — the fast path, so a small repo still
// answers 200 with the full report in a single request. If the job
// is still running after that, the API answers 202 with a jobId and
// live progress; the client polls GET /api/scan/jobs/{jobId} until
// the job is done (200, report included) or errors. No scan is ever
// killed for taking too long — the job keeps running in the
// background (after() keeps this invocation alive past the response).
import { NextResponse } from "next/server";
import { after } from "next/server";
import { FAST_PATH_WAIT_MS, getOrStartJob, jobSnapshot, waitForJob } from "@/lib/jobs";
import { ScanError } from "@/lib/scan";

export const maxDuration = 60;

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ owner: string; repo: string }> },
) {
  const { owner, repo } = await ctx.params;
  let job;
  try {
    job = getOrStartJob(owner, repo);
  } catch (err) {
    if (err instanceof ScanError) {
      return NextResponse.json({ error: err.message, kind: err.kind }, { status: err.status });
    }
    return NextResponse.json({ error: "Scan failed. Try again in a bit.", kind: "unknown" }, { status: 500 });
  }
  // Keep the job alive past this response on Vercel: after() runs
  // after the response is sent, inside the same invocation.
  after(async () => {
    await job.promise.catch(() => undefined);
  });
  const finished = await waitForJob(job, FAST_PATH_WAIT_MS);
  if (finished.status === "done" && finished.report) {
    return NextResponse.json(finished.report);
  }
  if (finished.status === "error" && finished.error) {
    // 404 repo not found/private, 429 GitHub rate limit, 502 GitHub
    // upstream error, 400 bad owner/repo format.
    return NextResponse.json({ error: finished.error.message, kind: finished.error.kind }, { status: finished.error.status });
  }
  // Still running: 202 with the job ID and honest live progress.
  // The scan continues in the background — poll the job endpoint.
  return NextResponse.json(jobSnapshot(finished), { status: 202 });
}
