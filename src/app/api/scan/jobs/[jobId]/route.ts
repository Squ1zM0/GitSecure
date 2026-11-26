// Job poll endpoint (Phase 8).
//
// GET /api/scan/jobs/{jobId} — the live state of one async scan job:
// running (with honest progress: current step, files scanned so far,
// commits scanned so far, dependencies checked, advisories detailed),
// done (with the full report), or error (plain-English message).
// The job ID is a random UUID — it carries no owner, repo, or secret
// fragment, so polling it reveals nothing sensitive.
//
// A job lives in memory only (see src/lib/jobs.ts): it does NOT
// survive a cold start, a redeploy, or a poll that lands on a
// different serverless instance. An unknown ID answers 404 with
// plain English telling the client to start the scan again.
import { NextResponse } from "next/server";
import { getJob, jobSnapshot } from "@/lib/jobs";

export const maxDuration = 60;

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ jobId: string }> },
) {
  const { jobId } = await ctx.params;
  const job = getJob(jobId);
  if (!job) {
    return NextResponse.json(
      {
        error:
          "That scan is no longer running here — the server restarted or the scan finished a while ago. Start the scan again and it will pick up from the beginning.",
        kind: "job-not-found",
      },
      { status: 404 },
    );
  }
  return NextResponse.json(jobSnapshot(job));
}
