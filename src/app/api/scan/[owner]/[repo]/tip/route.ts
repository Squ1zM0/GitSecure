// Current-tip endpoint (Phase 16) — GET /api/scan/[owner]/[repo]/tip
//
// One cheap git-protocol info/refs round trip (resolveRemoteHead) that
// answers which branch and HEAD sha the repo is on right now. The
// report page uses it for exactly one thing: a finished report saved
// in sessionStorage from an earlier visit renders immediately only if
// its HEAD sha still matches the live tip — otherwise the saved report
// is stale and a fresh scan starts. No scan runs here, no state is
// held, and no scan behaviour changes.
import { NextResponse } from "next/server";
import { resolveRemoteHead } from "@/lib/history";
import { ScanError, validateOwnerRepo } from "@/lib/scan";

export const maxDuration = 60;

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ owner: string; repo: string }> },
) {
  const { owner, repo } = await ctx.params;
  try {
    validateOwnerRepo(owner, repo);
  } catch (err) {
    if (err instanceof ScanError) {
      return NextResponse.json({ error: err.message, kind: err.kind }, { status: err.status });
    }
    throw err;
  }
  const tip = await resolveRemoteHead(owner, repo);
  if (!tip.ok) {
    if (tip.reason === "not-found") {
      return NextResponse.json(
        { error: "Repository not found (or it is private). GitSecure scans public repos only.", kind: "not-found" },
        { status: 404 },
      );
    }
    if (tip.reason === "timeout") {
      return NextResponse.json(
        { error: "GitHub took too long to answer. Try again.", kind: "timeout" },
        { status: 504 },
      );
    }
    return NextResponse.json(
      { error: "GitHub couldn't be reached. Try again in a bit.", kind: "upstream" },
      { status: 502 },
    );
  }
  return NextResponse.json({ branch: tip.branch, headSha: tip.headSha });
}
