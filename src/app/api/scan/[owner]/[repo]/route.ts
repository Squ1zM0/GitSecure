import { NextResponse } from "next/server";
import { canViewFull } from "@/lib/owner";
import { scanRepoWithTimeout, ScanError, toPublicReport } from "@/lib/scan";

export const maxDuration = 60;

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ owner: string; repo: string }> },
) {
  const { owner, repo } = await ctx.params;
  const url = new URL(_req.url);
  const wantsFull = url.searchParams.get("full") === "1";
  try {
    const full = await scanRepoWithTimeout(owner, repo);
    if (wantsFull) {
      const { allowed } = await canViewFull(owner);
      if (allowed) return NextResponse.json(full);
    }
    return NextResponse.json(toPublicReport(full));
  } catch (err) {
    if (err instanceof ScanError) {
      // 404 repo not found/private, 429 GitHub rate limit, 504 scan
      // timeout, 400 bad owner/repo format, 502 GitHub upstream error.
      return NextResponse.json({ error: err.message, kind: err.kind }, { status: err.status });
    }
    return NextResponse.json({ error: "Scan failed. Try again in a bit.", kind: "unknown" }, { status: 500 });
  }
}
