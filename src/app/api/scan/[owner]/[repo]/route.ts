import { NextResponse } from "next/server";
import { isOwnerModeEnabled } from "@/lib/owner";
import { scanRepo, toPublicReport } from "@/lib/scan";

export const maxDuration = 60;

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ owner: string; repo: string }> },
) {
  const { owner, repo } = await ctx.params;
  const url = new URL(_req.url);
  const wantsFull = url.searchParams.get("full") === "1";
  try {
    const full = await scanRepo(owner, repo);
    if (wantsFull && isOwnerModeEnabled()) {
      return NextResponse.json(full);
    }
    return NextResponse.json(toPublicReport(full));
  } catch (err) {
    const message = err instanceof Error ? err.message : "Scan failed.";
    return NextResponse.json({ error: message }, { status: 404 });
  }
}
