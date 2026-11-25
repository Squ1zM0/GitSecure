// Scan API — returns the FULL report to anyone, no sign-in, no login.
// Phase 4: the site only scans public repos, so the detail is
// information already public in the repo. Secrets are still redacted
// fragments only (see src/lib/scan.ts / redact.ts).
import { NextResponse } from "next/server";
import { scanRepoWithTimeout, ScanError } from "@/lib/scan";

export const maxDuration = 60;

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ owner: string; repo: string }> },
) {
  const { owner, repo } = await ctx.params;
  try {
    const full = await scanRepoWithTimeout(owner, repo);
    return NextResponse.json(full);
  } catch (err) {
    if (err instanceof ScanError) {
      // 404 repo not found/private, 429 GitHub rate limit, 504 scan
      // timeout, 400 bad owner/repo format, 502 GitHub upstream error.
      return NextResponse.json({ error: err.message, kind: err.kind }, { status: err.status });
    }
    return NextResponse.json({ error: "Scan failed. Try again in a bit.", kind: "unknown" }, { status: 500 });
  }
}
