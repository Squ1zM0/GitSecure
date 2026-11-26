// Start-scan endpoint (Phase 16) — POST /api/scan/start { owner, repo }
//
// The report page renders its progress shell immediately now, so the
// browser needs a way to run the FIRST chunk (the HEAD chunk): the
// chunk endpoint only continues a scan from a cursor. This route runs
// exactly one chunk from a fresh scan and returns the same partial
// shape POST /api/scan/chunk returns, so the client driver treats its
// response as the first chunk response and keeps driving from the
// cursor it carries. Backward-compatible addition: no existing route
// changes, no scan behaviour changes — advanceScan with a null cursor
// is what the chunk route's callers already rely on per chunk.
import { NextResponse } from "next/server";
import { advanceScan } from "@/lib/chunks";
import { ScanError } from "@/lib/scan";

export const maxDuration = 60;

export async function POST(req: Request) {
  let body: { owner?: unknown; repo?: unknown };
  try {
    body = (await req.json()) as { owner?: unknown; repo?: unknown };
  } catch {
    return NextResponse.json(
      { error: "That request wasn't valid JSON. Send { owner, repo } to start a scan.", kind: "bad-format" },
      { status: 400 },
    );
  }
  const { owner, repo } = body;
  if (typeof owner !== "string" || typeof repo !== "string" || !owner || !repo) {
    return NextResponse.json(
      { error: "Send { owner, repo } to start a scan.", kind: "bad-format" },
      { status: 400 },
    );
  }
  try {
    const result = await advanceScan({ owner, repo, cursor: null });
    return NextResponse.json(result);
  } catch (err) {
    if (err instanceof ScanError) {
      // Phase 15 (rate-limit recovery): the reset time travels with
      // the error when GitHub said when the limit resets, so the
      // client can say honestly how long to wait.
      return NextResponse.json({ error: err.message, kind: err.kind, ...(err.resetAtMs !== undefined ? { resetAtMs: err.resetAtMs } : {}) }, { status: err.status });
    }
    return NextResponse.json({ error: "Scan failed. Try again in a bit.", kind: "unknown" }, { status: 500 });
  }
}
