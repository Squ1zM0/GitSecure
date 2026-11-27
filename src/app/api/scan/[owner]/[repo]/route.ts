// Scan API - returns the FULL report to anyone, no sign-in, no login.
// Phase 4: the site only scans public repos, so the detail is
// information already public in the repo. Secrets are still redacted
// fragments only (see src/lib/scan.ts / redact.ts).
//
// Phase 9: stateless chunked scans (see src/lib/chunks.ts). There is
// NO server-side job any more - GET drives chunks in-process for up to
// ~40 s (the fast path, so a small repo still answers 200 with the
// full report in a single request). If the scan is still running after
// that, the API answers 202 with a CURSOR and the partial results so
// far; the caller resumes by passing the cursor back (?cursor=... on
// this endpoint, or POST /api/scan/chunk). A server restart, cold
// start, or a poll landing on a different instance loses nothing -
// the next request simply continues from the cursor. The old
// the old unknown-job dead-end is gone: there is no job to lose.
// (Phase 16, Worker B: 40 s, not 50 - a chunk that started just
// before a 50 s deadline still ran a full chunk past it, and live
// invocations reached 52.8–63.6 s against Vercel's 60 s ceiling.
// See API_FAST_PATH_WAIT_MS in src/lib/chunks.ts for the arithmetic.)
import { NextResponse } from "next/server";
import { API_FAST_PATH_WAIT_MS, runScanLoop } from "@/lib/chunks";
import { filterHistoryFindings } from "@/lib/scan-state";
import { ScanError } from "@/lib/scan";
import type { SecretFinding } from "@/lib/types";

export const maxDuration = 60;

/** Phase 17 caller-carried fallback: optional ?historyFindings=
 *  (base64url JSON array of secret findings, same encoding family
 *  as the cursor). Validated with the assemble-stage shape filter;
 *  anything malformed, oversized, or absent is ignored, and the
 *  scan runs with in-process accumulation only - the finished
 *  report then carries the honest limits line when earlier
 *  findings could not be recovered (see chunks.ts).
 *
 *  URL-length limit, stated honestly: a URL carries only a few KB
 *  in practice (browsers ~2–8 KB, proxies/CDNs often less), so
 *  only a handful of findings can ride here - the decoded JSON is
 *  capped at 8 KB (~8 findings at ~1 KB each). A large set
 *  (DefinitelyTyped-scale is ~400 KB) can never ride in a query
 *  string. This fallback does NOT replace the server store (see
 *  scan-state.ts); it only narrows the hole for small resumes. A
 *  bare curl …?cursor= resume still carries nothing. */
export const MAX_GET_HISTORY_FINDINGS_BYTES = 8192;
export function parseHistoryFindingsParam(value: string | null): SecretFinding[] {
  if (!value || value.length > MAX_GET_HISTORY_FINDINGS_BYTES * 2) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as unknown;
  } catch {
    return [];
  }
  const findings = filterHistoryFindings(parsed);
  if (Buffer.byteLength(JSON.stringify(findings), "utf8") > MAX_GET_HISTORY_FINDINGS_BYTES) return [];
  return findings;
}

export async function GET(
  req: Request,
  ctx: { params: Promise<{ owner: string; repo: string }> },
) {
  const { owner, repo } = await ctx.params;
  const url = new URL(req.url);
  const cursor = url.searchParams.get("cursor");
  const historyFindings = parseHistoryFindingsParam(url.searchParams.get("historyFindings"));
  try {
    const result = await runScanLoop(owner, repo, {
      cursor: cursor || null,
      budgetMs: API_FAST_PATH_WAIT_MS,
      historyFindings,
    });
    if (result.status === "done" && result.report) {
      return NextResponse.json(result.report);
    }
    // Still running: 202 with the cursor and the partial results so
    // far. Resume with ?cursor=... - nothing is lost by waiting.
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
