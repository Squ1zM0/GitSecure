// Chunk endpoint (Phase 9) — the resumable scan API.
//
// POST /api/scan/chunk { cursor?, head?, historyFindings? }
//
// Advances a scan by exactly ONE chunk and returns the partial
// results plus the next cursor:
//
//   { status: "partial", cursor, partial, chunkFindings, progress, note }
//   { status: "done", report }
//
// - No cursor: runs the HEAD chunk and returns a cursor at the
//   history stage (with the HEAD partial in `partial.head`).
// - History cursor: scans the next chunk of history (git protocol:
//   up to 200 commits; GitHub API: 10 commits) and returns those
//   findings in `chunkFindings`. The caller appends them to its own
//   accumulated history findings.
// - Assemble cursor: merges the HEAD partial (`head` in the body, or
//   re-derived server-side when absent) with the accumulated history
//   findings (`historyFindings` in the body), runs the dependency flaw
//   check, and returns the finished report.
//
// The server holds no state between calls: everything needed to
// continue lives in the cursor, and everything accumulated lives with
// the caller. A bogus cursor answers 400 with plain English — the
// caller discards it and starts a fresh scan. The cursor protocol is
// documented in README.md ("Scan cursors").
import { NextResponse } from "next/server";
import { advanceScan } from "@/lib/chunks";
import { ScanError } from "@/lib/scan";

export const maxDuration = 60;

export async function POST(req: Request) {
  let body: { cursor?: unknown; head?: unknown; historyFindings?: unknown };
  try {
    body = (await req.json()) as { cursor?: unknown; head?: unknown; historyFindings?: unknown };
  } catch {
    return NextResponse.json(
      { error: "That request wasn't valid JSON. Send { cursor } to continue a scan, or {} to start one.", kind: "bad-format" },
      { status: 400 },
    );
  }
  if (body.cursor !== undefined && body.cursor !== null && typeof body.cursor !== "string") {
    return NextResponse.json(
      { error: "The cursor must be a string. Send {} to start a fresh scan.", kind: "bad-format" },
      { status: 400 },
    );
  }
  const head = body.head as Parameters<typeof advanceScan>[0]["head"];
  const historyFindings = body.historyFindings as Parameters<typeof advanceScan>[0]["historyFindings"];
  // The cursor pins the repo; the URL carries no owner/repo on this
  // endpoint, so they come from the cursor itself. A body without a
  // cursor cannot start a scan — the caller needs an owner/repo, which
  // is what GET /api/scan/[owner]/[repo] is for.
  if (body.cursor === undefined || body.cursor === null) {
    return NextResponse.json(
      { error: "Send a cursor to continue a scan, or start one at GET /api/scan/[owner]/[repo].", kind: "bad-format" },
      { status: 400 },
    );
  }
  // Decode the cursor here only to learn the repo — advanceScan does
  // the strict validation and answers 400 on anything malformed. A
  // body whose cursor cannot even be decoded gets the same plain
  // answer here, so a bogus cursor is never a crash.
  let owner = "";
  let repo = "";
  try {
    const raw = Buffer.from(body.cursor, "base64url").toString("utf8");
    const parsed = JSON.parse(raw) as { owner?: unknown; repo?: unknown };
    if (typeof parsed.owner === "string") owner = parsed.owner;
    if (typeof parsed.repo === "string") repo = parsed.repo;
  } catch {
    // Falls through to the 400 below.
  }
  if (!owner || !repo) {
    return NextResponse.json(
      { error: "That scan link doesn't look right — it may be from an older scan or pasted wrong. Starting a fresh scan instead.", kind: "bad-format" },
      { status: 400 },
    );
  }
  try {
    const result = await advanceScan({
      owner,
      repo,
      cursor: body.cursor,
      head: head ?? null,
      historyFindings: Array.isArray(historyFindings) ? historyFindings : [],
    });
    return NextResponse.json(result);
  } catch (err) {
    if (err instanceof ScanError) {
      return NextResponse.json({ error: err.message, kind: err.kind }, { status: err.status });
    }
    return NextResponse.json({ error: "Scan failed. Try again in a bit.", kind: "unknown" }, { status: 500 });
  }
}
