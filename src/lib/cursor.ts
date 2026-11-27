// Scan cursors (Phase 9) - the whole resumability mechanism.
//
// WHY: Phase 8 stored scans as in-memory jobs. A job does not survive a
// cold start, a redeploy, or a poll landing on a different serverless
// instance - the client got a 404 and had to start over. Phase 9
// holds no scan job on the server - in-progress findings live in the short-lived store (see scan-state.ts).
// Instead, every chunk response returns a CURSOR: a small, self-contained,
// base64url-encoded JSON object that says exactly where the scan got to.
// The client passes the cursor back with the next request and the scan
// continues from that point. A server restart, cold start, or different
// instance changes nothing - there is no job to lose, so the old dead-end
// is impossible.
//
// WHAT A CURSOR CARRIES: owner/repo/branch, the pinned HEAD sha, the
// stage (head → history → assemble), and the position inside the stage:
//   - history via the git protocol: `histResumeAfter` (the last commit
//     scanned, exclusive - the next chunk walks older commits);
//   - history via the GitHub API: `histPage` / `histIdx` / `histPageShas`
//     (the next list page, the next index in it, and that page's SHAs, so
//     the next chunk need not re-list).
// WHAT A CURSOR NEVER CARRIES: findings, file contents, or any secret
// fragment. Partial results live with the caller (the browser keeps them
// in sessionStorage, see resume.ts; an API caller keeps them and sends
// the accumulated history findings back with the assemble call). A cursor
// is therefore safe to put in a URL, share, or log.
//
// VALIDATION: decodeCursor is strict. Anything malformed, from the wrong
// repo, or with out-of-range numbers is rejected with a plain-English
// ScanError (400) - the caller discards it and starts a clean scan.
// A cursor can never make the server scan a different repo than the
// request URL names, and the pinned HEAD sha is re-checked at assemble
// time, so a scan whose repo moved mid-flight restarts cleanly instead
// of reporting stale results.

import { ScanError } from "./scan";

export type CursorStage = "head" | "history" | "assemble";

export interface ScanCursorData {
  v: 1;
  owner: string;
  repo: string;
  branch: string;
  /** Pinned HEAD sha (40 hex) the scan started from. */
  headSha: string;
  stage: CursorStage;
  /** "git" (git protocol) or "api" (GitHub API, when the git path
   *  fails - e.g. a history pack too large to clone; the pack
   *  download is byte-bounded while it runs, see history.ts
   *  PACK_MAX_BYTES). */
  historyMethod: "git" | "api";
  /** History commits scanned so far (this scan, newest-first). */
  histScanned: number;
  /** Git path: full sha of the last commit scanned (exclusive), or
   *  null before the first history chunk. */
  histResumeAfter: string | null;
  /** API path: next commits-list page (1-based). */
  histPage: number;
  /** API path: next index into histPageShas. */
  histIdx: number;
  /** API path: SHAs of the current list page (≤100). */
  histPageShas: string[];
  /** True once every history commit has been walked. */
  histDone: boolean;
  /** Why history stopped early, if it did - the report says so. */
  histStop: "rate-limit" | "truncated" | null;
  /** Short human note for an early history stop (rate limit, guard). */
  histNote: string | null;
}

const NAME_RE = /^[A-Za-z0-9_.-]+$/;
const SHA_RE = /^[0-9a-f]{40}$/;

function badCursor(): ScanError {
  return new ScanError(
    400,
    "bad-format",
    "That scan link doesn't look right - it may be from an older scan or pasted wrong. Starting a fresh scan instead.",
  );
}

export function encodeCursor(data: ScanCursorData): string {
  const json = JSON.stringify(data);
  return Buffer.from(json, "utf8").toString("base64url");
}

/** Decode and strictly validate a cursor string. `owner`/`repo` are the
 *  request's own values - a cursor for a different repo is rejected.
 *  Throws ScanError (400, plain English) on anything malformed. */
export function decodeCursor(raw: string, owner: string, repo: string): ScanCursorData {
  let parsed: unknown;
  try {
    const json = Buffer.from(raw, "base64url").toString("utf8");
    parsed = JSON.parse(json) as unknown;
  } catch {
    throw badCursor();
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw badCursor();
  const d = parsed as Record<string, unknown>;
  const isStr = (v: unknown): v is string => typeof v === "string";
  const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
  if (d.v !== 1) throw badCursor();
  if (!isStr(d.owner) || !NAME_RE.test(d.owner) || d.owner !== owner) throw badCursor();
  if (!isStr(d.repo) || !NAME_RE.test(d.repo) || d.repo !== repo) throw badCursor();
  if (!isStr(d.branch) || !NAME_RE.test(d.branch) || d.branch.length > 200) throw badCursor();
  if (!isStr(d.headSha) || !SHA_RE.test(d.headSha)) throw badCursor();
  if (d.stage !== "head" && d.stage !== "history" && d.stage !== "assemble") throw badCursor();
  if (d.historyMethod !== "git" && d.historyMethod !== "api") throw badCursor();
  if (!isNum(d.histScanned) || d.histScanned < 0 || d.histScanned > 10_000_000 || !Number.isInteger(d.histScanned)) throw badCursor();
  if (d.histResumeAfter !== null && (!isStr(d.histResumeAfter) || !SHA_RE.test(d.histResumeAfter))) throw badCursor();
  if (!isNum(d.histPage) || !Number.isInteger(d.histPage) || d.histPage < 1 || d.histPage > 100_000) throw badCursor();
  if (!isNum(d.histIdx) || !Number.isInteger(d.histIdx) || d.histIdx < 0 || d.histIdx > 100) throw badCursor();
  if (!Array.isArray(d.histPageShas) || d.histPageShas.length > 100 || d.histPageShas.some((s) => !isStr(s) || !SHA_RE.test(s))) throw badCursor();
  if (typeof d.histDone !== "boolean") throw badCursor();
  if (d.histStop !== null && d.histStop !== "rate-limit" && d.histStop !== "truncated") throw badCursor();
  if (d.histNote !== null && (!isStr(d.histNote) || d.histNote.length > 500)) throw badCursor();
  return d as unknown as ScanCursorData;
}

/** A fresh cursor for a scan that has just finished its HEAD chunk. */
export function initialHistoryCursor(head: {
  owner: string;
  repo: string;
  branch: string;
  headSha: string;
  historyMethod: "git" | "api";
}): ScanCursorData {
  return {
    v: 1,
    owner: head.owner,
    repo: head.repo,
    branch: head.branch,
    headSha: head.headSha,
    stage: "history",
    historyMethod: head.historyMethod,
    histScanned: 0,
    histResumeAfter: null,
    histPage: 1,
    histIdx: 0,
    histPageShas: [],
    histDone: false,
    histStop: null,
    histNote: null,
  };
}
