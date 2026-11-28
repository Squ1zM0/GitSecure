// Compare-window pre-filter for the API history path (Phase 21,
// Workstream B).
//
// `scanHistoryApiChunk` used to fetch every commit's patch
// individually (1 REST call per commit). Most windows contain no
// secret at all, so the chunk first fetches ONE compare call for the
// whole window (`GET /repos/{owner}/{repo}/compare/{base}...{head}`)
// and scans the window's aggregate diff for secret patterns. A clean
// window costs exactly 1 call; only a window WITH a hit falls back to
// the per-commit fetches, which attribute each finding to its exact
// commit. The per-commit fetch is the confirmation step, not the
// search step - attribution is preserved exactly.
//
// SHAPE (verified live 2026-11-28 against Squ1zM0/GitSecure,
// compare 2cf477a...d206bb4 vs the per-commit detail for d206bb4):
// the compare response's `files[]` objects carry the same fields as
// the per-commit endpoint's (`filename`, `status`, `additions`,
// `deletions`, `changes`, `patch`, `sha`, `blob_url`, `raw_url`,
// `contents_url`), and for a one-commit window the patch text is
// byte-identical to the per-commit patch. The pre-filter therefore
// reuses the same added-line parsing and the same detectors as the
// per-commit path.
//
// KNOWN LIMIT (not a shape difference - the aggregate diff is a NET
// diff from base to head): a secret added and then removed again
// inside the same window leaves no trace in the aggregate diff, so
// the pre-filter cannot see it. The per-commit path would have
// caught it. The exposure is bounded by the window, which is the
// chunk's own take (default 10 commits, max 100) - never the 250 the
// design names for the whole-scan case. Anything the pre-filter
// cannot vouch for (truncated diff, a range that does not cover the
// window, a diverged base) falls back to the per-commit fetches, so
// the fallback is always the exact old behaviour.
//
// No literal secret-pattern strings appear in this file: the
// detectors live in ./secrets and are called, never restated.

import { scanLinesForSecrets, type ScannedLine } from "./secrets";
import { isSkippablePath } from "./paths";

/** The compare endpoint covers at most 250 commits per call. A
 *  chunk's window is at most 100 commits (the chunk-size cap), so
 *  this is never hit from `scanHistoryApiChunk` - it is a defensive
 *  bound for any future caller that windows wider. */
export const COMPARE_WINDOW_MAX_COMMITS = 250;

/** The compare endpoint returns at most 300 files; past that the
 *  file list is cut short and a secret in a dropped file would be
 *  invisible to the pre-filter. A window touching this many files is
 *  sent to the per-commit fallback instead of trusted. */
export const COMPARE_MAX_FILES = 300;

/** Parse a unified-diff patch into its added lines, with new-file
 *  line numbers taken from the hunk headers - the same shape the
 *  clone path feeds the detectors. Removed lines and context lines
 *  are not scanned. (Moved here from history.ts so both the
 *  per-commit path and this pre-filter share the one parser.) */
export function parsePatchAddedLines(patch: string): ScannedLine[] {
  const lines: ScannedLine[] = [];
  let newLine = 0;
  for (const raw of patch.split("\n")) {
    const line = raw.replace(/\r$/, "");
    const hunkM = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunkM) {
      newLine = parseInt(hunkM[1], 10);
      continue;
    }
    if (line.startsWith("+++")) continue;
    if (line.startsWith("+")) {
      lines.push({ line: newLine, text: line.slice(1) });
      newLine++;
    } else if (line.startsWith(" ")) {
      newLine++;
    }
    // "-" (removed) lines do not advance newLine.
  }
  return lines;
}

/** Resolve the compare base for a window of commit SHAs, newest
 *  first. The compare `base...head` covers every commit reachable
 *  from head but not from base, so the base must be the commit
 *  immediately older than the window:
 *  - `nextPageSha`: the SHA right after the window on the same list
 *    page (the usual case - every listed commit is an ancestor of
 *    the head, so the net diff covers exactly the window, plus any
 *    side-branch commits merged inside it).
 *  - `oldestFirstParent`: the first parent of the window's oldest
 *    commit, from a freshly listed page (used when the window runs
 *    to the end of the page and there is no next SHA).
 *  Returns null when no base can be determined - the window ends at
 *  the root commit, whose own diff no compare can express - and the
 *  caller must fall back to the per-commit fetches. */
export function resolveCompareBase(
  windowShas: string[],
  nextPageSha: string | null,
  oldestFirstParent: string | null,
): string | null {
  if (windowShas.length === 0) return null;
  if (typeof nextPageSha === "string" && nextPageSha.length > 0) return nextPageSha;
  if (typeof oldestFirstParent === "string" && oldestFirstParent.length > 0) return oldestFirstParent;
  return null;
}

export type CompareFetch = (url: string, timeoutMs: number) => Promise<Response | null>;

export type CompareWindowOutcome = "clean" | "hit" | "unusable" | "rate-limited";

export interface CompareWindowScan {
  outcome: CompareWindowOutcome;
}

/** Same rate-limit test as history.ts's `isApiRateLimited` (kept
 *  local here so this module does not import history.ts). */
function isRateLimited(res: Response): boolean {
  return res.status === 429 || (res.status === 403 && res.headers.get("x-ratelimit-remaining") === "0");
}

interface CompareFile {
  filename?: string;
  patch?: string;
}

interface CompareBody {
  status?: string;
  ahead_by?: number;
  behind_by?: number;
  total_commits?: number;
  truncated?: boolean;
  files?: CompareFile[];
}

/**
 * Fetch one compare window and scan its aggregate diff for secret
 * patterns.
 *
 * - "clean": the aggregate diff was fetched, covers the window, and
 *   no file's added lines matched a secret pattern. The caller may
 *   skip the per-commit fetches for the whole window.
 * - "hit": a pattern matched. The caller fetches the individual
 *   commit patches in the window to attribute the finding exactly.
 *   The pre-filter findings themselves are discarded - only the
 *   boolean survives, so no finding here can ever carry a wrong
 *   commit.
 * - "unusable": the compare could not vouch for the window (network
 *   failure, non-OK status, unreadable body, truncated diff, a
 *   range that covers fewer commits than the window, a diverged
 *   base, or 300+ files). The caller falls back to the per-commit
 *   fetches - the exact old behaviour.
 * - "rate-limited": the API quota stopped the compare. The caller
 *   stops without advancing, exactly as for a rate-limited detail
 *   fetch.
 *
 * The pre-filter runs the RAW detectors only (no triage): a detector
 * match triage would dismiss still triggers the per-commit fetch,
 * which is the authoritative step - a false positive here costs one
 * window of detail fetches, never a wrong finding. The same
 * skippable-path rule as the per-commit path applies, so a match in
 * a skipped path does not trigger a fetch either.
 */
export async function scanCompareWindow(
  apiBase: string,
  owner: string,
  repo: string,
  baseSha: string,
  headSha: string,
  expectedCommits: number,
  fetchFn: CompareFetch,
  timeoutMs: number,
): Promise<CompareWindowScan> {
  if (expectedCommits < 1 || expectedCommits > COMPARE_WINDOW_MAX_COMMITS) {
    return { outcome: "unusable" };
  }
  const res = await fetchFn(
    `${apiBase}/repos/${owner}/${repo}/compare/${encodeURIComponent(baseSha)}...${encodeURIComponent(headSha)}`,
    timeoutMs,
  );
  if (!res) return { outcome: "unusable" };
  if (isRateLimited(res)) return { outcome: "rate-limited" };
  if (!res.ok) return { outcome: "unusable" };
  let body: CompareBody;
  try {
    body = (await res.json()) as CompareBody;
  } catch {
    return { outcome: "unusable" };
  }
  if (!body || typeof body !== "object" || !Array.isArray(body.files)) {
    return { outcome: "unusable" };
  }
  // The diff must be whole: a truncated diff, or a range covering
  // fewer commits than the window, may silently omit a window
  // commit's changes. A range covering MORE commits than the window
  // (a merge pulled in side-branch commits) is a safe superset - the
  // aggregate still contains every surviving window change.
  if (body.truncated === true) return { outcome: "unusable" };
  if (typeof body.total_commits === "number" && body.total_commits < expectedCommits) {
    return { outcome: "unusable" };
  }
  // A diverged base means neither side is the other's ancestor, so
  // the diff is measured from the merge base and may exclude window
  // commits. "ahead" is the expected shape (base is an ancestor of
  // head); an absent status (a minimal mock) is not held against it.
  if (typeof body.status === "string" && body.status !== "ahead") {
    return { outcome: "unusable" };
  }
  // Past the file cap the file list is cut short - a secret in a
  // dropped file would be invisible.
  if (body.files.length >= COMPARE_MAX_FILES) return { outcome: "unusable" };

  const headShort = headSha.slice(0, 7);
  for (const f of body.files) {
    if (!f.patch || typeof f.filename !== "string" || isSkippablePath(f.filename)) continue;
    const addedLines = parsePatchAddedLines(f.patch);
    // Findings are discarded - only the hit boolean matters. The
    // commit passed here is the window head; attribution happens in
    // the per-commit confirmation step, never from this scan.
    const found = scanLinesForSecrets({ path: f.filename }, addedLines, headShort);
    if (found.length > 0) return { outcome: "hit" };
  }
  return { outcome: "clean" };
}
