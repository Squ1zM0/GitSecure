// Plain-English error copy for a failed scan (Phase 16).
//
// The report page used to own this mapping (src/app/[owner]/[repo]/page.tsx):
// it ran the scan server-side and rendered the error page itself. Phase 16
// renders the progress shell immediately and the scan runs client-side, so
// the client (ScanProgress) needs the same words when a scan fails before
// any progress was made - and the page still needs them for a bad
// owner/repo name, the one failure it can still know server-side. One
// module, shared by both, so the wording can never drift between the
// surfaces. Pure functions, client-safe (no node imports).
import { rateLimitBody } from "./rate-limit";

/** Every kind a scan failure can carry, from the scan engine (ScanError)
//  plus "unknown" for a failure the route could not classify. */
export type ScanErrorKind =
  | "not-found"
  | "private"
  | "rate-limit"
  | "timeout"
  | "bad-format"
  | "head-moved"
  | "upstream"
  | "unknown";

/** Plain-English title + body for a scan that failed outright. The API
 *  carries the matching HTTP status; the page and the progress card show
 *  the same words. */
export function scanErrorCopy(
  kind: ScanErrorKind,
  owner: string,
  repo: string,
  resetAtMs: number | null = null,
): { title: string; body: string } {
  switch (kind) {
    case "not-found":
      return {
        title: `Couldn't find ${owner}/${repo}`,
        body: "We couldn't find that repo on GitHub, or it is private. GitSecure only scans public repos - check the spelling of the owner and repo names, and make sure the repo is public.",
      };
    case "private":
      return {
        title: `${owner}/${repo} is private`,
        body: "That repo is private, and GitSecure only scans public repos.",
      };
    case "rate-limit":
      // Phase 15 (rate-limit recovery): the page Freddy hit live
      // stranded him with no sense of the wait. When GitHub's
      // response said when the limit resets, say so honestly ("in
      // about N minutes"); when it did not, say "within the hour"
      // - never an invented countdown.
      return {
        title: "GitHub's request limit was hit",
        body: rateLimitBody(resetAtMs),
      };
    case "timeout":
      return {
        title: "GitHub took too long to answer",
        body: "A request to GitHub timed out, so this scan couldn't run right now. The scan itself has no time limit - try again in a bit.",
      };
    case "bad-format":
      return {
        title: "That doesn't look like a valid repo",
        body: "Owner and repo names can only use letters, numbers, dots, hyphens and underscores - check for typos or extra characters.",
      };
    case "head-moved":
      return {
        title: `The repo changed while scanning ${owner}/${repo}`,
        body: "New commits landed while the scan was running, so the saved progress belongs to the previous HEAD. Start a fresh scan for the new HEAD.",
      };
    default:
      return {
        title: `Couldn't scan ${owner}/${repo}`,
        body: "Something went wrong on our side. Try again in a bit.",
      };
  }
}

/** The retry button wording for a terminal scan error. The rate-limit
 *  case gets its own label ("Try this scan again") - same mechanism as
 *  the other error states, its own wording. */
export function scanErrorRetryLabel(kind: ScanErrorKind): string {
  return kind === "rate-limit" ? "Try this scan again" : "Retry this scan";
}
