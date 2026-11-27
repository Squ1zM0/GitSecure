// GitHub rate-limit reset time (Phase 15, rate-limit recovery).
//
// Freddy hit the "GitHub's request limit was hit" page live and it
// stranded him: only a "Scan another repo" button, no sense of how
// long to wait. The limit is the shared unauthenticated GitHub quota
// (60 requests/hour from the egress IP - Freddy's standing ruling
// from Phase 6 still holds: no GITHUB_TOKEN, do not raise it). What
// this module does is make the dead-end page helpful instead: when
// GitHub's own response says when the limit resets, the page says
// so honestly; when it cannot know, it says "resets within the
// hour" and never invents a countdown.
//
// Pure functions, client-safe (no node imports): the page, the scan
// API, the chunk route, and ScanProgress all share them, so the
// wording can never drift between the surfaces.
//
// Sources, in order of authority:
//   - `retry-after` (seconds): GitHub sends it on secondary limits.
//   - `x-ratelimit-reset` (epoch seconds): the primary quota's reset.
// A reset time in the past (clock skew, or an already-reset limit)
// counts as unknown - the copy falls back to "within the hour".

/** Read a rate-limit reset time (epoch ms) from a response's headers.
 *  Returns null when GitHub did not say, or the time is not in the
 *  future. `now` is injectable for tests; production passes Date.now(). */
export function parseResetAtMs(
  headers: { get(name: string): string | null },
  now: number = Date.now(),
): number | null {
  const candidates: number[] = [];
  const retryAfter = headers.get("retry-after");
  if (retryAfter !== null) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds > 0) candidates.push(now + seconds * 1000);
  }
  const reset = headers.get("x-ratelimit-reset");
  if (reset !== null) {
    const epochSeconds = Number(reset);
    if (Number.isFinite(epochSeconds) && epochSeconds > 0) candidates.push(epochSeconds * 1000);
  }
  const future = candidates.filter((t) => t > now);
  return future.length > 0 ? Math.min(...future) : null;
}

/** Whole minutes until the reset, rounded up, at least 1. Null when
 *  the reset time is unknown. */
export function resetMinutes(resetAtMs: number | null, now: number = Date.now()): number | null {
  if (resetAtMs === null) return null;
  return Math.max(1, Math.ceil((resetAtMs - now) / 60000));
}

/** The honest reset phrase: "resets in about N minutes" when GitHub
 *  said when, "resets within the hour" when it did not. */
export function resetPhrase(resetAtMs: number | null, now: number = Date.now()): string {
  const minutes = resetMinutes(resetAtMs, now);
  return minutes === null
    ? "resets within the hour"
    : `resets in about ${minutes} minute${minutes === 1 ? "" : "s"}`;
}

/** Page-level rate-limit body: the dead-end page Freddy hit. Keeps
 *  the existing honest tone ("Too many requests went to GitHub at
 *  once…") and adds the wait, honestly known or hourly. */
export function rateLimitBody(resetAtMs: number | null, now: number = Date.now()): string {
  return `Too many requests went to GitHub at once, so this scan couldn't run right now. GitHub's request limit ${resetPhrase(resetAtMs, now)} - try this scan again then.`;
}

/** Chunk-driver rate-limit copy (ScanProgress): the scan paused
 *  mid-flight rather than failing before it started, so it says
 *  where the scan resumes from as well as how long to wait. */
export function rateLimitPausedBody(resetAtMs: number | null, now: number = Date.now()): string {
  return `GitHub's request limit was hit, so the scan paused here. The limit ${resetPhrase(resetAtMs, now)} - retry then, and the scan picks up from the last finished chunk.`;
}
