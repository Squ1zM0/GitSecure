// Owner-mode gate — STUBBED in the MVP, honestly.
// Full GitHub OAuth owner verification is NOT built yet. The full report is
// only served when the server-side env var GITSECURE_OWNER_MODE is "true"
// (local/dev use: `GITSECURE_OWNER_MODE=true npm run dev`). There is no
// query-param bypass, no hardcoded owner, and no fake OAuth flow.
// In production (env unset) every request gets the public report only:
// score + counts, no detail. See README.md "Owner verification (stub)".
export function isOwnerModeEnabled(): boolean {
  return process.env.GITSECURE_OWNER_MODE === "true";
}
