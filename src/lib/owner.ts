// Owner gate (Phase 2): real GitHub OAuth via Auth.js — see src/lib/auth.ts.
//
//   canViewFull(owner) is true when EITHER:
//     1. the local/dev env flag GITSECURE_OWNER_MODE=true is set (local
//        testing only — never set in production), OR
//     2. the signed-in GitHub user's login matches the repo owner
//        (case-insensitive).
//   Otherwise false: public score + counts only.
//
// Production default is safe: with no OAuth env vars set, the GitHub
// provider is not configured, auth() returns null, and the full view
// stays off. There is no query-param bypass, no hardcoded owner, and no
// fake OAuth flow. Live OAuth is code-complete but credentials-pending
// (Freddy must create the GitHub OAuth App and set the four env vars —
// exact steps in README.md). The pure gate logic is tested with session
// mocks in scripts/test-owner-gate.ts.

export function isOwnerModeEnabled(): boolean {
  return process.env.GITSECURE_OWNER_MODE === "true";
}

/** True when all four OAuth env vars are present (credentials configured). */
export function isOAuthConfigured(): boolean {
  return Boolean(
    process.env.GITHUB_ID && process.env.GITHUB_SECRET && process.env.NEXTAUTH_SECRET && process.env.NEXTAUTH_URL,
  );
}

export type OwnerSession = { user?: { githubLogin?: string } } | null;

/** Pure gate: does this session belong to the repo owner? */
export function isOwnerSession(session: OwnerSession, owner: string): boolean {
  const login = session?.user?.githubLogin;
  if (!login) return false;
  return login.toLowerCase() === owner.toLowerCase();
}

/** Full access check for a repo owner string. Server-side only. */
export async function canViewFull(owner: string): Promise<{ allowed: boolean; login: string | null }> {
  if (isOwnerModeEnabled()) return { allowed: true, login: null };
  // OAuth not configured at all: do not even call auth() — Auth.js would
  // throw UntrustedHost/MissingSecret on every scan and spam the logs.
  // The full view simply stays off (safe production default).
  if (!isOAuthConfigured()) return { allowed: false, login: null };
  try {
    const { auth } = await import("./auth");
    const session = await auth();
    const login = session?.user?.githubLogin ?? null;
    return { allowed: isOwnerSession(session, owner), login };
  } catch {
    // Auth misconfigured or unavailable: fail closed — public view only.
    return { allowed: false, login: null };
  }
}
