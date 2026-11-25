// GitHub OAuth owner verification (Phase 2 — CODE COMPLETE, CREDENTIALS
// PENDING). Real Auth.js (NextAuth v5) with the GitHub provider.
//
// How it works: a signed-in user whose GitHub login matches the repo owner
// gets the full report; everyone else (and signed-out users) gets the
// public score + counts only. The GitHub login is taken from the OAuth
// profile at sign-in and stored in the session JWT — never from a query
// param, cookie, or client input.
//
// Credentials live ONLY in env vars (GITHUB_ID, GITHUB_SECRET,
// NEXTAUTH_SECRET, NEXTAUTH_URL) — never hardcoded, never committed.
// Production default is safe: with no OAuth env vars set, the GitHub
// provider is not configured, auth() always returns null, and the full
// view stays off (see isOAuthConfigured in owner.ts).
//
// LIVE OAUTH IS NOT TESTED YET: it needs Freddy to create a GitHub OAuth
// App and set the four env vars in Vercel (exact steps in README.md).
// The gate logic itself is unit-tested with session mocks in
// scripts/test-owner-gate.ts (`npm run test:owner-gate`).

import NextAuth, { type DefaultSession } from "next-auth";
import GitHub from "next-auth/providers/github";

declare module "next-auth" {
  interface Session {
    user: { githubLogin?: string } & DefaultSession["user"];
  }
}

declare module "@auth/core/jwt" {
  interface JWT {
    githubLogin?: string;
  }
}

const githubConfigured = Boolean(process.env.GITHUB_ID && process.env.GITHUB_SECRET);

export const { handlers, auth, signIn, signOut } = NextAuth({
  // No providers at all when the OAuth App credentials are absent: the
  // sign-in page has nothing to offer and every session stays null.
  // This is the safe production default, not a misconfiguration.
  providers: githubConfigured ? [GitHub] : [],
  callbacks: {
    async jwt({ token, profile }) {
      const login = (profile as { login?: string } | undefined)?.login;
      if (typeof login === "string" && login.length > 0) token.githubLogin = login;
      return token;
    },
    async session({ session, token }) {
      session.user.githubLogin = typeof token.githubLogin === "string" ? token.githubLogin : undefined;
      return session;
    },
  },
});
