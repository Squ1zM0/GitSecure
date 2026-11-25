// Auth.js route handlers: /api/auth/signin, /api/auth/callback/github,
// /api/auth/signout, /api/auth/session, ... — provided by NextAuth.
// The GitHub provider is only active when GITHUB_ID / GITHUB_SECRET are
// set (see src/lib/auth.ts). With no OAuth env vars, sign-in has no
// provider and every request gets the public report only — so these
// routes answer 503 "not configured" instead of letting Auth.js throw
// its UntrustedHost / MissingSecret configuration errors.
import { NextResponse } from "next/server";
import { handlers } from "@/lib/auth";
import { isOAuthConfigured } from "@/lib/owner";

function notConfigured() {
  return NextResponse.json(
    { error: "GitHub OAuth is not configured on this deployment. The repo owner must create a GitHub OAuth App and set GITHUB_ID, GITHUB_SECRET, NEXTAUTH_SECRET and NEXTAUTH_URL — see README.md." },
    { status: 503 },
  );
}

export const GET = isOAuthConfigured() ? handlers.GET : notConfigured;
export const POST = isOAuthConfigured() ? handlers.POST : notConfigured;
