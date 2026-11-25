# GitSecure

**Is this repo safe?** GitSecure is the security mirror for GitHub. Take any public
repo, swap `github.com` for `git-secure.com`, and get a plain-English security
report — no install, no sign-up.

```
github.com/Squ1zM0/TechDirect  →  git-secure.com/Squ1zM0/TechDirect
```

## What it checks (MVP)

- **Leaked secrets** — Discord and Slack webhooks, AWS keys, GitHub tokens, Stripe
  and OpenAI keys, database URLs, private keys, committed `.env` files, hardcoded
  passwords. Checked in current files **and in full history** (newest-first, via
  an ephemeral clone — a secret deleted from HEAD but still in an old commit is
  caught, up to the caps below).
- **Frameworks (Tiers 1–2)** — JS/TS (Next.js, React, Vue, Angular, Svelte, Vite,
  Express, Nest, Nuxt, Astro), Python (Django, Flask, FastAPI), Rust (Cargo /
  RustSec via OSV), Go (Gin, Echo, Fiber), Ruby (Rails, Sinatra), PHP (Laravel,
  Symfony, WordPress), Java/Kotlin (Spring Boot, Spring Framework, Kotlin),
  .NET (ASP.NET Core). Versions come from lockfiles where possible; unpinned (`*` /
  `latest`) versions are flagged; if a version cannot be determined, the report
  says so instead of guessing. Vite specifics: dev-server exposure, SSR, and
  `VITE_` variables leaking into the client bundle.
- **Dependency flaws** — known vulnerabilities in direct and transitive
  dependencies, checked against [OSV.dev](https://osv.dev) (npm / PyPI /
  crates.io / Go / RubyGems / Packagist / Maven / NuGet), with full advisory
  detail (summary, CVSS, fixed version) for every advisory found, up to 50 per
  scan — any beyond that are listed with their advisory ID and a link.
- **Security posture** — missing `SECURITY.md`, no Dependabot, `.gitignore` gaps,
  and risky GitHub Actions patterns (`pull_request_target`, `write-all`, secrets
  echoed into logs).

Every finding is plain English: what it is, what it lets an attacker do, and the
exact fix, in order.

## What you see — and what you don't

Everyone sees the **score (0–100) and the counts only**. Full detail (file names,
line numbers, redacted secret fragments, framework versions, vulnerability IDs)
is available to the repo owner only.

Secrets are **never shown in full** (fragment only: first 4 chars … last 2),
**never stored**, and **never live-validated** (the scanner never calls the
service a credential belongs to).

## Run it

```bash
npm install
npm run dev        # http://localhost:3000
npm run build      # production build (must pass before any push)
```

Optional env (server-side only, never in the repo):

- `GITHUB_TOKEN` — a GitHub token raises the API rate limit from 60 to 5,000
  requests/hour. Without it, scans may hit the unauthenticated limit.
- `GITSECURE_OWNER_MODE=true` — local/dev owner mode only (see below).
- `GITHUB_ID`, `GITHUB_SECRET`, `NEXTAUTH_SECRET`, `NEXTAUTH_URL` — GitHub
  OAuth App credentials for owner verification (see below). With none of
  these set, the full view stays off everywhere — that is the safe default.

## Routes

- `/` — home page, explains GitSecure, owner/repo input.
- `/[owner]/[repo]` — scan report for a public repo (public view by default).
- `/api/scan/[owner]/[repo]` — JSON report. `?full=1` returns the full report
  only when the requester is verified as the repo owner; otherwise it returns
  the public report.
- `/api/auth/*` — GitHub sign-in (Auth.js): `/api/auth/signin`,
  `/api/auth/callback/github`, `/api/auth/signout`, `/api/auth/session`.
  Returns 503 "not configured" until the OAuth App credentials are set.

## Owner verification (code complete, credentials pending — read this)

Owner verification is **implemented with real GitHub OAuth (Auth.js /
NextAuth v5, GitHub provider)** in `src/lib/auth.ts` + `src/lib/owner.ts`:
a signed-in user whose GitHub login matches the repo owner gets the full
report; everyone else (and signed-out users) gets the public score + counts
only. The gate logic is unit-tested with session mocks
(`npm run test:owner-gate`, 20 checks). The local/dev env flag
`GITSECURE_OWNER_MODE=true` still works for local testing only.

**Live OAuth is NOT wired up yet** — it needs a GitHub OAuth App, which
only Freddy can create. Until then the full view stays off in production
(safe default: with no OAuth env vars set, the auth routes answer 503 and
every scan returns the public report). Exact steps for Freddy:

1. GitHub → Settings → Developer settings → OAuth Apps → New OAuth App.
   - Application name: `GitSecure`
   - Homepage URL: `https://gitsecure.vercel.app/`
   - Authorization callback URL: `https://gitsecure.vercel.app/api/auth/callback/github`
2. Copy the Client ID → `GITHUB_ID`; generate a Client Secret → `GITHUB_SECRET`.
3. Generate a random secret for `NEXTAUTH_SECRET` (e.g. `openssl rand -base64 32`).
   Set `NEXTAUTH_URL=https://gitsecure.vercel.app/`.
4. In Vercel → GitSecure project → Settings → Environment Variables, add all
   four (`GITHUB_ID`, `GITHUB_SECRET`, `NEXTAUTH_SECRET`, `NEXTAUTH_URL`),
   then redeploy.
5. Verify: visit a repo page as the repo owner, sign in with GitHub, open
   `?full=1` — the owner banner appears. Sign out (or visit as a different
   user) — the public view returns. No credentials are ever hardcoded or
   committed; env vars are the only place they live.

## Honest limits (Phase 2)

- **History depth:** full history, newest-first, via an ephemeral `git clone`
  into `/tmp` (deleted after the scan). Caps: **1,000 commits / 50 MB of
  patches / 45 s**. Measured on Squ1zM0/TechDirect (62 commits, 40.8 MB of
  patches): history step 6–12 s, whole scan ~15 s — inside the 60 s route
  limit. A secret in a very old commit of a huge repo may still be missed,
  and the report says when a cap was hit. If the runtime has no `git`
  binary, or the clone fails, the scan falls back to API patches of the
  5 most recent commits and says so in the report's limits.
- **HEAD limits:** max 250 files (fetched 10 at a time), 200 KB per file,
  3 MB total; binary, `dist`, `node_modules` and `.next` skipped. Manifests
  and configs are scanned first.
- **Findings caps:** at most 100 secret findings and 100 advisories listed
  per report (the report says how many more were found).
- **Dependency check:** up to 60 pinned dependencies per scan via OSV.dev;
  full advisory detail (summary, CVSS, fixed version) fetched for up to 50
  advisories per scan — any beyond that are listed with their advisory ID
  and an osv.dev link. If OSV is unreachable the scan continues and says so.
- **Rate limits:** unauthenticated GitHub API is 60 requests/hour. A scan uses
  roughly 7 API calls plus raw file fetches.
- GitSecure is **not a replacement for GitHub Advanced Security**.

## Dogfooding note

Scanning GitSecure's own repo (`Squ1zM0/GitSecure`) returns score **3 / F**
with 6 secret findings — all known-fake: the test fixtures that are
deliberately detector bait (`.env` fixture, `hunter2hunter2` password,
fake Postgres URL in the test file), plus the official AWS example key in
an old README commit. No real secret is in the repo. The scanner does not
skip test files on purpose: real leaks hide in "just a test" files too, so
a scanner that ignored them would miss real ones.

## Tests

```bash
npm run test:scanner     # synthetic fixture with FAKE planted secrets only
                         # (tests/fixtures/fake-repo + fake-repo-tier2) —
                         # 48 checks: detection, redaction, Tier 1 + Tier 2
                         # fingerprinting, and the public/full split
npm run test:history     # full-history regression: a fake secret planted in
                         # an old commit of a throwaway local repo, removed
                         # from HEAD — 9 checks, clone + log + detect
npm run test:owner-gate  # GitHub OAuth gate logic with session mocks, no
                         # network — 20 checks, incl. fail-closed default
npm run test:techdirect  # live scan of the real public repo Squ1zM0/TechDirect
                         # (score 83/B, 62 history commits, ~15 s)
```

The fixture uses invented credentials only (including the official AWS example
key, assembled in memory by the test from fragments). Never put a real leaked secret in a test, and never commit a literal secret-pattern value, even a fake one: GitHub push protection blocks those on push.

## Tech

Next.js 16 (App Router) + TypeScript + React 19 + Auth.js (NextAuth v5,
GitHub provider). No paid services, no external database. Deployable on
the Vercel free tier.

## Project notes

Full spec and decisions: `GITSECURE.md`. Repo: https://github.com/Squ1zM0/GitSecure
(public, main). Domain: git-secure.com (not purchased — do not buy without a
separate explicit go-ahead; start on a Vercel subdomain).
