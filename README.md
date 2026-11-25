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
  dependencies, checked against [OSV.dev](https://osv.dev) (a free public
  database of known software flaws; npm / PyPI / crates.io / Go / RubyGems /
  Packagist / Maven / NuGet), with full advisory detail (a plain summary, a
  severity score, and the version that fixes it) for every advisory found,
  up to 50 per scan — any beyond that are listed with their advisory ID and
  a link.
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
  Streams a loading state first ("Scanning the repo… checking files, then
  history, then dependencies") while the ~15 s live scan runs.
- `/api/scan/[owner]/[repo]` — JSON report. `?full=1` returns the full report
  only when the requester is verified as the repo owner; otherwise it returns
  the public report. Errors carry honest statuses: 400 bad owner/repo format,
  404 repo not found or private, 429 GitHub rate limit, 504 scan timeout,
  502 GitHub upstream error.
- `/api/auth/*` — GitHub sign-in (Auth.js): `/api/auth/signin`,
  `/api/auth/callback/github`, `/api/auth/signout`, `/api/auth/session`.
  Returns 503 "not configured" until the OAuth App credentials are set.
- `/mcp` — MCP server for AI assistants (Streamable HTTP transport,
  stateless). `/api/mcp` is an alias for the same handler. See
  "Use with your AI assistant (MCP)" below.

## Use with your AI assistant (MCP)

GitSecure speaks the Model Context Protocol, so an LLM can scan a repo
for you. Canonical server URL: **`https://gitsecure.vercel.app/mcp`**
(`/api/mcp` works too). No sign-up, no API key. The home page has
copyable config snippets for Claude, Cursor, VS Code, and Windsurf/Cline
(the report page has a short version of the same section).

```json
{ "mcpServers": { "gitsecure": { "url": "https://gitsecure.vercel.app/mcp" } } }
```

Tools (all public reports only — see below):

- `scan_repo` (owner, repo) — run a live security scan, return the public
  report: score, grade, counts, summary, limits. Use when someone asks
  whether a repo is safe.
- `get_report` (owner, repo) — read or refresh the public report for a
  repo. Runs a fresh live scan each time (GitSecure never stores reports).
- `list_checks` (no args) — what GitSecure checks, in plain English, plus
  the honest limits. Use before a scan, or to explain a score.

**MCP returns public reports only, always.** No file names, line numbers,
secret fragments, vulnerability IDs, or framework versions ever leave over
MCP — there is no `full` parameter and no owner-mode flag. Full detail
stays owner-only via the signed-in web flow. A scan takes about 15 seconds;
owner/repo names are validated the same way as on the site, and a bad
name, a missing/private repo, or a GitHub rate limit comes back as a
plain-English error, never a stack trace. The endpoint is stateless (a
fresh server per request, no session state, no git binary needed — the
scan falls back to API patches when git is unavailable), so it works on
the Vercel serverless runtime. A plain `GET /mcp` is refused with a 4xx:
in stateless mode the server holds no SSE stream (MCP clients use POST).

Test it against a local production server (real protocol handshake with
the SDK client — initialize, tools/list, live `scan_repo` calls):

```bash
npm run build && npm start     # in one terminal
npm run test:mcp               # in another — 49 checks
```

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

## Honest limits

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
- **Dependency check:** up to 60 pinned dependencies per scan via OSV.dev
  (a free public database of known software flaws); full advisory detail (a
  plain summary, a severity score, and the version that fixes it) fetched for
  up to 50 advisories per scan — any beyond that are listed with their
  advisory ID and an osv.dev link. If OSV is unreachable the scan continues
  and says so.
- **Rate limits:** unauthenticated GitHub API is 60 requests/hour. A scan uses
  roughly 7 API calls plus raw file fetches.
- GitSecure is **not a replacement for GitHub Advanced Security**.

## Dogfooding note

Scanning GitSecure's own repo (`Squ1zM0/GitSecure`) returns score **0 / F**
with 6 secret findings — all known-fake: the test fixtures that are
deliberately detector bait (`.env` fixture, `hunter2hunter2` password,
fake Postgres URL in the test file), plus the official AWS example key in
an old README commit. No real secret is in the repo. The scanner does not
skip test files on purpose: real leaks hide in "just a test" files too, so
a scanner that ignored them would miss real ones.

(The repo scored 3 / F in the MVP-era note; it is 0 / F now because the
Phase 2 push added `package-lock.json` — 119 dependencies fingerprinted —
Tier 2 fixtures, and a fake `vite.config.ts`, which add framework,
dependency and Vite posture deductions plus unpinned-version deductions.
The 6 secret findings are unchanged. The change is in the repo's
contents, not the scanner.)

## Phase 3 Part A — functionality polish (built 2026-11-25, not pushed, not deployed)

No scanner logic, scores, or public/full split changed — polish only.
TechDirect still scans 83/B (verified locally, production server).

- **Loading state:** `src/app/[owner]/[repo]/loading.tsx` streams instantly
  ("Scanning the repo… Checking files… then the full history, then
  dependencies…") while the ~15 s live scan runs. Verified on the production
  server: report-page time-to-first-byte fell from ~22 s to ~0.05 s.
- **Home form:** button disables and reads "Scanning…" while navigating;
  pasted `github.com` / `git-secure.com` URLs are accepted with any trailing
  path (`/tree/main`, `/issues/…`, trailing slash, `.git`); owner/repo names
  are validated to letters, numbers, dots, hyphens and underscores with a
  plain-English error; empty input gets a helpful message. Logic covered by
  16 cases run against the shipped function (see below).
- **Honest scan errors:** `ScanError` in `src/lib/scan.ts` carries a kind +
  HTTP status — 400 bad owner/repo format (validated before any GitHub call),
  404 repo not found or private, 429 GitHub rate limit (429, or 403 with
  `x-ratelimit-remaining: 0`), 504 scan timeout (55 s race inside the 60 s
  route limit; GitHub fetch timeouts also map to 504), 502 GitHub upstream
  error. The scan API returns the status; the report page shows the matching
  plain-English message with a "Scan another repo" action. Caveat: the
  report *page* itself still returns HTTP 200 for a failed scan — Next.js
  App Router pages cannot set a response status; only the API carries the
  honest status.
- **Report page:** "Scan another repo" link at the top and a button at the
  bottom; the technical history-depth string is now plain English under the
  score ("History checked: 62 commits, newest first" — the full limits list
  below is unchanged); one plain line explains the score and what would raise
  it (`explainScore` in `src/lib/score.ts`).
- **Plain English:** "CVSS" and "OSV.dev" are explained in plain words on
  first use in the UI ("a free public database of known software flaws",
  "a severity score"); vulnerability lines now read as one plain sentence —
  what the flaw is, what it affects, and what to upgrade to. "Honest limits
  (Phase 2)" renamed to "Honest limits".
- **Rate limit:** not triggerable safely in testing (would need burning the
  unauthenticated quota); the 429 path is code-reviewed only, mapped from
  GitHub's 429 and rate-limit 403 responses.
- **Mobile:** verified at 360 px with a real headless-Chromium render of
  the production server (home, loading state, report, error page): no
  horizontal overflow on any page (`scrollWidth` 360 = viewport 360, zero
  overflowing elements), text readable, input full-width with the button
  stacked below, counts in a clean two-column grid. Screenshots in
  `/tmp/gitsecure-{home,loading,report,error}-360.png` (ephemeral — rerun
  `node /tmp/render-360.mjs` to reproduce while the prod server runs).
- **Verification (2026-11-25):** `npm run build` exit 0; `test:scanner`
  48/48, `test:history` 9/9, `test:owner-gate` 20/20, `test:techdirect`
  83/B, 62 history commits, ~15 s. Production server (`npm start`) checked
  by curl: home 200, TechDirect report 200 (TTFB 0.05 s), scan API 200
  (83/B), not-found API 404, bad-format API 400.

## Phase 3 Part B — MCP server for LLMs (built 2026-11-25, not pushed, not deployed)

No scanner logic, scores, or public/full split changed. TechDirect still
scans 83/B (verified locally and over MCP).

- **Endpoint:** `/mcp` (canonical) + `/api/mcp` (alias), Next.js App
  Router routes (`src/app/mcp/route.ts`, `src/app/api/mcp/route.ts`,
  handler in `src/lib/mcp.ts`). Official MCP TypeScript SDK
  `@modelcontextprotocol/sdk` **1.32.2** (exact pin, no caret) + `zod`
  4.3.5, Streamable HTTP transport via
  `WebStandardStreamableHTTPServerTransport` (web-standard Request/Response,
  fits App Router). Stateless: a fresh server + transport per request
  (`sessionIdGenerator: undefined`), JSON responses (`enableJsonResponse`)
  so a ~15 s scan comes back as one response; no in-memory session state,
  no git binary required (scan falls back to API patches). `maxDuration`
  60. Note: Next 16 with `cacheComponents` rejects the `runtime` and
  `dynamic` route segment configs — the routes export only `maxDuration`.
- **Tools:** `scan_repo` (owner, repo — live scan, public report),
  `get_report` (owner, repo — same public report, fresh scan each time,
  documented as read/refresh), `list_checks` (no args — the four checks
  in plain English plus honest limits). Descriptions say when to use each,
  what it returns, and what it does NOT return. Input schemas validate
  owner/repo with the same rules as the site; bad input, missing/private
  repos, and rate limits return plain-English errors, never a stack trace.
- **Public-only, always:** every MCP response goes through
  `toPublicReport`. No tool accepts a `full` parameter or any owner-mode
  flag. Proved by `npm run test:mcp`, which scans Squ1zM0/GitSecure
  (0/F, 6 known-fake findings) over MCP and asserts the response contains
  no file names, line numbers, or secret fragments.
- **Human view:** `src/components/McpSection.tsx` (copy buttons use
  `navigator.clipboard` with a textarea fallback and a "Copied" state).
  Full version on the home page (`src/app/page.tsx`): MCP server URL plus
  copyable config snippets for Claude, Cursor, VS Code, and Windsurf/Cline
  (snippets live in `src/lib/mcp-config.ts`, all valid JSON — the test
  parses each one), plus one plain line explaining the LLM gets the public
  score and counts only. Compact version on the report page: URL + Claude
  snippet + link back to the home page for the rest.
- **Verification (2026-11-25):** `npm run build` exit 0;
  `test:scanner` 48/48, `test:history` 9/9, `test:owner-gate` 20/20,
  `test:techdirect` 83/B (62 history commits, ~15 s), `test:mcp` 49/49
  against a local production server (`npm run build` + `npm start`):
  real SDK-client handshake (initialize), tools/list (3 tools, no `full`
  param on any), `list_checks`, `scan_repo` Squ1zM0/TechDirect 83/B
  (0 secrets, 4 vulns, public-only fields absent, no `js-yaml` package
  name), `scan_repo` Squ1zM0/GitSecure 0/F (6 secrets counted, no file
  names / line numbers / fragments), `get_report` TechDirect 83/B, bad
  format + missing repo plain-English errors with no stack trace, all
  four config snippets valid JSON, plain GET /mcp refused with a 4xx.
  Raw curl initialize on both `/mcp` and `/api/mcp` returns 200 with a
  proper JSON-RPC result. Home page renders the full MCP section (5 copy
  buttons), report page the compact one (2 copy buttons). No literal
  secret-pattern values committed (fixtures still use `__SECRET_n__`
  placeholders; test-assembled fakes only).
- **Limits that remain:** a scan over MCP takes the same ~15 s as on the
  web (one JSON response, no streaming progress); the MCP client timeout
  in the test is 120 s. A GET that asks for `text/event-stream` opens a
  standalone SSE stream the transport holds open — MCP clients use POST,
  so this is not probed. Live OAuth is still pending (see above), so the
  full view stays off in production; MCP never had a full view at all.
  Dogfood score note: GitSecure itself is 0/F now, not 3/F (see
  "Dogfooding note" above — Phase 2 push changed the repo's contents).

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
npm run test:mcp         # MCP end-to-end: needs a running production server
                         # (npm run build && npm start) — real SDK-client
                         # handshake, tools/list, live scan_repo calls for
                         # TechDirect (83/B) and GitSecure (0/F, public-only
                         # proof), error cases, snippet JSON validity —
                         # 49 checks. Set MCP_BASE_URL to test another server.
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
