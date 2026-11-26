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
  severity score, and the version that fixes it) fetched for every advisory
  found, in batches inside a time budget — any advisory past the budget is
  still listed, with its advisory ID and a link, and the report says how
  many got full detail. Every advisory found is listed; there is no cap.
- **Security posture** — missing `SECURITY.md`, no Dependabot, `.gitignore` gaps,
  and risky GitHub Actions patterns (`pull_request_target`, `write-all`, secrets
  echoed into logs).

Every finding is plain English: what it is, what it lets an attacker do, and the
exact fix, in order.

## What you get

Everyone gets the **full report** — the score (0–100) and counts, plus the
full detail: file names, line numbers, redacted secret fragments, framework
versions, and vulnerability IDs with the version that fixes each one. No
sign-up, no login. That works because GitSecure only scans **public repos**,
so the detail is information already public in the repo.

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

No login is needed for the full view — there is no sign-in flow and no
env var gates it.

## Routes

- `/` — home page, explains GitSecure, owner/repo input.
- `/[owner]/[repo]` — full scan report for a public repo. Streams a loading
  state first ("Scanning the repo… checking files, then history, then
  dependencies") while the ~15 s live scan runs.
- `/api/scan/[owner]/[repo]` — the full JSON report, same detail as the page.
  No sign-in, no `?full` flag. Errors carry honest statuses: 400 bad
  owner/repo format, 404 repo not found or private, 429 GitHub rate limit,
  504 scan timeout, 502 GitHub upstream error.
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

Tools (all return the full report — see below):

- `scan_repo` (owner, repo) — run a live security scan, return the full
  report: score, grade, counts, summary, limits, and the full detail
  (file names, line numbers, redacted secret fragments, framework
  versions, vulnerability IDs). Use when someone asks whether a repo is safe.
- `get_report` (owner, repo) — read or refresh the full report for a
  repo. Runs a fresh live scan each time (GitSecure never stores reports).
- `list_checks` (no args) — what GitSecure checks, in plain English, plus
  the scan notes. Use before a scan, or to explain a score.

**MCP returns the full report, like the web flow.** Secrets are still
redacted fragments only — never shown in full. There is no `full`
parameter and no login. A scan takes about 15 seconds; owner/repo names
are validated the same way as on the site, and a bad name, a missing/private
repo, or a GitHub rate limit comes back as a plain-English error, never a
stack trace. The endpoint is stateless (a fresh server per request, no
session state, no git binary needed — the scan falls back to API patches
when git is unavailable), so it works on the Vercel serverless runtime.
A plain `GET /mcp` is refused with a 4xx: in stateless mode the server
holds no SSE stream (MCP clients use POST).

Test it against a local production server (real protocol handshake with
the SDK client — initialize, tools/list, live `scan_repo` calls):

```bash
npm run build && npm start     # in one terminal
npm run test:mcp               # in another — 49 checks
```

## No login

There is no sign-in flow and no owner verification. Phase 4 (2026-11-25)
removed the GitHub OAuth owner gate entirely — the Auth.js route
(`src/app/api/auth`), `src/lib/auth.ts`, and `src/lib/owner.ts` are
deleted, and `next-auth` is no longer a dependency. Rationale: the site
only scans public repos, so the full detail is information already public
in the repo. The redaction rule did not change: a secret is never shown
in full.

## Scan limits (developer notes — not shown on the site)

- **History depth:** full history, newest-first, via an ephemeral `git clone`
  into `/tmp` (deleted after the scan). Caps: **1,000 commits / 50 MB of
  patches / 45 s**. Measured on Squ1zM0/TechDirect (62 commits, 40.8 MB of
  patches): history step 6–12 s, whole scan ~15 s — inside the 60 s route
  limit. A secret in a very old commit of a huge repo may still be missed,
  and the report says when a cap was hit. If the runtime has no `git`
  binary, or the clone fails, the scan falls back to API patches of the
  5 most recent commits and says so in the report's limits.
- **HEAD scan: unlimited.** Every file in the HEAD tree is scanned,
  manifests and configs first (fetched 10 at a time). There is no
  file-count cap and no per-file or total size cap — no 250, no 1,000,
  no 5,000. Binary, `dist`, `node_modules` and `.next` paths are skipped:
  generated/vendored paths, not source files. The 60 s route limit and
  GitHub rate limits still exist, so a gigantic repo may hit a time/rate
  boundary — if it does, the report says plainly how many files were
  actually scanned and that it stopped for time/rate, never pretending
  it scanned everything.
- **No result-count caps (Phase 5).** Every secret finding, every
  dependency, every advisory, every posture and framework finding is
  listed — no 100-secret cap, no 200-dependency slice, no 100-advisory
  cap. The report page renders huge lists progressively (100 at a time
  with "Show more" / "Show all"), with collapsible groups, filters, and
  a file map — the data is never capped to make the page fit.
- **Dependency check (Phase 5):** every pinned dependency is asked about
  via OSV.dev, in batches of 1,000 per query, inside a 15 s query budget;
  full advisory detail is fetched for every advisory found, in batches
  of 8 inside a 12 s detail budget. A repo with thousands of deps (e.g.
  DefinitelyTyped, 9,401) cannot always be fully queried inside the
  55 s scan timeout — if a budget runs out, the report says plainly how
  many deps were checked and how many advisories got full detail. A
  budget never drops a finding from the list. If OSV is unreachable the
  scan continues and says so.
- **Rate limits:** unauthenticated GitHub API is 60 requests/hour. A scan uses
  roughly 7 API calls plus raw file fetches.
- GitSecure is **not a replacement for GitHub Advanced Security**.

## Dogfooding note

Scanning GitSecure's own repo (`Squ1zM0/GitSecure`) returns score **0 / F**
with 8 secret findings — all known-fake: the test fixtures that are
deliberately detector bait (`.env` fixture, `hunter2hunter2` password,
fake Postgres URL in the test files), plus the official AWS example key in
an old README commit. No real secret is in the repo. The scanner does not
skip test files on purpose: real leaks hide in "just a test" files too, so
a scanner that ignored them would miss real ones.

(The repo scored 3 / F in the MVP-era note, then 0 / F after the Phase 2
push added `package-lock.json` — 119 dependencies fingerprinted — Tier 2
fixtures, and a fake `vite.config.ts`. It was 1 / F in Phase 4: deductions
76 (secrets: 4 high + 2 medium) + 19 (posture) + 4 (2 unpinned deps × 2)
= 99, with 6 secrets counted. It is 0 / F in Phase 5, for two honest
reasons, measured 2026-11-25 against remote head e99ab65b: (a) 8 secrets,
not 6 — the fake database URL in the test scripts is found at HEAD *and*
in the older commits that introduced it (same line, different commit = a
distinct finding); (b) 196 vulnerabilities — Phase 5 removed the 60-dep
OSV query cap, so all 202 pinned deps are now checked, including the
Tier 2 fixtures with deliberately old versions (Django 4.2.0, Laravel,
Echo, Fiber…), which carry many real advisories. Deductions far exceed
100, so the score floors at 0. The change is the scanner now reporting
everything it finds, not a regression.)

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
  (83/B), not-found API 404, bad-format API 400. (The owner gate and its
  test were removed in Phase 4 — see below.)

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
- **Tools:** `scan_repo` (owner, repo — live scan, full report),
  `get_report` (owner, repo — same full report, fresh scan each time,
  documented as read/refresh), `list_checks` (no args — the four checks
  in plain English plus scan notes). Descriptions say when to use each,
  what it returns, and what it does NOT return. Input schemas validate
  owner/repo with the same rules as the site; bad input, missing/private
  repos, and rate limits return plain-English errors, never a stack trace.
- **Full reports over MCP (Phase 4):** MCP used to return public-only
  reports through `toPublicReport`, with no file names, line numbers, or
  secret fragments. Phase 4 flipped it: MCP returns the full report, like
  the web flow — secrets still redacted fragments only. `npm run test:mcp`
  now scans Squ1zM0/GitSecure (0/F, 8 known-fake findings) over MCP and
  asserts the response carries the full detail while containing no full
  fake secret.
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
  placeholders; test-assembled fakes only). (The owner gate, its test,
  and the public-only MCP rule were removed in Phase 4 — see below.)
- **Limits that remain:** a scan over MCP takes the same ~15 s as on the
  web (one JSON response, no streaming progress); the MCP client timeout
  in the test is 120 s. A GET that asks for `text/event-stream` opens a
  standalone SSE stream the transport holds open — MCP clients use POST,
  so this is not probed. Dogfood score note: GitSecure itself is 0/F now,
  not 3/F (see "Dogfooding note" above — Phase 2 push changed the repo's
  contents).

## Tests

```bash
npm run test:scanner     # synthetic fixture with FAKE planted secrets only
                         # (tests/fixtures/fake-repo + fake-repo-tier2) —
                         # 68 checks: detection, redaction, Tier 1 + Tier 2
                         # fingerprinting, the Phase 4 full report, Phase 5
                         # 150-finding no-cap proof + score floor + nav links
npm run test:history     # full-history regression: a fake secret planted in
                         # an old commit of a throwaway local repo, removed
                         # from HEAD — 9 checks, clone + log + detect
npm run test:public-full # Phase 4: no login flow, no owner gate, no
                         # "Honest limits" copy anywhere in src; no file-count
                         # cap in the scanner; full detail + redaction —
                         # 56 checks, no network (incl. Phase 5 no-cap and
                         # navigation source checks)
npm run test:techdirect  # live scan of the real public repo Squ1zM0/TechDirect
                         # (score 83/B, 62 history commits, filesScanned =
                         # full scannable tree — 2,802, ~12 s via tarball)
npm run test:mcp         # MCP end-to-end: needs a running production server
                         # (npm run build && npm start) — real SDK-client
                         # handshake, tools/list, live scan_repo calls for
                         # TechDirect (83/B, full detail) and GitSecure
                         # (0/F, 8 secrets, full detail, no full fake
                         # secret), error cases, snippet JSON validity —
                         # 51 checks. Set MCP_BASE_URL to test another server.
```

The fixture uses invented credentials only (including the official AWS example
key, assembled in memory by the test from fragments). Never put a real leaked secret in a test, and never commit a literal secret-pattern value, even a fake one: GitHub push protection blocks those on push.

## Tech

Next.js 16 (App Router) + TypeScript + React 19. No paid services, no
external database, no auth library (Phase 4 removed NextAuth — there is
no login flow). Deployable on the Vercel free tier.

## Phase 4 — full report for everyone + unlimited file scan (built 2026-11-25)

Freddy's word, same day: the site only works on public repos, so give ALL
the information to ANY user that calls — no login flow. And remove the
"Honest limits" section from the site. Plus: the file scan is unlimited —
NOT 250, and NOT a higher cap either. No file-count cap at all.

- **Owner gate removed, everywhere.** Scan API returns the full report to
  anyone (no sign-in, no `?full` flag, no owner check). Report page shows
  the full detail to anyone. MCP `scan_repo` / `get_report` return the full
  report too. Deleted: `src/lib/auth.ts`, `src/lib/owner.ts`,
  `src/app/api/auth/[...nextauth]/route.ts`, and the `next-auth`
  dependency (lockfile re-synced). `src/lib/types.ts` has one report shape
  now (`FullReport`); `toPublicReport` is gone. Home "What you see" card
  rewritten as "What you get"; footer, MCP copy, README and GITSECURE.md
  updated — nothing on the site promises a login-gated view anymore.
- **"Honest limits" section removed** from the home page and everywhere in
  the UI. Scan limits live in code comments and developer docs only now
  (README "Scan limits" section above, `src/lib/scan.ts` header).
- **Unlimited HEAD scan.** Removed `MAX_FILES = 250`, `MAX_FILE_BYTES =
  200_000`, `MAX_TOTAL_BYTES = 3_000_000` and the `slice(0, MAX_FILES)` —
  the scan now reads the whole non-skipped tree, manifests and configs
  first. Binary / dist / node_modules / `.next` skipping stays
  (not source files, not a cap). GitHub tree pagination: the recursive
  tree call returns the whole tree in one response (up to 100k entries);
  a truncated flag is reported honestly. Files arrive via ONE tarball
  download (codeload) instead of one HTTPS request per file — measured:
  2,802 separate raw fetches took ~120 s no matter the concurrency
  (raw.githubusercontent.com answers ~25 requests/s from one client),
  while the 1.7 MB TechDirect tarball downloads in ~1.4 s; whole scan
  ~12 s. If the tarball is unavailable the scan falls back to per-file
  fetches and still scans everything, just slower. A 55 s scan timeout
  still exists inside the 60 s route limit — on timeout the report says
  how many files had been fetched, never pretending it finished.
  History caps unchanged (1,000 commits / 50 MB / 45 s).
- **Redaction unchanged and re-tested:** secrets are still fragments only.
  Proved by `test:scanner` (full-report checks), `test:public-full`
  (fixture scan, no full fake secret), and `test:mcp` (GitSecure dogfood
  over MCP, no full fake secret).
- **Verification (2026-11-25):** `npm run build` exit 0; `test:scanner`
  56/56, `test:history` 9/9, `test:public-full` 32/32, `test:techdirect`
  83/B with filesScanned = 2,802 (full scannable tree, proved against an
  independent tree-API count), whole scan ~12 s via the tarball path;
  `test:mcp` 49/49 against a local production server. Pushed to main;
  live checks below in GITSECURE.md.

## Phase 5 — no result-count caps + navigation for huge reports (built 2026-11-25)

Freddy's word, from a live DefinitelyTyped report (61,814 files, 9,401
dependencies, grade F, "100 possible leaked secrets"): "Shouldn't be
capped at 100." So no result list is capped any more, and the report
page grew real navigation for lists with hundreds to thousands of
findings.

- **Secrets: no cap.** Removed the `slice(0, 100)` on the deduped
  findings in `src/lib/scan.ts` (extracted as exported `dedupeSecrets`,
  so the test proves a 150-finding set comes back whole). HEAD and
  history findings are all listed, with file, line, type, and redacted
  fragment; `counts.secrets` is the true total. Same for the history
  path — history findings were only ever truncated by that same slice.
- **Advisories: no cap.** Removed `VULN_CAP = 100` in `src/lib/osv.ts` —
  every advisory OSV returns is listed.
- **Dependencies: no cap.** Removed the `deps.slice(0, 200)` in the
  report assembly — all dependencies are listed (and the report page
  now has a Dependencies section, which it did not before).
- **Posture / frameworks:** were never capped; verified by grep, still
  are not. The only remaining `slice(0, 5)` anywhere is inside one
  VITE_ posture detail string, which lists the first 5 variable names
  and says "+N more" — an honest inline summary, not a findings cap.
- **OSV fetch budgets (not caps).** The old 60-dep query slice and the
  fixed 50-detail cap are gone. Queries now run in batches of 1,000
  (measured: ~3 s per 1,000-query batch vs ~1.5 s per 100-query batch)
  inside a 15 s budget; detail fetches run in batches of 8 inside a
  12 s budget for every unique advisory ID. A budget can leave an
  advisory ID-only or a dep unchecked for flaws, but it never drops a
  finding, and the report says plainly how many deps were checked and
  how many advisories got full detail. Consequence, measured: the
  GitSecure dogfood scan now finds 196 vulnerabilities (was a handful)
  because all 202 pinned deps are checked, including the Tier 2
  fixtures with deliberately old versions — and the dogfood score moved
  1/F → 0/F, honestly.
- **Score:** `computeScore` already clamped 0–100; verified with 150
  critical secrets → 0/F, never negative, never NaN. DefinitelyTyped
  stays 0/F, now with everything listed.
- **Report-page navigation** (`src/components/ReportLists.tsx`,
  link helpers in `src/lib/links.ts`): collapsible groups by secret
  type / advisory / file (counts shown, collapsed by default when the
  list is large); dropdown filters for type and severity plus text
  search by file / advisory / package / name (counts shown are always
  the true filtered and total counts); a Map view — an SVG spider of
  the top 24 files by finding count around the repo node, plus a paged
  chip list of all files with secrets (one node per file, never one per
  finding, so it stays fast at phone width); every secret row links to
  the exact file and line on GitHub (`blob/{branch or commit}/{file}
  #L{line}`, history findings link to their commit), every
  vulnerability links to its OSV.dev advisory page, and every finding
  has an in-page anchor (`#secret-12`, …) with a copy-link button — a
  shared anchor link opens the page with that finding expanded and
  scrolled into view, even past the first 100.
- **Redaction unchanged and re-tested:** fragments only, including in
  map tooltips and link labels (tooltips carry file + count only).
  Proved by `test:scanner` (150-finding report, no full fake secret),
  `test:public-full`, `test:mcp` (dogfood over MCP, no full fake
  secret), and a render-to-string check of the map.
- **Verification (2026-11-25):** `npm run build` exit 0;
  `test:scanner` 68/68, `test:history` 9/9, `test:public-full` 56/56,
  `test:techdirect` 83/B with filesScanned = 2,802, `test:mcp` 51/51
  against a local production server. Live (after push, commit
  7ed620e0): DefinitelyTyped API 200, 0/F, **403 secrets listed**,
  61,814 files, 9,401 dependencies; TechDirect API still 83/B.
  Full live numbers in GITSECURE.md.

## Project notes

Full spec and decisions: `GITSECURE.md`. Repo: https://github.com/Squ1zM0/GitSecure
(public, main). Domain: git-secure.com (not purchased — do not buy without a
separate explicit go-ahead; start on a Vercel subdomain).
