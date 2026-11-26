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
  found. Every advisory found is listed; there is no cap, and no time
  budget either — the scan runs as a background job (Phase 8), so the
  flaw check covers every pinned dependency and details every advisory.
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
  dependencies") while the ~15 s live scan runs. A large repo that is
  still running after the ~50 s fast-path wait shows live progress
  instead (files and commits scanned so far) and polls until the job
  finishes — it never times out.
- `/api/scan/[owner]/[repo]` — the full JSON report, same detail as the page.
  No sign-in, no `?full` flag. A small repo answers 200 in one request;
  a large repo answers **202 with a `jobId` and live progress** — poll
  `GET /api/scan/jobs/{jobId}` until the job is done (200, report
  included) or errors. Errors carry honest statuses: 400 bad
  owner/repo format, 404 repo not found or private, 404 job not found
  (the server restarted — start the scan again), 429 GitHub rate limit,
  502 GitHub upstream error. There is no 504 scan timeout any more.
- `/api/scan/jobs/{jobId}` — live state of one async scan job: running
  (current step, files/commits/deps/advisories so far), done (with the
  full report), or error (plain-English message). Job IDs are random
  UUIDs and carry no owner, repo, or secret fragment.
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
  repo. If a scan of the repo is already running it picks up that same
  scan; if one finished in the last few minutes it returns that result
  from memory; otherwise it runs a fresh live scan. GitSecure never
  stores reports on disk or in a database.
- `list_checks` (no args) — what GitSecure checks, in plain English, plus
  the scan notes. Use before a scan, or to explain a score.

**MCP returns the full report, like the web flow.** Secrets are still
redacted fragments only — never shown in full. There is no `full`
parameter and no login. A scan takes about 15 seconds for a small repo; owner/repo names
are validated the same way as on the site, and a bad name, a missing/private
repo, or a GitHub rate limit comes back as a plain-English error, never a
stack trace. A large repo keeps running in the background: the tool polls
the scan job server-side for ~50 s, and if it is still running it says so
with its live progress — call `get_report` again for the same repo and it
picks up the same scan instead of starting over. The endpoint is stateless
(a fresh server per request, no session state, no git binary needed — the
scan falls back to API patches when git is unavailable), so it works on
the Vercel serverless runtime. Scan jobs themselves live in memory only
(see "How scans run" below): a job does not survive a cold start, and a
call that lands on another instance starts a fresh scan.
A plain `GET /mcp` is refused with a 4xx: in stateless mode the server
holds no SSE stream (MCP clients use POST).

Test it against a local production server (real protocol handshake with
the SDK client — initialize, tools/list, live `scan_repo` calls):

```bash
npm run build && npm start     # in one terminal
npm run test:mcp               # in another — 51 checks
```

## No login

There is no sign-in flow and no owner verification. Phase 4 (2026-11-25)
removed the GitHub OAuth owner gate entirely — the Auth.js route
(`src/app/api/auth`), `src/lib/auth.ts`, and `src/lib/owner.ts` are
deleted, and `next-auth` is no longer a dependency. Rationale: the site
only scans public repos, so the full detail is information already public
in the repo. The redaction rule did not change: a secret is never shown
in full.

## How scans run (Phase 8 — developer notes)

There are no scan caps left to list. A scan runs as an **async job**
(`src/lib/jobs.ts`): the API / report page / MCP start one, wait up to
~50 s for it (the fast path — TechDirect answers 200 in ~12–19 s), and
if it is still running answer 202 with a job ID; the client polls
`GET /api/scan/jobs/{jobId}` for live progress (current step, files
scanned so far, commits checked so far, dependencies checked) until
the job finishes. **No scan is ever killed for taking too long** — the
old 55 s timeout race is gone, and the job keeps running in the
background (`after()` keeps the invocation alive past the response).

- **Jobs are in-memory only.** No durable store, no paid service, no
  database. A job does NOT survive a cold start, a redeploy, or a poll
  that lands on a different serverless instance — a poll for an unknown
  ID answers 404 telling the client to start the scan again. Finished
  jobs are kept for 10 minutes (so the report page can reload without
  re-scanning), then dropped. That is the only sense in which GitSecure
  "stores" a report: in memory, for minutes, never on disk. Job IDs are
  random UUIDs and carry no owner, repo, or secret fragment.
- **One job per repo.** Starting a scan while one is already running (or
  recently finished) returns the same job — MCP `get_report` picks up a
  running scan instead of starting a second one.
- **History depth:** full history, newest-first, to the oldest commit —
  no commit cap, no patch-size cap, no time cap. The scan uses the
  **git-protocol path** first (pure JS, no git binary, no GitHub REST
  quota — it clones over the git smart-HTTP protocol and walks commits
  directly, with findings cached per commit SHA so a re-scan only walks
  new commits), then an ephemeral `git clone` into `/tmp` (deleted after
  the scan) where a git binary exists, then the **API history path** as a
  last resort (it pages the GitHub commits API and fetches each commit's
  patch, per-commit attribution). The report says which path was used
  and exactly how many commits were checked. Only if every path fails
  does it fall back to patches of the 5 most recent commits. The only
  remaining history bounds are physical ones: an emergency memory guard
  (500 MB of patches) and a walk safety valve (40 s / 700 MB heap) that
  stop a giant walk cleanly with an honest note — and a size gate
  (repos over 100 MB, e.g. DefinitelyTyped at 818 MB, skip the
  clone-based paths entirely because the pack cannot fit in a
  serverless function, and go through the API path instead). A history
  failure is never a failed scan: the report carries a note and the
  HEAD scan still completes in full.
- **HEAD scan: unlimited.** Every file in the HEAD tree is scanned,
  manifests and configs first (fetched from one tarball download,
  falling back to per-file fetches). There is no
  file-count cap and no per-file or total size cap — no 250, no 1,000,
  no 5,000. Binary, `dist`, `node_modules` and `.next` paths are skipped:
  generated/vendored paths, not source files. The tarball download has
  a **streaming memory guard** (the download aborts mid-stream past
  500 MB and the per-file fallback still scans every file) — a guard,
  not a cap. GitHub rate limits still exist; if a fetch fails, the
  report says plainly how many files were actually scanned, never
  pretending it scanned everything.
- **No result-count caps (Phase 5).** Every secret finding, every
  dependency, every advisory, every posture and framework finding is
  listed — no 100-secret cap, no 200-dependency slice, no 100-advisory
  cap. The report page renders huge lists progressively (100 at a time
  with "Show more" / "Show all"), with collapsible groups, filters, and
  a file map — the data is never capped to make the page fit.
- **Dependency check (Phase 8):** every pinned dependency is asked about
  via OSV.dev, in batches of 1,000 per query, and full advisory detail
  is fetched for every advisory found, in batches of 8 — with **no time
  budget on either phase**. The old 15 s query / 12 s detail budgets
  existed to fit the 55 s scan timeout, and that timeout is gone. A
  repo with thousands of deps (e.g. DefinitelyTyped, 9,401) is now
  fully queried and fully detailed inside the background job. If OSV is
  unreachable the scan continues and says so.
- **"About this scan" (was "Scan limits").** The report page no longer
  lists caps. A complete scan says so once, with the exact counts
  (files, history commits, dependencies checked, advisories with full
  detail), and nothing else. A scan that could not cover everything
  states exactly what it could not cover, one line per fact. The
  standing facts stay: public repos only; no secret is ever stored,
  logged, or shown in full.
- **Rate limits:** unauthenticated GitHub API is 60 requests/hour. A scan uses
  roughly 7 API calls plus raw file fetches — but the API history path
  (Phase 6) uses about one request per commit, so a repo with more than
  ~50 commits can hit the unauthenticated limit on Vercel; when it does,
  the scan keeps the findings so far and says so plainly. Setting a
  `GITHUB_TOKEN` env var raises the limit to 5,000/hour.
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
                         # from HEAD — 23 checks, clone + API path (mock
                         # GitHub API: pagination, per-commit attribution,
                         # rate-limit behaviour)
npm run test:tier3       # Tier 3 infra detectors on fixtures (Docker,
                         # Kubernetes, Terraform, GitHub Actions, Vercel /
                         # Supabase) — 40 checks, no network
npm run test:public-full # Phase 4: no login flow, no owner gate, no
                         # "Honest limits" copy anywhere in src; no file-count
                         # cap in the scanner; full detail + redaction —
                         # 56 checks, no network (incl. Phase 5 no-cap and
                         # navigation source checks)
npm run test:techdirect  # live scan of the real public repo Squ1zM0/TechDirect
                         # (score 83/B, 62 history commits, filesScanned =
                         # full scannable tree — 2,802, ~12 s via tarball)
npm run test:ui-phase7   # Phase 7: dial, lists, map, CSS, no-sign-in copy —
                         # 52 checks, no network
npm run test:jobs-phase8 # Phase 8: async scan jobs — a slow scan completes
                         # via the job/poll path (fake runner, no network),
                         # dedupe, job-ID safety, TTL eviction, error jobs,
                         # the rewritten "About this scan" copy (buildLimits),
                         # live progress text (ScanProgress render), OSV
                         # detail with no time budget (stubbed slow OSV:
                         # 160 advisories, ~14 s of detail fetches, all
                         # detailed) — 44 checks
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
  (README "How scans run" section above, `src/lib/scan.ts` header) —
  renamed "About this scan" in Phase 8.
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
  History caps unchanged (1,000 commits / 50 MB / 45 s). [Phase 4
  record — both superseded in Phase 8: the timeout is gone (async
  jobs) and the history caps are gone (git-protocol history, no caps).]
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

## Phase 6 — Tier 3 fingerprinting + API-based full history (built 2026-11-25)

Freddy: "Continue development yourself, Auto — you know the vision."
The vision: fingerprint every framework a repo uses and alert on flaws
in its stack. Phase 6 does Tier 3 (infra) and fixes the oldest live
caveat — Vercel has no git binary, so live history fell back to 5
commits while local scans read all 62 TechDirect commits.

- **Tier 3 detectors** (`src/lib/infra.ts`, fixtures in
  `tests/fixtures/fake-repo-tier3/`, `npm run test:tier3` 40/40):
  Docker (Dockerfile `FROM` image + tag, compose `image:` entries —
  `latest`/missing tag means version unknown + unpinned), Kubernetes
  manifests (Deployment/StatefulSet/etc. + container images, version
  honestly unknown), Terraform (providers from `required_providers` /
  `provider` blocks — an exact version is a version, a range like
  `~> 5.0` is not; a missing constraint is flagged), GitHub Actions
  (`uses: owner/action@ref` — tag/SHA/branch; `@main`/`@master`/no ref
  is unpinned), Vercel preset and Supabase config where a version can
  be read honestly. Versions are never guessed. Risky patterns become
  posture findings with a plain-English detail ending in an exact
  `Fix:` — Dockerfile running as root, `latest` base images,
  secret-looking build args, K8s `privileged` / `hostNetwork` /
  `hostPID` / `runAsUser: 0`, unpinned Terraform providers, unpinned
  Action refs. `pull_request_target` is not duplicated (scan.ts owns
  it) and exposed ports are deliberately not flagged (too noisy).
- **Actions flaws via OSV:** GitHub Action deps are checked against
  OSV.dev's "GitHub Actions" ecosystem (`actions: "GitHub Actions"` in
  `src/lib/osv.ts`); a full SHA ref is not a queryable version, so it
  is reported as version null (pinned) and skipped by the OSV query.
- **API history path** (`src/lib/history.ts`, `scanHistoryViaApi`):
  pages the commits API (100/page, `Link` next headers) up to the same
  1,000-commit / 50 MB / 45 s caps, fetches each commit's patch (5
  concurrent), scans added lines only with hunk-accurate line numbers,
  per-commit attribution, redacted fragments only. A 429 / 403 with an
  empty rate-limit bucket stops gracefully — findings so far are kept
  and the note says a `GITHUB_TOKEN` raises the limit. One bad commit
  never fails the scan. The report says which path was used (clone vs
  API). The old 5-commit patch fallback only runs if the API path also
  fails. Tested against a local mock GitHub API (`test:history` now
  23/23): planted secret in an old commit found and attributed to the
  right commit, pagination across list pages, rate-limit behaviour.
- **Verification (2026-11-25):** `npm run build` exit 0;
  `test:scanner` 68/68, `test:tier3` 40/40, `test:history` 23/23,
  `test:public-full` 56/56, `test:techdirect` 83/B with filesScanned =
  2,802, `test:mcp` 51/51. End-to-end: `actions/checkout` scan finds
  3 GitHub Action frameworks (checkout v7, setup-node v6,
  upload-artifact v7) with 27 vulnerabilities; API history against the
  real GitHub API scans all 62 TechDirect commits in ~6 s,
  unauthenticated. Live numbers after the push are in GITSECURE.md.

## Phase 7 — UI/UX redesign (built 2026-11-25, design only)

No scan behaviour, caps, scoring, redaction, or API/MCP contracts
changed — TechDirect is still 83/B, all suites still green. What
changed is how the report looks and reads.

- **Identity** (`src/app/globals.css`): one type scale
  (clamp-based h1, 1.25rem h2), one spacing system (`--space-1`…`--space-6`),
  one colour system as custom properties. Real dark mode via
  `prefers-color-scheme` — every surface, input, code block, pill and
  button is redefined for dark, including a dark-text-on-green button
  (`--on-accent`) so the primary button keeps its contrast in both
  themes. Inline code wraps only when it must (`overflow-wrap:
  break-word`, no `word-break: break-all`) — no more mid-word breaks.
- **Score dial** (`src/components/ScoreDial.tsx`, bands in
  `src/lib/score.ts`: `gradeBand` A/B good, C fair, D/F poor): an SVG
  arc 0–100 with the score and grade in the middle, colour-coded by
  band with the grade word beside it — colour + label together, never
  colour alone. The hero also carries a one-sentence verdict
  (`biggestProblem`) and the counts as a clean stat grid (2 columns at
  phone width, 3 on desktop); the secrets stat only turns red when
  the count is above zero.
- **Home**: hero first screen (lede, designed mirror-URL strip, one
  big scan input), "What it checks" as four scannable cards, styled
  error (`role=alert`) and scanning state (spinner + honest progress
  text, `role=status`). `parseInput()` is byte-identical.
- **Findings**: cards with a severity-coloured left border, clear
  title, file:line, plain-English what + fix in a shaded block, and a
  prominent GitHub file+line link next to the copy-link. Collapsible
  groups get a rotating chevron and a fade on open; filter result
  counts are `aria-live`. The spider map has a legend, a centre node
  big enough for its label, hover/focus states, and keyboard-reachable
  nodes (Tab + Enter to filter) plus the file-chip buttons.
- **Loading / error**: loading is a designed screen (spinner + the
  three real scan steps, honest wording); errors keep the
  `errorCopy()` wording in a red-bordered card with a clear next
  action.
- **Motion & a11y**: 120–180 ms transitions on hover/focus/open only;
  `prefers-reduced-motion` disables them all. Focus-visible rings
  everywhere, skip link, tap targets ≥44px, input and button stack
  cleanly at 360px, zero horizontal overflow at 1280px and 360px.
- **Verification (2026-11-25):** `npm run build` exit 0;
  `test:scanner` 68/68, `test:tier3` 40/40, `test:history` 23/23,
  `test:public-full` 56/56, `test:ui-phase7` 52/52 (new — dial, lists,
  map, CSS, no-sign-in copy), `test:techdirect` 83/B with "Scanned
  all 2802 files in the tree", `test:mcp` 51/51. **Visually verified
  in a real headless Chromium** (Playwright, cached Chromium build):
  home / loading / TechDirect report / error page at 1280px light and
  dark and at 360px, plus the GitSecure dogfood report (0/F) with the
  secrets list and spider map — click a map node filters the list live
  (2 of 8 secrets, 1 file). Screenshots in
  `test-results/phase7/`. Pushed as 146ffb85 (81 files, remote head +
  tree verified by read-back); live: home 200, TechDirect report 200
  83/B with the new UI, DefinitelyTyped report 200 0/F with 403 of 403
  secrets listed. Three defects found by looking and fixed the
  same run: the mobile scan input was 220px tall (column flex-basis),
  inline code broke mid-word, and the dark-mode button was white text
  on light green.

## Phase 8 — async scan jobs + remaining caps removed (built 2026-11-25)

Freddy's word, from a screenshot of the live TechDirect report's "Scan
limits" section: "Fix all of the scan limits as much as you can so you
don't have limit limits." So the limits went away instead of being
reworded — what remained was the 55 s scan timeout, the OSV query/detail
time budgets, and the tarball whole-buffer read, and all three are gone.

- **Async scan jobs** (`src/lib/jobs.ts`, `src/app/api/scan/jobs/[jobId]/route.ts`,
  `src/components/ScanProgress.tsx`): a scan starts a job and the caller
  waits up to ~50 s for it (fast path — TechDirect still answers 200 in
  one request, ~12–19 s). Still running after that, the API answers 202
  with a job ID and live progress, and the client polls the job endpoint
  until the job is done. The report page shows honest live progress while
  a job runs (current step, "1,200 of 2,802 files scanned", commits
  checked so far) and reloads the finished report — never a spinner that
  lies. Jobs dedupe by owner/repo, so a second start (or MCP `get_report`)
  joins the running scan. The job store is **in-memory only** (no durable
  store, no paid service): a job does not survive a cold start, a redeploy,
  or a poll on another instance — an unknown ID answers 404 telling the
  client to start again. Finished jobs are kept 10 minutes, then dropped.
  Job IDs are random UUIDs carrying no owner, repo, or secret fragment.
  The job is kept alive past the 202 response with Next.js `after()`.
  Live progress comes from `scanRepo`'s `onProgress` callback
  (`src/lib/progress.ts` — client-safe, no node imports, so the browser
  bundle never pulls in `node:child_process`).
- **55 s timeout: gone.** `scanRepoWithTimeout` / `SCAN_TIMEOUT_MS` are
  deleted; `scanRepo` runs to completion in the background job. Individual
  GitHub fetches still have short abort timeouts (a hung upstream fails
  that fetch, not the scan).
- **OSV budgets: gone.** `checkDependencies` takes no budget by default —
  every pinned dep is queried (batches of 1,000) and every advisory gets
  full detail (batches of 8). Callers can still pass an explicit budget;
  the report only mentions uncovered deps/advisories when one ran out.
- **Tarball guard: streaming, not a cap.** The download is read chunk by
  chunk and aborted mid-stream past 500 MB; tripping it only switches to
  the per-file fallback, which still scans every file. The decompressed
  tar is still materialised in memory (a physical bound, stated in code).
- **"Scan limits" rewritten as "About this scan"** (`buildLimits` in
  `src/lib/scan.ts`, pure and tested): a complete scan says so once with
  the exact counts and nothing else; a partial scan states exactly what
  it could not cover, one line per fact. History's own numbers live in
  `history.ts` (owned by the history worker) — this phase states none,
  and the report's history line carries only the method and the exact
  count scanned (clone / git-protocol / API).
- **MCP:** `scan_repo` / `get_report` poll the job server-side for ~50 s;
  a still-running large repo comes back as plain English with live
  progress and the job ID, and `get_report` picks up the same scan.
- **Phase 7 UI untouched:** dial, verdict, stat grid, collapsible groups,
  filters, spider map, GitHub links, copy-link anchors, dark mode,
  360 px mobile, ≥44 px tap targets, reduced-motion — all still green
  (`test:ui-phase7` 52/52, unchanged).
- **Verification (2026-11-25):** `npm run build` exit 0;
  `test:scanner` 68/68, `test:tier3` 40/40, `test:history` 23/23,
  `test:public-full` 56/56, `test:ui-phase7` 52/52,
  `test:jobs-phase8` 44/44 (new), `test:techdirect` 83/B with
  filesScanned = 2,802 and the new three-line "About this scan"
  ("Scanned all 2802 files in the tree…", "History checked: 62 commits,
  newest first (ephemeral git clone).", "Public repos only…"),
  `test:mcp` 51/51 against a local production server. Live (local
  production server, not pushed): scan API 200 in ~19 s, report page 200
  with the dial and "About this scan", bogus job ID 404 with
  `job-not-found`. Not verified live: a real 202/poll round-trip on a
  repo that takes over 50 s (no available public repo reliably exceeds
  the fast path from this machine — DefinitelyTyped fits in ~30 s); the
  job/poll path is proved by the fake-slow-runner test instead. Not
  pushed, not deployed — another worker owns the push.

## Project notes

Full spec and decisions: `GITSECURE.md`. Repo: https://github.com/Squ1zM0/GitSecure
(public, main). Domain: git-secure.com (not purchased — do not buy without a
separate explicit go-ahead; start on a Vercel subdomain).
