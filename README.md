# GitSecure

**Is this repo safe?** GitSecure is the security mirror for GitHub. Take any public
repo, swap `github.com` for `git-secure.com`, and get a plain-English security
report — no install, no sign-up.

```
github.com/Squ1zM0/GitSecure  →  git-secure.com/Squ1zM0/GitSecure
```

## What it checks (MVP)

- **Leaked secrets** — Discord and Slack webhooks, AWS keys, GitHub tokens, Stripe
  and OpenAI keys, database URLs, private keys, committed `.env` files, hardcoded
  passwords. Checked in current files **and in full history** (newest-first, via
  an ephemeral clone — a secret deleted from HEAD but still in an old commit is
  caught, up to the caps below). Every secret finding carries a **triage**
  annotation (Phase 10): `likely-test-key`, `likely-genuine-leak`, or
  `uncertain`, from three layers — the file's path and contents, the key
  itself (type, size, fingerprint against published test keys, whether its
  public half is committed in the same repo), and the detector's own result.
  A likely-test finding is still listed and still counted in the secrets
  total, with a test-key fix instead of "rotate it" — but it deducts
  nothing from the score (Phase 12): test keys ×0, uncertain ×0.5,
  genuine leaks ×1. The report shows the breakdown and what the score
  would be if every secret counted in full, so the adjustment is always
  checkable.
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
**never stored after the scan finishes** (in-progress findings are kept only as redacted fragments, deleted at finish or after 7 days), and **never live-validated** (the scanner never calls the
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
  still running after the ~50 s fast-path wait shows the HEAD report
  first (provisional score, clearly labelled) with live progress
  underneath it, and the scan continues chunk by chunk until it is
  done — it never times out, and closing the page loses nothing: it
  picks up where it left off when you come back.
- `/api/scan/[owner]/[repo]` — the full JSON report, same detail as the page.
  No sign-in, no `?full` flag. A small repo answers 200 in one request;
  a large repo answers **202 with a cursor and the partial results so
  far** — resume with `?cursor=...` on the same endpoint, or advance
  one chunk at a time with `POST /api/scan/chunk` (see "Scan cursors"
  below). Errors carry honest statuses: 400 bad owner/repo format or
  bad cursor, 404 repo not found or private, 409 repo changed mid-scan
  (start a fresh scan for the new HEAD), 429 GitHub rate limit, 502
  GitHub upstream error. There is no 504 scan timeout any more, and
  there is no "scan no longer running" dead-end: the server holds no
  scan state to lose.
- `POST /api/scan/chunk` — advance a scan by exactly one chunk.
  Body `{ cursor, head?, historyFindings? }`; returns the partial
  results plus the next cursor, or the finished report. See "Scan
  cursors" below.
- `/mcp` — MCP server for AI assistants (Streamable HTTP transport,
  stateless). `/api/mcp` is an alias for the same handler. See
  "Use with your AI assistant (MCP)" below.

## Scan cursors (Phase 9)

A scan is a sequence of **chunks**, and the server holds **no scan job** between them. The cursor carries the resume position; the partial findings of a scan in progress are kept in a short-lived store (redacted fragments only, deleted when the scan finishes or after 7 days) so a resume on another instance loses nothing. Instead, every chunk response returns a **cursor**: a small
base64url JSON object that says exactly where the scan got to
(owner/repo/branch, the pinned HEAD sha, the stage, and the position
inside the stage). The caller passes the cursor back with the next
request and the scan continues from that point. A server restart, cold
start, redeploy, or a request landing on a different instance changes
nothing — there is no job to lose.

The three stages:

1. **head** — the current files: secrets, frameworks, dependencies,
   posture. One chunk. The HEAD report renders first and fast, with a
   provisional score (clearly labelled — it counts HEAD secrets +
   posture only, and changes when the rest lands).
2. **history** — newest-first, in commit chunks: up to 200 commits per
   chunk over the git protocol, 10 per chunk over the GitHub API.
   Live progress throughout (commits scanned so far, secrets found so
   far). A rate limit stops cleanly at the next unscanned commit — the
   cursor points at it, and a later call retries it when quota returns.
3. **assemble** — merge HEAD + history, run the OSV flaw check, score.
   Idempotent: safe to retry with the same inputs.

What a cursor carries: the repo, the pinned HEAD sha, the stage, and
the resume position (git path: the last commit scanned; API path: the
next list page / index / that page's SHAs). What it never carries:
findings, file contents, or any secret fragment — partial results live
with the caller (the browser keeps them in `sessionStorage`; an API
caller keeps them and sends the accumulated history findings back with
the assemble call). A cursor is safe to put in a URL or share.

```bash
# Start: a small repo answers 200 with the full report.
curl https://gitsecure.vercel.app/api/scan/Squ1zM0/GitSecure

# A huge repo answers 202 with a cursor + partial results.
# Resume it — as many times as it takes, on any instance:
curl "https://gitsecure.vercel.app/api/scan/torvalds/linux?cursor=<cursor>"

# Or advance exactly one chunk at a time:
curl -X POST https://gitsecure.vercel.app/api/scan/chunk \
  -H 'Content-Type: application/json' \
  -d '{"cursor": "<cursor>", "historyFindings": [...]}'
```

A bogus cursor answers 400 with plain English ("That scan link
doesn't look right…") — the caller discards it and starts fresh,
never a crash. If the repo changes mid-scan (new commits land), the
assemble step answers 409 and the scan restarts cleanly for the new
HEAD. A partial history is never presented as complete: the report
says exactly how many commits were checked and why it stopped.

Honest bound: `torvalds/linux` is ~4 GB with ~1M commits. Its HEAD
report renders (the tarball is streamed, never materialised whole —
see "How scans run"), and history streams newest-first and survives
restarts — but a full 1M-commit history walk takes a very long time
even chunked, and the unauthenticated GitHub API quota (60 req/hour)
bounds the API path to a few chunks per hour. The scan says exactly
how far it got; it does not fake completion.

## Use with your AI assistant (MCP)

GitSecure speaks the Model Context Protocol, so an LLM can scan a repo
for you. Canonical server URL: **`https://git-secure.com/mcp`**
(`/api/mcp` works too). No sign-up, no API key. The home page has
copyable config snippets for Claude, Cursor, VS Code, and Windsurf/Cline
(the report page has a short version of the same section).

```json
{ "mcpServers": { "gitsecure": { "url": "https://git-secure.com/mcp" } } }
```

Tools (all return the full report — see below):

- `scan_repo` (owner, repo) — run a live security scan, return the full
  report: score, grade, counts, summary, limits, and the full detail
  (file names, line numbers, redacted secret fragments, framework
  versions, vulnerability IDs). Use when someone asks whether a repo is safe.
- `get_report` (owner, repo) — read or refresh the full report for a
  repo. It runs a fresh live scan — finished reports are never stored, so the result is always current. If a scan is
  already running, resume it with `resume_scan` and the cursor instead
  of starting over.
- `resume_scan` (cursor) — continue a scan that is still running, from
  the cursor `scan_repo` or `get_report` returned. The cursor carries
  the whole resume position, so the scan continues from the last
  finished chunk instead of starting over, even if the server
  restarted since. Returns the full report when the scan finishes, or
  another still-running message with a fresh cursor.
- `list_checks` (no args) — what GitSecure checks, in plain English, plus
  the scan notes. Use before a scan, or to explain a score.

**MCP returns the full report, like the web flow.** Secrets are still
redacted fragments only — never shown in full. There is no `full`
parameter and no login. A scan takes about 15 seconds for a small repo; owner/repo names
are validated the same way as on the site, and a bad name, a missing/private
repo, or a GitHub rate limit comes back as a plain-English error, never a
stack trace. A large repo keeps running in chunks: the tool drives the chunks
server-side with the cursor for ~50 s, and if it is still running it
says so with its live progress and the cursor — call `resume_scan`
with that cursor to continue it from the last finished chunk. The
endpoint is stateless (a fresh server per request, no session state,
no git binary needed — the scan falls back to API patches when git is
unavailable), so it works on the Vercel serverless runtime. The scan
itself holds no server-side state either (see "Scan cursors" above):
a resume that lands on another instance simply continues from the
cursor.
A plain `GET /mcp` is refused with a 4xx: in stateless mode the server
holds no SSE stream (MCP clients use POST).

Test it against a local production server (real protocol handshake with
the SDK client — initialize, tools/list, live `scan_repo` calls):

```bash
npm run build && npm start     # in one terminal
npm run test:mcp               # in another — 56 checks
```

## No login

There is no sign-in flow and no owner verification. Phase 4 (2026-11-25)
removed the GitHub OAuth owner gate entirely — the Auth.js route
(`src/app/api/auth`), `src/lib/auth.ts`, and `src/lib/owner.ts` are
deleted, and `next-auth` is no longer a dependency. Rationale: the site
only scans public repos, so the full detail is information already public
in the repo. The redaction rule did not change: a secret is never shown
in full.

## How scans run (Phase 9 — developer notes)

There are no scan caps left to list. A scan runs as **stateless
chunks** (`src/lib/chunks.ts`, cursor in `src/lib/cursor.ts`): the API
/ report page / MCP drive chunks for up to ~50 s (the fast path —
TechDirect answers 200 in one request), and if the scan is still
running answer 202 with a cursor and the partial results so far; the
caller resumes with the cursor (`?cursor=...` or
`POST /api/scan/chunk`) until the scan finishes. **No scan is ever
killed for taking too long** — the old 55 s timeout race is gone, and
there is no background job to keep alive.

- **The server holds no scan job.** A short-lived store holds in-progress findings only (redacted fragments, 7-day expiry, deleted at finish). No database of reports, no in-memory job map. A chunk response's
  cursor carries the whole resume position, and the partial results
  live with the caller (the browser: `sessionStorage` — a reload or a
  closed tab resumes from the last finished chunk, with a plain
  "Resumed — picked up where it left off" line; an API caller: its own
  memory, sending accumulated history findings back at assemble time).
  A server restart, cold start, redeploy, or a request landing on a
  different instance loses nothing. The Phase 8 in-memory job store
  (`src/lib/jobs.ts`) is deleted; the "scan is no longer running"
  dead-end it caused is impossible now, because there is no job to lose.
- **HEAD first, history streams.** The HEAD chunk renders first
  (provisional score, labelled); history then streams newest-first
  with live progress, and the finished report swaps in without a
  reload. The report page never re-scans on reload once a finished
  report is saved in `sessionStorage` for the same HEAD.
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
  stop a giant walk cleanly with an honest note — and a streaming byte
  bound on the pack download (150 MB: isomorphic-git buffers the whole
  pack in memory, so past that the clone aborts and history goes
  through the API path instead, e.g. DefinitelyTyped at 818 MB). A history
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
  not a cap. Repos over 1 GB (torvalds/linux, ~4 GB) stream the tarball
  instead of materialising it: entries are secret-scanned as they
  arrive and only manifests/configs/workflows/infra files are kept in
  memory, so the HEAD step cannot OOM the function. GitHub rate limits
  still exist; if a fetch fails, the report says plainly how many files
  were actually scanned, never pretending it scanned everything.
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
  fully queried and fully detailed inside the assemble chunk. If OSV is
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
                         # 73 checks: detection, redaction, Tier 1 + Tier 2
                         # fingerprinting, the Phase 4 full report, Phase 5
                         # 150-finding no-cap proof + score floor + nav links,
                         # Phase 9 whole-content detector equivalence
                         # (incl. cross-line values and matches hiding
                         # inside a cross-line span)
npm run test:history     # full-history regression: a fake secret planted in
                         # an old commit of a throwaway local repo, removed
                         # from HEAD — 70 checks, clone + API path (mock
                         # GitHub API: pagination, per-commit attribution,
                         # rate-limit behaviour) + the pack-download byte
                         # bound (a pack past 150 MB aborts the clone and
                         # history falls through to the API path)
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
                         # 87 checks, no network (incl. the provisional
                         # report label and the Phase 10 triage pills,
                         # test-key fix, and verdict filter, plus the
                         # Phase 11 verdict sections, dead-end labels,
                         # and usage-map edges)
npm run test:usage-phase11 # Phase 11: secret usage analysis — identifier-
                         # only references (never the secret value), test
                         # vs non-test references, dead ends, capped
                         # lists with true totals, triage upgrade on
                         # production use, and the usage-never-matches-
                         # the-value regression — 64 checks, no network
npm run test:triage-phase10 # Phase 10: layered secret triage — the Linux
                         # SGX self-test signing key and the device-tree
                         # test data triage likely-test-key with the
                         # test-key Fix; a production-path private key
                         # and an AWS key in deploy/ stay CRITICAL and
                         # likely-genuine-leak; the same token in a
                         # fixture file vs src/ gets different verdicts;
                         # known-fingerprint match, weak key, public
                         # counterpart, Stripe test mode, AWS example
                         # value, uncertain case, history-lines triage,
                         # the no-finding-dropped regression, the score-
                         # unchanged rule, and the counts split — 59
                         # checks, no network
npm run test:cursor-phase9 # Phase 9: stateless chunked scans — cursor
                         # round-trip + bogus cursors, chunked API-path and
                         # git-path history resume with identical final
                         # reports, rate-limit mid-history resume, assemble
                         # equivalence, sessionStorage resume helpers,
                         # provisional reports, no in-memory job store
                         # anywhere in src — 181 checks
npm run test:deps-phase13 # Phase 13: dependency-flaw fixes — upgraded
                         # fixture + real-dep versions return zero OSV
                         # advisories; kept-vulnerable fixtures still
                         # flag; repo-wide total 73, deduction 206 —
                         # 22 checks, needs network (api.osv.dev)
npm run test:score-phase12 # Phase 12 + 13: triage-weighted scoring —
                         # test keys ×0, uncertain ×0.5, genuine ×1,
                         # would-be score, frozen Phase 12 repro
                         # (197/547) and current Phase 13 repro
                         # (73/206) — 36 checks, no network
npm run test:mcp         # MCP end-to-end: needs a running production server
                         # (npm run build && npm start) — real SDK-client
                         # handshake, tools/list, live scan_repo calls for
                         # TechDirect (83/B, full detail) and GitSecure
                         # (0/F, 34 secrets — 32 triage likely-test-key,
                         # 2 uncertain; 73 vulnerabilities after the
                         # Phase 13 fixes — full detail, no full fake
                         # secret), error cases,
                         # snippet JSON validity, resume_scan with a bogus
                         # cursor, usage annotations on findings — 60 checks.
                         # Set MCP_BASE_URL to test another server.
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

## Phase 9 — resumable chunked scans, no in-memory jobs (built 2026-11-25)

Trigger: Freddy screenshotted the live site failing on torvalds/linux —
"That scan is no longer running — The server restarted while the scan of
torvalds/linux was running, so the scan was interrupted. Nothing was
half-reported — start it again and it will run from the beginning." That
was the exact failure Phase 8 predicted honestly (jobs are in-memory
only; a poll landing on a different serverless instance gets 404
job-not-found and restarts). Phase 9 fixes it for real: **the server
holds no scan state between requests at all**, so there is no job to
lose and the old dead-end is impossible.

- **Stateless, client-driven chunked scan** (`src/lib/cursor.ts`,
  `src/lib/chunks.ts`, `src/app/api/scan/chunk/route.ts`;
  `src/lib/jobs.ts` and the jobs route are deleted). The scan API
  returns a session/cursor after the first chunk; each subsequent
  request advances exactly one chunk — HEAD in the first chunk,
  history in commit-range chunks newest-first (API path: 10 commits
  per chunk; git path: 200 commits or ~30 s per chunk), assemble last
  (OSV runs inside the assemble chunk) — and returns the partial
  results plus the next cursor. The client accumulates results and
  drives the next chunk. A server restart, cold start, or a poll
  landing on a different instance changes nothing: the next request
  simply continues from the cursor. The 202 + polling shape stays,
  but the poll carries the cursor, not a server-side job ID. A bogus
  cursor answers 400 in plain English with a clean restart, never a
  crash; a repo whose HEAD moved mid-scan answers 409
  (`head-moved`).
- **The cursor** is base64url JSON, v1, strictly validated. It
  carries owner/repo/branch, the pinned HEAD sha, the stage
  (`head` | `history` | `assemble`), the history method and resume
  point (git: last scanned commit sha; API: next list page + index +
  that page's SHAs), commits scanned so far, and the stop reason
  (rate-limit / truncated). It never carries findings, file contents,
  or secret fragments. Full protocol, with curl examples, in "Scan
  cursors" above.
- **Progress persists in the browser** (`src/lib/resume.ts`):
  the report page saves cursor + accumulated results in
  sessionStorage after every chunk, so a reload or a closed tab
  resumes from the last completed chunk and says plainly
  "Resumed — picked up where it left off (N history commits checked,
  M secrets found so far)". A finished report saved for the same HEAD
  renders immediately with no re-scan.
- **HEAD first, history streams** (`src/components/ReportView.tsx`,
  `src/components/ScanProgress.tsx`): the HEAD report (score,
  frameworks, deps, HEAD secrets) renders first as a provisional
  report, clearly labelled; history streams newest-first underneath
  with live progress (commits scanned so far, secrets found so far).
  The user is never stuck on a spinner with nothing to show.
- **MCP gets the same resumability** (`src/lib/mcp.ts`): `scan_repo`
  drives the chunk loop server-side with the cursor and returns the
  cursor + progress when still running; new tool `resume_scan`
  (`{ cursor }`) continues it. Plain API callers get partial +
  nextCursor on every call. No server-side job state anywhere.
- **HEAD streaming for giant repos** (`src/lib/scan.ts`): a tarball
  past the 100 MB compressed buffer switch streams instead of
  buffering (gunzip + incremental tar parse, files
  secret-scanned as they arrive, only retainable files kept —
  peak memory is the largest single file, not the whole tree).
  Measured on torvalds/linux from disk (no network): gunzip 4.7 s,
  tar parse 6.9 s, parse + secret scan 34.5 s for 103,737 files /
  1.68 GB, 20 HEAD secrets — the whole HEAD step fits in one ~50 s
  chunk when the tarball arrives promptly. Two fixes made that fit:
  the secret detector runs each pattern once over the whole file
  instead of once per line (was ~56 s of regex on Linux, now ~28 s;
  results identical — guarded by an equivalence test that compares
  the new scan against the old per-line scan, including values split
  across lines and matches hiding inside a cross-line span), and the
  tar parser uses 1 MB gunzip chunks plus a memcmp end-of-archive
  check (was ~31 s of parse overhead, now ~2 s over gunzip). No path
  fetches the recursive tree on the happy path any more (it costs ~4 s
  and comes back truncated at 71k of ~97k entries for Linux — the
  tarball is the complete file list); the tree is fetched only when a
  tarball transport fails and the per-file fallback needs a file list.
  Manifests/configs are
  always retained even when the 100 MB retained-bytes budget runs
  out (a flood of .ts/.js files must not crowd out the files the
  dependency step needs; the report still says when retention was
  incomplete). Validated end-to-end on microsoft/vscode (1.8 GB,
  streaming path): HEAD completes in 25–33 s, 20,648 files scanned =
  20,648 total, 474 HEAD secrets, 1,714 deps.
- **Honest bound on torvalds/linux-scale histories.** Linux is ~4 GB
  with ~1M commits; the pack-download byte bound (150 MB) still applies,
  so history goes through the API path, newest-first,
  10 commits per chunk, and a full history walk will take a very long
  time even chunked. The fix is resumability, not pretending the
  whole history finishes in one visit: the scan makes steady
  newest-first progress, survives restarts, and says exactly how far
  it got. A partial history is never presented as complete. One
  physical bound remains: the HEAD chunk needs the 275 MB tarball
  inside its ~50 s budget. Measured from this VM, codeload delivered
  it in 8 s one day and ~90 s the next (repeated downloads from one
  IP get throttled); on a slow-download day the HEAD chunk stops
  cleanly at 50 s and retries from its cursor — nothing lost, no
  dead-end — until a fast window lets it through. Vercel's network
  may differ; the live torvalds/linux check below is the proof.
- **Rules unchanged:** unlimited files, unlimited findings, full
  detail to anyone, no login, secrets redacted fragments only, never
  stored/logged/live-validated, public repos only, git-protocol
  history first, no caps. Phase 7 UI untouched (dial, verdict, stat
  grid, collapsible groups, filters, spider map, GitHub links,
  copy-link anchors, dark mode, 360 px mobile, ≥44 px tap targets,
  reduced-motion).
- **Verification (2026-11-25, local):** `npm run build` exit 0;
  `test:scanner` 73/73 (68 + 5 new detector-equivalence checks),
  `test:tier3` 40/40, `test:history` 56/56, `test:public-full` 56/56,
  `test:ui-phase7` 53/53, `test:cursor-phase9` 181/181 (new:
  chunked API-path and git-path resume produce the identical final
  report to an uninterrupted scan, rate-limit mid-history resume,
  bogus cursors, sessionStorage resume helpers, provisional
  reports, no `lib/jobs` import / jobs route / "no longer running"
  copy anywhere in src), `test:techdirect` 83/B with "Scanned all
  2802 files in the tree" and 62/62 history via git protocol,
  `test:mcp` 56/56 (51 + 5 resume_scan checks) against a local
  production server. Secret-pattern grep clean (fixtures assemble
  fakes from fragments, as before).
- **Pushed 2026-11-25 as 8f4ffa4f** (remote head + tree verified by
  read-back: 118 entries, new files present, jobs files gone).
  **Live (2026-11-25, after the push):** home 200; `POST
  /api/scan/chunk` with no cursor answers the new Phase 9 400;
  TechDirect live scan **200 in 8.5 s, 83/B, 2,802 files, 62/62
  history, 0 secrets, 4 vulns**; MCP initialize 200 (protocol
  2025-03-26, gitsecure 0.1.0), tools/list shows all four tools
  including `resume_scan` with a `{ cursor }` input.
  **torvalds/linux live, the honest result:** the HEAD chunk 504s
  at ~51 s on a slow-download day — the 275 MB tarball does not
  always arrive inside the 50 s chunk budget from Vercel, so the
  first two attempts stopped cleanly and retried the HEAD chunk
  from its cursor (clean retry, no dead-end, nothing half-reported).
  The third attempt landed in a fast window and **returned 202 with
  the full HEAD: 96,985 of 96,985 files scanned, 20 HEAD secrets**
  (the same 20 the local disk profile found), plus the first history
  chunk (10 commits). Two further `POST /api/scan/chunk` calls —
  each a fresh serverless invocation carrying only the cursor —
  advanced history **10 → 20 → 30 commits**, no errors, no
  re-scan of HEAD. That is the Phase 9 proof: a restart between
  chunks loses nothing. A fresh `GET ?cursor=…` resume then hit
  the shared Vercel IP's unauthenticated GitHub quota (429) — the
  quota, not the cursor, was the blocker; the scan answers 429
  instead of crashing, as designed. Full Linux history (~1M
  commits, API path, 10 per chunk) remains a very long walk, and
  the report will say exactly how far it got — it is never
  presented as complete.

## Phase 10 — secret triage: test keys vs genuine leaks (built 2026-11-25)

Trigger: Freddy's screenshot of the live torvalds/linux report flagging
`tools/testing/selftests/sgx/sign_key.pem:1` as a CRITICAL private key with
the fix "treat this key as compromised, rotate it" — but that is the
Linux kernel's intentional SGX self-test signing key, and the finding
above it (`drivers/of/unittest-data/tests-phandle.dtsi`, line 9) is
device-tree test data too. GitSecure cried CRITICAL on test keys.

Fix: a layered triage pipeline (`src/lib/triage.ts`) that runs as a
post-processing layer over the existing detectors — the detectors
themselves do not change. Triage annotates every secret finding, and
the report, API, and MCP all carry the annotation:

- **Layer 1 — static context.** Path signals (`test/`, `tests/`,
  `testing/`, `selftests/`, `unittest-data`, `fixtures/`, `examples/`,
  `docs/`, …), filename signals (`test`, `fixture`, `dummy`, `example`,
  `sample`, `mock`, `fake`, …), content signals in the same file and
  nearby lines ("test", "testing", "for testing only", "do not use in
  production", "example", "dummy", "fake", "sample", "testcase",
  "selftest", "unittest"). Usage signals where cheap: a key file
  referenced only from test files (retained files only — manifests,
  configs, workflows, infra, source).
- **Layer 2 — cryptographic inspection.** A minimal DER parser reads
  the key where the format allows (RSA PKCS#1/PKCS#8, EC SEC1, SPKI
  public keys, X.509 certificates): key type and size (RSA 1024 vs
  4096, EC curve), whether it is weak/short in a way real production
  keys would not be, whether its fingerprint matches a small built-in
  list of famous published test keys (**fingerprints only, never the
  keys themselves** — the Linux SGX self-test signing key, verified
  2026-11-25 by fetching the file from torvalds/linux and hashing its
  DER), whether it matches a known example value (the AWS
  documentation example key, hash only), whether it is a Stripe
  test-mode key (`sk_test_` can never move real money), and whether
  its public half is committed in the same repo (matching SHA-256 of
  the RSA modulus / EC public point). No credential is ever
  live-validated, stored, or logged; triage only reads content the
  scanner already held, and only redacted fragments leave the scanner.
- **Layer 3 — the scanner's own evidence.** The detector result (type,
  confidence, fragment) is the third input, not the verdict: a
  high-confidence private-key match in a production path stays high;
  the same match in a self-test path with matching test signals gets
  downgraded.

**Verdict model (points).** A fingerprint match against a known
published test key, or a match against a published example value, is
decisive → `likely-test-key`. Otherwise: test path +4, filename test
token +2, content test phrase +2, public counterpart in repo +3, weak
key +2, test-only usage +2, Stripe test mode +3; production path −4,
production filename −2, production usage −2, production-grade key
(RSA ≥ 4096, EC P-384+) −2. ≥ +4 → `likely-test-key`; ≤ −2 →
`likely-genuine-leak`; a high-confidence detector match with no test
signals at all → `likely-genuine-leak`; anything else → `uncertain`
(keeps detector severity, says a human should check).

**Never deletion, never score inflation (Phase 10 rule — changed in
Phase 12, see below).** A likely-test finding is NOT
removed from the report and NOT removed from the counts — it is shown
with its triage label, a plain-English explanation naming the signals
("This looks like an intentional test key: it lives in
tools/testing/selftests/, its fingerprint matches a published test
key…"), and a different Fix ("Confirm this key is only used by tests
and never signs real artifacts; if it does, rotate it"). A genuine
leak keeps CRITICAL and its existing Fix. **Scoring rule as built in
Phase 10: triage never changes the score.** A likely-test finding still
deducted its detector severity, because a test key that turns out to be
a real key is still a leak, and the score must not reward relabelling.
**That rule was overturned in Phase 12** (Freddy, 2026-11-26: an F for
34 test fixtures is a false alarm, and false alarms train people to
ignore real ones): a likely-test-key now deducts nothing, an uncertain
finding deducts at half weight, and a genuine leak (or an untriaged
finding) deducts in full. The honest split is still shown separately:
`counts.testKeySecrets` — "of which N look like test
keys" — in the stat grid and the secrets list. The report page filters
by triage verdict (a "Likely test keys" filter); MCP carries the same
annotation in every secret finding.

**Where it runs.** HEAD findings are triaged in `scanHead` after the
whole tree is scanned (so the public-counterpart and usage signals see
the complete repo); history findings are triaged at creation in
`history.ts` (clone stream, API path, API chunk, git-protocol walk —
the git path triages from the full new-file content) and in the patch
fallback in `scan.ts`; `assembleReport` fills in any annotation missing
from an older client/cursor with a path+detector-only verdict, so every
finding in every finished report carries triage. The provisional report
carries the same annotations (HEAD triaged in `scanHead`, history at
creation).

**Verification (2026-11-25, local):** `npm run build` exit 0;
`test:scanner` 73/73, `test:tier3` 40/40, `test:history` 56/56,
`test:public-full` 56/56, `test:ui-phase7` 62/62 (was 53 — 9 new
triage UI checks), `test:cursor-phase9` 181/181,
`test:triage-phase10` 59/59 (new), `test:techdirect` 83/B with
filesScanned = 2,802 ("Scanned all 2802 files in the tree"), history
62/62 via git protocol, `test:mcp` — see note below. No literal
secret-pattern values committed (grep-verified; the AWS example key
appears only as a SHA-256 hash constant plus a runtime-assembled
string in the test, as before).
**Live verification (2026-11-26, after 9be330d4):** home 200; live
GitSecure self-scan 0/F, **22 secrets, all 22 likely-test-key**
(`counts.testKeySecrets` 22, history 22, files 77) — the count moved
20 → 22 because the Phase 10 commit itself added the triage test
fixture line, found at HEAD and in its introducing commit, same
pattern as before; live TechDirect 83/B, 0 secrets, 4 vulns, 2,802
files, 62/62 history; live torvalds/linux HEAD chunk 96,985/96,985
files, all 20 HEAD secrets likely-test-key — `sign_key.pem`
likely-test-key (signals `test-path:testing`, `known-test-key`; test-key
Fix) and `tests-phandle.dtsi` likely-test-key on its own signals
(`test-path:unittest-data`, `filename-test:tests`,
`content-test:testcase`); MCP initialize 200, tools/list shows
`scan_repo`, `get_report`, `resume_scan`, `list_checks`.

**Dogfood note (Phase 10, measured 2026-11-25):** the MCP dogfood
scan of Squ1zM0/GitSecure now counts **20 secrets, not 8** — all 20
triage `likely-test-key` (`counts.testKeySecrets` 20). The count moved
because the repo's history grew (20 commits now): the same known-fake
fixture secrets are found at HEAD and again in their introducing
commits (e.g. the test-scanner.ts fake passwords at HEAD and at
8f4ffa4). The score is still 0/F. The pre-change code was verified to
return the same 20 (see GITSECURE.md) — triage annotates, it never
adds findings — so the `test:mcp` "counts 8 secrets" assertion was
updated to 20 with this reason, and a new check asserts all 20 are
test keys. Live, the count is now **22** (see the live-verification
note above): the two Phase 10 pushes added the triage test fixture
line, found at HEAD and in its introducing commit b4ca165 — the
`test:mcp` assertions now say 22, all 22 test keys.

## Phase 11 — secret usage: in use vs true dead end + the track through the spider web (built 2026-11-26)

Trigger: Freddy, voice message — separate the likely-test results so
there is a way to click and see them, and, while scanning, determine
what each finding is dependent on and whether anything else in the code
uses it. If something else calls it, it is in use, not a test key;
if nothing does, it is a true dead end. Follow that track through the
spider web.

**Usage analysis (`src/lib/usage.ts`).** For every secret finding, the
scanner searches the repo's own HEAD files for references to the
finding's **identifier only** — the variable/env name, the key
filename, or the config key — outside the file where it was found.
It never searches for or stores the secret value itself, and never
matches on the redacted fragment. The identifier is taken from the
detector match itself (password-style detectors include the name) or
the `NAME =` immediately preceding the match start, with the fragment
identifying the exact match when a line holds several; a URL scheme is
not a name (a bare `postgres://…` line yields no identifier), a match
inside a string yields the name inside the string, and `.env` findings
use only their defined variable names (the bare `.env` basename is not
an identifier — every repo mentions ".env" in prose). Every finding
carries a `usage` annotation (`SecretUsage` in `src/lib/types.ts`):
`referencedBy` (non-test code, file:line, first 10) with
`referencedByTotal`, `referencedByTests` (test code, first 10) with
`referencedByTestsTotal`, and `deadEnd: true` only when a usable
identifier was found and nothing anywhere references it (no identifier
→ `deadEnd: false`, liveness undetermined). References in test files
alone do NOT count as "in use". History findings get usage from HEAD
files only (`historyOnly: true`) — the report says so in the About
section, since a history-only value may have been used by code that no
longer exists. API/clone/patch history paths have no HEAD files to
search, so those findings carry no `usage`.

**Triage feed-back.** Usage is a new triage signal, applied after the
Phase 10 verdict: (a) a likely-test-key referenced by non-test code is
upgraded to at minimum `uncertain`, the explanation naming the
referencing file; (b) it upgrades further to `likely-genuine-leak`
when the referencing non-test file is production-ish (`src/`, `lib/`,
`app/`, `config/`, `deploy/`, `scripts/`, repo-root config) AND the
detector type is a credential type (AWS key, token, webhook, database
URL, hardcoded password, private key — `env-file` and
`generic-high-entropy-secret` excluded); (c) zero references anywhere
adds signal `usage-dead-end` (+2 toward `likely-test-key`) and the
explanation says plainly "Nothing in this repo references this key —
a true dead end." A decisive fingerprint match is NOT overridden by a
docs/examples-only reference (stays likely-test-key, reference
recorded); production-path usage still upgrades it. Usage never
changes the score on its own — it feeds the triage verdict, and Phase
12 weights the score by that verdict (test keys ×0, uncertain ×0.5,
genuine ×1).

**Separated likely-test section.** The report page now partitions the
secrets list into three verdict sections, in order: **Likely genuine
leaks** (open by default), **Uncertain — needs a human check** (open by
default; findings with no triage annotation count as uncertain, never
silently as test keys), **Likely test keys** (collapsed by default, own
count, expands on click — only test-key findings, each with its triage
explanation and test-key Fix). Group-by type/file works as sub-groups
inside each section; the verdict filter still works alongside and
auto-opens its section; a shared `#secret-N` link opens the section
holding that finding. The honest counts line keeps the split ("N
secrets, of which M look like test keys"). Dead-end findings show a
"Dead end" pill; in-use findings show a "Used by: file:line" line;
history-only findings note usage was checked against the current files
only.

**The track through the spider web.** The map (`UsageMap` in
`src/components/ReportLists.tsx`) is now a usage graph: repo node at
the centre, finding nodes (S1…S12) on an inner ring, file nodes on an
outer ring. Edges per finding: solid = used in non-test code, dashed =
test-only use, thin grey = the file the finding itself lives in (the
other hop of the track). Click a finding node to highlight its track
(everything else dims) with a detail panel naming the finding, its
file:line, and its references, plus a "Show this finding in the list"
button; click again to deselect. Click a file node to filter the list
to that file. Dead-end findings are grey dashed nodes labelled "dead
end" with **no** outgoing edges. Legend included; nodes are
keyboard-reachable (Tab + Enter/Space); ≥44 px hit targets; 120–150 ms
motion under the existing prefers-reduced-motion rule; dark mode via
the existing CSS vars. With no `usage` data (older report) the map
falls back to the Phase 5 file-count spider unchanged. API and MCP
carry `usage` on every secret finding; `list_checks` names "secret
usage — in use vs dead end".

**Verification (2026-11-26, local):** `npm run build` exit 0;
`test:scanner` 73/73, `test:triage-phase10` 59/59, `test:tier3` 40/40,
`test:history` 56/56, `test:public-full` 56/56,
`test:cursor-phase9` 181/181, `test:usage-phase11` 75/75 (64 + 9 new
Phase 11.1 comment-strip checks),
`test:ui-phase7` 87/87 (was 62 — 29 new Phase 11 checks: verdict
sections, dead-end labels, usage-map edges, no-usage fallback),
`test:mcp` 60/60 (was 58), `test:techdirect` 83/B with filesScanned =
2,802, history 62/62 via git protocol. Dogfood self-scan (local):
0/F, 32 secrets, all 32 likely-test-key, 3 dead ends, 0 in use — 6 false
triage flips found during the phase were fixed in `usage.ts` (3
database-url via the URL-scheme guard, 2 hardcoded-password via
match-anchoring, 1 env-file via dropping the `.env` basename; the
env-file finding now correctly shows `deadEnd: true`). No literal
secret-pattern values committed (grep-verified). UI visually verified
by the UI worker via a render harness + headless Chromium screenshots
at 360 px and 1280 px (light + dark), zero horizontal overflow, in
`test-results/phase11/`.

**Phase 11.1 — comment mentions are not usage (live false flip,
fixed 2026-11-26).** The first live self-scan after the Phase 11 push
flipped one fixture to `likely-genuine-leak`: `api_key` named in
`usage.ts`'s own doc comments was counted as a production reference.
Fix: comments are stripped before matching (string-aware,
length-preserving, line numbers unchanged); string literals still
count as references. The stripper resets quote state at each newline,
or a regex literal full of quotes traps it across lines and the next
block comment never opens — found by testing against the real file.
MCP dogfood counts updated 22 → 32 (history grew to 25 commits;
Phase 11 added fixtures — same pattern as Phases 5/10).

## Phase 12 — triage-weighted scoring: the score must reflect real risk (built 2026-11-26)

Trigger: Freddy — "But that live proof with an F scored inaccurate
because every single one is a test, so we need to make sure that the
scoring system is accurate if finding tests." The live GitSecure
self-scan scored 0/F, but all 34 of its secrets were likely-test-keys
(32 likely-test-key, 2 uncertain, 0 genuine). Phase 10's rule
("triage never changes the score") is **overturned** by this phase:
a score that calls 34 test fixtures an F is a false alarm, and false
alarms train people to ignore real ones.

**The new rule (scoring core, Worker A).** `computeScore` returns a
`ScoreDetail` — score, grade, per-component deductions, per-verdict
finding counts, and the would-be score — carried on the report as
`scoreDetail`, so the API, report page, and MCP can never show a
score that disagrees with the sections. Weights: likely-test-key ×0,
uncertain ×0.5 (per-finding deduction rounded at the total), genuine
leak ×1, no triage annotation ×1 (a test key is never assumed without
evidence). `wouldBeScore` is the score the old full-weight rule would
have given the same input. Findings are still never removed and still
counted in the secrets total — only their weight changes.

**The explanation in the UI (Worker B).** Next to the dial, the report
hero states the rule in plain English with the actual numbers from
`scoreDetail`: how many secrets were excluded as test keys, how many
counted at half weight, how many at full weight — and BOTH scores, the
adjusted score and the would-be score, so the reader can see the
test-key adjustment and verify it. The verdict and the one-line
explanation pick the real driver by deduction size: a repo with zero
genuine secrets is never told its biggest problem is "N leaked
secrets — rotate and remove these first"; it is told the test keys
are excluded and named the real driver instead (vulnerabilities,
posture, or genuine secrets, whichever deducts most). An older cached
report without `scoreDetail` renders the Phase 7 wording unchanged —
the explanation renders nothing and the verdict falls back, never
crashing.

**MCP prose.** `list_checks` in `src/lib/mcp.ts` states the new rule
with the weights instead of the old "never changes the score" line.
No MCP tool behaviour changed — prose only.

**Measured self-scan breakdown (Worker A,
`test-results/phase12-score-breakdown.md`, real local scan of
Squ1zM0/GitSecure, 2026-11-26).** 34 secrets, 197 vulnerabilities,
15 posture issues, 3 unpinned frameworks, 79 files, 27 history
commits. Secrets deduction falls 384 → 8 (32 test keys at ×0, 2
uncertain at half weight: 2 × 8 × 0.5 = 8); vulnerabilities 547,
posture 84, unpinned 6; total 645, so the new self-scan score is
still **0/F** — and the would-be score is 0/F too. Phase 12 fixes
the false-alarm secrets component; it does not and cannot lift the
self-scan grade while the other components stand. The 197
vulnerabilities are real OSV advisories on deliberately old
dependency versions in the Tier 2 test fixtures, and the posture
items are fixture-driven configs — both are scored as real, unchanged
by Phase 12; any future change to how fixture-driven vulns/posture
score is a separate decision.

**Verification (2026-11-26, local):** `npm run build` exit 0;
`test:ui-phase7` 110/110 (was 87 — 23 new Phase 12 checks:
explanation with the three counts and both scores, all-test-key
verdict naming the real driver, would-be score shown, graceful
fallback with no `scoreDetail`, full `ReportView` render with and
without the detail, MCP prose). No literal secret-pattern values
committed (grep-verified; fixtures still use `__SECRET_n__`
placeholders, test-assembled fakes only). NOT pushed — the
coordinator integrates and pushes.

## Phase 13 — fix the dependency flaws for real (built 2026-11-26)

Freddy: "Fix the dep flaws." Phase 12 left 197 vulnerabilities at full
weight — real OSV advisories on deliberately old pinned versions in
the repo's own fixtures. This phase upgrades the versions instead of
relabelling them. Measured split: real deps 2, Tier 2 fixtures 65,
Tier 1 fixtures 130 in-scan, Tier 3 fixtures 0. Upgraded: Django
4.2.0 → 5.2.17, next 14.2.5 → 15.5.29, fiber v2.49.0 → v2.52.14,
sinatra 3.0.5 → 4.2.0, puma 6.4.0 → 7.2.1, phpunit 10.5.0 → 10.5.62,
diff 8.0.2 → 8.0.4, zod 4.3.5 → 4.6.7 (all branch-correct fixed
versions, re-checked clean on OSV). Kept vulnerable, one per
ecosystem for detection coverage: Echo v4.11.1, rails 7.1.3,
laravel/framework v10.34.2, spring-core 6.1.2, Flask 3.0.0, vite
5.0.0, tokio 1.0.0. Result, measured with the scanner's own code:
**197 → 73 vulnerabilities** (20 medium, 53 low), deduction 547 →
**206**; total 302, so the self-scan is still **0/F** honestly — the
kept fixtures plus posture (84, untouched) still floor it. No
critical or high vulns remain. New `npm run test:deps-phase13` 22/22;
full suite green (scanner 73/73, tier3 40/40, history 56/56,
public-full 56/56, cursor 181/181, triage 63/63, usage 77/77, score
36/36, UI 110/110, MCP 62/62, TechDirect 83/B). Live verification:
self-scan 73 vulns, scoreDetail `{secrets 8, vulns 206, posture 84,
unpinned 4}`, secrets still 34 (32 test keys, 2 uncertain).

## Phase 14 — dogfooding integrity: the repo itself must be secure (built 2026-11-26)

Freddy: "I don't want our platform to try and help people secure their repositories without the repository itself being secure." The self-scan was 0/F (302 deductions) because the repo shipped deliberately vulnerable test fixtures. This phase makes the repo itself genuinely secure. Diagnosed first (test-results/phase14-self-scan-inventory.md): 73 vulns, all kept-vulnerable fixtures; posture 15, 13 fixture-driven, 2 real; secrets 34 (32 test keys, 2 uncertain); unpinned 4 points, both fixture-owned. The honest fix: vulnerable fixture manifests and risky infra configs are no longer committed as scannable files — tests generate them at test time in temp dirs from in-memory strings (scripts/fixture-gen.ts, byte-identical contents), so detection coverage is equal or better (new test:fixtures-phase14 42/42 proves the generated fixtures detect the exact same 73 advisory IDs) while the committed repo holds no vulnerable pinned version. Real gaps fixed for real: SECURITY.md (reports to motdhvacr@gmail.com) and .github/dependabot.yml (npm, weekly). Two real scanner bugs fixed in the same phase: history usage search ran against an empty corpus (git.TREE walk over the no-checkout clone visited 0 blobs, so no history finding could ever be in-use) and doc-prose mentions counted as production usage (the 2 uncertain api_key fixtures are settled to likely-test-key by the evidence, not by weakening triage — secrets deduction 8 → 0). No gaming: no exclusions, no special-casing Squ1zM0/GitSecure anywhere (grep-proved), no severity changes, no deleted tests. Local HEAD-only self-scan of the working copy: 0 vulnerabilities, 0 posture issues, 0 unpinned deps, 18 HEAD secrets all likely-test-key — projected full-scan score 100/A; the live numbers are measured after the push. Full suite green (scanner 73/73, tier3 40/40, history 66/66, public-full 56/56, cursor 181/181, triage 63/63, usage 91/91, score 36/36, deps 22/22, fixtures 42/42, UI 110/110, MCP 62/62, TechDirect 83/B). Live verification: self-scan 100/A — 37 secrets, all likely-test-key, 0 vulnerabilities, 0 posture issues, scoreDetail {secrets 0, vulns 0, posture 0, unpinned 0, excluded 37, wouldBeScore 0}, files 86, history 31 commits.

## Phase 15 — user experience + zero REST calls (built 2026-11-26)

Freddy: "Continue and develop the app. Improving user experience." Audit first (test-results/phase15-ux-audit.md, 16 findings with screenshots): the Linux dead-end is fixed at the root — a HEAD-chunk timeout now returns a partial cursor so the resume path engages, and every page-level error state has a "Retry this scan" button; DefinitelyTyped's report no longer overflows at 360 px; the chunk-error card names the failure reason and the progress reached, and the provisional banner says "paused" instead of the stale "still running" once the driver errors; provisional reports say "So far: …" instead of "Scan complete."; a branded 404 explains the owner/repo shape; the score-0 dial dot, the empty "Used by: ;", the "about 15 seconds" loading promise (now 15–30), sub-44 px buttons, the missing visible input label, the runner-up score deduction, and four disagreeing fix versions for one package are all fixed; the MCP section has a plain-English line and collapsed snippets on the canonical https://git-secure.com/mcp. Freddy added mid-phase: a "Roll all into report" button in the score hero that downloads the entire scan as one Markdown file (every finding, fragment-only secrets, provisional labelled). Freddy's live rate-limit dead end is fixed too: the 429 page has a "Try this scan again" button and honest reset wording from GitHub's headers ("resets in about N minutes", else "resets within the hour" — never an invented countdown). And the last REST call is gone: branch + HEAD now come from `git ls-remote`, the file list from the tarball, and both size gates are streaming bounds — a full happy-path scan makes 0 api.github.com requests (test:zero-rest 26/26, TechDirect still 83/B, 2,802 files, 62 history commits via git protocol). No token was added or needed for this: Freddy separately reversed his Phase 6 no-token ruling himself on 2026-11-26 (fine-grained PAT as GITHUB_TOKEN in Vercel, 5,000/hr) — the zero-REST work neither depends on it nor changes it. Full suite green (scanner 73/73, history 70/70, cursor 192/192, UI 155/155, report-markdown 30/30, resilience 45/45, zero-rest 26/26, MCP 62/62, TechDirect 83/B). Live verification: home 200 on git-secure.com, self-scan 100/A, TechDirect 83/B.

## Phase 16 — report page loads in seconds; visible resume; honest copy (built 2026-11-26)

Freddy: "This page couldn't load" on git-secure.com/vinta/awesome-python in iPhone Safari. The report page was a server component awaiting a 50-second scan loop before rendering, and Vercel's 60-second function ceiling made big-repo pages a coin flip between loading after a minute and a cut stream Safari reports as a failed page (pre-fix live measurement: TTFB 0.82 s, total 52.80 s; another run took 63.6 s and returned only the loading shell). The fix: the page now renders the progress screen immediately with zero server await — the browser drives the scan chunk-by-chunk via new endpoints POST /api/scan/start and GET /api/scan/[owner]/[repo]/tip (local shell 0.029–0.53 s; headless responseStart 81 ms). A reload mid-scan now shows a resume line with real retained progress ("Resumed — picked up where it left off (200 history commits checked, 0 secrets found so far)") instead of a bare spinner. The API/MCP loop got the same ceiling audit: its budget is now 40 s with the deadline threaded into every chunk (worst case ~53 s), and the assemble stage is exempt from the start floor after a cold-run MCP regression showed resuming a self-scan returned only 18 of 37 secrets — that fix plus the test following the documented resume contract brought test:mcp to 62/62. Copy is honest now: "Small repos usually take 15–30 seconds; a large repo with a long history takes several minutes" plus a live commits-per-minute line; the provisional report no longer claims "0 vulnerabilities" before the dependency check runs; and "is a excellent score" is now "is an excellent score". Headless verification: awesome-python finished in 4m25s wall (vs 16 minutes on the device browser pre-fix) at 91/A, 0 secrets, 0 vulns, 3 posture, 126 files, 3,350 history commits — identical to the device-browser result; 360 px shows no overflow. Known gap, pre-existing since Phase 9 and not fixed here: for huge repos whose history spans multiple invocations via GET/MCP, earlier chunks' history findings are still lost on resume — a Phase 17-sized redesign, proposed not started. Full suite green (test:phase16-a 56, test:phase16-worker-b 25/25, test:ui-phase16c 45/45, MCP 62/62, TechDirect 83/B). Live verification (2026-11-26, push ee86cad3): awesome-python shell 200, TTFB 0.53 s, total 1.03 s (was 52.80–63.6 s); TechDirect 83/B; self-scan 100/A; awesome-python finished live via the chunk API at 91/A, 0 secrets, 0 vulns, 3 posture, 126 files, 3,350 history commits; MCP initialize 200 on https://git-secure.com/mcp.

## Phase 17 — best security as possible: close the history-findings hole + coverage audit (built 2026-11-26)

Freddy: "It works and it works well! ... continue for the best security as possible." Part 1 closes the Phase 9 hole the Phase 16 report named honestly: for huge repos spanning multiple invocations, earlier history chunks' findings were lost on GET/MCP resume (only POST-chunk callers carry accumulation) — proven on docker/awesome-compose, 24 secrets via chunk accumulation vs 14 via GET resume, all 10 history findings silently lost while both paths scored 0/F. The design (test-results/phase17/accumulation-design.md) is durable per-scan accumulation in Upstash Redis direct via REST ($0 free tier, fragments only, 7-day TTL backstop, deleted at assemble, one write per invocation boundary) — and the code went live when the store was provisioned on 2026-11-27: src/lib/scan-state.ts (NoopStore default, UpstashRestStore on env vars only, wired into runScanLoop only), plus an honest degradation line so a report says earlier history findings may be missing instead of silently misreporting, and a caller-carried fallback (optional historyFindings on MCP resume_scan and GET). Provisioned 2026-11-27 (Upstash Redis gitsecure-scan-state, Free, us-east-1, via the Vercel Marketplace); the public 'never stored' copy was updated the same day to the honest wording (fragments only, deleted at finish or after 7 days). The live multi-invocation proof run is still owed. The proof harness also found a second defect, fixed here: a chunked scan's final history chunk cached tail commits as the repo's complete history (live: a GET scan answered 150 commits instead of 3,350) — a resumed walk now writes nothing to the cache. Part 2 adds 9 secret detectors (Anthropic, Google, npm, PyPI, SendGrid, Telegram, Hugging Face, GitLab, name-anchored AWS secret keys, plus Slack xoxe-), pyproject.toml / poetry.lock / Dart pubspec parsers (modern Python repos previously had zero OSV coverage), Cargo dev/build/workspace deps, and 4 posture checks (curl-pipe-to-shell, Dockerfile ENV secrets, K8s hostIPC/allowPrivilegeEscalation, Compose privileged/host networking). No scoring, cap, or redaction changes. New suites test:phase17-worker-b 70/70, test:phase17-worker-c 81/81, test:history 79/79. A walk-budget fix landed during verification (pre-existing: jsdiff on giant lockfiles made history chunks take 174 s locally and 504 live — now a hash-based fast diff above 1,000 lines plus file-granularity budget checks; chunk 1 is ~22 s, harness chunk path finds the true complete 30 secrets on awesome-compose). Live verification (2026-11-27, push 73beb18c, 411 files): full offline suite 1,345 PASS / 0 FAIL, build exit 0, secret-pattern grep clean, test:mcp exit 0 (62 checks; two earlier runs in the same session failed the GitSecure resume checks on upstream timeouts — git clone took 109.8 s from this VM at the time — then passed with no code change, a local-test timing weakness, not a regression). Live: shell ~1 s (awesome-python TTFB 0.66 s, total 1.07 s); TechDirect 83/B; self-scan 100/A (37 test keys, commit 73beb18c); awesome-python 91/A via the chunk API; MCP initialize 200. Harness live re-run on docker/awesome-compose MATCHES — chunk 30 vs GET 30 secrets, depth 274 = 274, exit 0, first history chunk 18.7 s (was a 504). Honest limit: the live GET scan finished in a single invocation (41.6 s) thanks to the walk fix, so the store itself is still unproven live; the DefinitelyTyped-scale multi-invocation proof stays owed.

## Project notes

Full spec and decisions: `GITSECURE.md`. Repo: https://github.com/Squ1zM0/GitSecure
(public, main). Domain: git-secure.com — live since 2026-11-26 (Cloudflare Registrar, Vercel Valid Configuration, apex serves the site, www 307-redirects to apex).
