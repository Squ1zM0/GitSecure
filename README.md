<img src="public/logo.png" width="360" alt="GitSecure logo">

# GitSecure

**Is this repo safe?** GitSecure is the security mirror for GitHub. Take any public
repo, swap `github.com` for `git-secure.com`, and get a plain-English security
report - no install, no sign-up.

```
github.com/Squ1zM0/GitSecure  →  git-secure.com/Squ1zM0/GitSecure
```

## What it checks

- **Leaked secrets** - 22 detectors: Discord and Slack webhooks and tokens,
  AWS keys, GitHub tokens, Stripe and OpenAI keys, Anthropic, Google, npm,
  PyPI, SendGrid, Telegram, Hugging Face, and GitLab tokens, database URLs,
  private keys, JWTs, committed `.env` files, hardcoded passwords, and
  high-entropy strings. Checked in current files **and in full history**,
  newest first - a secret deleted from HEAD but still in an old commit is
  caught. Every finding carries a **triage** annotation:
  `likely-test-key`, `likely-genuine-leak`, or `uncertain`, from three
  layers: the file's path and contents, the key itself (type, size,
  fingerprint against published test keys, whether its public half is
  committed in the same repo), and the detector's own result. A
  likely-test finding is still listed and still counted in the secrets
  total, with a test-key fix instead of "rotate it" - but it deducts
  nothing from the score (see "Scoring" below). The report shows the
  breakdown and what the score would be if every secret counted in
  full, so the adjustment is always checkable.
- **Secret usage** - for every secret, the scanner searches the repo's
  own files for references to the finding's **identifier only** (the
  variable or env name, never the secret value) and reports whether it
  is used in non-test code, used in tests only, or a **true dead end**
  that nothing references. Usage feeds triage: a test key referenced by
  production code is upgraded to at least `uncertain`.
- **Dangerous code patterns** - 20 rules across JS/TS, Python, Go, Ruby,
  Java, and PHP: command injection, SQL injection, unsafe
  deserialization, weak crypto (weak hash, weak random tokens, hardcoded
  IV, broken cipher), path traversal, SSRF, open CORS, cookies without
  HttpOnly/Secure/SameSite, JWT `none` algorithm, TLS verification off,
  plain HTTP, weak TLS versions, secrets in logs, stack traces in error
  responses, debug mode, and XSS sinks (`innerHTML`, `eval`). A sink
  only counts when tainted input reaches it in the same statement.
- **CI pipelines** - GitHub Actions (10 checks: `pull_request_target`
  with checkout, `write-all` permissions, secrets echoed into logs,
  curl-pipe-to-shell, script injection through `${{ }}` interpolation,
  secrets passed to third-party actions, artifact poisoning, cache
  poisoning, unpinned reusable workflows, self-hosted runners) plus
  GitLab CI, CircleCI, Jenkins, Azure Pipelines, and Bitbucket Pipelines
  (curl-pipe-to-shell, secret echo, `latest` images, script injection,
  unpinned refs, static cloud keys).
- **Container hardening** - running as root or with no `USER`, `ADD` of
  a remote URL, `latest` base images, no `HEALTHCHECK`, and dangerous
  capabilities (`SYS_ADMIN`, `ALL`). Plus Dockerfile `ENV` secrets,
  Kubernetes `hostIPC` / `allowPrivilegeEscalation`, and Compose
  privileged mode or host networking.
- **Exposed files** - committed private keys, SQL dumps, backup files
  (`.bak`, `.orig`, `.swp`), Terraform state (`.tfstate`), and committed
  databases (`.sqlite`, `.db`).
- **Supply chain** - install scripts (`postinstall`, `preinstall`,
  `prepare`) in `package.json`.
- **Frameworks** - JS/TS (Next.js, React, Vue, Angular, Svelte,
  SvelteKit, Vite, Express, Nest, Nuxt, Astro, Fastify, Koa, Hono),
  Python (Django, Flask, FastAPI), Rust (Cargo), Go (Gin, Echo, Fiber),
  Ruby (Rails, Sinatra), PHP (Laravel, Symfony, WordPress), Java/Kotlin
  (Spring Boot, Spring Framework), .NET (ASP.NET Core), plus Docker,
  Kubernetes, Terraform, GitHub Actions, Vercel, and Supabase.
  Versions come from lockfiles where possible; unpinned (`*` /
  `latest`) versions are flagged; if a version cannot be determined,
  the report says so instead of guessing.
- **Dependency flaws** - known vulnerabilities in direct and transitive
  dependencies, checked against [OSV.dev](https://osv.dev) (a free public
  database of known software flaws; npm / PyPI / crates.io / Go /
  RubyGems / Packagist / Maven / NuGet / GitHub Actions), with full
  advisory detail (a plain summary, a severity score, and the version
  that fixes it) fetched for every advisory found. Every advisory found
  is listed; there is no cap and no time budget.
- **Security posture** - missing `SECURITY.md`, no Dependabot,
  `.gitignore` gaps, and risky configuration patterns.

Every finding is plain English: what it is, what it lets an attacker do,
and the exact fix, in order.

## Scoring

The score is 0-100 with a grade (A/B good, C fair, D/F poor). Secrets
are weighted by triage verdict: likely-test-key x0, uncertain x0.5,
genuine leak x1, untriaged x1. A test key is never assumed without
evidence. The report shows both the adjusted score and the **would-be
score** (what the score would be if every secret counted at full
weight), plus the per-component deductions, so the adjustment is
verifiable. Findings are never removed and still count in the totals;
only their weight changes.

## The report

- **Score dial** with the grade, a one-sentence verdict naming the real
  driver, and the counts as a stat grid.
- **Map view (default)** - a dynamic, pannable, zoomable plane: the repo
  at the centre, findings on an inner ring, files on an outer ring, with
  labelled edges ("used in code", "used in tests", "lives in", "found
  in"). Drag to pan, wheel or pinch to zoom, click a node to zoom to it
  and open its detail, pin nodes, drag nodes to untangle the map, step
  along connections with a breadcrumb. Node captions and test connections
  appear as you zoom in, and always for the selected track. The list view
  is one tap away, with collapsible groups by type and verdict, filters,
  and text search.
- **Full detail** - every secret row links to the exact file and line on
  GitHub (history findings link to their commit), every vulnerability
  links to its OSV.dev advisory page, and every finding has an in-page
  anchor (`#secret-12`) with a copy-link button.
- **Roll all into report** - a button in the score hero downloads the
  entire scan as one Markdown file (every finding, fragment-only
  secrets, provisional reports labelled).

## What you get

Everyone gets the **full report** - the score (0-100) and counts, plus
the full detail: file names, line numbers, redacted secret fragments,
framework versions, and vulnerability IDs with the version that fixes
each one. No sign-up, no login. That works because GitSecure only scans
**public repos**, so the detail is information already public in the
repo.

Secrets are **never shown in full** (fragment only: first 4 chars ...
last 2), **never stored after the scan finishes** (in-progress findings
are kept only as redacted fragments, deleted at finish or after 7
days), and **never live-validated** (the scanner never calls the
service a credential belongs to).

## Run it

```bash
npm install
npm run dev        # http://localhost:3000
npm run build      # production build (must pass before any push)
```

Optional env (server-side only, never in the repo):

- `GITHUB_TOKEN` - a GitHub token raises the API rate limit from 60 to
  5,000 requests/hour. Without it, scans may hit the unauthenticated
  limit.
- `KV_REST_API_URL` / `KV_REST_API_TOKEN` - an Upstash Redis store for
  durable per-scan accumulation across serverless invocations. Without
  it, a huge repo whose scan spans multiple invocations can lose earlier
  history findings on resume, and the report says so instead of
  silently misreporting.

No login is needed for the full view - there is no sign-in flow and no
env var gates it.

## Routes

- `/` - home page, explains GitSecure, owner/repo input.
- `/[owner]/[repo]` - full scan report for a public repo. The progress
  screen renders immediately; the browser drives the scan chunk by
  chunk. A large repo shows the HEAD report first (provisional score,
  clearly labelled) with live progress underneath it, and the scan
  continues until it is done - it never times out, and closing the page
  loses nothing: it picks up where it left off when you come back.
- `/api/scan/[owner]/[repo]` - the full JSON report, same detail as the
  page. A small repo answers 200 in one request; a large repo answers
  **202 with a cursor and the partial results so far** - resume with
  `?cursor=...` on the same endpoint, or advance one chunk at a time
  with `POST /api/scan/chunk` (see "Scan cursors" below). Errors carry
  honest statuses: 400 bad owner/repo format or bad cursor, 404 repo not
  found or private, 409 repo changed mid-scan (start a fresh scan for
  the new HEAD), 429 GitHub rate limit, 502 GitHub upstream error. There
  is no 504 scan timeout, and there is no "scan no longer running"
  dead-end: the server holds no scan state to lose.
- `POST /api/scan/chunk` - advance a scan by exactly one chunk. Body
  `{ cursor, head?, historyFindings? }`; returns the partial results
  plus the next cursor, or the finished report. See "Scan cursors"
  below.
- `/mcp` - MCP server for AI assistants (Streamable HTTP transport,
  stateless). `/api/mcp` is an alias for the same handler. See
  "Use with your AI assistant (MCP)" below.

## Scan cursors

A scan is a sequence of **chunks**, and the server holds **no scan job**
between them. Every chunk response returns a **cursor**: a small
base64url JSON object that says exactly where the scan got to
(owner/repo/branch, the pinned HEAD sha, the stage, and the position
inside the stage). The caller passes the cursor back with the next
request and the scan continues from that point. A server restart, cold
start, redeploy, or a request landing on a different instance changes
nothing - there is no job to lose. The partial findings of a scan in
progress are kept in a short-lived store (redacted fragments only,
deleted when the scan finishes or after 7 days) so a resume on another
instance loses nothing; API callers can also carry the accumulated
history findings themselves and send them back at assemble time.

The three stages:

1. **head** - the current files: secrets, frameworks, dependencies,
   posture. One chunk. The HEAD report renders first and fast, with a
   provisional score (clearly labelled - it counts HEAD secrets +
   posture only, and changes when the rest lands).
2. **history** - newest-first, in commit chunks: up to 200 commits per
   chunk over the git protocol, 10 per chunk over the GitHub API.
   Live progress throughout (commits scanned so far, secrets found so
   far). A rate limit stops cleanly at the next unscanned commit - the
   cursor points at it, and a later call retries it when quota returns.
3. **assemble** - merge HEAD + history, run the OSV flaw check, score.
   Idempotent: safe to retry with the same inputs.

What a cursor carries: the repo, the pinned HEAD sha, the stage, and
the resume position (git path: the last commit scanned; API path: the
next list page / index / that page's SHAs). What it never carries:
findings, file contents, or any secret fragment.

```bash
# Start: a small repo answers 200 with the full report.
curl https://git-secure.com/api/scan/Squ1zM0/GitSecure

# A huge repo answers 202 with a cursor + partial results.
# Resume it - as many times as it takes, on any instance:
curl "https://git-secure.com/api/scan/torvalds/linux?cursor=<cursor>"

# Or advance exactly one chunk at a time:
curl -X POST https://git-secure.com/api/scan/chunk \
  -H 'Content-Type: application/json' \
  -d '{"cursor": "<cursor>", "historyFindings": [...]}'
```

A bogus cursor answers 400 with plain English ("That scan link
doesn't look right...") - the caller discards it and starts fresh,
never a crash. If the repo changes mid-scan (new commits land), the
assemble step answers 409 and the scan restarts cleanly for the new
HEAD. A partial history is never presented as complete: the report
says exactly how many commits were checked and why it stopped.

Honest bound: `torvalds/linux` is ~4 GB with ~1M commits. Its HEAD
report renders (the tarball is streamed, never materialised whole),
and history streams newest-first and survives restarts - but a full
1M-commit history walk takes a very long time even chunked, and the
unauthenticated GitHub API quota (60 req/hour) bounds the API path to
a few chunks per hour. The scan says exactly how far it got; it does
not fake completion.

## Use with your AI assistant (MCP)

GitSecure speaks the Model Context Protocol, so an LLM can scan a repo
for you. Canonical server URL: **`https://git-secure.com/mcp`**
(`/api/mcp` works too). No sign-up, no API key. The home page has
copyable config snippets for Claude, Cursor, VS Code, and Windsurf/Cline
(the report page has a short version of the same section).

```json
{ "mcpServers": { "gitsecure": { "url": "https://git-secure.com/mcp" } } }
```

Tools (all return the full report):

- `scan_repo` (owner, repo) - run a live security scan, return the full
  report: score, grade, counts, summary, limits, and the full detail
  (file names, line numbers, redacted secret fragments, framework
  versions, vulnerability IDs). Use when someone asks whether a repo is
  safe.
- `get_report` (owner, repo) - read or refresh the full report for a
  repo. It runs a fresh live scan - finished reports are never stored,
  so the result is always current. If a scan is already running, resume
  it with `resume_scan` and the cursor instead of starting over.
- `resume_scan` (cursor) - continue a scan that is still running, from
  the cursor `scan_repo` or `get_report` returned. The cursor carries
  the whole resume position, so the scan continues from the last
  finished chunk instead of starting over, even if the server
  restarted since. Returns the full report when the scan finishes, or
  another still-running message with a fresh cursor.
- `list_checks` (no args) - what GitSecure checks, in plain English,
  plus the scan notes. Use before a scan, or to explain a score.

**MCP returns the full report, like the web flow.** Secrets are still
redacted fragments only - never shown in full. There is no `full`
parameter and no login. A scan takes about 15 seconds for a small repo;
owner/repo names are validated the same way as on the site, and a bad
name, a missing/private repo, or a GitHub rate limit comes back as a
plain-English error, never a stack trace. A large repo keeps running
in chunks: the tool drives the chunks server-side with the cursor for
~50 s, and if it is still running it says so with its live progress
and the cursor - call `resume_scan` with that cursor to continue it
from the last finished chunk. The endpoint is stateless (a fresh server
per request, no session state, no git binary needed - the scan falls
back to API patches when git is unavailable), so it works on the
Vercel serverless runtime. A plain `GET /mcp` is refused with a 4xx:
in stateless mode the server holds no SSE stream (MCP clients use
POST).

Test it against a local production server (real protocol handshake with
the SDK client - initialize, tools/list, live `scan_repo` calls):

```bash
npm run build && npm start     # in one terminal
npm run test:mcp               # in another - 62 checks
```

## How scans run

- **Stateless chunks** (`src/lib/chunks.ts`, cursor in
  `src/lib/cursor.ts`): the API / report page / MCP drive chunks for
  up to ~50 s (the fast path), and if the scan is still running answer
  202 with a cursor and the partial results so far; the caller resumes
  with the cursor until the scan finishes. **No scan is ever killed
  for taking too long.**
- **The server holds no scan job.** A short-lived store holds
  in-progress findings only (redacted fragments, 7-day expiry, deleted
  at finish). No database of reports, no in-memory job map. A chunk
  response's cursor carries the whole resume position, and the partial
  results live with the caller (the browser: `sessionStorage` - a
  reload or a closed tab resumes from the last finished chunk, with a
  plain "Resumed - picked up where it left off" line; an API caller:
  its own memory, sending accumulated history findings back at
  assemble time).
- **HEAD first, history streams.** The HEAD chunk renders first
  (provisional score, labelled); history then streams newest-first
  with live progress, and the finished report swaps in without a
  reload. The report page never re-scans on reload once a finished
  report is saved in `sessionStorage` for the same HEAD.
- **History depth:** full history, newest-first, to the oldest commit -
  no commit cap, no patch-size cap, no time cap. The scan uses the
  **git-protocol path** first (pure JS, no git binary, no GitHub REST
  quota - it clones over the git smart-HTTP protocol and walks commits
  directly, with findings cached per commit SHA so a re-scan only walks
  new commits), then an ephemeral `git clone` into `/tmp` (deleted after
  the scan) where a git binary exists, then the **API history path** as
  a last resort (it pages the GitHub commits API and fetches each
  commit's patch, per-commit attribution). The report says which path
  was used and exactly how many commits were checked. Only if every
  path fails does it fall back to patches of the 5 most recent commits.
  The only remaining history bounds are physical ones: an emergency
  memory guard (500 MB of patches) and a walk safety valve (40 s /
  700 MB heap) that stop a giant walk cleanly with an honest note -
  and a streaming byte bound on the pack download (150 MB:
  isomorphic-git buffers the whole pack in memory, so past that the
  clone aborts and history goes through the API path instead).
  A history failure is never a failed scan: the report carries a note
  and the HEAD scan still completes in full.
- **HEAD scan: unlimited.** Every file in the HEAD tree is scanned,
  manifests and configs first (fetched from one tarball download,
  falling back to per-file fetches). There is no file-count cap and no
  per-file or total size cap. Binary, `dist`, `node_modules` and
  `.next` paths are skipped: generated/vendored paths, not source
  files. The tarball download has a **streaming memory guard** (the
  download aborts mid-stream past 500 MB and the per-file fallback
  still scans every file) - a guard, not a cap. Repos over 1 GB
  (torvalds/linux, ~4 GB) stream the tarball instead of materialising
  it: entries are secret-scanned as they arrive and only
  manifests/configs/workflows/infra files are kept in memory, so the
  HEAD step cannot OOM the function. GitHub rate limits still exist;
  if a fetch fails, the report says plainly how many files were
  actually scanned, never pretending it scanned everything.
- **No result-count caps.** Every secret finding, every dependency,
  every advisory, every posture and framework finding is listed. The
  report page renders huge lists progressively (100 at a time with
  "Show more" / "Show all"), with collapsible groups, filters, and
  the map - the data is never capped to make the page fit.
- **Dependency check:** every pinned dependency is asked about via
  OSV.dev, in batches of 1,000 per query, and full advisory detail is
  fetched for every advisory found, in batches of 8 - with **no time
  budget on either phase**. If OSV is unreachable the scan continues
  and says so.
- **"About this scan".** A complete scan says so once, with the exact
  counts (files, history commits, dependencies checked, advisories
  with full detail), and nothing else. A scan that could not cover
  everything states exactly what it could not cover, one line per
  fact. The standing facts stay: public repos only; no secret is ever
  stored, logged, or shown in full.
- **Rate limits:** unauthenticated GitHub API is 60 requests/hour. A
  scan on the happy path makes 0 api.github.com requests (branch and
  HEAD come from `git ls-remote`, the file list from the tarball), but
  the API history path uses about one request per commit, so a repo
  with a long history can hit the unauthenticated limit on Vercel;
  when it does, the scan keeps the findings so far and says so
  plainly. Setting a `GITHUB_TOKEN` env var raises the limit to
  5,000/hour.
- GitSecure is **not a replacement for GitHub Advanced Security**.

## Dogfooding

Scanning GitSecure's own repo (`Squ1zM0/GitSecure`) returns score
**100 / A** (measured 2026-11-28, live, against the current main):
39 secrets, all 39 triaged likely-test-key, 0 vulnerabilities,
0 posture issues, 374 files scanned, 59 history commits, 225
dependencies. The 39 findings are all known-fake detector bait in
the test scripts and docs - the scanner does not skip test files on
purpose, because real leaks hide in "just a test" files too. The
would-be score with every secret at full weight is 0, which is shown
on the report alongside the 100 so the test-key adjustment is
checkable, not hidden. Vulnerable dependency versions used to prove
detection are generated at test time from in-memory strings, never
committed as scannable files, and the repo ships a `SECURITY.md` and
Dependabot config.

The baseline repo used for regression checks is `Squ1zM0/TechDirect`:
**73 / C** (0 secrets, 4 vulnerabilities, 4 posture issues, full
history) - the posture count includes one genuine finding, a script
injection in a workflow file, found by the scanner itself.

## Tests

```bash
npm run test:scanner     # synthetic fixtures with FAKE planted secrets only
npm run test:history     # full-history regression: a fake secret planted in
                         # an old commit, removed from HEAD
npm run test:tier3       # Tier 3 infra detectors on fixtures (Docker,
                         # Kubernetes, Terraform, GitHub Actions, Vercel /
                         # Supabase) - no network
npm run test:public-full # no login flow, no owner gate, no file-count cap,
                         # full detail + redaction - no network
npm run test:techdirect  # live scan of the real public repo Squ1zM0/TechDirect
npm run test:history-git # live git-protocol history against the real GitHub API
npm run test:ui-phase7   # dial, lists, map, CSS, no-sign-in copy - no network
npm run test:usage-phase11 # secret usage analysis - no network
npm run test:triage-phase10 # layered secret triage - no network
npm run test:cursor-phase9 # stateless chunked scans - no network
npm run test:deps-phase13 # dependency-flaw fixes - needs network (api.osv.dev)
npm run test:score-phase12 # triage-weighted scoring - no network
npm run test:mcp         # MCP end-to-end: needs a running production server
                         # (npm run build && npm start). Set MCP_BASE_URL to
                         # test another server.
```

Counts from the 2026-11-28 run (all passing):

| Suite | Checks |
| --- | ---: |
| test:scanner | 73 |
| test:history | 79 |
| test:tier3 | 40 |
| test:public-full | 56 |
| test:cursor-phase9 | 192 |
| test:triage-phase10 | 63 |
| test:usage-phase11 | 91 |
| test:score-phase12 | 40 |
| test:deps-phase13 | 22 |
| test:fixtures-phase14 | 42 |
| test:ui-phase7 | 175 |
| test:map-phase18 | 102 |
| test:map-phase19 | 112 |
| test:code-risks-phase19 | 81 |
| test:posture-phase19 | 78 |
| test:phase20 | 53 |
| test:assemble-head-validation | 16 |
| test:phase17-worker-b | 70 |
| test:phase17-worker-c | 81 |
| test:phase17-worker-f | 48 |
| test:phase16-a | 56 |
| test:phase16-worker-b | 31 |
| test:ui-phase15c | 36 |
| test:ui-phase16c | 45 |
| test:report-markdown | 30 |
| test:resilience-phase15 | 47 |
| test:zero-rest | 26 |
| test:mcp | 62 |
| **Total** | **1,847** |

The fixture uses invented credentials only (including the official AWS
example key, assembled in memory by the test from fragments). Never
put a real leaked secret in a test, and never commit a literal
secret-pattern value, even a fake one: GitHub push protection blocks
those on push.

## Tech

Next.js 16 (App Router) + TypeScript + React 19. No paid services, no
external database, no auth library (there is no login flow).
Deployable on the Vercel free tier. Live at https://git-secure.com.

## Changelog

- **Secrets + fingerprinting** - 22 secret detectors, full-history
  scanning, OSV dependency flaws, framework fingerprinting (JS/TS,
  Python, Rust, Go, Ruby, PHP, Java/Kotlin, .NET, Docker, Kubernetes,
  Terraform, Actions, Vercel, Supabase), posture checks, 0-100 score.
- **Full report for everyone** - no login flow, no owner gate; the file
  scan is unlimited, with no result-count caps.
- **MCP server** - `scan_repo`, `get_report`, `resume_scan`,
  `list_checks` at `https://git-secure.com/mcp`.
- **Resumable chunked scans** - stateless cursors, no server-side job
  state; a restart between chunks loses nothing.
- **Secret triage** - likely-test-key / uncertain / likely-genuine-leak,
  with triage-weighted scoring and a would-be score on every report.
- **Secret usage** - in use vs true dead end, with the track through
  the map; likely-test findings separated into their own section.
- **Dogfooding integrity** - vulnerable fixtures are generated at test
  time, never committed; the repo itself scans 100/A.
- **Zero REST calls** - a full happy-path scan makes 0 api.github.com
  requests; branch and HEAD come from `git ls-remote`.
- **Report page loads fast** - the progress screen renders immediately
  and the browser drives the scan; reloads resume visibly.
- **Coverage audit** - 9 more secret detectors, modern Python/Dart/Cargo
  parsers, 4 more posture checks, durable per-scan accumulation in
  Upstash Redis so multi-invocation resumes lose nothing.
- **Dynamic map plane** - pan, zoom, pin, drag, traverse, labelled
  clickable edges, sector layout, map as the default view.
- **Deeper checks** - dangerous code patterns, CI pipelines everywhere,
  TLS and network, secrets in logs and errors, frontend XSS sinks,
  container hardening, exposed files, install-script supply chain.

The full build log lives in `GITSECURE.md`.

## License

MIT. See `LICENSE`.

## Security

To report a vulnerability in GitSecure itself, see `SECURITY.md`.
