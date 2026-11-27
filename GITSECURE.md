# GitSecure — Cobalt side project (MVP approved, 2026-11-25)

Mirror-site concept: `github.com/{owner}/{repo}` -> `git-secure.com/{owner}/{repo}`
No install, no config — swap the URL, get a security report.

## Decisions (Freddy, 2026-11-25, 12:59 PM MST)
- GREEN LIGHT: build the MVP in the background, solo, no intervention.
- Repo: https://github.com/Squ1zM0/GitSecure — public, created
  2026-11-25T19:56:43Z, default branch main. MVP pushed 2026-11-25,
  commit 090972850ebacc034d7fe82100871ea981f04af4, 36 files, verified by
  read-back. Connector: custom.github-gitsecure (fine-grained token,
  Contents read/write on GitSecure only; permissions admin/maintain/push).
- Domain: git-secure.com — prices Freddy gave: $22 / $10 (recorded as given;
  do NOT buy without a separate explicit go-ahead; start on Vercel subdomain).
- Report visibility, FLIPPED (Freddy, 2026-11-25, 3:38 PM MST): the site
  only scans PUBLIC repos, so the full detail that used to be owner-only
  now goes to ANYONE who calls — no login flow, no OAuth. Rationale: it is
  all information already public in the repo. The redaction rule is NOT
  flipped: a secret is still never shown in full, only a redacted fragment.
- PHASE 3 DONE 2026-11-25: plain/fluid human flow (loading state, input
  validation, honest API statuses, plain-English pass, mobile 360px clean)
  + MCP server for LLMs (see "Phase 3" sections below). Pushed as
  1a0387ea7b16530383059047aaa8cbcb4a70dd31 (59 files), verified by read-back
  and live: home 200 with the MCP section, live scan API 83/B, live MCP
  initialize 200 (gitsecure 0.1.0) and tools/list returns exactly
  scan_repo, get_report, list_checks.
- PHASE 4 (Freddy, 2026-11-25, ~3:38–3:39 PM MST): full report for
  EVERYONE (no login flow — owner gate + Auth.js deleted), "Honest
  limits" section removed from the site, and the HEAD file scan made
  UNLIMITED — no file-count cap at all (no 250, no 1,000, no 5,000).
  See "Phase 4 status" below. Redaction rule unchanged. Pushed
  2026-11-25 as 836180c9 (+ eb69e148 cleanup push for stale files the
  helper left behind), verified live: home 200 with no Honest limits,
  live scan API TechDirect full 83/B with filesScanned 2,802, live MCP
  scan_repo full with redacted detail.
- PHASE 5 (Freddy, 2026-11-25, "Shouldn't be capped at 100."): no
  result-count caps anywhere (secrets, advisories, dependencies — the
  DefinitelyTyped proof case), OSV query/detail as time budgets that
  never drop a finding, plus real navigation on the report page for
  huge lists: collapsible groups, type/severity/file filters, a file
  map, a GitHub blob link on every secret and an in-page anchor per
  finding. See "Phase 5 status" below.
- PHASE 6 (Freddy, 2026-11-25, "Continue development yourself, Auto —
  you know the vision."): Tier 3 infra fingerprinting (Docker /
  Kubernetes / Terraform / GitHub Actions / CI configs) and the
  API-based full-history path that fixes the Vercel no-git live caveat
  (live history fell back to 5 commits; now it pages the commits API
  for the full history). See "Phase 6 status" below.
- PHASE 7 (built 2026-11-25, solo, design only): UI/UX redesign —
  coherent identity, real dark mode, score dial, report hero with a
  one-sentence verdict, actionable finding cards, usable spider map,
  designed loading/error screens, motion + accessibility. No scan
  behaviour, caps, scoring, redaction, or API/MCP contracts changed.
  First phase visually verified in a real headless Chromium (earlier
  phases could not render the UI). See "Phase 7 status" below.
- PHASE 8 (built 2026-11-25, solo, NOT pushed): git-protocol history
  + per-commit cache — replaces the REST-API history path (which stopped
  at 56/62 TechDirect commits on the 60 req/hour unauthenticated quota)
  with isomorphic-git over the git protocol (0 REST calls, 62/62 live),
  caches findings per commit SHA, and removes the 1000-commit / 50 MB /
  45 s history caps (only an emergency memory guard remains). No
  GITHUB_TOKEN — Freddy's ruling. See "Phase 8 status" below.
- PHASE 8 (built 2026-11-25, solo): async scan jobs + the remaining
  caps removed, from Freddy's screenshot of the live TechDirect
  report's "Scan limits" section — "Fix all of the scan limits as
  much as you can so you don't have limit limits." The 55 s scan
  timeout is gone (jobs run to completion in the background), the OSV
  query/detail time budgets are gone (every dep queried, every
  advisory detailed), the tarball guard is a streaming memory guard
  (not a cap), and "Scan limits" is rewritten as "About this scan".
  History internals (git-protocol path + per-commit cache) belong to
  the history worker; this phase only calls its exported interface
  and states no history numbers. See "Phase 8 status" below. NOT
  pushed, NOT deployed — another worker owns the push.
- PHASE 10 (built 2026-11-25, solo): layered secret triage — test keys
  vs genuine leaks, from Freddy's direction: "Distinguishing intentional
  test keys from genuine credential leaks requires a layered triage
  pipeline combining static context analysis, cryptographic
  inspection, and automated secret-scanning." Trigger: his screenshot
  of the live torvalds/linux report flagging the Linux SGX self-test
  signing key as CRITICAL. See "Phase 10 status" below.
- PHASE 12 (built 2026-11-26, two workers: scoring core + score
  explanation UI/docs): triage-weighted scoring — Freddy's direction:
  "But that live proof with an F scored inaccurate because every
  single one is a test, so we need to make sure that the scoring
  system is accurate if finding tests." Phase 10's rule "triage never
  changes the score" is OVERTURNED: likely-test-key ×0, uncertain
  ×0.5, genuine leak ×1, and the report hero explains the adjustment
  with the actual numbers and both scores. See "Phase 12 status"
  below. NOT pushed — the coordinator integrates and pushes.
- DEPLOYED 2026-11-25 by Freddy: live at https://gitsecure.vercel.app/,
  verified live by Cobalt (home page + live TechDirect scan 83/B, matching
  the local test). Vercel MCP still returns 403 on team scope
  ffrench0598-6221s-projects, so the dashboard deployment state could not
  be checked; live serving is the proof. Do NOT disconnect/reconnect
  Vercel unprompted. Note: https://git-secure.vercel.app/ is a different
  Vite template project, not GitSecure.

## Why
Other mirrors in the TechDirect sweep read / summarise / diagram / podcast a repo.
None check whether it is safe. Proof it matters: 2026-11-06 AIoN incident —
a Discord webhook sat in a public commit in SqulzMD/aion-index (commit
620105ba80e15f1c515b1f797404d06d5ffd5ae7, from 2026-02-03) until a bot flagged
it and deleted it. GitSecure would have caught it in February.

## Pillars
1. **Leaked secrets — HEAD + full history.** Discord/Slack webhooks, AWS keys,
   GitHub PATs, Stripe/OpenAI/database URLs, private keys, .env, hardcoded
   passwords. Deleting a file does not delete the commit.
2. **Framework / stack fingerprinting + flaw watch (added 2026-11-25).**
   Detect every framework / runtime / infra piece in use, with exact versions,
   then map it to known flaws. See below.
3. **Security posture.** Missing SECURITY.md, Dependabot, secret scanning;
   dangerous GitHub Actions patterns; secrets that could print in logs;
   overly broad workflow permissions.
4. **Dependency risk.** Known vulnerable / badly outdated packages.
5. **Exposure hygiene.** Emails, internal URLs, IPs, PII, .gitignore gaps.

Each finding: what it is, where (file:line:commit), severity, exact fix
(rotate/revoke, move to GitHub Secrets, rewrite history, upgrade to X).

## Framework fingerprinting — how it works
- **Detection sources:** package.json / lockfiles, requirements.txt / Pipfile,
  Gemfile, go.mod, composer.json, pom.xml / build.gradle, Cargo.toml,
  Dockerfile, framework config files (next.config, vite.config, angular.json,
  etc.), imports, and directory conventions. Monorepos get a per-package stack.
- **Coverage goal (2026-11-25, Freddy): anything and everything, for every
  user — not just one stack.** Vite, Rust, JS/TS, and all dependencies, plus
  every other ecosystem we can fingerprint reliably. Architecture must be
  pluggable: adding an ecosystem = adding a detector + an advisory source,
  not rebuilding the scanner. Launch in tiers (below) so "everything" is a
  roadmap, not a day-one promise.
- **Tier 1 (MVP):** JS/TS — npm / pnpm / yarn / bun, package.json + lockfiles;
  Next.js, React, Vue, Angular, Svelte, Vite, Express, Nest, Nuxt, Astro.
  Vite specifics: vite.config, plugins, dev-server exposure, SSR config,
  `VITE_`-prefixed env vars leaking into the client bundle.
  Python — requirements / Pipfile / poetry, Django, Flask, FastAPI.
  Rust — Cargo.toml / Cargo.lock, crates.io; RustSec Advisory DB,
  `cargo audit` / `cargo deny` equivalents, unsafe-code and yanked-crate flags.
- **Tier 2:** Go (go.mod, Gin/Echo/Fiber), Ruby (Gemfile, Rails), PHP
  (composer.json, Laravel/Symfony/WordPress), Java/Kotlin (Maven/Gradle,
  Spring), .NET (NuGet, ASP.NET), Swift/Kotlin mobile, Elixir, Dart/Flutter.
- **Tier 3 — infra / everything else:** Docker / Docker Compose, Kubernetes
  manifests, Terraform, GitHub Actions, Vercel / Supabase / Postgres config,
  CMSs, static-site generators, CI pipelines, shell scripts.
- **Dependencies, all of them:** direct + transitive, dev vs prod, lockfile
  drift (manifest and lock out of sync), unpinned / `*` / `latest`, abandoned
  / yanked / typosquat-suspect packages, duplicate versions of the same dep.
  A flaw in a transitive dep counts — that is where most real-world CVEs hide.
- **Catalog:** build a maintained framework registry — web (Next.js, React,
  Vue, Angular, Svelte, Django, Flask, Laravel, Rails, Express, FastAPI...),
  mobile, CMS, runtime (Node, Python, Go, PHP, Rust...), infra (Docker,
  Supabase, Vercel, Postgres...). Each entry: how to detect it, where its
  version lives, its advisory sources, its EOL dates.
- **Helping every user:** reports in plain English, not CVE-speak — what it
  is, what it lets an attacker do, what to upgrade to, in what order. A
  non-technical repo owner should be able to act on it, not just a senior dev.
- **Flaw mapping:** version -> OSV.dev / GitHub Advisory DB / NVD / framework
  security advisories. Report: CVE/advisory ID, affected versions, fixed
  version, severity, what breaks if exploited, upgrade path.
  Example from our own stack: Price-Cal is Next 14.2.5 / React 18.3.1;
  Leave Tracker is Next 15.5 / React 18.2 — GitSecure should be able to say
  exactly that, then say whether that Next version has a known flaw and what
  version fixes it.
- **Watch, not just scan:** a one-off scan goes stale the day a new CVE drops.
  V2: remember the fingerprinted stack, re-check advisories on a schedule,
  alert when a new flaw lands on a framework/version the repo actually uses.
  That turns GitSecure from a report into a monitor.
- **Accuracy rules:** prefer lockfile-pinned versions over ranges; flag
  unpinned / `*` / `latest` as a finding; report transitive deps separately
  from direct ones; say when a version could not be determined instead of
  guessing.

## Hard rules
- Never show a full secret. Type, location, confidence, redacted fragment only.
- Scan, report, throw it away. No storing secrets.
- No live-validating a credential by calling the service it belongs to.
- No bulk scraping. Public repos first; private repos only via owner-consented
  GitHub App.
- Not a replacement for GitHub Advanced Security; say so, and tune false
  positives in the open.

## Autonomous scope for Cobalt
Scaffold repo, scanner engine (Gitleaks/TruffleHog-style detectors + custom
Discord webhook detector), framework fingerprinting module + registry,
one-page report UI, test on own repos (TechDirect, Price-Cal, Voices By Fred;
aion-index commit as regression test), deploy on Vercel, iterate.

## Decisions needed from Freddy (only these — 1 and 2 answered 2026-11-25)
1. DONE: repo Squ1zM0/GitSecure, domain git-secure.com.
2. DONE, then FLIPPED (Phase 4, Freddy 2026-11-25): was "full detail
   owner-only; public gets score + counts" — now everyone gets the full
   report, no login flow, because the site only scans public repos.
3. OPEN: Launch: free side tool, or later paid monitoring / alerts / badge?
   (Not a blocker for the MVP — build free.)

## Phases
- MVP: secret scan (HEAD + history), framework fingerprint + known-flaw check,
  redacted report, security score.
- **Phase 2 (built and pushed 2026-11-25, commit 870f889f, live on Vercel):**
  full-history clone scanning, Tier 2 frameworks (Go/Ruby/PHP/Java/.NET),
  full OSV advisory detail, real GitHub OAuth owner gate (code complete,
  credentials pending — REMOVED in Phase 4, see below). Details in
  "Phase 2 status". LIVE
  CAVEAT (verified 2026-11-25): the Vercel serverless runtime has no git
  binary, so live scans fall back to API patches of the 5 most recent
  commits and say so in the report; full-history (62 commits on TechDirect)
  works locally where git exists. Fixing that in production needs either
  a GITHUB_TOKEN in Vercel or an API-based history path — a Phase 3 item,
  not a Phase 2 blocker. **FIXED in Phase 6 (2026-11-25): the API history
  path now scans the full history on Vercel too — see "Phase 6 status".**
- V1: + dependencies, workflows, posture checks.
- V2: stack watch / alerts, GitHub App, private repos, CI badge.

## Phase 3 Part A — functionality polish (built 2026-11-25, pushed + live 2026-11-25 as commit 1a0387ea)

Polish only — no scanner logic, scores, or public/full split changed.
TechDirect still 83/B, verified locally and on the production server.

- **Loading state** (`src/app/[owner]/[repo]/loading.tsx`): streams instantly
  while the ~15 s live scan runs — "Scanning the repo… Checking files…
  then the full history, then dependencies for known flaws." Report-page
  time-to-first-byte on the production server fell from ~22 s to ~0.05 s
  (full page still ~15 s). Static progress text describing the steps in
  order, not a live per-step indicator — the scan is one server-side job.
- **Home form** (`src/app/page.tsx`): button disables and reads "Scanning…"
  while navigating; pasted github.com / git-secure.com URLs accepted with
  any trailing path (`/tree/main`, `/issues/…`, trailing slash, `.git`);
  owner/repo validated to letters, numbers, dots, hyphens, underscores with
  a plain-English error; empty input gets a helpful message. Parse logic
  covered by 16 cases run against the exact shipped function
  (all pass; script in /tmp/test-parseinput.ts, ephemeral). Client flow
  also verified in a real headless browser: pasting
  `https://github.com/Squ1zM0/TechDirect/tree/main` navigated to
  `/Squ1zM0/TechDirect` with the button showing "Scanning…".
- **Honest scan errors** (`ScanError` in `src/lib/scan.ts`, kind + HTTP
  status): 400 bad owner/repo format (validated before any GitHub call),
  404 repo not found or private, 429 GitHub rate limit (GitHub 429, or 403
  with `x-ratelimit-remaining: 0`; other 403s are 502), 504 scan timeout
  (55 s race inside the 60 s route limit; GitHub fetch timeouts also map
  to 504), 502 GitHub upstream error, 500 unknown. The scan API returns
  the status; the report page shows the matching plain-English message
  with a "Scan another repo" action. Caveat: the report *page* itself
  still returns HTTP 200 for a failed scan — Next.js App Router pages
  cannot set a response status; only the API carries the honest status.
- **Report page**: "Scan another repo" link at the top and a button at the
  bottom; the technical history-depth string is now plain English under
  the score ("History checked: 62 commits, newest first" — full limits
  list below unchanged); one plain line explains the score and what would
  raise it (`explainScore` in `src/lib/score.ts`, e.g. "83 out of 100
  (grade B) is a good score. Most of the points lost come from 4 known
  flaws in dependencies — upgrading the affected packages would raise
  the score.").
- **Plain English**: "CVSS" and "OSV.dev" explained in plain words on
  first use everywhere in the human UI ("a free public database of known
  software flaws", "a severity score"); the only remaining "CVSS" is a
  code comment in `src/lib/osv.ts`. Vulnerability lines now read as one
  plain sentence — what the flaw is, what it affects, and what to upgrade
  to (advisory summary folded into `plainEnglish` in `src/lib/osv.ts`;
  the report page no longer renders the summary twice). "Honest limits
  (Phase 2)" renamed to "Honest limits" (home page + README).
- **Rate limit (429)**: NOT triggerable safely in testing (would need
  burning the unauthenticated quota); the 429 path is code-reviewed only.
- **Mobile (360 px)**: verified with a real headless-Chromium render of
  the production server (home, loading, report, error pages):
  `scrollWidth` 360 = viewport 360, zero overflowing elements, text
  readable, input full-width with button stacked below, counts in a clean
  two-column grid. Screenshots in /tmp (ephemeral).
- **Verification (2026-11-25)**: `npm run build` exit 0;
  `test:scanner` 48/48, `test:history` 9/9, `test:owner-gate` 20/20,
  `test:techdirect` 83/B (62 history commits, ~15 s). Production server
  (`npm start`) checked by curl: home 200, TechDirect report 200
  (TTFB 0.05 s), scan API 200 (83/B), not-found API 404, bad-format API
  400. No literal secret-pattern values committed (fixtures still use
  `__SECRET_n__` placeholders; test-assembled fakes only).

## Phase 3 Part B — MCP server for LLMs (built 2026-11-25, pushed + live 2026-11-25 as commit 1a0387ea)

No scanner logic, scores, or public/full split changed. TechDirect still
83/B, verified locally and over MCP.

- **Endpoint:** `/mcp` (canonical) + `/api/mcp` (alias) — Next.js App
  Router routes (`src/app/mcp/route.ts`, `src/app/api/mcp/route.ts`,
  handler in `src/lib/mcp.ts`). Official MCP TypeScript SDK
  `@modelcontextprotocol/sdk` **1.32.2** (exact pin in package.json, no
  caret, no "latest") + `zod` 4.3.5, Streamable HTTP transport via the
  SDK's `WebStandardStreamableHTTPServerTransport` (web-standard
  Request/Response, fits App Router). Stateless: a fresh McpServer +
  transport per request (`sessionIdGenerator: undefined`), JSON responses
  (`enableJsonResponse: true`) so a ~15 s scan comes back as one
  response; no in-memory session state, no git binary required (the scan
  path already falls back to API patches when git is unavailable). Routes
  export only `maxDuration = 60` — Next 16 with `cacheComponents`
  rejects the `runtime` and `dynamic` route segment configs (build
  failed twice on those before they were removed).
- **Tools:** `scan_repo` (owner, repo — live scan, public report),
  `get_report` (owner, repo — same public report; a fresh live scan each
  time, documented as read/refresh — GitSecure never stores reports),
  `list_checks` (no args — the four checks in plain English plus the
  honest limits). Descriptions say when to use each, what it returns,
  and what it does NOT return. Input schemas validate owner/repo with
  the same rules as the site (letters/numbers/dots/hyphens/underscores);
  bad input, missing/private repos, and rate limits return
  plain-English errors, never a stack trace.
- **HARD RULE — MCP returns PUBLIC reports only, always:** every MCP
  response goes through `toPublicReport`. No tool accepts a `full`
  parameter or any owner-mode flag. Proved by `npm run test:mcp`, which
  scans Squ1zM0/GitSecure (0/F, 6 known-fake findings) over MCP and
  asserts the response contains no file names, line numbers, or secret
  fragments. **SUPERSEDED IN PHASE 4:** MCP now returns the full report
  like the web flow (secrets still redacted); `toPublicReport` is gone
  and the dogfood score is 1/F — see "Phase 4 status" above.
- **Human view:** `src/components/McpSection.tsx` — "Use with your AI
  assistant (MCP)". Full version on the home page: MCP server URL
  (https://git-secure.com/mcp) plus copyable config snippets for
  Claude, Cursor, VS Code, and Windsurf/Cline (snippets in
  `src/lib/mcp-config.ts`, all valid JSON — the test parses each one),
  plus one plain line explaining the LLM gets the public score and
  counts only, never full detail. Compact version on the report page:
  URL + Claude snippet + link to the home page for the rest. Copy
  buttons use `navigator.clipboard` with a textarea fallback and a
  "Copied" state. Verified in the rendered production HTML: 5 copy
  buttons on home, 2 on the report page.
- **Test** (`scripts/test-mcp.ts`, `npm run test:mcp`): uses the SDK's
  own Client + StreamableHTTPClientTransport against a running local
  production server (`npm run build` + `npm start`; `MCP_BASE_URL`
  overrides the server). Real protocol handshake (initialize),
  tools/list, live `scan_repo` calls. 49 checks, all passing
  2026-11-25: TechDirect 83/B (0 secrets, 4 vulns, public-only fields
  absent, no `js-yaml` package name), GitSecure 0/F (6 secrets counted,
  no file names / line numbers / fragments), `get_report` TechDirect
  83/B, bad format + missing repo plain-English errors with no stack
  trace, all four snippets valid JSON, plain GET /mcp refused with a
  4xx (406 without an SSE Accept header — stateless, no stream held).
  Raw curl initialize on both `/mcp` and `/api/mcp` returns 200.
- **Verification (2026-11-25):** `npm run build` exit 0;
  `test:scanner` 48/48, `test:history` 9/9, `test:owner-gate` 20/20,
  `test:techdirect` 83/B (62 history commits, ~15 s), `test:mcp` 49/49.
  No literal secret-pattern values committed (fixtures still use
  `__SECRET_n__` placeholders; test-assembled fakes only).
- **Limits that remain:** a scan over MCP takes the same ~15 s as on the
  web (one JSON response, no streaming progress); the MCP client timeout
  in the test is 120 s. A GET that asks for `text/event-stream` opens a
  standalone SSE stream the transport holds open — MCP clients use POST,
  so this is not probed in the test (a probe hung until killed).
  Dogfood score correction: GitSecure itself is 0/F now, not 3/F — the
  Phase 2 push changed the repo's contents (see dogfooding note above),
  not the scanner.

## Phase 4 status — full report for everyone + unlimited file scan (built 2026-11-25, Freddy's word ~3:38–3:39 PM MST)

- **Visibility flip.** The site only scans public repos, so the full
  detail that used to be owner-only now goes to ANYONE who calls — no
  login flow. Scan API `/api/scan/[owner]/[repo]` returns the full
  report to anyone (no sign-in, no `?full` flag, no owner check); the
  report page shows the full detail to anyone; MCP `scan_repo` /
  `get_report` return the full report too. Deleted: `src/lib/auth.ts`,
  `src/lib/owner.ts`, `src/app/api/auth/[...nextauth]/route.ts`, and the
  `next-auth` dependency (package.json + package-lock.json re-synced via
  `npm install`, exit 0, 6 packages removed). `src/lib/types.ts` has one
  report shape now (`FullReport`); `toPublicReport` is gone. Home "What
  you see" card rewritten as "What you get"; footer, MCP copy, README
  and this spec updated. The GitHub OAuth App steps are obsolete and
  deleted from the README — nobody needs to create one.
- **"Honest limits" section removed** from the home page and everywhere
  in the UI (Freddy: "No need for it."). Not moved to a footer or modal.
  Scan limits live in code comments and developer docs only now (README
  "How scans run" section — called "Scan limits" until Phase 8 renamed
  it — `src/lib/scan.ts` header).
- **Unlimited HEAD scan.** Removed `MAX_FILES = 250`, `MAX_FILE_BYTES =
  200_000`, `MAX_TOTAL_BYTES = 3_000_000` and the `slice(0, MAX_FILES)` —
  the scan now reads the whole non-skipped tree, manifests and configs
  first. Binary / dist / node_modules / `.next` skipping stays
  (generated/vendored paths, not source files — not a cap). GitHub tree
  pagination: the recursive tree call returns the whole tree in one
  response (up to 100k entries); a truncated flag is reported honestly.
  No other numeric file cap remains (grep-verified: no `MAX_FILES`,
  no `slice(0, N)` on the file list, no "250 files" in the scanner).
  The 55 s scan timeout inside the 60 s route limit still exists — on
  timeout the report says how many files had been fetched (live progress
  tracker in `scan.ts`), never pretending it finished. History caps
  unchanged (1,000 commits / 50 MB / 45 s). [Phase 4 record — both
  superseded in Phase 8: the timeout is gone (async jobs) and the
  history caps are gone (git-protocol history, no caps).]
- **Tarball read (needed to make unlimited actually complete).** The
  first unlimited build fetched each file separately from
  raw.githubusercontent.com — 2,802 fetches took ~120 s at 10-way AND
  at 40-way concurrency (measured: ~25 requests/s from one client, so
  concurrency was never the bottleneck), which blew the 55 s route
  timeout and made the proof-case repo un-scannable live. Fix, same
  scan, different transport: one tarball download from codeload
  (`fetchHeadFilesViaTarball` in `src/lib/scan.ts`, minimal tar reader,
  gunzip via node:zlib, entries never written to disk) — TechDirect's
  1.7 MB tarball downloads in ~1.4 s and the whole scan is ~12 s.
  If the tarball is unavailable the scan falls back to per-file fetches
  and still scans everything, just slower (the report says so in
  `limits`). The 500 MB tarball download guard is a memory guard with
  that same fallback, not a scan cap — no file is ever skipped because
  of it.
- **Redaction unchanged and re-tested.** Secrets are still fragments
  only (first 4 chars … last 2), never stored, never live-validated.
  Proved by `test:scanner` (full-report checks incl. a fragment with a
  JSON-escaped `"` — compared against the parsed report, not raw JSON),
  `test:public-full` (fixture scan, no full fake secret), and `test:mcp`
  (GitSecure dogfood over MCP, no full fake secret).
- **Verification (2026-11-25):** `npm run build` exit 0 (after clearing
  a stale `.next` cache that still referenced the deleted auth route);
  `test:scanner` 56/56 (was 48 — more checks added), `test:history` 9/9,
  `test:public-full` 32/32 (new, replaces `test:owner-gate`),
  `test:techdirect` 83/B with filesScanned = 2,802 — the full scannable
  tree, proved against an independent tree-API count (2,802 in the tree;
  local scan ~12 s via the tarball path), `test:mcp` 51/51 against a
  local production server (was 49 — two checks added: filesScanned
  > 250 and fixed versions present). No literal secret-pattern values
  committed (grep-verified; fixtures still use `__SECRET_n__`
  placeholders, test-assembled fakes only).
- **Pushed 2026-11-25, commit 836180c93f33464272c8d7c9c984ec0cb07ee905**
  (57 files, verified by read-back). **Then a second push was needed,
  eb69e1486926da02b9c6ca3d5afdf6ca897a0b5d:** the push helper
  (`gh-push-gitsecure.py`) passed `base_tree` when creating the new
  tree, so files deleted locally silently PERSISTED on the remote —
  the first push left `src/lib/auth.ts`, `src/lib/owner.ts`, the
  NextAuth route and `scripts/test-owner-gate.ts` on main, and the
  stale auth route (importing `next-auth`, no longer a dependency)
  broke the Vercel build, so the old deployment kept serving for
  ~15 minutes. Root-cause fix: the helper no longer passes `base_tree`
  (its docstring already promised a full tree replacement); the
  re-push removed the 4 stale files (remote tree now exactly the local
  working copy: 57 files + 19 directory entries) and Vercel deployed.
- **Live verification (2026-11-25, after eb69e148):** home 200, no
  "Honest limits", no sign-in / owner-only copy, "What you get" present;
  live scan API `Squ1zM0/TechDirect` 200, kind full, 83/B,
  filesScanned = 2,802, all detail fields present, js-yaml + fixed
  versions present, "Scanned all 2802 files in the tree" in limits
  (history 5 commits — the known Vercel no-git fallback); live MCP
  initialize 200 (protocol 2025-03-26, gitsecure 0.1.0), `scan_repo`
  Squ1zM0/GitSecure returns kind full with file names, line numbers
  and redacted fragments, no full fake secret. Live dogfood is 9/F
  with 5 secrets (not the local 1/F with 6): the Vercel history
  fallback only scans the 5 most recent commits, so the AWS example
  key in the old README commit is out of the window — the known live
  history caveat, not a scanner change.

## Phase 5 status — no result-count caps + navigation for huge reports (built 2026-11-25, Freddy's word: "Shouldn't be capped at 100.")

- **Trigger.** Freddy's screenshot of a live DefinitelyTyped report:
  61,814 files, 9,401 dependencies, grade F, "100 possible leaked
  secrets". The 100 was the cap, not the count.
- **Caps removed.**
  - Secrets: `dedupedAll.slice(0, 100)` in `src/lib/scan.ts` is gone —
    the dedupe is now exported `dedupeSecrets()` with no cap. HEAD +
    history findings are ALL listed (history was only ever truncated
    by that same slice; `src/lib/history.ts` itself never capped
    findings). `counts.secrets` is the true total.
  - Dependencies: `deps.slice(0, 200)` in the report assembly is gone
    — all dependencies listed. The report page gained a Dependencies
    section (it had none).
  - Advisories: `VULN_CAP = 100` in `src/lib/osv.ts` is gone — every
    advisory OSV returns is listed.
  - Posture / frameworks: never capped; grep-verified still uncapped.
    The only remaining `slice(0, 5)` is inside one VITE_ posture
    detail string (first 5 variable names + "+N more") — an honest
    inline summary, not a findings cap.
  - OSV query/detail: the hidden `slice(0, 60)` on queryable deps and
    the fixed `DETAIL_CAP = 50` are gone. Queries run in batches of
    1,000 inside a 15 s budget (measured: 1,000-query batch ~2.9 s,
    100-query batch ~1.5 s — big batches are far more efficient);
    detail fetches run in batches of 8 inside a 12 s budget for every
    unique advisory ID. A budget can leave an advisory ID-only or a
    dep unchecked for flaws, but never drops a finding, and the report
    says plainly how many deps were checked (`depsChecked` /
    `depsQueryable`) and how many advisories got full detail.
    `checkDependencies` returns the new counts; `scan.ts` reports them
    in `limits`.
- **Score.** `computeScore` already clamped 0–100; verified with 150
  critical secrets → exactly 0, grade F, never negative, never NaN.
  DefinitelyTyped stays 0/F with everything listed.
- **Report-page navigation** (`src/components/ReportLists.tsx`, link
  helpers in `src/lib/links.ts`, styles in `src/app/globals.css`):
  - Collapsible groups by secret type / file, advisory / package,
    posture title / severity — counts on every group, collapsed by
    default when the filtered list is large (>50).
  - Filters: dropdowns for type and severity, text search by file
    name (secrets), advisory/package (vulns), title/detail (posture),
    ecosystem + direct/transitive + name (dependencies). Every count
    line shows the true filtered count of the true total.
  - Map view (secrets): an SVG spider — repo node in the centre, the
    top 24 files by finding count around it, node size ∝ count, plus a
    paged chip list of every file with secrets. One node per file,
    never one per finding; works at phone width (SVG scales,
    `overflow-x: auto`, min-width 320px). Clicking a file filters the
    list to it. Tooltips carry file + count only — never a fragment.
  - Direct links: every secret row links to the exact file and line on
    GitHub (`github.com/{owner}/{repo}/blob/{branch|commit}/{file}
    #L{line}` — HEAD findings use the branch, history findings use
    their commit sha); every vulnerability links to its OSV.dev
    advisory page; every finding has an in-page anchor (`#secret-12`,
    `#vuln-3`, `#posture-2`, `#dep-5`) plus a copy-link button
    (clipboard API with textarea fallback, same as the MCP copy
    buttons). A shared anchor link clears the filters, forces the flat
    list open past the linked finding, and scrolls it into view.
  - Progressive rendering stays: 100 findings per chunk with "Show
    more" / "Show all", per list and per group.
- **Redaction unchanged and re-tested.** Fragments only, including in
  map tooltips and link labels. Proved by `test:scanner` (150-finding
  report, no full fake secret), `test:public-full`, `test:mcp`
  (dogfood over MCP, no full fake secret), a render-to-string check of
  the map (7/7), and a live blob-link check (200, real file content).
- **Verification (2026-11-25):** `npm run build` exit 0;
  `test:scanner` 68/68, `test:history` 9/9, `test:public-full` 56/56,
  `test:techdirect` 83/B with filesScanned = 2,802 (13.3 s),
  `test:mcp` 51/51 against a local production server. Dogfood moved
  1/F (6 secrets) → 0/F (8 secrets, 196 vulns) — honest: the fake
  database URL is now found at HEAD and in its introducing commits,
  and all 202 pinned deps are now OSV-checked (Tier 2 fixtures carry
  many real advisories). Test assertions updated with the measured
  values and the reason; see `scripts/test-mcp.ts` header.
- **Pushed 2026-11-25, commit 7ed620e0e9a3def9f2b4aa1c7618b75e2779dc61**
  (59 files, remote head + remote tree verified by read-back: exact
  match with local).
- **Live verification (2026-11-25, after 7ed620e0):** home 200;
  live scan API `Squ1zM0/TechDirect` 200, 83/B, filesScanned 2,802
  (2.8 s); live scan API `DefinitelyTyped/DefinitelyTyped` 200, 0/F,
  kind full, **403 secrets listed (counts.secrets 403 — the old "100"
  was the cap, not the count)**, filesScanned 61,814, dependencies
  9,401 listed, vulnerabilities 92 listed, frameworks 4, posture 1,
  history 5 commits (Vercel no-git fallback, known caveat), 28–36 s.
  Lists equal their counts (secrets 403/403, deps 9,401/9,401, vulns
  92/92); longest fragment 7 chars (redacted); no truncation line in
  limits. Secret types: hardcoded-password 301, private-key 41,
  generic-high-entropy 24, database-url 20, jwt-token 9, aws-access-key
  5, slack-token 2, github-token 1 — across 225 files, all HEAD.
  Live DT report page 200: Group by / type / severity / file-name
  filters, List/Map toggle, "Showing 403 of 403 secrets",
  "Showing 9401 of 9401 dependencies", anchors secret-0…secret-99
  rendered with "Show more (100 of 303 remaining)" / "Show all 403"
  (progressive rendering confirmed), Copy link buttons, 100 distinct
  GitHub blob links on the first page; the first link
  (`.../blob/master/.github/workflows/CI.yml#L132`) resolves 200 to
  the real file. Live MCP initialize 200 (protocol 2025-03-26,
  gitsecure 0.1.0).

## Phase 6 status — Tier 3 fingerprinting + API-based full history (built 2026-11-25, Freddy: "Continue development yourself, Auto — you know the vision.")

Two spec items, in order:

- **1. Tier 3 framework fingerprinting** (`src/lib/infra.ts`, fixtures
  `tests/fixtures/fake-repo-tier3/`, `npm run test:tier3` 40/40).
  Docker (Dockerfile `FROM` image[:tag], compose `image:`), Kubernetes
  manifests (Deployment / StatefulSet / DaemonSet / Job / CronJob / Pod
  + container images), Terraform (`required_providers` / `provider`
  blocks + `required_version`), GitHub Actions (`uses: owner/action@ref`),
  Vercel preset, Supabase config. Versions are read honestly or
  reported null — `latest` / missing tag, a Terraform range (`~> 5.0`),
  a 40-char SHA ref, and a K8s manifest version are all null, never
  guessed; `latest`/missing/branch refs are unpinned. Risky patterns
  are posture findings with a plain-English detail ending in an exact
  `Fix:`: Dockerfile running as root (or no USER), `latest` base image,
  secret-looking build args, remote-URL `ADD`, K8s `privileged` /
  `hostNetwork` / `hostPID` / `runAsUser: 0`, unpinned Terraform
  providers, unpinned Action refs. Deliberately NOT flagged: exposed
  ports (too noisy), `pull_request_target` (scan.ts already owns it),
  `persist-credentials: true` (default behaviour). Action deps are
  OSV-checked via the "GitHub Actions" ecosystem (`actions` in the
  osv.ts ecosystemMap); a SHA ref is not queryable, so it stays
  version-null. Wiring in `src/lib/scan.ts`: workflow files feed
  `parseWorkflowActions` into the dep loop, `detectInfraFrameworks`
  merges into the frameworks list (one entry per name, known version
  wins), `infraFindings` feeds the posture list. End-to-end proof:
  `actions/checkout` scans to 3 Action frameworks (checkout v7,
  setup-node v6, upload-artifact v7) with 27 vulnerabilities.
- **2. API-based full history on Vercel** (`src/lib/history.ts`,
  `scanHistoryViaApi`, `HistoryScanResult.method: "clone" | "api"`).
  When the git binary is unavailable or the clone fails, the scan now
  pages the GitHub commits API (100/page, `Link` next headers) up to
  the same 1,000-commit / 50 MB / 45 s caps, fetches each commit's
  patch (5 concurrent, 12 s per-fetch timeout), scans added lines only
  with hunk-accurate line numbers, per-commit attribution, redacted
  fragments only. Rate limit (429 / 403 with an empty bucket) stops
  gracefully: findings so far kept, note says a `GITHUB_TOKEN` raises
  the limit. One bad commit never fails the scan. The report says
  which path was used (`History scan (GitHub API — no git binary in
  this runtime)` vs `(ephemeral git clone)`). The old 5-commit patch
  fallback only runs if the API path also fails. Tested against a
  local mock GitHub API (`test:history` 9 → 23 checks): planted secret
  in an old commit found + attributed to the right commit, pagination
  across list pages, rate-limit behaviour. Live proof: API history
  against the real GitHub API scans all 62 TechDirect commits in
  ~6 s, unauthenticated.
- **Verification (2026-11-25):** `npm run build` exit 0;
  `test:scanner` 68/68, `test:tier3` 40/40, `test:history` 23/23,
  `test:public-full` 56/56, `test:techdirect` 83/B with filesScanned =
  2,802, `test:mcp` 51/51 against a local production server. No
  literal secret-pattern values committed (grep-verified; fixtures
  use `__SECRET_n__` placeholders, test-assembled fakes only).
- **Pushed 2026-11-25, commit c58d7b077d1419e2057996043de92bc0d574697d**
  (68 files, remote head + remote tree verified by read-back: exact
  match with local, no stale files).
- **Live verification (2026-11-25, after c58d7b07):** home 200; live scan
  API `Squ1zM0/TechDirect` 200, 83/B, filesScanned 2,802,
  historyCommitsScanned **56 via the API path** (was 5 — the Vercel
  no-git fallback is gone; the report says "History scan (GitHub API —
  no git binary in this runtime)"). NOT all 62: the scan stops at 56
  because the unauthenticated GitHub API limit is 60 requests/hour and
  a full 62-commit API history needs ~65 requests from Vercel (repo +
  tree + commits list + API list + 62 detail fetches), so the quota
  runs out first — the report says so honestly ("GitHub API rate limit
  was hit — scanned 56 commits before stopping. Setting a GITHUB_TOKEN
  raises the limit."). The code is correct — the same API path run
  from a machine with quota scans all 62 in ~6 s — the fix is setting
  a `GITHUB_TOKEN` env var in Vercel (5,000/hour), which needs
  dashboard access (Vercel MCP is 403, so Cobalt cannot set it). Live
  Tier 3 example (`actions/checkout`) could NOT be verified live in
  this session: the two TechDirect verification scans consumed the
  shared unauthenticated quota, so the checkout scan answers 429
  "request limit was hit" — same root cause, same fix. Tier 3 is
  verified locally end-to-end instead (`actions/checkout`: 3 GitHub
  Action frameworks with versions, 27 vulnerabilities) and by
  `test:tier3` 40/40. Live MCP initialize 200 (protocol 2025-03-26,
  gitsecure 0.1.0).

## Phase 7 status — UI/UX redesign, design only (built 2026-11-25, solo)

No scan behaviour, caps, scoring, redaction, or API/MCP contracts
changed. `parseInput()` byte-identical, `errorCopy()` wording kept,
`computeScore`/`explainScore` untouched (only pure presentation
helpers added: `gradeBand`, `gradeWord`, `biggestProblem` in
`src/lib/score.ts`). TechDirect still 83/B.

- **Identity** (`src/app/globals.css`, rewritten): one type scale
  (clamp h1, 1.25rem h2), one spacing system (`--space-1`…`--space-6`),
  one colour system as custom properties. REAL dark mode via
  `prefers-color-scheme`: every surface, input, code block, pill and
  button redefined for dark. Primary buttons use `--on-accent` text
  (white on dark green in light mode, dark green on light green in
  dark mode) so contrast holds in both themes. Inline code uses
  `overflow-wrap: break-word` — it wraps only when it must, never
  mid-word.
- **Score dial** (`src/components/ScoreDial.tsx`): SVG arc 0–100 with
  the score and grade in the middle, colour-coded by band (green A/B,
  amber C, red D/F) with the grade word beside it — colour + label
  together, never colour alone. `role="img"` with a full accessible
  label ("Security score 83 out of 100, grade B, good").
- **Report hero** (`src/app/[owner]/[repo]/page.tsx`): dial +
  grade chip ("Grade B — good") + one-sentence verdict (the biggest
  problem) + summary + `explainScore` + counts as a clean stat grid
  (2 columns at phone width, 3 on desktop). The secrets stat only
  turns red when its count is above zero — a 0 no longer looks like
  an alarm.
- **Home** (`src/app/page.tsx`): hero first screen — lede, the
  mirror-URL strip as a designed element (struck-through github.com →
  git-secure.com), one big scan input. "What it checks" is four
  scannable cards. Error is a styled box (`role=alert`); scanning
  state is a spinner + honest progress text (`role=status`).
- **Findings** (`src/components/ReportLists.tsx`): cards with a
  severity-coloured left border, title, file:line, plain-English what,
  fix in a shaded block, prominent GitHub file+line link next to the
  copy-link. Collapsible groups: rotating chevron, fade on open, clear
  open/closed state. Filter result counts are `aria-live="polite"`.
  Spider map: legend, centre node enlarged so "This repo" fits inside
  it, hover/focus states, nodes keyboard-reachable (Tab, Enter/Space
  to filter) with focus-visible rings, plus the file-chip buttons
  below. "Show more" pager unchanged in behaviour, now a flex row.
- **Loading / error**: `loading.tsx` is a designed screen — spinner +
  the three real scan steps, honest wording ("A full scan usually
  takes about 15 seconds… there is nothing to click"). Error pages
  keep the `errorCopy()` wording in a red-bordered card with a "Scan
  another repo" button.
- **Motion & a11y**: 120–180 ms transitions (hover, focus, group
  open) only; `prefers-reduced-motion` disables all transitions and
  animations. Focus-visible rings everywhere, skip link to `#main`,
  tap targets ≥44px, input and button stack cleanly at 360px.
- **New test** (`scripts/test-ui-phase7.ts`, `npm run test:ui-phase7`,
  52 checks): dial renders (SVG, band class, score + grade,
  accessible label, dasharray gauge), grade bands, verdict, secrets
  list (blob links incl. history-commit refs, anchors, copy buttons,
  filters, List/Map toggle, aria-live counts, fragments only), map
  (legend, keyboard-reachable nodes, file-chip buttons), stylesheet
  (dark mode, reduced motion, focus-visible, ≥44px targets,
  on-accent button text, no mid-word code breaks), no "Honest limits"
  / sign-in copy on the human pages, no literal secret-pattern values
  in the UI files.
- **Visual verification — actually done this phase, in a real
  headless Chromium** (Playwright 1.65.1 + cached Chromium headless
  shell, local production server): home, loading (captured mid-scan),
  TechDirect report, and an error page at 1280px light AND dark and
  at 360px, plus the GitSecure dogfood report (0/F, 8 secrets) with
  the secrets list and spider map — clicking a map node filters the
  list live (2 of 8 secrets, 1 file). Zero horizontal overflow on
  every render. Screenshots in `test-results/phase7/`:
  home-desktop-light/dark, home-360, loading-desktop,
  report-techdirect-desktop (+ dark), report-techdirect-360,
  error-desktop, report-gitsecure-secrets-list,
  report-gitsecure-secrets-map, report-gitsecure-map-closeup.
  Three defects found by looking and fixed the same run: the mobile
  scan input rendered 220px tall (column flex-basis leaking into
  height), inline code broke mid-word (`github.com` → `gi/thub.com`),
  and the dark-mode primary button was white text on light green.
  One cosmetic fix after the map close-up: the centre "This repo"
  label overflowed its circle (r 26 → 34, font 11 → 10).
- **Verification (2026-11-25):** `npm run build` exit 0;
  `test:scanner` 68/68, `test:tier3` 40/40, `test:history` 23/23,
  `test:public-full` 56/56, `test:ui-phase7` 52/52,
  `test:techdirect` 83/B with filesScanned = 2,802 ("Scanned all 2802
  files in the tree"), `test:mcp` 51/51 against a local production
  server. No literal secret-pattern values committed (grep-verified;
  fixtures still use `__SECRET_n__` placeholders, test-assembled
  fakes only). Dogfood note: local GitSecure scan is 0/F with 8
  secrets, 196 vulns, 30 frameworks, 202 deps, 15 posture issues, 62
  files, 13 history commits — the file count moved 68 → 62 because
  the Phase 6 push changed the repo's contents; the 8 secret findings
  are the same known-fake fixtures.
- **Code pushed 2026-11-25, commit 146ffb855cba973d8bffcefaa39c42dde5dc78db**
  (81 files, remote head + remote tree verified by read-back: exact
  match with local). This spec/README live-verification note followed
  as a docs-only commit.
- **Live verification (2026-11-25, after 146ffb85):** home 200 with
  the new hero + "What it checks" cards, no "Honest limits" / sign-in
  copy; live TechDirect report 200, 83/B, new dial + stat grid +
  verdict in served HTML, filesScanned 2,802, history 56 commits via
  the API path (the known unauthenticated-quota limit — Freddy's
  ruling stands, no GITHUB_TOKEN); live DefinitelyTyped report 200,
  0/F, "Showing 403 of 403 secrets", 61,814 files, dial aria-label
  "Security score 0 out of 100, grade F, needs urgent attention".
  Deployment state checked by live serving (Vercel MCP still 403 on
  the team scope, so the dashboard could not be checked).

## Phase 8 status — async scan jobs + remaining caps removed (built 2026-11-25, solo, NOT pushed)

Trigger: Freddy's screenshot of the live TechDirect report's "Scan
limits" section — "Fix all of the scan limits as much as you can so
you don't have limit limits."

- **Async scan jobs** (`src/lib/jobs.ts`, `src/app/api/scan/jobs/[jobId]/route.ts`,
  `src/components/ScanProgress.tsx`, `src/lib/progress.ts`).
  A scan now runs as a job: the API (`GET /api/scan/[owner]/[repo]`),
  the report page, and MCP all start (or join) one and wait up to
  ~50 s for it — the fast path, so TechDirect still answers 200 in a
  single request (~12 s direct, ~19 s over the live API). If the job
  is still running, the API answers **202 with a jobId and live
  progress**; the client polls `GET /api/scan/jobs/{jobId}` until the
  job is done (200, report included) or errors. The report page shows
  honest live progress while a job runs — current step, files scanned
  so far ("1,200 of 2,802 files scanned"), commits checked so far,
  dependencies checked — then reloads the finished report. MCP tools
  poll the job server-side for ~50 s; a still-running large repo comes
  back as plain English with live progress and the job ID, and
  `get_report` picks up the SAME job (jobs dedupe by owner/repo)
  instead of starting over.
- **Job store: in-memory only, documented.** No durable store, no paid
  service, no database. A job does NOT survive a cold start, a redeploy,
  or a poll that lands on a different serverless instance — an unknown
  ID answers 404 `job-not-found` telling the client to start the scan
  again. Finished jobs are kept 10 minutes (so the report page can
  reload without re-scanning), then dropped. That is the only sense in
  which GitSecure "stores" a report: in memory, for minutes, never on
  disk. Job IDs are `crypto.randomUUID()` — random, and carrying no
  owner, repo, or secret fragment. The job is kept alive past the 202
  response with Next.js `after()` (route + page). Progress flows from
  `scanRepo`'s `onProgress` callback; the progress types live in
  `src/lib/progress.ts`, which imports nothing, so the browser bundle
  never pulls in `node:child_process` — the first build failed on
  exactly that (ScanProgress imported `stepLabel` from scan.ts), and
  the split fixed it.
- **55 s timeout: gone.** `scanRepoWithTimeout` and `SCAN_TIMEOUT_MS`
  are deleted; `scanRepo` runs to completion in the background job.
  Individual GitHub fetches still have short abort timeouts (12 s in
  ghJson, 10 s per raw file, 30 s tarball) — a hung upstream fails
  that fetch, not the scan.
- **OSV budgets: gone** (`src/lib/osv.ts`). `checkDependencies` takes
  no budget by default: every pinned dep is queried in batches of
  1,000 and every advisory gets full detail in batches of 8, with
  progress reported per batch. An explicit budget can still be passed;
  the report only mentions uncovered deps/advisories when one ran out.
  Proved by the new test with stubbed slow OSV (700 ms per detail
  fetch, 160 advisories ≈ 14 s — past the old 12 s budget): all 160
  detailed, detailCapped 0.
- **Tarball guard: streaming, not a cap** (`src/lib/scan.ts`).
  The download is read chunk by chunk via `getReader()` and aborted
  mid-stream past 500 MB (before: the whole response was buffered
  with `arrayBuffer()` and then checked). Tripping it only switches to
  the per-file fallback, which still scans every file. The decompressed
  tar is still materialised whole in memory — a physical bound, stated
  in the code comment, not a cap.
- **"Scan limits" rewritten as "About this scan"** (`buildLimits` in
  `src/lib/scan.ts`, pure and tested; heading changed in
  `src/app/[owner]/[repo]/page.tsx`). A complete scan says so once
  with the exact counts — files, history commits, dependencies
  checked, advisories with full detail — and nothing else. A partial
  scan states exactly what it could not cover, one line per fact.
  The standing facts stay (public repos only; secrets never
  stored/logged/shown in full). The old cap lines are gone from the
  UI, README.md, and this spec's live-truth sections (the historical
  Phase 2–7 sections keep their records of what was built then).
- **History: wired to the git-protocol orchestrator (integration).**
  `scan.ts` now calls `scanHistory()` from `history.ts` — git protocol
  first (no REST quota, cached on repeats), then the git-binary clone,
  then the GitHub API as a last resort; only when every path fails does
  it fall back to API patches of the 5 most recent commits. The progress
  callback the jobs phase asked for exists: `onProgress?: (commitsScanned:
  number) => void` on `scanHistory` / `scanHistoryViaGit`, called per
  commit walked on the git path (and on a full cache hit), so live
  progress shows commits scanned so far *during* the history step. The
  clone and API paths report their count on return, which is honest
  about what is known when. `HistoryScanResult.method` is
  `"clone" | "api" | "git"` and carries `cachedCommits` /
  `commitsFetched` / `restCalls` / `gitRequests`; the report's history
  line carries only the method and the exact count scanned.
- **Phase 7 UI untouched.** Dial, verdict, stat grid, collapsible
  groups, filters, spider map, GitHub links, copy-link anchors, dark
  mode, 360 px mobile, ≥44 px tap targets, reduced-motion — all still
  green (`test:ui-phase7` 52/52, unchanged). `loading.tsx` copy updated
  to say a very large repo keeps running in the background with live
  progress instead of timing out.
- **New test** (`scripts/test-jobs-phase8.ts`, `npm run test:jobs-phase8`,
  44 checks): a slow fake runner completes via the job/poll path past
  a short fast-path wait, dedupe by owner/repo, UUID job IDs, unknown
  IDs, TTL eviction, error jobs, `buildLimits` copy (complete + partial),
  `ScanProgress` render text, the OSV no-budget proof, and source
  checks (no 55 s race, streaming tarball guard, no OSV budget
  constants, no "Scan limits" heading, 202 + `after()` in the API).
- **Verification (2026-11-25):** `npm run build` exit 0;
  `test:scanner` 68/68, `test:tier3` 40/40, `test:history` 23/23,
  `test:public-full` 56/56, `test:ui-phase7` 52/52,
  `test:jobs-phase8` 44/44 (new), `test:techdirect` 83/B with
  filesScanned = 2,802, history 62 commits, limits now exactly three
  lines ("Scanned all 2802 files in the tree…", "History checked: 62
  commits, newest first (git protocol — no git binary, no REST
  quota).", "Public repos only…"),
  `test:mcp` 51/51 against a local production server. Live against
  that local server: scan API 200 in ~19 s,
  report page 200 with the dial and "About this scan", bogus job ID
  404 `job-not-found`. No literal secret-pattern values committed
  (grep-verified; fixtures still use `__SECRET_n__` placeholders).
  Pushed as cf88fe4c (88 files), head verified by read-back; live
  TechDirect scan 200, 83/B, history 62/62 via the git protocol, no
  rate-limit line; live second scan 0.33 s (cache working).
- **NOT verified live:** a real 202/poll round-trip on a repo that
  takes over 50 s. No available public repo reliably exceeds the
  fast path from this machine (DefinitelyTyped fits in ~30 s), so the
  job/poll path is proved by the fake-slow-runner test, not by a live
  202. The push worker should re-verify on Vercel, where a cold
  start / multi-instance poll can also be observed (an unknown-ID 404
  there is expected behaviour, not a bug).

## Phase 8 status — git-protocol history + per-commit cache (built 2026-11-25, solo, NOT pushed)

Fixes the Phase 6 live caveat (history stopped at 56 of 62 TechDirect
commits because the unauthenticated REST quota is 60 req/hour and one
API history needs ~65 requests) WITHOUT a GITHUB_TOKEN (Freddy's
ruling stands — no token, do not raise it).

- **Git-protocol history** (`scanHistoryViaGit` in `src/lib/history.ts`,
  `isomorphic-git` **1.44.19** exact pin + `diff` **8.0.2** exact pin —
  pure JS, no git binary, no REST API). Clones over the git smart-HTTP
  protocol (github.com, not api.github.com), walks `git.log` newest-first
  with `includeChanges`, diffs each commit against its first parent
  with jsdiff and scans ADDED lines only, with the same detectors,
  skippable-path rules, and redacted fragments as the clone path.
  Merge commits get no diff (matching `git log -p`); the root commit is
  diffed against the empty tree. One shared isomorphic-git object cache
  across log + readBlob — without it the TechDirect walk took ~40 s,
  with it ~4 s. Measured live: clone ~4.6 s, log 62 commits ~2.2 s.
- **Per-commit cache** (in-memory only — no durable store exists in
  this project and none was added): findings keyed by commit SHA
  (redacted fragments only, never a secret value), plus the cached HEAD
  tip per `owner/repo@branch`. A re-scan resolves the remote HEAD over
  the git protocol (one info/refs request, zero REST quota) and, when
  the tip is unchanged, returns the cached findings without fetching a
  single commit. When the tip moved, only commits newer than the cached
  tip are walked. `scanHistory({owner, repo, branch, commit, method})`
  is the orchestrator scan.ts should call: git protocol first, then the
  git-binary clone, then the API path as a last resort only.
  `HistoryScanResult` gains `method: "clone" | "api" | "git"`,
  `cachedCommits`, `commitsFetched`, `restCalls`, `gitRequests`;
  `historyLimitsLine(result)` builds the one limits line naming the
  path used. The clone path still works unchanged where a git binary
  exists; the API path is untouched as the last resort.
- **Caps removed as caps.** The old 1000-commit / 50 MB / 45 s history
  caps are gone from the clone and git-protocol paths — history runs to
  the oldest commit, one file at a time, never buffered whole. The only
  remaining limit is `HISTORY_MEMORY_GUARD_BYTES` (500 MB), an emergency
  memory guard: if it ever trips, the result is `truncated: true` with
  a note naming the last commit scanned and that older commits were not
  checked — a partial scan is never presented as complete. `MAX_HISTORY_
  COMMITS` / `MAX_HISTORY_PATCH_BYTES` / `HISTORY_TIMEOUT_MS` stay
  exported (the API fallback still uses them); they no longer cap the
  clone or git paths.
- **Verification (2026-11-25):** `npm run build` exit 0;
  `test:history` 53/53 (was 23 — 30 new: git path over a real smart-HTTP
  server via `git http-backend`, 1005-commit repo past the old cap,
  cache reuse, zero-REST assertion); `test:scanner` 68/68;
  `test:techdirect` 83/B, filesScanned 2,802, history 62 commits.
  Live proof (`npm run test:history-git`, scripts/scan-history-git-live.ts):
  `scanHistoryViaGit` on Squ1zM0/TechDirect returns **62/62 commits
  with 0 REST history calls** (counted with a fetch wrapper: 0 calls to
  api.github.com; the only git-protocol request counted is the 1
  info/refs HEAD check — the clone's pack requests go through
  isomorphic-git's own HTTP client to github.com, never the REST API),
  10.0 s wall; a second scan in the same process reuses all 62 from
  cache (0 fetched, 419 ms). No literal secret-pattern values committed
  (grep-verified; fixtures still use `__SECRET_n__` placeholders,
  test-assembled fakes only). The memory-guard trip path is NOT directly
  tested (the guard is a module constant, not an option) — it is code-
  reviewed only. Pushed as cf88fe4c (88 files, remote head and tree
  verified by read-back); live TechDirect 83/B, 62/62 via git protocol,
  second scan 0.33 s (cache working live).

## Phase 8.1 status — giant-repo history fix (built 2026-11-25, integration)

Found live, after the Phase 8 push (cf88fe4c): the DefinitelyTyped scan
**500s at ~23 s, reproducibly**, returning a Next.js error page, while
TechDirect (62 commits) works in ~8 s. Root cause, measured:
DefinitelyTyped is **818 MB with 91,984 commits** (TechDirect: 3.8 MB,
62 commits). The Phase 8 git-protocol path clones the whole repo and
walks every commit inside a 1 GB Vercel function with 512 MB /tmp —
the clone OOM-crashes the function before the walk's guards can trip.
Phase 5 never hit this: live history then was only 5 commits.

- **Size gate** (`HISTORY_CLONE_SIZE_LIMIT_KB` = 100 MB in
  `src/lib/history.ts`, `repoSizeKb` from the repo API's `size` field
  passed through `scanRepo` → `scanHistory`). Above the limit, both
  clone-based paths (git protocol and binary clone) are skipped and
  history goes straight through the API path, which pages newest-first
  and stops honestly at quota/caps with a note. The note names the
  size and the reason. HEAD is still scanned in full whatever the repo
  size. This is a physical bound of the runtime, not a scan cap.
- **History can never 500 a scan.** `scanHistory` catches per-path
  (a throwing path falls through to the next one), and `scanRepo`
  wraps the history await in try/catch degrading to the patch
  fallback. A history failure is a note in the report, never a
  failed scan.
- **Walk safety valve** (`scanHistoryViaGit`): every 64 commits the
  walk checks wall-clock (> 40 s) and heap (> 700 MB) and stops
  cleanly with `truncated: true` and an honest note naming the last
  commit scanned. The old truncated note now says "safety guard
  (time or memory)" instead of only "memory guard".
- **Test:** `test:history` gains the size-gate checks (huge repo →
  API path, note names size + reason, webhook still found).
- **Honest remainder:** full history of a 92k-commit repo cannot be
  walked inside one serverless invocation without durable
  cross-invocation storage, which the project does not have. The API
  path's partial history + note is the honest maximum today; a
  durable per-commit cache (KV/DB) would be a separate, paid
  decision, not taken here.
- **Live verification (2026-11-25, after push 6f1402ab):**
  DefinitelyTyped scan **200 in 36.4 s, 0/F, 403 secrets listed,
  61,814 files**, history 48 commits via the API path with the honest
  size-gate + rate-limit notes ("This repo is 818 MB — too large to
  clone… GitHub API rate limit was hit — scanned 48 commits before
  stopping."). TechDirect still **83/B, 62/62 via git protocol**
  (one transient 429 on the shared Vercel IP quota during
  verification, then 200 on retry — the scan correctly answers 429
  instead of crashing when the quota is gone). MCP initialize 200,
  protocol 2025-03-26. Tests after integration: build exit 0;
  scanner 68/68, tier3 40/40, history 56/56 (53 + 3 size-gate),
  public-full 56/56, jobs-phase8 44/44, ui-phase7 52/52, techdirect
  83/B, mcp 51/51, history-git live proof 62/62 with 0 REST calls.

## Phase 9 status — resumable chunked scans, no in-memory jobs (built 2026-11-25, solo)

Trigger: Freddy screenshotted the live site failing on torvalds/linux —
"That scan is no longer running". That was the exact failure Phase 8
predicted honestly (jobs in-memory only; a poll on another instance
gets 404 job-not-found). Phase 9 removes the job store entirely: the
server holds NO scan state between requests. The scan API returns a
cursor after the first chunk; each request advances exactly one chunk
(HEAD, then history in commit-range chunks newest-first, then
assemble with OSV inside it) and returns partial results plus the
next cursor; the client accumulates and drives the next chunk. A
restart, cold start, or different instance changes nothing. Progress
persists in sessionStorage (cursor + accumulated results), so a reload
or closed tab resumes from the last completed chunk and says so
("Resumed — picked up where it left off", with counts). HEAD renders
first as a clearly-labelled provisional report; history streams
newest-first with live progress. MCP gets the same resumability
(`scan_repo` drives the chunk loop with the cursor; new `resume_scan`
tool continues it). Cursor protocol documented in README.md ("Scan
cursors"). Rules unchanged: unlimited files/findings, full detail to
anyone, no login, fragments only, public repos only, git-protocol
history first, no caps. Phase 7 UI untouched.

HEAD performance (the blocker found mid-phase): the Linux HEAD chunk
exceeded its 50 s budget. Measured from disk (no network): gunzip
4.7 s, tar parse 6.9 s, parse + secret scan 34.5 s for 103,737 files /
1.68 GB, 20 HEAD secrets. Fixes: the secret detector runs each
pattern once over the whole file instead of once per line (~56 s of
regex → ~28 s; results identical, guarded by an equivalence test
against the old per-line scan, including cross-line values and
matches hiding inside a cross-line span); the tar parser uses 1 MB
gunzip chunks + a memcmp end-of-archive check (parse overhead ~31 s
→ ~2 s over gunzip). Streaming mode skips the recursive-tree call
(~4 s, and truncated at 71k of ~97k entries for Linux — the tarball
is the complete file list) and always retains manifests/configs even
when the 100 MB retained-bytes budget runs out. Validated end-to-end
on microsoft/vscode (1.8 GB, streaming path): HEAD in 25–33 s,
20,648 files = 20,648 total, 474 HEAD secrets, 1,714 deps.

Honest bound: Linux is ~4 GB / ~1M commits; the >100 MB size gate
still sends history through the API path, 10 commits per chunk, so a
full history walk takes a very long time even chunked — resumability,
not instant completion, is the fix, and a partial history is never
presented as complete. The HEAD chunk needs the 275 MB tarball
inside ~50 s; codeload delivered it in 8 s one day and ~90 s the
next from this VM (repeated downloads from one IP get throttled).
On a slow-download day the HEAD chunk stops cleanly at 50 s and
retries from its cursor — nothing lost, no dead-end.

Tests: scanner 73/73, tier3 40/40, history 56/56, public-full 56/56,
ui-phase7 53/53, cursor-phase9 181/181 (new: interrupted mid-history
resume produces the identical final report, bogus cursors, second
page-load resume), techdirect 83/B (2,802 files, 62/62 history),
mcp 56/56. Build exit 0. Pushed 2026-11-25 as 8f4ffa4f (remote head +
tree verified by read-back). Live: home 200, chunk route live (new
Phase 9 400 without a cursor), TechDirect 200 in 8.5 s, 83/B, 2,802
files, 62/62 history; MCP initialize 200, tools/list shows
resume_scan. torvalds/linux live: HEAD chunk 504s at ~51 s twice on
a slow-download day, then the third attempt returned 202 with the
full HEAD (96,985/96,985 files, 20 secrets — same 20 as the local
disk profile) + 10 history commits; two fresh `POST /api/scan/chunk`
calls advanced history 10 → 20 → 30 with only the cursor — the
resume proof. A fresh `GET ?cursor=…` resume then hit the shared
Vercel IP's unauthenticated GitHub quota (429), not a cursor
failure. Full Linux history (~1M commits) remains a very long walk;
the report always says exactly how far it got.

## Phase 10 status — layered secret triage: test keys vs genuine leaks (built 2026-11-25, solo)

Trigger: Freddy's screenshot of the live torvalds/linux report flagging
`tools/testing/selftests/sgx/sign_key.pem:1` as a CRITICAL private key
with the fix "treat this key as compromised, rotate it" — but that is
the Linux kernel's intentional SGX self-test signing key, and the
finding above it (`drivers/of/unittest-data/tests-phandle.dtsi`, line
9) is device-tree test data too. GitSecure cried CRITICAL on test keys.

- **The pipeline (`src/lib/triage.ts`).** A post-processing layer over
  the existing detectors — the detectors themselves do not change.
  Triage annotates every secret finding; the report, API, and MCP all
  carry the annotation (`SecretFinding.triage` in `src/lib/types.ts`:
  verdict, signals, explanation, adjustedSeverity, adjustedConfidence,
  fix). Three layers:
  - **Layer 1 — static context.** Path signals (`test/`, `tests/`,
    `testing/`, `selftests/`, `unittest-data`, `fixtures/`, `examples/`,
    `docs/`, `samples/`, `demo/`, `spec/`, `mocks/`, `testdata` — exact
    segments plus narrow substring rules for `unittest`/`selftest` so
    a bare "test" substring never matches "latest" or "contest"),
    filename tokens (`test`, `fixture`, `dummy`, `example`, `sample`,
    `mock`, `fake`, `placeholder`, `stub` — token-based, never
    substring), content signals in the same file and nearby lines
    ("test", "testing", "for testing only", "do not use in
    production", "example", "dummy", "fake", "sample", "testcase",
    "selftest", "unittest" — word-boundary regexes). Usage signals
    where cheap: a key file referenced only from test files (HEAD
    only, retained files).
  - **Layer 2 — cryptographic inspection.** A minimal DER parser reads
    the key where the format allows (RSA PKCS#1/PKCS#8, EC SEC1, SPKI
    public keys, X.509 certificates): key type and size (RSA 1024 vs
    4096, EC curve), whether it is weak/short in a way real production
    keys would not be (RSA < 2048, EC < P-256), whether its fingerprint
    matches a small built-in list of famous published test keys
    (**fingerprints only, never the keys themselves** — the Linux SGX
    self-test signing key, DER SHA-256 verified 2026-11-25 by fetching
    the file from torvalds/linux and hashing it), whether it matches a
    known example value (the AWS documentation example key, SHA-256
    hash only), whether it is a Stripe test-mode key (`sk_test_` can
    never move real money), and whether its public half is committed
    in the same repo (matching SHA-256 of the RSA modulus / EC public
    point). No credential is ever live-validated, stored, or logged;
    triage only reads content the scanner already held, and only
    redacted fragments leave the scanner.
  - **Layer 3 — the scanner's own evidence.** The detector result
    (type, confidence, fragment) is the third input, not the verdict:
    a high-confidence private-key match in a production path stays
    high; the same match in a self-test path with matching test signals
    gets downgraded.
- **Verdict model (points).** A fingerprint match against a known
  published test key, or a match against a published example value, is
  decisive → `likely-test-key`. Otherwise: test path +4, filename test
  token +2, content test phrase +2, public counterpart in repo +3,
  weak key +2, test-only usage +2, Stripe test mode +3; production path
  −4, production filename −2, production usage −2, production-grade key
  (RSA ≥ 4096, EC P-384+) −2. ≥ +4 → `likely-test-key`; ≤ −2 →
  `likely-genuine-leak`; a high-confidence detector match with no test
  signals at all → `likely-genuine-leak`; anything else → `uncertain`
  (keeps detector severity, says a human should check).
- **Never deletion, never score inflation (the scoring rule — as
  built in Phase 10, CHANGED in Phase 12, see "Phase 12 status").** A
  likely-test finding is NOT removed from the report and NOT removed
  from the counts — it is shown with its triage label, a plain-English
  explanation naming the signals ("This looks like an intentional test
  key: it lives in tools/testing/selftests/, its fingerprint matches a
  published test key…"), and a different Fix ("Confirm this key is only
  used by tests and never signs real artifacts; if it does, rotate
  it"). A genuine leak keeps CRITICAL and its existing Fix. **Triage
  never changes the score (Phase 10 rule, overturned in Phase 12)**:
  a likely-test finding still deducts its detector severity, because a
  test key that turns out to be a real key is still a leak, and the
  score must not reward relabelling. Phase 12 overturned this
  (Freddy, 2026-11-26: an F for 34 test fixtures is a false alarm):
  test keys now deduct nothing, uncertain findings half, genuine leaks
  in full. The
  honest split is shown separately: `counts.testKeySecrets` — "of which
  N look like test keys" — in the stat grid (`ReportView.tsx`) and the
  secrets list (`ReportLists.tsx`), which also gains a triage-verdict
  filter ("Likely test keys" / "Likely genuine leaks" / "Uncertain").
  MCP carries the same annotation in every secret finding (and
  `list_checks` names it).
- **Where it runs.** HEAD findings are triaged in `scanHead` after the
  whole tree is scanned (so the public-counterpart and usage signals
  see the complete repo; only files with findings are retained for it,
  bounded by the finding count). History findings are triaged at
  creation in `history.ts` (clone stream, API path, API chunk,
  git-protocol walk — the git path triages from the full new-file
  content) and in the patch fallback in `scan.ts` (from the added
  lines). `assembleReport` fills in any annotation missing from an
  older client/cursor with a path+detector-only verdict
  (`ensureTriage`), so every finding in every finished report carries
  triage. The provisional report carries the same annotations (HEAD
  triaged in `scanHead`, history at creation); `provisional.ts` stays
  client-safe and does NOT import the server-only (node:crypto) triage
  module.
- **The two screenshot cases, proved.** `tools/testing/selftests/sgx/
  sign_key.pem` triages `likely-test-key` with the test-key Fix
  (test-path signal + the built-in SGX fingerprint; the live proof is
  below). `drivers/of/unittest-data/tests-phandle.dtsi` line 9
  triages `likely-test-key` on its own signals (unittest-data path +
  `tests` filename token + `testcase` content). Control:
  `src/config/prod.key` and an AWS key in `deploy/` stay
  `likely-genuine-leak` at full severity — and the same token in a
  fixture file vs `src/` gets different verdicts.
- **Verification (2026-11-25, local):** `npm run build` exit 0;
  `test:scanner` 73/73, `test:tier3` 40/40, `test:history` 56/56,
  `test:public-full` 56/56, `test:ui-phase7` 62/62 (was 53 — 9 new
  triage UI checks: pills, explanation, test-key Fix, verdict filter,
  count line, adjusted severity, pill styles),
  `test:cursor-phase9` 181/181, `test:triage-phase10` 59/59 (new —
  both screenshot cases, the production control, fixture-vs-src,
  fingerprint match, uncertain case, weak key, public counterpart,
  Stripe test mode, AWS example value, history-lines triage, the
  no-finding-dropped regression, the score-unchanged rule, and the
  counts split), `test:techdirect` 83/B with filesScanned = 2,802
  ("Scanned all 2802 files in the tree"), history 62/62 via git
  protocol. No literal secret-pattern values committed (grep-verified;
  the AWS example key appears only as a SHA-256 hash constant plus a
  runtime-assembled string in the test, as before — one literal in a
  triage.ts comment was caught and removed before pushing).
- **Dogfood count moved 8 → 20 (measured, not a regression).** The MCP
  dogfood scan of Squ1zM0/GitSecure now counts 20 secrets, all 20
  triaging `likely-test-key`. The count moved because the repo's
  history grew (20 commits now): the same known-fake fixture secrets
  are found at HEAD and again in their introducing commits (e.g. the
  test-scanner.ts fake passwords at HEAD and at 8f4ffa4). The score is
  still 0/F. Proved not to be a triage regression: the pre-change code
  (remote head b30124a8, checked out to a scratch tree, built and run
  locally) returns the same 20 secrets for the same repo — triage
  annotates, it never adds findings. The `test:mcp` "counts 8 secrets"
  assertion was updated to 20 with this reason, plus a new check that
  all 20 are test keys. Live, the count is now **22** (see the
  live-verification note below): the two Phase 10 pushes added the
  triage test fixture line, found at HEAD and in b4ca165 — the
  `test:mcp` assertions now say 22, all 22 test keys.
- **Live verification (2026-11-26, after 9be330d4):** home 200; live
  GitSecure self-scan 0/F, 22 secrets, all 22 likely-test-key
  (`counts.testKeySecrets` 22, history 22, files 77) — the count moved
  20 → 22 because the Phase 10 commit itself added the triage test
  fixture line, found at HEAD and in its introducing commit; live
  TechDirect 83/B, 0 secrets, 4 vulns, 2,802 files, 62/62 history;
  live torvalds/linux HEAD chunk 96,985/96,985 files, all 20 HEAD
  secrets likely-test-key — `tools/testing/selftests/sgx/sign_key.pem`
  likely-test-key (signals `test-path:testing`, `known-test-key`;
  test-key Fix "Confirm this key is only used by tests and never signs
  real artifacts; if it does, rotate it.") and
  `drivers/of/unittest-data/tests-phandle.dtsi:9` likely-test-key on its
  own signals (`test-path:unittest-data`, `filename-test:tests`,
  `content-test:testcase`); MCP initialize 200, tools/list shows
  `scan_repo`, `get_report`, `resume_scan`, `list_checks`. The control
  case is the GitSecure self-scan itself: the score stays 0/F because
  triage never changes the score — the 22 test-key findings still count
  in full, shown separately as "of which 22 look like test keys".
  (Phase 10 rule; overturned in Phase 12 — under the new rule the test
  keys deduct nothing, and the self-scan stays 0/F on vulnerabilities
  alone. See "Phase 12 status".)

## Phase 11 status — secret usage: in use vs true dead end + the track through the spider web (built 2026-11-26, solo)

Trigger: Freddy, voice message — separate the likely-test results so
there is a way to click and see them, and, while scanning, determine
what each finding is dependent on and whether anything else in the code
uses it. If something else calls it, it is in use, not a test key; if
nothing does, it is a true dead end. Follow that track through the
spider web.

- **Usage analysis (`src/lib/usage.ts`, new).** For every secret
  finding, the scanner searches the repo's own HEAD files for
  references to the finding's **identifier only** — variable/env name,
  key filename, or config key — outside the file where it was found.
  It never searches for or stores the secret value itself, and never
  matches on the redacted fragment. Identifier extraction is
  match-anchored: the name comes from the detector match itself
  (password-style detectors include the name) or the `NAME =`
  immediately preceding the match start, with the fragment identifying
  the exact match when a line holds several; fallback to the line-start
  assignment runs only when the line holds no detector match. Guards:
  a URL scheme is not a name (bare `postgres://…` yields no
  identifier); a match inside a string yields the name inside the
  string, never the test's own variable; `.env` findings use only
  their defined variable names (the bare `.env` basename is not an
  identifier). References in test files (Phase 10 `isTestFilePath`)
  go in `referencedByTests` and do NOT count as "in use"; non-test
  references go in `referencedBy`. Lists capped at 10 with true
  totals; `deadEnd: true` only when a usable identifier was found and
  nothing anywhere references it (no identifier → `deadEnd: false`,
  "liveness undetermined"). One prefilter pass per file, then exact
  per-identifier attribution. HEAD usage is computed in `scanHead`
  after the whole tree is scanned; history usage comes from HEAD files
  only (`historyOnly: true`) in the git-protocol path of `history.ts`
  (API/clone/patch paths leave `usage` absent — no HEAD files
  available); `buildLimits` gains the plain-English history-usage line;
  the provisional report carries usage through and stays client-safe
  (no triage import).
- **Triage feed-back (`src/lib/triage.ts`).** Applied after the Phase
  10 verdict. (a) `likely-test-key` + non-test reference → at minimum
  `uncertain`, explanation names the file. (b) Further →
  `likely-genuine-leak` when the referencing non-test file is
  production-ish (`src/`, `lib/`, `app/`, `config/`, `deploy/`,
  `scripts/`, repo-root config) AND the detector type is a credential
  type (AWS key, token, webhook, database URL, hardcoded password,
  private key; `env-file` and `generic-high-entropy-secret` excluded)
  — rule stated in a code comment. (c) Zero references → signal
  `usage-dead-end` (+2 toward `likely-test-key`) + the exact sentence
  "Nothing in this repo references this key — a true dead end." A
  decisive fingerprint match is not overridden by a docs/examples-only
  reference (stays `likely-test-key`, reference recorded);
  production-path usage still upgrades it. Usage never changes the
  score on its own — it feeds the triage verdict, and Phase 12 weights
  the score by that verdict (test keys ×0, uncertain ×0.5, genuine
  ×1).
- **Separated likely-test section (`ReportLists.tsx`).** The secrets
  list partitions into three `<details>` verdict sections, in order:
  Likely genuine leaks (open by default), Uncertain — needs a human
  check (open by default; no-triage findings count as uncertain),
  Likely test keys (collapsed by default, own count, expands on click;
  only test-key findings, each with triage explanation and test-key
  Fix). Group-by type/file works as sub-groups inside each section;
  the verdict filter still works alongside and auto-opens its section;
  a shared `#secret-N` link opens the section holding that finding.
  Dead-end findings show a "Dead end" pill; in-use findings show
  "Used by: file:line"; history-only findings note usage was checked
  against the current files only. The honest counts line keeps the
  split.
- **The track through the spider web (`UsageMap`, replaces `FileMap`
  in map view).** Repo node centre, finding nodes (S1…S12) inner ring,
  file nodes outer ring (rendering caps only: 12 findings most-used
  first, 24 files; the full list stays below). Edges: solid accent =
  used in non-test code, dashed = test-only use, thin grey = the file
  the finding itself lives in (the other hop of the track). Click a
  finding node → its track stays full-strength, everything else dims,
  detail panel names the finding, file:line, and references, with a
  "Show this finding in the list" button (sets the `#secret-N` hash);
  click again to deselect. Click a file node → filters the list to that
  file. Dead-end findings are grey dashed nodes labelled "dead end"
  with **no** edges. Legend; keyboard-reachable nodes (Tab +
  Enter/Space); ≥44 px hit targets; 120–150 ms motion under the
  existing prefers-reduced-motion rule; dark mode via existing CSS
  vars. No `usage` data (older report) → the Phase 5 file-count spider
  renders unchanged. API and MCP carry `usage` on every secret finding;
  `list_checks` names "secret usage — in use vs dead end".
- **Verification (2026-11-26, local):** `npm run build` exit 0 (one
  blocker found at integration: `ReportLists.tsx:61` TS2352 on the UI
  worker's local `SecretUsage` mirror cast — fixed by the coordinator
  by deleting the mirror and importing the real `SecretUsage` from
  `src/lib/types.ts`); `test:scanner` 73/73, `test:triage-phase10`
  59/59, `test:tier3` 40/40, `test:history` 56/56,
  `test:public-full` 56/56, `test:cursor-phase9` 181/181,
  `test:usage-phase11` 64/64 (new — key referenced by src/ code,
  test-only references, dead end, capped lists with true totals,
  usage-never-matches-the-value regression, upgrade-rule cases),
  `test:ui-phase7` 87/87 (was 62 — 29 new Phase 11 checks),
  `test:mcp` 60/60 (was 58), `test:techdirect` 83/B with filesScanned
  = 2,802, history 62/62 via git protocol. Dogfood self-scan (local):
  0/F, 22 secrets, 22/22 likely-test-key — 6 false flips found during
  the phase were fixed in `usage.ts` (3 database-url via the
  URL-scheme guard, 2 hardcoded-password via match-anchoring, 1
  env-file via dropping the `.env` basename; the env-file finding now
  correctly shows `deadEnd: true`). No literal secret-pattern values
  committed (grep-verified). UI visually verified via render harness +
  headless Chromium screenshots at 360 px and 1280 px (light + dark),
  zero horizontal overflow, in `test-results/phase11/`; two defects
  found by looking and fixed (finding-node labels struck through by
  their own edges; a no-usage finding mislabelled "unused").
- **Phase 11.1 — comment mentions are not usage (live false flip,
  fixed 2026-11-26).** The first live self-scan after the Phase 11
  push flipped one fixture to `likely-genuine-leak`: the test-scanner
  fixture `api_key = "FAKEPW"` (identifier `api_key`) was "referenced
  from src/lib/usage.ts:140,190,191 in production code" — but those
  are mentions inside usage.ts's own doc comments, not uses of the
  value. Fix (`src/lib/usage.ts`, `stripComments`, applied before the
  prefilter and attribution): comments are stripped from file content
  before matching, replacing every comment character with a space so
  offsets and line numbers are unchanged; string literals are NOT
  stripped (`process.env["api_key"]` in code is a real reference).
  The stripper is string-aware so `//` inside a URL string does not
  eat the rest of the line, and it resets single/double-quote state
  at each newline — a regex literal full of quotes (`/^[\"']?…/`)
  otherwise leaves the tracker stuck in quote state across lines, so
  the next line's block comment never opens (that was the second
  bug, found by testing the stripper against the real file: lines
  190/191 stripped, line 140 survived). Regression tests in
  `test-usage-phase11` case (ix): comment-only mentions (line,
  block, `#` full-line) → no reference, dead end, stays
  likely-test-key; string-literal reference counts; URL-string and
  regex-quote-trap unit checks. Suite now 75/75 (was 64). Local
  self-scan after the fix: 0/F, 32 secrets, all 32 likely-test-key,
  3 dead ends, 0 in use. MCP dogfood counts updated 22 → 32 (history
  grew to 25 commits; Phase 11 added new fake-secret fixtures —
  same pattern as Phases 5/10, reason recorded in test-mcp.ts).
- **Live verification (2026-11-26, after d0306925):** home 200; live
  TechDirect 83/B, 0 secrets, 4 vulns, 2,802 files, 62/62 history;
  live GitSecure self-scan 0/F, 34 secrets, 32 likely-test-key, 2
  uncertain, 0 likely-genuine-leak — the likely-test section is
  clickable and separate, dead-end findings labelled, in-use findings
  show their track in the map; MCP initialize 200, tools/list shows
  `scan_repo`, `get_report`, `resume_scan`, `list_checks`.

## Phase 12 status — triage-weighted scoring: the score must reflect real risk (built 2026-11-26, two workers)

Trigger: Freddy — "But that live proof with an F scored inaccurate
because every single one is a test, so we need to make sure that the
scoring system is accurate if finding tests." The live GitSecure
self-scan scored 0/F, but all 34 of its secrets were likely-test-keys
(32 likely-test-key, 2 uncertain, 0 genuine). **Phase 10's rule
("triage never changes the score") is OVERTURNED by this phase**: a
score that calls 34 test fixtures an F is a false alarm, and false
alarms train people to ignore real ones.

- **The new rule (scoring core, Worker A — `src/lib/score.ts`,
  `src/lib/types.ts`).** `computeScore` returns a `ScoreDetail`:
  score, grade, per-component deductions (`secretsDeduction`,
  `vulnDeduction`, `postureDeduction`, `unpinnedDeduction`),
  per-verdict finding counts (`secretsFullWeight`,
  `secretsHalfWeight`, `secretsExcluded` — counts of FINDINGS, not
  points), and `wouldBeScore`. Weights: likely-test-key ×0, uncertain
  ×0.5 (the per-finding deduction is rounded at the total via
  `Math.round`), likely-genuine-leak ×1, no triage annotation ×1 (a
  test key is never assumed without evidence). `wouldBeScore` is the
  score the old (Phase 10) full-weight rule would have given the same
  input — every secret at full weight, same other components — clamped
  0–100. The report carries it as `FullReport.scoreDetail`, on finished
  AND provisional reports (both `assembleReport` in `src/lib/scan.ts`
  and `buildProvisionalReport` in `src/lib/provisional.ts` build it
  from the same `computeScore`), so the API, the report page, and MCP
  can never show a score that disagrees with the sections. Findings
  are still never removed and still counted in `counts.secrets` — only
  their weight changes.
- **The explanation in the UI (Worker B — `src/components/
  ScoreDial.tsx`, `src/components/ReportView.tsx`).** Next to the dial,
  in the report hero, a `ScoreExplanation` paragraph states the rule in
  plain English with the actual numbers from `scoreDetail`: how many
  secrets were excluded as test keys, how many counted at half weight,
  how many at full weight — and BOTH scores, the adjusted score and
  the would-be score, so the reader can see the test-key adjustment
  and verify it ("If every secret counted at full weight, the score
  would be 0 instead of 83." — or "would still be 0" when the
  adjustment changes nothing; "No secrets were found…" when there are
  none). The verdict (`adjustedVerdict`) and the one-line explanation
  (`adjustedExplainScore`, both in `ScoreDial.tsx`) pick the real
  driver by deduction size — secrets, vulnerabilities, posture,
  unpinned, ties broken in that order. A repo with zero genuine
  secrets is never told its biggest problem is "N leaked secrets —
  rotate and remove these first": it is told the test keys are
  excluded and named the real driver instead. The Phase 7 helpers
  (`biggestProblem`, `explainScore` in `src/lib/score.ts`) are
  untouched — the adjusted helpers fall back to them when the detail
  is absent, and `ScoreExplanation` renders nothing, so an older
  cached report without `scoreDetail` renders exactly as before, never
  crashes. No new stylesheet rules: the explanation reuses the
  existing `.score-explain` class, so dark mode, 360 px mobile, tap
  targets ≥44 px, and reduced-motion are unchanged (Phase 7 intact).
- **MCP prose (Worker B — `src/lib/mcp.ts`, prose only).** The
  `list_checks` text states the new rule with the weights ("a
  likely-test-key deducts nothing, an uncertain finding deducts at
  half weight, and a likely-genuine-leak — or a finding with no triage
  annotation — deducts at full weight") and notes the report shows the
  breakdown and the would-be score so the adjustment is always
  checkable. No MCP tool behaviour or plumbing changed.
- **Measured self-scan breakdown (Worker A,
  `test-results/phase12-score-breakdown.md`, real local scan of
  Squ1zM0/GitSecure, 2026-11-26).** 34 secrets, 197 vulnerabilities,
  15 posture issues, 3 unpinned frameworks, 79 files, 27 history
  commits. Old-rule score 0/F. Secrets: 384 points (16 high × 15 =
  240, 18 medium × 8 = 144) — 32 test keys 368 points, 2 uncertain 16
  points, 0 genuine. Vulnerabilities: 547 points (51 medium × 5 =
  255, 146 low × 2 = 292). Posture: 84 points (5 high, 6 medium, 2
  low, 2 info). Unpinned: 6 points. Under the Phase 12 rule the
  secrets deduction falls 384 → 8 (2 × 8 × 0.5), but the new total is
  still 8 + 547 + 84 + 6 = 645, so the new self-scan score is still
  **0/F** (wouldBeScore 0/F). Phase 12 fixes the false-alarm secrets
  component; it does not and cannot lift the self-scan grade while the
  other components stand. The 197 vulnerabilities are real OSV
  advisories on deliberately old dependency versions in the Tier 2
  test fixtures (Django 4.2.0, Laravel, Echo, Fiber, …) — the flaws in
  them are real flaws in real pinned versions, so relabelling them
  harmless would be wrong; they stay at full weight per the Phase 12
  scope (secrets only). Same for posture (Tier 3 fixture configs plus
  the committed `.env` fixture, missing SECURITY.md / Dependabot, Vite
  dev-server items). Any future change to how fixture-driven
  vulns/posture score is a separate decision, not part of this phase.
- **Verification (2026-11-26, local):** `npm run build` exit 0;
  `test:ui-phase7` 110/110 (was 87 — 23 new Phase 12 checks:
  explanation with the three counts and both scores, all-test-key
  verdict naming the real driver, would-be score shown, graceful
  fallback with no `scoreDetail`, full `ReportView` render with and
  without the detail, MCP prose). No literal secret-pattern values
  committed (grep-verified; fixtures still use `__SECRET_n__`
  placeholders, test-assembled fakes only). NOT pushed — the
  coordinator integrates and pushes.

## Phase 13 status — fix the dependency flaws for real (built 2026-11-26, three workers)

Trigger: Freddy — "Fix the dep flaws." Phase 12 measured the self-scan
at 0/F with 197 vulnerabilities (547 points) — real OSV advisories on
deliberately old pinned versions in the repo's own test fixtures — and
deliberately left them at full weight. This phase upgrades the versions
instead of relabelling them.

- **Measured split (before, real local scan of Squ1zM0/GitSecure).**
  197 vulns: real dependencies 2 (`diff` 8.0.2, `zod` 4.3.5 in
  `package-lock.json`), Tier 2 fixtures 65 (Echo 28, Fiber 19, Laravel
  7, Puma 4, Rails 1, Sinatra 2, PHPUnit 1, spring-core 3), Tier 1
  fixtures 130 in-scan (Django 4.2.0 ×96, vite 5.0.0 ×23, tokio 1.0.0
  ×9, Flask 3.0.0 ×2; next 14.2.5 ×38 shadowed in-scan by the root
  `package.json` next 16.4.6 via the name+ecosystem dedupe, first
  pinned wins). Tier 3 fixtures contribute 0 vulns. Full 197-row
  grouped inventory: `test-results/phase13-vuln-inventory.md`.
- **Real dependencies (fixed first — the actual risk).** `diff`
  8.0.2 → 8.0.4 (GHSA-73rr-hh4g-fpgx / CVE-2026-24001, LOW —
  parsePatch/applyPatch infinite loop, DoS; GitSecure diffs patches
  with it) and `zod` 4.3.5 → 4.6.7 (GHSA-mrhx-c7xc-m3w5 /
  CVE-2023-54404, HIGH, CVSS 7.5 — uncontrolled resource consumption,
  OOM). Both re-checked clean on OSV; exact pins preserved;
  `package-lock.json` updated with `npm install --package-lock-only`
  (only the two entries changed). `npm audit` is blocked in this
  sandbox (registry policy 403), so the evidence is an OSV batch query
  of all 215 lockfile packages. Build exit 0 after the upgrade.
  Caveat: `node_modules/` still held the old copies (no full install
  was run), so the fixed versions take effect on the next fresh
  install — which is what the Vercel deploy does.
- **Upgrades (branch-correct fixed versions).** The scanner's
  `fixedVersion` is the first `fixed` event across all advisory
  ranges and misleads on multi-branch advisories, so every target was
  re-checked per-advisory against the OSV API for the range actually
  containing the installed version: Django 4.2.0 → 5.2.17 (10 of its
  96 advisories have no 4.2 fix at all; 5.2 is the LTS line), next
  14.2.5 → 15.5.29 (26 of 38 have no 14.2 fix), fiber/v2 v2.49.0 →
  v2.52.14, sinatra 3.0.5 → 4.2.0 (no 3.x fix exists), puma 6.4.0 →
  7.2.1, phpunit/phpunit 10.5.0 → 10.5.62. Manifest + lockfile kept
  consistent where both exist (fake-repo has no lockfiles).
  Unfixable: none in this scope — every advisory had a fix in some
  release line. `org.example:unresolvable` stays version-null by
  design (proves unresolvable versions stay null).
- **Kept vulnerable (one per ecosystem, detection coverage).**
  Echo v4.11.1 (28, Go), rails 7.1.3 (1, Ruby — preserves the
  lockfile-wins test), laravel/framework v10.34.2 (7, PHP — preserves
  the lockfile-wins test), spring-core 6.1.2 (3, Java — the only
  vulnerable Java package, preserves the `${spring.version}` test),
  Flask 3.0.0 (2, PyPI), vite 5.0.0 (23, npm), tokio 1.0.0 (9,
  crates). Note: 2 of Echo's advisories have no fix in the v4 line
  (need v5.4.0), 4 of Laravel's only in 12.x, 2 of spring-core's need
  6.2.11+ — future fixes are major jumps, recorded here, not taken.
  Fixture-only caveat: fake-repo's `package.json` now pairs next
  15.5.29 with React 18.3.1, which is not a supported combination for
  a real Next 15 app — fixture-only, nothing is installed or run from
  it; React stays 18.3.1 (0 vulns, fingerprint assertion intact).
- **No gaming.** No fixture directory excluded from scanning, no
  severity changed, no fixture deleted to drop the count. The score
  improves only because the versions are actually fixed.
- **Result (measured, scanner's own code over the local working
  copy).** 197 → **73 vulnerabilities** (20 medium, 53 low), vuln
  deduction 547 → **206**; total deductions 8 + 206 + 84 + 4 = 302 —
  self-scan still **0/F**, honestly, because the deliberately kept
  fixtures (73 vulns) plus posture (84) still floor it. No critical
  or high vulns remain. Posture untouched (15 issues, out of scope).
- **Tests.** New `npm run test:deps-phase13` 22/22 (upgraded versions
  return zero advisories live on OSV; kept fixtures still flag;
  repo-wide total 73, deduction 206). Fingerprint assertions updated
  with reasons recorded (Next.js 15.5.29, Django 5.2.17, Fiber
  v2.52.14, Sinatra 4.2.0). `test:score-phase12` keeps the frozen
  Phase 12 repro (197/547) and adds a Phase 13 repro (73/206).
  `test:ui-phase7` fixture updated to the Phase 13 numbers (73
  vulns, deduction 206). `test:mcp` header + scoreDetail checks
  updated (73 vulns, deduction 206). Full suite: build exit 0;
  scanner 73/73, tier3 40/40, history 56/56, public-full 56/56,
  cursor 181/181, triage 63/63, usage 77/77, score 36/36, deps 22/22,
  UI 110/110, MCP 62/62 (was 61, +1 for the 73-vuln count check),
  techdirect 83/B (test:mcp + test:techdirect run live after the push).
- **Live verification (2026-11-26, after the push).** Home 200;
  live GitSecure self-scan 0/F, **73 vulnerabilities** (20 medium,
  53 low), scoreDetail `{secretsDeduction 8, vulnDeduction 206,
  postureDeduction 84, unpinnedDeduction 4}` — exactly the projected
  numbers; secrets still 34 (32 test keys, 2 uncertain), files 86,
  history 29 commits. Live TechDirect still 83/B, 2,802 files, 62/62
  history. MCP 62/62 against the local production server, scanning
  the live remote.

## Phase 14 status — dogfooding integrity: the repo itself must be secure (built 2026-11-26, four workers)

Trigger: Freddy — "I need you to figure this out, but I don't want
our platform to try and help people secure their repositories
without the repository itself being secure." The self-scan scored
0/F on its own scan: 302 deductions (secrets 8, vulns 206, posture
84, unpinned 4). Phase 13 fixed the fixable dep flaws (197 → 73
vulns) but the repo still shipped deliberately vulnerable test
fixtures and fixture-driven posture gaps. This phase makes the repo
itself genuinely secure — it must earn a good grade on its own scan,
honestly, not by gaming the score.

- **Diagnosed first (test-results/phase14-self-scan-inventory.md).**
  Real local scan of remote 858bd7aa: 73 vulns, ALL kept-vulnerable
  fixtures (Echo v4.11.1 ×28, vite 5.0.0 ×23, tokio 1.0.0 ×9,
  laravel/framework v10.34.2 ×7, spring-core 6.1.2 ×3, Flask 3.0.0
  ×2, rails 7.1.3 ×1); zero advisories on any real dep or Phase 13
  upgrade. Posture 15: 13 fixture-driven, 2 real (no SECURITY.md,
  no Dependabot). Secrets 34: 32 likely-test-key, 2 uncertain (the
  `api_key` fixtures, kept uncertain by doc-prose mentions of the
  identifier). Unpinned 4 points: 2 fixture-owned null-version deps
  (Microsoft.NET.Sdk.Web in app.csproj, org.example:unresolvable in
  pom.xml). Per-component table sums to 302, score 0/F.
- **The fixture problem, solved honestly
  (scripts/fixture-gen.ts).** Vulnerable fixture manifests and risky
  infra configs are no longer committed as scannable files. Tests
  generate them at test time in temp directories from in-memory
  strings (byte-identical contents: Echo v4.11.1, vite 5.0.0, tokio
  1.0.0, laravel v10.34.2, spring-core 6.1.2, Flask 3.0.0, rails
  7.1.3) via `loadFakeRepo()` / `loadFakeRepoTier2()` /
  `loadFakeRepoTier3()` and `writeTempFixtureDir()`. Moved to
  generation: vite and Flask/tokio versions out of the committed
  fake-repo manifests (clean versions kept: next 15.5.29, Django
  5.2.17, serde), Echo out of go.mod (Fiber v2.52.14 kept), laravel
  out of composer.lock, rails out of Gemfile.lock, spring-core +
  org.example:unresolvable out of pom.xml; deleted outright:
  fake-repo/.env, tier2/app.csproj, tier3/Dockerfile,
  tier3/k8s/deployment.yaml, tier3/main.tf; fake-repo/vite.config.ts
  rewritten clean (`export default {};` — it must not even import
  from "vite", which alone trips the plugins finding). The generated
  .env uses a `__SECRET_0__` placeholder; the generated vite config
  builds the public variable via `"VITE_" + "API_URL"` so no committed
  file carries a literal `VITE_` token. Detection coverage is equal
  or better: the new `test:fixtures-phase14` suite proves the
  generated fixtures detect the exact same 73 advisory IDs, the same
  3 vite + 9 infra posture items, and exactly the 13 fixture-driven
  posture items through `buildPosture`. Nothing was kept committed
  for lack of a generation path; no test was deleted.
- **Real posture gaps, fixed for real.** `SECURITY.md` (repo root;
  vulnerability reports to motdhvacr@gmail.com, no other
  reporting contact exists in the repo; acknowledgement within 3
  business days, fix or plan within 30 days for real-risk issues, no
  bounty program, safe harbor) and `.github/dependabot.yml` (npm, `/`,
  weekly, 10 open PRs; no github-actions entry — the repo has no
  workflows at all). Posture deduction 84 → 80 from those two alone
  (each low, 2 points). No real workflow or .gitignore gaps existed
  to fix. The 13 fixture-driven posture items are gone with the
  fixture migration, not by exclusion.
- **Scanner correctness fixes (two real bugs, same phase).**
  (a) History usage search saw an empty corpus: `readHeadUsageCorpus`
  in `src/lib/history.ts` walked `git.TREE` over the `noCheckout:
  true` isomorphic-git clone and visited 1 entry (root) / 0 blobs, so
  the corpus was an empty non-null Map and the null-corpus fallback
  never triggered — no history finding could ever be reported
  in-use, and genuinely referenced history secrets were mis-triaged
  as dead-end test keys. Fixed by replacing the walk with a recursive
  `git.readTree` from the tip commit's tree (same bounds, same
  cache). (b) Doc-prose mentions counted as production usage: the 2
  uncertain `api_key` fixtures were kept uncertain only because the
  identifier is quoted in GITSECURE.md:1294/1301 and README.md:1228
  (the Phase 11.1 write-up describing the comment-strip fix). Same
  class of false positive as Phase 11.1's code comments: `.md`/`.mdx`/
  `.txt`/`.rst`/`.adoc` and `docs/` files are now skipped entirely in
  the usage search (they contribute to neither `referencedBy` nor
  `referencedByTests`); a reference from real code still counts. No
  triage or scoring rule changed; no docs edited as a workaround.
  Net effect on the self-scan: secrets deduction 8 → 0 (all 34
  likely-test-key, 0 uncertain), total 302 → 294 before the fixture
  migration — measured by a direct local scanRepo run against the
  live remote, not assumed.
- **The 2 uncertain secrets, settled.** Both are test fixtures
  (`scripts/test-scanner.ts:104`, `FAKE` repeated; and
  `scripts/test-usage-phase11.ts:333`, the `__SECRET_9__`
  placeholder). Neither is real; no rotation or removal needed; the
  Bug 2 fix above settles them to likely-test-key on the evidence,
  not by weakening triage.
- **No gaming.** No scanner exclusions for our own repo, no
  special-casing Squ1zM0/GitSecure anywhere in the scanner (proved
  by a grep test in the new suite: the only `Squ1zM0` mentions in
  `src/lib` are doc comments / MCP tool examples), no severity
  downgrades, no relabelling flaws harmless, no deleted tests or
  coverage. The scanner treats our repo exactly like any other
  public repo — same code path, no owner/repo checks.
- **Measured result (local, before push).** HEAD-only self-scan of
  the working copy with the scanner's own code: **0 vulnerabilities
  (was 73), 0 posture issues (was 15), 0 unpinned direct deps (was
  2), 18 HEAD secrets, all likely-test-key** (was 16: the 2 new ones
  are the Phase 14 test lines themselves, both test keys). Projected
  full-scan deductions after the push: secrets 0 + vulns 0 + posture
  0 + unpinned 0 = **score 100, grade A** — the history findings
  will add more test-key secrets (old commits still hold the deleted
  fixtures), but at weight 0 they cannot move the score. The exact
  live secret count is measured after the push, not projected here.
- **Tests.** New `npm run test:fixtures-phase14` 42/42 (generated
  fixtures detect the exact same 73 advisory IDs; committed
  manifests scanned via live OSV with zero advisories, excluding
  nothing; zero unpinned direct deps; no owner/repo special-casing).
  `test:usage-phase11` 91/91 (was 75 — new case (x): docs-only
  mention → dead end, stays test key; (vi-b) updated with the reason
  recorded). `test:history` 66/66 (was 56 — new git-path block:
  history finding with HEAD references shows them, prose mention
  excluded). Full suite, coordinator-verified: build exit 0;
  scanner 73/73, tier3 40/40, history 66/66, public-full 56/56,
  cursor 181/181, triage 63/63, usage 91/91, score 36/36, deps 22/22,
  fixtures 42/42, UI 110/110, MCP 62/62 (local production server,
  scanning the live remote), techdirect 83/B. `test:mcp` dogfood
  assertions describe the pre-Phase-14 remote and are updated in the
  docs follow-up push with the measured live numbers.
- **Live verification (2026-11-26, after the push).** Home 200;
  live GitSecure self-scan **100/A**: 37 secrets, all
  likely-test-key (0 uncertain, 0 genuine), **0 vulnerabilities, 0
  posture issues**, scoreDetail `{secretsDeduction 0, vulnDeduction
  0, postureDeduction 0, unpinnedDeduction 0, secretsExcluded 37,
  wouldBeScore 0}`, files 86, history 31 commits — the projected
  100/A, exactly. Secrets are 37, not 34: history grew to 31 commits
  (the Phase 14 push itself plus the new Phase 14 test lines, found
  at HEAD and in their introducing commits). Live TechDirect still
  83/B, 2,802 files, 62/62 history. MCP 62/62 against the local
  production server, scanning the live remote (dogfood assertions
  updated to the measured post-push numbers in the docs follow-up
  push).

## Phase 15 status — user experience + zero REST calls on the happy path (built 2026-11-26)

### UX audit + fixes (Freddy: "Continue and develop the app. Improving user experience.")

Audit first (`test-results/phase15-ux-audit.md`, 16 findings, ranked, each with a screenshot or measurement; 29 screenshots in `test-results/phase15/`): home explains the tool in seconds, input validation correct, zero overflow on home/TechDirect/GitSecure at 1280 + 360 px light/dark, contrast AA everywhere sampled, keyboard/focus/skip link work, dial has role="img" + full aria-label, filter counts aria-live with true counts, copy-link verified in the real clipboard, verdict sections and map click-to-track work. The fixes, in audit priority order:

- **Linux dead-end (finding 1, HIGH):** a fetch-level timeout inside the HEAD chunk threw instead of returning a partial cursor, so torvalds/linux ended on a terminal error page after minutes of a static screen and the Phase 9 resume path never engaged. `headChunkOrTimeoutPartial()` in `src/lib/chunks.ts` now returns a partial cursor on a HEAD timeout (with HEAD meta known), so `ScanProgress` mounts and resume engages. Adjacent bug found by testing: a mid-download body-stream error crashed the chunk with an unhandled `'error'` event on the `Readable.fromWeb` stream — one line (`input.on("error", …)` in `streamHeadFilesViaTarball`) converts it to the 504 the driver turns into a partial cursor. Every page-level error state now has a **"Retry this scan"** button (`src/components/RetryScanButton.tsx`) next to "Scan another repo".
- **DT mobile overflow (finding 2, HIGH):** DefinitelyTyped overflowed 426 vs 360 px from long unbreakable paths. The GitHub link label is now just "View on GitHub" (the path is already shown above it), plus `overflow-wrap: anywhere` on `.github-link`, `code.inline`, `.finding`, and `.report-list li`. Verified on the real DT provisional report at 360 px: scrollWidth = 360, zero overflowing elements.
- **DT never finishes (finding 3, HIGH, UX half):** the chunk-error card now classifies the failure (rate-limit vs network vs other) and shows progress reached ("So far: 61,814 of 61,814 files scanned · 403 possible leaked secrets found so far."); a 429 fails fast instead of burning three retries. When the driver errors, the provisional banner reads "paused — history and dependency checks stopped here" instead of the stale "still running". The "Retry from where it left off" button was proven live on a real chunked DT run: the retried chunk carried the saved cursor and history resumed at 10 commits.
- **Usage map legibility (finding 4):** file labels are now basenames with head + "…" + tail, counts sit inside their node circles, labels sit radially outward and x-clamped, centre circle paints after the edges so no edge strikes through "This repo". Verified on the real self-scan map at 1280 px.
- **Provisional wording (finding 5):** `plainSummary()` takes `provisional`, so provisional reports say "So far: …" instead of "Scan complete. ". Zero-secret reports now read "No leaked secrets were found…" (finding 7, capitalisation).
- **Branded 404 (finding 6):** new `src/app/not-found.tsx` explains the `git-secure.com/owner/repo` shape with the Squ1zM0/GitSecure example and links home. Bare-owner URLs no longer land on the stock Next.js 404.
- **Small copy fixes (findings 8, 9, 11, 12, 13, 14, 15):** score-0 dial no longer renders a stray red dot (butt cap at 0); track detail omits the empty "Used by:" segment; loading copy says "usually takes 15–30 seconds" (TechDirect measured 27.1 s); copy buttons and file chips raised to the project's own 44 px rule; the scan input has a visible "GitHub repo to scan" label; the score explanation appends the runner-up deduction ("Plus 4 known flaws in dependencies, which cost 8 points…"); per package, one reconciled fix version (max of the advisory fixed versions, `src/lib/versions.ts`) so four js-yaml findings no longer disagree.
- **MCP onboarding (finding 10):** one plain-English line ("MCP lets an AI assistant like Claude call GitSecure for you — no account needed"), the four JSON snippets collapsed behind one `<details>`, canonical URL now `https://git-secure.com/mcp` (apex is canonical: www 307-redirects to apex, verified live 2026-11-26), mobile code blocks get a right-edge fade.
- **"Roll all into report" (Freddy, added mid-phase):** a button in the score hero card, top-right next to the dial (full-width under 560 px), that downloads the ENTIRE scan as one Markdown file (`gitsecure-report-{owner}-{repo}-{short-sha}.md`) — score, grade, summary, explanation, every secret with triage verdict, every vulnerability (Fix line reconciled, same as the page), posture issue, dependency and framework, plus scan metadata. No truncation even for findings hidden behind collapsed groups/filters. Generated client-side from the `FullReport` already on the page (`src/lib/report-markdown.ts`, `src/components/RollAllButton.tsx`); no API route. Secrets fragment-only, exactly as on the page. Works on finished and provisional reports (provisional labelled in the file). Verified by a real browser download and `test:report-markdown` 30/30.
- **Rate-limit recovery (Freddy, live friction):** the "GitHub's request limit was hit" page had only "Scan another repo". It now has a **"Try this scan again"** button re-running the same repo, and honest reset wording from GitHub's own headers (`src/lib/rate-limit.ts`: `retry-after` / `x-ratelimit-reset` → "resets in about N minutes", else "resets within the hour" — never an invented countdown). `resetAtMs` passes through the scan API error JSON (additive, backward compatible). A genuine live 429 render was not triggered (would burn the shared quota); the path is proven by mocked tests + the shared button mechanism verified live.
- **Tests:** new `test:resilience-phase15` 45/45, `test:report-markdown` 30/30, `test:ui-phase15c` 32/32; UI suite 110 → 155; cursor 181 → 192; score 36 → 40. Full suite green at integration (see below).

### Zero REST calls on the happy path (worker D)

Trigger: Freddy thought rate limiting was rectified, but the 429s
kept coming — Phase 8 had moved history off REST (a scan went from
~65 REST calls to 1), and the remaining 429s came from that last call
plus the shared-IP bucket. The answer is YES: the last REST call can
go away entirely, with no token (Freddy's Phase 6 ruling stands —
this phase adds no token, proposes none, and needs none).

- **Branch + HEAD sha over the git protocol** (`resolveRemoteHead`
  in `src/lib/history.ts`): one `getRemoteInfo` call to github.com —
  NOT api.github.com — returns both the HEAD symref
  (`refs/heads/main`) and every branch head's sha. It replaces the
  REST repo-info fetch (default branch, size, private flag) AND the
  commits-list call that fetched the HEAD sha. A missing or private
  repo answers 401 on info/refs, which maps to the same plain-English
  404 ("Repository not found (or it is private)"); anything else is
  a 502, and a request that does not answer inside 12 s (the same
  bound ghJson used to give the REST calls) is a 504 — the meta step
  never guesses a branch and never hangs the scan.
- **The file list comes from the tarball, not the tree**
  (`src/lib/scan.ts`, `scanHead`): the tarball's entries ARE the
  file list, complete by construction — the recursive-tree API call
  is gone from the happy path and is fetched only when a tarball
  transport fails and the per-file fallback needs a list. As a side
  effect the count is now exact: the tree used to list symlinks the
  tarball skips, so a complete scan could report "Fetched X of Y".
- **Both size gates are streaming bounds now — no size is read at
  all**, because the repo `size` only ever came from the REST
  repo-info call. The HEAD transport is chosen by the download
  itself: past `TARBALL_BUFFER_SWITCH_BYTES` (100 MB compressed —
  ~300–500 MB decompressed for source-heavy repos, which fits a 1 GB
  function; codeload sends no Content-Length, so the size can only
  be measured while the bytes arrive) the whole-buffer path switches
  to the streaming reader, which scans the same files with bounded
  memory. The history gate is a byte bound on the pack download
  (`boundedGitHttp` in `src/lib/history.ts`, `PACK_MAX_BYTES`
  150 MB): isomorphic-git buffers the whole pack in memory
  (`collect(response.packfile)`), so past the bound the underlying
  request is aborted and the clone fails with `PackTooLargeError`,
  and the orchestrator falls through to the API path with a
  plain-English note saying why. The old REST-based gates (100 MB
  repo size for history, 1 GB for streaming HEAD) are deleted, along
  with `repoSizeKb` on `HeadPartial` and on `scanHistory`'s options.
  The "git" method pin is now honoured as documented (git then API);
  it used to fall through to the default order.
- **A tarball stall is a timeout on both transports**: the
  whole-buffer download converts an abort to ScanError 504 (the
  streaming path already did), so the chunk driver returns a
  resumable partial cursor instead of falling through to a per-file
  crawl that would likely stall too. Only a genuinely unavailable
  tarball (404/500/parse error) takes the per-file fallback.
- **What stays REST (fallback only):** the recursive-tree fetch when
  the tarball is unavailable; the API history path when cloning is
  impossible; the 5-commit patch fallback; and `fetchHeadSha`, kept
  for the chunked driver's resume re-validation (`chunks.ts:271`,
  worker A's file — a git-protocol replacement for that one call is
  a follow-up, not this phase). None of them runs on a happy-path
  scan. There is deliberately NO REST fallback for the branch/HEAD
  lookup: the git protocol is the same GitHub infra the tarball and
  the clone already depend on, so if it is unreachable the scan
  cannot proceed anyway — it fails plainly instead of burning the
  quota it just escaped.
- **Tradeoff, stated plainly:** a too-large pack is now discovered
  by downloading up to 150 MB first (bounded, aborts cleanly, no
  OOM — heap flat in the live DefinitelyTyped probe), whereas the old
  REST gate skipped the attempt entirely. A giant repo's history step
  therefore costs a ~1–2 min doomed download before the API fallback
  runs; the chunked driver pays it once per scan (the cursor flips to
  "api" on the first chunk) and the report says why.
- **Test-only seam** (`setRemoteHeadResolverForTests` in
  `src/lib/history.ts`): lets the chunked-scan tests point scanHead
  at a mock git server or a scripted failure without threading an
  option through the driver. Production code never sets it; tests
  reset it in a finally block.
- **Proof — `npm run test:zero-rest` 26/26** (`scripts/test-zero-rest.ts`):
  bounded-client unit checks (PackTooLargeError + byte count + abort
  + non-pack passthrough); fixture legs against a mock git server
  (resolveRemoteHead branch + HEAD sha, git history 0 REST); a live
  full `scanRepo("Squ1zM0", "TechDirect")` under a fetch-layer
  counter — **0 api.github.com requests** (fetch hosts during the
  scan: codeload.github.com=1, api.osv.dev=5), still 83/B, 2,802
  files, 62 history commits over the git protocol, HEAD sha matching
  resolveRemoteHead — plus a tree cross-check (test-side REST call,
  outside the counting window) proving the tarball-derived file list
  matches the tree count 2,802 = 2,802. Live DefinitelyTyped pack
  probe (not a suite test): clone aborts at the bound,
  packTooLarge=true, heap 15 MB → 13 MB, 0 REST calls.
- **Legitimately changed assertions:** `test:history` 66 → 70 (the
  3 Phase 8.1 size-gate checks are gone; 4 pack-bound + 3
  orchestrator pack-fallback checks added). `test:cursor-phase9`
  stays 192/192, with 2 assertions reworded for the new transport:
  the HEAD-timeout partial keeps 0 files scanned (the whole-buffer
  download aborts before any entry is parsed — the old test forced
  the streaming transport with a fake 2 GB repo size), and the 429
  checks are retargeted at the tree fallback (the repo-info call
  they stubbed no longer exists). `test:ui-phase7` 152 → 155 is
  worker B's concurrent Phase 15 finding-2 checks, not this phase.
- **Verification (2026-11-26):** `npm run build` exit 0;
  `test:scanner` 73/73, `test:history` 70/70, `test:cursor-phase9`
  192/192, `test:public-full` 56/56, `test:tier3` 40/40,
  `test:triage-phase10` 63/63, `test:score-phase12` 40/40,
  `test:deps-phase13` 22/22, `test:usage-phase11` 91/91,
  `test:fixtures-phase14` 42/42, `test:ui-phase7` 155/155,
  `test:resilience-phase15` 45/45, `test:report-markdown` 30/30,
  `test:ui-phase15c` 32/32, `test:zero-rest` 26/26 (new),
  `test:techdirect` 83/B (2,802 files, 62 history commits),
  `test:history-git` 62/62 (0 REST), `test:mcp` 62/62 against a
  local production server. Live production server
  (`npm run build` + `npm start`, this VM, GITHUB_TOKEN unset):
  home 200, scan API `Squ1zM0/TechDirect` 200 in ~14 s, 83/B,
  2,802 files, 62 history commits via the git protocol. No literal
  secret-pattern values committed (grep-verified).
- **Integration (2026-11-26):** full suite re-run green at integration — build exit 0; scanner 73/73, tier3 40/40, history 70/70, public-full 56/56, cursor-phase9 192/192, triage 63/63, usage 91/91, score 40/40, deps 22/22, fixtures 42/42, UI 155/155, report-markdown 30/30, resilience 45/45, ui-phase15c 32/32, zero-rest 26/26, MCP 62/62 (local production server), techdirect 83/B. One integration fix: the MCP canonical URL moved from www to the apex (www 307-redirects to apex, verified live) and worker C's 4 URL assertions were updated with the reason recorded.
- **Note (2026-11-26, outside this task):** Freddy himself reversed
  the Phase 6 no-token ruling at 11:17 AM MST and a fine-grained
  PAT is now set as GITHUB_TOKEN in Vercel (5,000/hr authenticated
  quota). This phase does not depend on it in either direction: the
  happy path makes zero REST calls with or without a token, and the
  code already sends the token on the fallback REST calls when one
  is present. All proofs above ran from this VM with GITHUB_TOKEN
  unset (unauthenticated), which is the harder case.

## Phase 16 status — report page loads in seconds; visible resume; honest copy (built 2026-11-26)

Freddy, ~12:20 PM MST: iPhone Safari, "This page couldn't load" on
git-secure.com/vinta/awesome-python. Live device-browser evidence
folded in the same day: the scan DID complete (91/A, 0 secrets, 0
vulns, 3 posture, 126 files, 3,350 history commits, branch master,
commit 4c3cb15) but the page failed FOUR times after ~60 s with only
a Reload button (one tab disappeared entirely during a 60-second
wait); reloads returned to the same "Checking files…" stage with NO
resume indicator, progress count, or retry control; the provisional
report only appeared after re-entering through the homepage scan
form; history advanced ~400 commits per minute; total time 16 minutes
vs the page's stated "usually takes 15–30 seconds".

- **Pre-fix reproduction** (test-results/phase16/repro.md,
  repro-curl.txt): live awesome-python report run 1: TTFB 0.82 s,
  total 52.80 s, HTTP 200, 33,976 bytes; an earlier run took 63.6 s
  and returned only the loading shell (stream cut). Diagnosis: the
  report page is a server component awaiting `runScanLoop` with
  `FAST_PATH_WAIT_MS = 50_000`; Vercel's 60 s function ceiling makes
  big-repo pages a coin flip between "loads after a minute" and
  "stream cut, page fails" — Safari reports the cut stream as "This
  page couldn't load". Home page fine (0.9 s); not an asset problem.
  (Freddy's 12:19 home-page Safari failure is a separate stale-DNS
  issue on his phone, explicitly out of scope here.)
- **Worker A — zero server await (decision, measured):** the page
  renders `<ScanProgress cursor={null}>` immediately; the browser
  drives the scan via new additive endpoints `POST /api/scan/start`
  (one fresh HEAD chunk) and `GET /api/scan/[owner]/[repo]/tip`
  (branch + HEAD sha, so a finished report saved in sessionStorage
  renders immediately on reload only if its HEAD still matches the
  live tip). A single HEAD chunk cannot be proven to stay under ~5 s
  (measured locally 4.17 s awesome-python, 6.56 s GitSecure, before
  cold start; the tarball carries a 30 s abort timer), so zero await
  is the only budget that holds for every repo. Local shell time
  0.029–0.53 s (was 52.8–63.6 s). Resume: saved sessionStorage
  progress wins whenever it exists; on resume the resume line, the
  provisional report, AND the progress counts are set at once (new
  `progressFromSaved`); fixed a latent bug where the old code saved
  the empty initial state over real saved progress when the saved
  scan had 0 history commits (HEAD done, history not started).
  Terminal failure before any progress renders the full error page
  with the exact Phase 15 words. Error copy moved to
  `src/lib/scan-error-copy.ts` (byte-identical strings, shared by
  page + driver). New suite `test:phase16-a` 56 checks. Note: the
  old `export const instant = false` was dead (`instant` is not a
  route segment config); `export const dynamic` was NOT added — it
  is incompatible with `cacheComponents` (build error) and awaiting
  `params` already makes the page render on demand.
- **Worker B — API ceiling audit:** confirmed a single invocation
  could exceed ~55 s — the loop checked its deadline only *after*
  each chunk returned, so a chunk that started at 49 s of a 50 s
  budget ran a full chunk past it. Worst chunk: git-history ~30 s
  walk budget plus unbounded clone + full `git.log` parse + corpus
  read; API-history chunk had no budget at all; assemble re-ran
  `scanHead` + unbounded OSV. Also fixed a real hole: the streaming
  tarball's 55 s abort timer was cleared after headers, so a
  mid-body stall hung forever. Fix: new `API_FAST_PATH_WAIT_MS =
  40_000` for the API route + both MCP tools (the page keeps its
  50 s constant, now unused in production); `runScanLoop` passes
  its absolute deadline into every chunk; no new chunk starts
  unless `budget − 21 s` remains (first chunk always runs); worst
  case ~53 s < 55 s headroom. Measurements: TechDirect full loop
  20.4 s (83/B); awesome-python loop partial 32.2 s with 200
  commits + cursor. New suite `test:phase16-worker-b` 25/25.
- **Worker C — copy/state fixes:** home + loading copy scoped
  ("Small repos usually take 15–30 seconds; a large repo with a
  long history takes several minutes"); new pure helper
  `historyRatePerMin` in `src/lib/progress.ts` (commits/minute from
  measured numbers only, null under 100 commits or 20 s — no ETA
  exists before the scan finishes, only the observed rate, shown as
  a live line during the history step); provisional ReportView no
  longer claims "0 vulnerabilities" before the dependency check runs
  (stat tile "— / not checked yet", same in `report-markdown.ts`);
  typo fixed via shared helper `gradeWordWithArticle` in
  `src/lib/score.ts` ("an excellent" for A, used by `explainScore`
  and `ScoreDial`). New suite `test:ui-phase16c` 45/45;
  `test:ui-phase15c` 36/36.
- **MCP regression found at integration and fixed:** lone
  `test:mcp` cold run 51 pass / 12 fail — all 12 were `scan_repo
  GitSecure` returning a still-running cursor instead of report
  JSON (cold self-scan ~52 s > 40 s API budget — the tool's
  documented contract). Worse, resuming then returned only 18
  secrets instead of 37: the first invocation's history-chunk
  findings are lost on resume, because `runScanLoop` accumulates
  `historyFindings` in memory and GET/MCP callers never pass them
  back (only POST `/api/scan/chunk` clients, e.g. the browser via
  sessionStorage, do). Fix 1 (test): `scripts/test-mcp.ts` follows
  the documented resume contract — when `scan_repo` answers
  still-running it extracts the cursor and calls `resume_scan` (up
  to 6 attempts) until the full report arrives — 51 → 58 passes.
  Fix 2 (code, `src/lib/chunks.ts`): the assemble stage is exempt
  from the loop's start floor. Assemble is bounded and cheap
  (deadline-capped OSV + scoring, ~seconds), and stopping before it
  strands the scan across invocations where GET/MCP callers lose
  findings. Worst case with the exemption ~57 s bound. Proved by a
  new test (section 7 in `scripts/test-phase16-worker-b.ts`: mock
  API list/detail each sleep 11 s — split because each API fetch
  aborts at the 12 s `API_FETCH_TIMEOUT_MS` — so history ends after
  the 21 s floor; the loop still finishes in one call, 22,194 ms).
  Cold-server end-to-end after the fix: `test:mcp` 62/62, exit 0;
  local API TechDirect 83/B (200, 3.7 s, 2,802 files, 62 commits);
  self-scan 100/A (200, 6.1 s, 37 secrets, 34 commits).
- **Known remaining gap (honest, pre-existing Phase 9 limitation,
  not fixed here):** for huge repos whose history spans multiple
  invocations via GET/MCP, earlier chunks' history findings are
  still lost on resume. The assemble exemption fixes the mid-size
  case (history fits one chunk); awesome-python-scale MCP scans
  need the deeper cache/incremental-write fix — a Phase 17-sized
  redesign, proposed not started.
- **Verification (headless, local prod server):** Worker D offline
  suites 1,101 PASS, 0 FAIL; zero-rest 26/26; techdirect exit 0.
  Final headless run (`test-results/phase16/headless-final.json` +
  screenshots; the v1 run is discarded — its "finished" signal
  matched the provisional report because ReportView renders
  ScoreDial for provisional too; v2 uses "Scan complete.", which
  only the finished report prints): shell responseStart 81 ms;
  reload at 21.6 s after 200 history commits → resume line
  "Resumed — picked up where it left off (200 history commits
  checked, 0 secrets found so far)", no bare spinner; finished
  report at 264.8 s wall (4m25s vs 16 minutes on the device browser
  pre-fix): 91/A, 0 secrets, 0 vulns, 3 posture, 126 files, 3,350
  history commits, master 4c3cb15 — identical to the device-browser
  result; "an excellent score" renders correctly; 360 px
  scrollWidth 360, no overflow; Roll all into report present.
  (The JSON's `historyCommits: null` is a regex miss in the
  verification script — the finished text reads "History checked:
  3350 commits"; the count is confirmed from the screenshot.)
- **Live verification (2026-11-26, ~21:15–21:22 MST, push
  ee86cad3):** awesome-python shell 200, TTFB 0.53 s, total 1.03 s,
  22,754 bytes (was 52.80–63.6 s pre-fix); TechDirect API 200 in
  8.8 s, 83/B, 2,802 files, 62 history commits; self-scan API 200 in
  15.3 s, 100/A, 37 secrets all likely-test-key, 0 vulns, 0 posture,
  189 files, 35 history commits; awesome-python walked to a finished
  report via the public chunk API (16 calls to 3,200 commits + 2
  resume calls): 91/A, 0 secrets, 0 vulns, 1 framework, 1 dependency,
  3 posture, 126 files, 3,350 history commits, scoreDetail
  `{postureDeduction 9, everything else 0, wouldBeScore 91}` —
  identical to Freddy's device-browser result; MCP initialize 200 in
  0.64 s on https://git-secure.com/mcp. Roll all into report is
  present in the rendered finished report on this build (local
  headless, screenshots) — the served shell HTML correctly does not
  contain it, since the report renders client-side.

## Phase 17 status — best security as possible: close the history-findings hole + coverage audit (built 2026-11-26)

Freddy: "It works and it works well! That's what's next for development please continue for the best security as possible." Two parts, plus a second defect the proof harness found live.

### Part 1 — the accumulation hole (highest priority)

The pre-existing Phase 9 limitation, named honestly in Phase 16 and never fixed until now: for huge repos whose history spans multiple serverless invocations, earlier chunks' history findings were LOST on resume for GET / MCP callers — only POST /api/scan/chunk callers carry accumulation. A security scanner that silently drops findings is the worst kind of bug for this tool. Proven with real numbers before any fix:
- Loss repro (6-commit fixture repo, fake secrets in chunks 1, 3, 5): POST-chunk path 3/3 secrets, 23/F; GET/MCP path 1/3 secrets, 73/C — and both reports still claimed "History checked: 6 commits", so the score was silently inflated (test-results/phase17/loss-repro/).
- Live-scale harness (test-results/phase17/resume-proof/, re-runnable, exit 1 while sets differ): docker/awesome-compose chunk path 24 secrets (14 HEAD + 10 history) vs GET path 14 (14 HEAD + 0 history) — all 10 history findings lost. vinta/awesome-python cannot demonstrate the hole (0 secrets on both paths, 91/A) and stays as the control run.
- Design (test-results/phase17/accumulation-design.md, 831 lines): durable per-scan accumulation in Upstash Redis direct via REST (raw fetch, no SDK). Key `gs:scan:v1:{owner}:{repo}:{headSha}`, value `{v:1, headSha, histScanned, historyFindings[]}` — redacted fragments only, never full secrets. SET with EX 604800 (7-day TTL, backstop only); DELETE at assemble (primary cleanup — a finished scan leaves nothing); one write per invocation boundary, not per chunk (~2–4 ops/scan, $0 at 10/100/1,000 scans/day; worst overage $0.14/mo). Why Upstash: Vercel KV no longer exists as a product (deprecated); Vercel Blob fails $0 above trivial volume (2,000 advanced ops/mo cap, over-cap on Hobby = Blob blocked 30 days); Cloudflare KV's eventual consistency (up to 60 s+) could re-create the loss; Supabase is second choice (couples GitSecure to VPT's service_role key or burns Freddy's last free project slot, free projects auto-pause after a week idle). Cost proof is scenario arithmetic (no analytics); the design plans against the tighter of Upstash's conflicting published limits (10K cmds/day vs 500K/mo).
- Implementation (src/lib/scan-state.ts, wired into runScanLoop only): `ScanStateStore` interface + `NoopStore` (default) + `UpstashRestStore` + test-only `MemoryScanStateStore`. Activates ONLY when `UPSTASH_REDIS_REST_URL`/`UPSTASH_REDIS_REST_TOKEN` (or the `KV_REST_API_*` pair) exist; a half-pair is NoopStore. Store failures never fail a scan. Monotonic guard on saves; corrupt/oversized/wrong-version values read as "no state".
- **HARD STOP, still in force: nothing is provisioned.** No store, account, or credential was created. Provisioning is Freddy's dashboard clicks (Vercel Dashboard → GitSecure → Storage → Browse Marketplace → Upstash Redis → Create → Free, region us-east-1 single-region, env vars auto-injected → redeploy; console fallback in design §4.2). Until then the code is inert (NoopStore) and the live multi-invocation proof run cannot happen — that verification is still owed after provisioning.
- Honest degradation (shipped now, works with no store): when a scan resumes with `histScanned > 0` but recovery fails, the report carries the line "History findings from earlier parts of this scan could not be recovered, so this report may be missing secrets from the first {N} commits checked — the history count above is how far the scan walked, not how many findings survived." Single-invocation scans never get the line. The hole is now a stated limitation, never a silent misreport. With store: loss-repro 3/3, 23/F, no line, store empty after assemble. Without store: 1/3, 73/C, with the line.
- Caller-carried fallback (additive, backward compatible, not the fix): optional `historyFindings` on MCP `resume_scan` (echoed in the still-running text for the model to pass back verbatim) and on GET as `?historyFindings=` base64url JSON (8 KB decoded cap — a DefinitelyTyped-scale set can never ride in a URL; a bare `curl …?cursor=` resume still carries nothing).
- Copy discipline: the public "never stored" promise (mcp.ts, README, page.tsx, layout.tsx) was NOT changed — the store is not provisioned, so claiming transient storage would be false. The locations that must change at provisioning time are listed in test-results/phase17/copy-after-provisioning.md. The cursor still never carries findings or secret fragments (Phase 9 rule stands).
- Tests: test:phase17-worker-c 81/81 (activation, validation, MemoryStore incl. TTL + monotonic guard, UpstashRestStore vs fake Upstash server over real fetch incl. non-2xx/hang/corrupt/oversized, loop round-trip, NoopStore, FailingStore, fallback, MCP + GET parser, redaction).

### Second defect found by the harness: history-cache poisoning

A chunked scan's final history chunk walks only the tail commits yet cached them as the repo's "complete" history: in src/lib/history.ts, `complete = !truncated && !chunkStopped` ignored the resume skip. Observed live locally: after a chunked awesome-python scan (3,350 commits), a GET scan on the same server answered in 1.7 s claiming 150 history commits. Fix (one file, src/lib/history.ts): a resumed/partial walk writes nothing to the cache (`cacheable = complete && !opts.resumeAfterSha`); only a walk that started from the beginning and completed may write a complete entry. The `complete` result flag is untouched — chunks.ts uses it to set `histDone` and move the cursor to assemble, so changing it would loop forever on empty chunks. Regression test (test-history.ts, "Phase 17 (Worker E)"): 5-commit fixture, chunk 1 newest 3 (complete: false), chunk 2 resumed remaining 2 (complete: true), fresh scan must report full depth 5 — before the fix it reported 2 scanned, 0 fetched, 2 cached (poisoned tail cache hit); after the fix 5 scanned, 5 fetched, 0 cached. test:history now 79/79.

### Walk-budget fix (found during live verification, pre-existing)

The live resume proof run failed on both paths with HTTP 504 FUNCTION_INVOCATION_TIMEOUT: a single history chunk for docker/awesome-compose took 174 s locally (60.5 s live = killed). Profiled: the hotspot is jsdiff `diffLines` inside `addedLines` on `package-lock.json` files in history — one lockfile diff with only 75 added lines took 43.8 s; two lockfiles in one commit took 51.5 s + 46.4 s; a 274-commit probe cost ~380 s, nearly all of it in ~10 lockfile diffs, all finding 0 secrets. Clone is 4 s, `git log` 13 s — both fine. The walk's budget checks only fired every 16 commits (40 s check every 64), so one commit with two 50 s diffs blew past every deadline and the Vercel 60 s ceiling. This is pre-existing (the walk/diff code is old; Phase 17 only added detectors) — exposed because Phase 17's verification is the first to run awesome-compose live. Fix (src/lib/history.ts only): `addedLines` is now a dispatcher — ≤1,000 lines on either side keeps jsdiff verbatim; above that a hash-based multiset-difference added-line computation, O(n) (threshold measured: jsdiff ≤25 ms @500 lines, ≤95 ms @1,000, ~1.9 s @5,000 and tens of seconds on real 10k-line lockfiles; fast path ~1 ms/1,000 lines at every size). Honest divergences documented in code: duplicate-line text can get a different line number than jsdiff's minimal-edit attribution (added-text multiset identical); a line moved within a file at equal count is invisible to the multiset — it cannot hide a secret from the full walk, since the line's first introduction always raises its count and is reported there. Plus file-granularity walk budget: the deadline is checked before each file's diff+scan, tripping mid-commit discards that commit whole (same rollback as the memory guard) and sets `chunkStopped`, so the cursor resumes from the last fully scanned commit with findings kept. New suite test:phase17-worker-f 48/48 (13/13 equivalence vs a jsdiff oracle; big-lockfile diff 12 ms vs 43.8 s, findings identical; chunk-budget test; resume findings exactly equal one unbounded run). Live-local: chunk 1 before → after 174 s → ~22 s (200 commits, 11 findings); harness chunk path 4 calls, ~56–59 s wall, 30 secrets (14 HEAD + 16 history), depth 274. Correction: the old "24 secrets" baseline was itself truncated (old report's limits line: history stopped early after 64 commits) — all 10 old findings are present in the new run plus 6 deeper ones (log depths 179–269); the true complete count is 30.

### Part 2 — detection coverage audit

- Secrets (src/lib/secrets.ts, 9 new detectors + 1 extension, each with detection + false-positive tests, all triage/usage flow-through verified): Anthropic `sk-ant-` keys; Google `AIza` keys; npm `npm_` tokens; PyPI `pypi-` tokens; SendGrid `SG.` keys; Telegram bot tokens; Hugging Face `hf_` tokens; GitLab `glpat-` tokens; name-anchored AWS secret access keys (the secret half of the pair — previously missed entirely); Slack `xoxe-` enterprise tokens (were silently missed by `xox[baprs]-`).
- Ecosystems (src/lib/frameworks.ts, src/lib/scan.ts, src/lib/osv.ts, src/lib/types.ts): pyproject.toml parser — the biggest OSV gap found, modern Python repos declare deps only here and previously had zero flaw coverage (exact `==` pins become versions; ranges yield null, never presented as a version; the `[project]` name/version strings are not dependencies); poetry.lock parser; Dart/Flutter pubspec.yaml + pubspec.lock parsers (new `pub` ecosystem → OSV "Pub"; `flutter:` SDK entries skipped; Flutter fingerprinted with version null); Cargo dev/build/workspace/target dependency sections; framework map + Fastify, Koa, Hono, SvelteKit.
- Posture (src/lib/infra.ts, src/lib/scan.ts): workflow piping a download into a shell (`curl|wget … | sh|bash`, high); Dockerfile `ENV` secrets (high — worse than `ARG`, lands in image config); K8s `hostIPC: true` and `allowPrivilegeEscalation: true` (high); Docker Compose `privileged: true` / `network_mode: host` (high — compose files previously had zero posture checks).
- Deliberately NOT added: Twilio SIDs (identifier, not a credential); Cloudflare 40-hex / Heroku UUID / bare 40-char base64 (indistinguishable from SHAs/UUIDs without a name anchor); Elixir Hex (needs a real Erlang-term parser); Swift/SPM (OSV has no Swift ecosystem to query — coordinator ruling: leave it out entirely rather than list dependencies that can't be checked); absence-style checks (missing `readOnlyRootFilesystem`, etc. — absence ≠ misconfiguration); `requirements.txt` `>=` lower-bound presentation (pre-existing inaccuracy, left untouched rather than risking Phase 13 fixture assertions).
- No scoring-weight, cap, or redaction changes. No exclusions, no severity changes, no special-casing. New suite test:phase17-worker-b 70/70; secret-pattern grep clean (fixtures assembled in memory from prefix + repeated character).

### Integration verification (round 2 — push 73beb18c, 2026-11-27)

- Build + full offline suite: 21 suites + `tsc --noEmit`, **1,345 PASS, 0 FAIL**, all exit 0 (log `test-results/phase17/integration-suite2.log`); `npm run build` exit 0; secret-pattern grep clean (0 findings over all changed files). New suites: `test:phase17-worker-b` 70/70, `test:phase17-worker-c` 81/81, `test:phase17-worker-f` 48/48.
- `test:mcp` (local production server): exit 0, 62 checks passed on the final run. Honest flake note: two earlier runs in the same session failed the GitSecure resume checks — once on a tarball-download timeout, once on a GitHub timeout — and two runs passed the report but showed usage on only 18/37 secrets. No code changed between those runs. Direct measurement from this VM at the time: `git clone --depth 1` of GitSecure took 109.8 s (3 s CPU — network wait) and the tarball 16.3 s; REST quota was fine (48/60). The resume path re-downloads HEAD and re-clones inside a 40 s budget, so a slow GitHub makes it marginal here; with a warm cache / recovered network the same build passes everything including the usage check. This is a local-test-environment timing weakness, not a code regression — no Phase 17 worker touched the clone, tarball, or network paths.
- Push: the first attempt was interrupted by a runtime restart (no output recorded); remote head was verified still 2d81d53e, so the retry could not duplicate anything. Retry landed **73beb18c** (411 files), verified by read-back: head SHA + tree 411 blobs, LICENSE present, all key files present.
- Live verification (2026-11-27, after deploy settled): home 200 (0.87 s); awesome-python shell 200, TTFB 0.66 s, total 1.07 s (Phase 16 bar ~1 s holds); TechDirect API 200 in 9.1 s, 83/B, 2,802 files, 62 history, 0 secrets, 4 vulns; self-scan API 200 in 15.9 s, 100/A, commit 73beb18c, 37 secrets all test keys, 0 vulns, 0 posture, 39 history; awesome-python finished live via the chunk API at 91/A, 0 secrets, 0 vulns, 3 posture, 126 files, 3,350 history commits, 19 calls, 352 s wall; MCP initialize 200 in 1.17 s on https://git-secure.com/mcp.
- Live harness re-run, docker/awesome-compose (`test-results/phase17/resume-proof/awesome-compose-live2/`): chunk path 4 calls, 53.4 s wall, **30 secrets (14 HEAD + 16 history), depth 274** — first history chunk 18.7 s (was a 504 before the walk fix). GET path 1 call, 41.6 s, **30 secrets, depth 274**. Diff: **MATCH, exit 0** — 0 lost, 0 gained, by identity and commit-qualified. Cache-poisoning live check passes inside the same run: the fresh GET after the chunked scan reported the full depth 274, not a poisoned tail.
- Honest mechanism note — read this before claiming the hole is closed: the live GET scan completed in a SINGLE invocation (41.6 s), so no resume occurred and the store was not exercised. The MATCH proves the walk-budget fix (a 274-commit lockfile-heavy history now fits inside one serverless invocation), not the accumulation store. The store is still unprovisioned (NoopStore in production), and a repo whose history genuinely spans invocations would still lose findings on GET/MCP resume until it is.
- Still owed after Freddy provisions Upstash: the live multi-invocation GET/MCP resume proof (design §4.6 step 9 — DefinitelyTyped-scale scan returning the identical finding set via GET/MCP as via POST-chunk accumulation), plus the copy updates in test-results/phase17/copy-after-provisioning.md.

## Presence SEO apply — on-site package staged 2026-11-26, applied 2026-11-27 (Phase 17 head)

The presence audit found the site in 0 of 27 search results with no OG tags, no JSON-LD, no canonical, and robots.txt/sitemap.xml/llms.txt all 404. The staged package in gitsecure-presence/seo/ (APPLY-MANIFEST.md) is now applied on top of Phase 17's head:
- Static files copied to public/: robots.txt, sitemap.xml (7 URLs — home, /mcp, 5 verified example reports; lastmod 2026-11-27 for home + reports, /mcp keeps 2026-11-26), llms.txt. Sitemap header comment updated from "STAGED, NOT APPLIED" to applied date.
- Root layout (src/app/layout.tsx): metadataBase https://git-secure.com, canonical "/", openGraph + twitter (card "summary", no og:image — public/og.png does not exist yet, per manifest item 0), both JSON-LD blocks inlined verbatim from the staged files (SoftwareApplication + WebSite), rendered in the body.
- Per-report metadata (src/app/[owner]/[repo]/page.tsx): generateMetadata with the page's own validateOwnerRepo; per-repo title + canonical; no score/grade (computed live after render).
- Copy fix in the same change (audit item 6): home MCP copy said "three tools" — now "four tools" with resume_scan listed (live tools/list returns four).
- Verified locally first against a fresh production server (build exit 0; robots 200 + Sitemap pointer, sitemap 200 + 7 urls, llms 200, home canonical + OG + Twitter + 2 JSON-LD parsing OK, no og:image, report title + canonical per-repo, home/report 200, "four tools" present). Lesson from this apply: killing `npm start`'s wrapper PID leaves the child next-server on :3000 — the first local check ran against that stale server (EADDRINUSE) and gave mixed results; kill the next-server itself (fuser -k 3000/tcp) and never rebuild under a running server.
- Still open, not part of this apply: public/og.png (1200×630, needed for summary_large_image + link previews); GitHub repo polish (description/homepage/topics — needs a suitably scoped token or doing by hand; the Contents-only push token 403s on it); Search Console submission + re-running the audit searches after a few days.

## Phase 2 status — built and pushed 2026-11-25, commit 870f889f, live at https://gitsecure.vercel.app/ (verified serving: home 200, live TechDirect scan 200, 83/B)
- Next.js 16 / React 19 / TypeScript + Auth.js (NextAuth 5.0.0-beta.32,
  GitHub provider), in ~/workspace/gitsecure/.
- `npm run build` passes (exit 0, 2026-11-25 ~20:50 MST). Routes:
  `/`, `/[owner]/[repo]`, `/api/scan/[owner]/[repo]`,
  `/api/auth/[...nextauth]` (signin / callback / signout / session).
- **1. Full-history scanning** (`src/lib/history.ts`): ephemeral
  `git clone --no-checkout --single-branch` to a fresh mkdtemp dir under
  `/tmp`, streams `git log -p --all` (newest-first) through the same
  detectors as HEAD, added lines only, redacted fragments only, clone dir
  deleted afterwards. Caps: 1000 commits / 50 MB of patches / 45 s, stated
  in every report's `limits`. Measured on Squ1zM0/TechDirect: 62 commits,
  40.8 MB of patches, log generated 0.7 s, detector scan of 23.4 MB of
  added lines 0.7 s, clone ~10 s, history step 6–12 s. Whole TechDirect
  scan ~15 s (was 71.5 s before the HEAD fetch was parallelised 10-way
  and the clone was started concurrently — both changes are in Phase 2,
  and are what keep a full scan inside the 60 s route limit). If git is
  missing from the runtime or the clone fails, the scan falls back to the
  MVP API patches (5 most recent commits) and says so.
  Regression test (`npm run test:history`, 9 checks): fake webhook planted
  in an old commit of a throwaway local repo, removed from HEAD — found,
  attributed to the right commit, redacted, temp dirs cleaned up.
  Live AIoN regression could NOT be re-run: SqulzMD/aion-index now 404s
  (private or deleted) as of 2026-11-25.
- **2. Tier 2 frameworks** (`src/lib/frameworks.ts`): Go (Gin/Echo/Fiber/Chi
  via go.mod), Ruby (Rails/Sinatra via Gemfile + Gemfile.lock, lockfile
  wins), PHP (Laravel/Symfony/WordPress via composer.json + composer.lock,
  plus wp-config.php detection with unknown version), Java/Kotlin (Spring
  Boot / Spring Framework / Kotlin via pom.xml incl. `${prop}` resolution
  and parent POM, plus build.gradle), .NET (ASP.NET Core via .csproj SDK +
  PackageReference; TargetFramework is NOT treated as a version).
  OSV ecosystems added: Go, RubyGems, Packagist, Maven, NuGet. Fixtures in
  tests/fixtures/fake-repo-tier2/ (go.mod, Gemfile + lock, composer.json +
  lock, pom.xml, build.gradle, app.csproj, wp-config.php); 14 new checks
  in test-scanner.ts (48 total, was 34 — the "31" in the old MVP note was
  a stale count).
- **3. OSV detail** (`src/lib/osv.ts`): full advisory detail (summary,
  CVSS, fixed version) now fetched for ALL advisories found, up to 50 per
  scan in batches of 8 (was: first 12); up to 100 advisories listed per
  scan; beyond-50 advisories listed with ID + osv.dev link and the report
  says how many were detail-capped.
- **4. GitHub OAuth owner gate** (`src/lib/auth.ts`, `src/lib/owner.ts`):
  real Auth.js with the GitHub provider; session carries the GitHub login
  from the OAuth profile; a matching login gets the full report, everyone
  else gets public only; `GITSECURE_OWNER_MODE=true` remains as local/dev
  fallback. Credentials live only in env vars (GITHUB_ID, GITHUB_SECRET,
  NEXTAUTH_SECRET, NEXTAUTH_URL) — none hardcoded anywhere (checked by
  test). Production default is safe: no env vars → auth routes answer 503
  "not configured", `canViewFull` never calls auth(), full view stays off,
  zero Auth.js errors logged. Gate logic tested with session mocks
  (`npm run test:owner-gate`, 20 checks). **REMOVED IN PHASE 4 (Freddy,
  2026-11-25): the whole gate is deleted — no OAuth App, no sign-in, no
  owner mode. Everyone gets the full report because the site only scans
  public repos. The historical record above is what Phase 2 built; it no
  longer exists in the code.**
- Live test (`npm run test:techdirect`, Squ1zM0/TechDirect): score 83,
  grade B — UNCHANGED from MVP (0 secrets, 4 vulns, all js-yaml 4.1.1 low
  with fixed versions, 0 frameworks, 2 deps, 3 posture issues, 250 of
  2,802 files). What changed legitimately: historyCommitsScanned 5 → 62
  (full history now), total scan ~15 s. Public JSON saved to
  test-results/techdirect-public-phase2-2026-11-25.json (MVP file kept).
- Production-server smoke test (local `next start`, no env vars):
  `/api/auth/session` → 503 clean "not configured" JSON; home → 200;
  report page → 200 (public view); 0 Auth.js errors in the log. Scan API
  for Squ1zM0/GitSecure → public JSON in 3.7 s, 2 history commits.
- Dogfooding: scanning Squ1zM0/GitSecure itself returns 1 / F with 6
  secret findings — all known-fake (test fixtures that are deliberate
  detector bait, plus the official AWS example key in an old README
  commit, 92c3a49). No real secret. Documented in README.md; the scanner
  deliberately does not skip test files. (Was 3 / F in the MVP-era note,
  then 0 / F after the Phase 2 push added package-lock.json — 119 deps
  fingerprinted — Tier 2 fixtures and a fake vite.config.ts. It is 1 / F
  now: deductions 76 + 19 + 4 = 99. The 0 / F was measured at remote
  d6a7e136; the Phase 3 push (5d8da890) changed the repo's contents and
  the unpinned count. The 6 secret findings are unchanged; the change is
  in the repo's contents, not the scanner. Re-verified 2026-11-25 in
  Phase 4.)
- History caps remain (1000 commits / 50 MB / 45 s) — a secret in a very
  old commit of a huge repo can still be missed, and the report says so
  when a cap hits. (The OAuth item above was removed in Phase 4.)
  [Phase 2 record — superseded in Phase 8, which removed the history
  caps entirely: history now runs to the oldest commit.]
- Next steps: push Phase 2 to Squ1zM0/GitSecure (main), deploy to Vercel.
  (The OAuth App step is gone — Phase 4 removed the gate entirely.)

## MVP status — built 2026-11-25, local only, NOT pushed, NOT deployed
- Next.js 16 / React 19 / TypeScript, App Router, in ~/workspace/gitsecure/.
- `npm run build` passes (exit 0, 2026-11-25 ~20:09 MST). See README for routes.
- Fixture test (`npm run test:scanner`): 31 checks pass — all 8 planted FAKE
  secret types detected, redaction verified (no full fake secret in output),
  Next.js 14.2.5 / React / Vite / Django / Serde fingerprinted, unpinned
  express flagged, public report leaks no file/line/fragment/framework names.
- Live test (`npm run test:techdirect`, Squ1zM0/TechDirect): score 83, grade B;
  0 secrets, 4 vulns (all js-yaml 4.1.1, low, fixed versions listed), 0
  frameworks (correct — TechDirect is a data repo, only js-yaml dev dep),
  2 deps, 3 posture issues, 250 of 2,802 files scanned, 5 history commits.
  Public JSON saved to test-results/techdirect-public-2026-11-25.json.
- Public-vs-owner split verified live on the production server: without owner
  mode, `/api/scan/...?full=1` returns kind "public"; with
  GITSECURE_OWNER_MODE=true it returns kind "full" with detail.
- STUBBED: GitHub OAuth owner verification (env-gated local/dev owner mode
  only, no bypass, no fake OAuth). History depth: HEAD + patches of the 5
  most recent commits only — full-history clone scanning is V2.
- Next steps: push to Squ1zM0/GitSecure (repo is empty, main), then deploy
  to Vercel (free tier), then set the git-secure.com domain — domain NOT
  purchased.
- NOTE: the push + deploy above are DONE (see Decisions at top). The MVP
  record above is historical — Phase 2 supersedes it; see "Phase 2 status".
