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
  (https://gitsecure.vercel.app/mcp) plus copyable config snippets for
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
  that local server (NOT pushed, NOT deployed): scan API 200 in ~19 s,
  report page 200 with the dial and "About this scan", bogus job ID
  404 `job-not-found`. No literal secret-pattern values committed
  (grep-verified; fixtures still use `__SECRET_n__` placeholders).
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
  reviewed only. NOT pushed, NOT deployed — the push worker owns that.

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
