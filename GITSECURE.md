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
  not a Phase 2 blocker.
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
  "Scan limits" section, `src/lib/scan.ts` header).
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
  unchanged (1,000 commits / 50 MB / 45 s).
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
- **Pushed 2026-11-25, commit [SHA — filled after push].**
- **Live verification (2026-11-25, after push):** [filled after push —
  home 200, TechDirect API 83/B, DefinitelyTyped API secrets count /
  filesScanned / 0/F with full list, DT report page navigation, live
  MCP initialize].

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
