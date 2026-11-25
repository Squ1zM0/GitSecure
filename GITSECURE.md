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
- Report visibility: FULL detail only for the repo owner; everyone else gets
  just the score and counts. This is a hard design rule for the MVP.
- PHASE 3 DONE 2026-11-25: plain/fluid human flow (loading state, input
  validation, honest API statuses, plain-English pass, mobile 360px clean)
  + MCP server for LLMs (see "Phase 3" sections below). Pushed as
  1a0387ea7b16530383059047aaa8cbcb4a70dd31 (59 files), verified by read-back
  and live: home 200 with the MCP section, live scan API 83/B, live MCP
  initialize 200 (gitsecure 0.1.0) and tools/list returns exactly
  scan_repo, get_report, list_checks.
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
2. DONE: full detail owner-only; public gets score + counts.
3. OPEN: Launch: free side tool, or later paid monitoring / alerts / badge?
   (Not a blocker for the MVP — build free.)

## Phases
- MVP: secret scan (HEAD + history), framework fingerprint + known-flaw check,
  redacted report, security score.
- **Phase 2 (built and pushed 2026-11-25, commit 870f889f, live on Vercel):**
  full-history clone scanning, Tier 2 frameworks (Go/Ruby/PHP/Java/.NET),
  full OSV advisory detail, real GitHub OAuth owner gate (code complete,
  credentials pending — see below). Details in "Phase 2 status". LIVE
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
  fragments.
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
  (`npm run test:owner-gate`, 20 checks). **STILL PENDING: live OAuth
  credentials** — Freddy must create the GitHub OAuth App (callback
  https://gitsecure.vercel.app/api/auth/callback/github) and set the four
  env vars in Vercel; exact steps in README.md. Live sign-in untested
  until then.
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
- Dogfooding: scanning Squ1zM0/GitSecure itself returns 0 / F with 6
  secret findings — all known-fake (test fixtures that are deliberate
  detector bait, plus the official AWS example key in an old README
  commit, 92c3a49). No real secret. Documented in README.md; the scanner
  deliberately does not skip test files. (Was 3 / F in the MVP-era note;
  the Phase 2 push added package-lock.json — 119 deps fingerprinted —
  Tier 2 fixtures and a fake vite.config.ts, which add framework,
  dependency and Vite posture deductions plus unpinned deductions. The 6
  secret findings are unchanged; the change is in the repo's contents,
  not the scanner. Re-verified 2026-11-25 during Phase 3 Part B.)
- STUBBED / STILL PENDING: live OAuth credentials (above). History caps
  remain (1000 commits / 50 MB / 45 s) — a secret in a very old commit of
  a huge repo can still be missed, and the report says so when a cap hits.
- Next steps: push Phase 2 to Squ1zM0/GitSecure (main), deploy to Vercel,
  then Freddy creates the OAuth App + sets the four env vars to switch
  the full view on for owners.

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
