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
- **Phase 2 (built 2026-11-25, local only, NOT pushed, NOT deployed):**
  full-history clone scanning, Tier 2 frameworks (Go/Ruby/PHP/Java/.NET),
  full OSV advisory detail, real GitHub OAuth owner gate (code complete,
  credentials pending — see below). Details in "Phase 2 status".
- V1: + dependencies, workflows, posture checks.
- V2: stack watch / alerts, GitHub App, private repos, CI badge.

## Phase 2 status — built 2026-11-25, local only, NOT pushed, NOT deployed
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
- Dogfooding: scanning Squ1zM0/GitSecure itself returns 3 / F with 6
  secret findings — all known-fake (test fixtures that are deliberate
  detector bait, plus the official AWS example key in an old README
  commit, 92c3a49). No real secret. Documented in README.md; the scanner
  deliberately does not skip test files.
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
