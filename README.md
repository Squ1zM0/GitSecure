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
  passwords. Checked in current files **and** in recent history.
- **Frameworks (Tier 1)** — JS/TS (Next.js, React, Vue, Angular, Svelte, Vite,
  Express, Nest, Nuxt, Astro), Python (Django, Flask, FastAPI), Rust (Cargo /
  RustSec via OSV). Versions come from lockfiles where possible; unpinned (`*` /
  `latest`) versions are flagged; if a version cannot be determined, the report
  says so instead of guessing. Vite specifics: dev-server exposure, SSR, and
  `VITE_` variables leaking into the client bundle.
- **Dependency flaws** — known vulnerabilities in direct and transitive
  dependencies, checked against [OSV.dev](https://osv.dev) (npm / PyPI /
  crates.io), with the version that fixes each one.
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

## Routes

- `/` — home page, explains GitSecure, owner/repo input.
- `/[owner]/[repo]` — scan report for a public repo (public view by default).
- `/api/scan/[owner]/[repo]` — JSON report. `?full=1` returns the full report
  only when owner mode is enabled; otherwise it returns the public report.

## Owner verification (stub — read this)

Full GitHub OAuth owner verification is **not built yet**. The full report is
only served when the server-side env var `GITSECURE_OWNER_MODE` is `"true"`
(local/dev use: `GITSECURE_OWNER_MODE=true npm run dev`). There is no
query-param bypass, no hardcoded owner, and no fake OAuth flow. In production
(env unset) every request gets the public report only. Building real OAuth
owner verification is the first post-MVP step — do not deploy the full view
publicly until it exists.

## Honest limits (MVP)

- **History depth:** HEAD tree + patches of the **5 most recent commits**
  (commits list: last 50). A secret buried in an old commit will **not** be
  caught yet. Full-history scanning (e.g. via a local clone) is a V2 item.
- **HEAD limits:** max 250 files, 200 KB per file, 3 MB total; binary, `dist`,
  `node_modules` and `.next` skipped. Manifests and configs are scanned first.
- **Dependency check:** up to 60 pinned dependencies per scan via OSV.dev; if
  OSV is unreachable the scan continues and says so.
- **Rate limits:** unauthenticated GitHub API is 60 requests/hour. A scan uses
  roughly 7 API calls plus raw file fetches.
- GitSecure is **not a replacement for GitHub Advanced Security**.

## Tests

```bash
npm run test:scanner     # synthetic fixture with FAKE planted secrets only
                         # (tests/fixtures/fake-repo) — checks detection,
                         # redaction, fingerprinting, and the public/full split
npm run test:techdirect  # live scan of the real public repo Squ1zM0/TechDirect
```

The fixture uses invented credentials only (including the official AWS example
key `AKIAIOSFODNN7EXAMPLE`). Never put a real leaked secret in a test.

## Tech

Next.js 16 (App Router) + TypeScript + React 19. No paid services, no external
database. Deployable on the Vercel free tier.

## Project notes

Full spec and decisions: `GITSECURE.md`. Repo: https://github.com/Squ1zM0/GitSecure
(public, main). Domain: git-secure.com (not purchased — do not buy without a
separate explicit go-ahead; start on a Vercel subdomain).
