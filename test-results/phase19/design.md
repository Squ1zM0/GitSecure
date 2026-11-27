# Phase 19 design - bigger security checks

Freddy, 2026-11-27: continue development on the app. The security checks are a good
starting point, but security is much bigger than what we have now. Give users a better
idea of how safe a repo is. Two standing rules for this phase: no em dashes anywhere
in the app, and do not restate the obvious in copy.

## Current coverage (audited 2026-11-27, live head 0a60fcd7)

- Secrets: 21 detectors (Anthropic, AWS access key, AWS secret key, database URL,
  Discord webhook, generic high entropy, GitHub token, GitLab token, Google API key,
  hardcoded password, Hugging Face, JWT, npm, OpenAI, private key, PyPI, SendGrid,
  Slack token, Slack webhook, Stripe secret key, Telegram bot token). HEAD + history,
  triaged, usage analysis, redacted fragments only.
- Dependency flaws: OSV.dev, direct + transitive, lockfile pinned versions win,
  unpinned flagged unknown.
- Framework fingerprinting: Tier 1 (JS/TS + Vite, Python, Rust), Tier 2 (Go, Ruby,
  PHP, Java, .NET), Tier 3 (Docker, K8s, Terraform, GitHub Actions, Vercel,
  Supabase).
- Posture: no SECURITY.md (low), no Dependabot (low), no .gitignore (medium),
  .gitignore gaps (medium), .env committed (high), curl pipe to shell (high),
  Dockerfile ENV secrets (high), K8s hostIPC / allowPrivilegeEscalation (high),
  Compose privileged / host networking (high), risky GitHub Actions patterns
  (pull_request_target, write-all permissions, secrets echoed into logs).
- Score 0-100 with triage weights (test-key 0, uncertain 0.5, genuine 1) and a
  wouldBeScore shown alongside. Baselines: TechDirect 83/B, self-scan 100/A,
  awesome-python 91/A.

## What is missing

A user reading a report today learns about leaked secrets, known bad
dependencies, and a handful of config gaps. They learn nothing about the code
itself: whether it runs shell commands on untrusted input, builds SQL from
strings, deserializes untrusted data, or hashes passwords with MD5. They learn
nothing about whether the CI pipeline can be hijacked, whether the container
runs as root, whether install scripts run arbitrary code, or whether backup
files and database dumps are committed. Those are the gaps this phase closes.

## New categories

### 1. Dangerous code patterns (new src/lib/code-risks.ts, the flagship)

Language aware detectors over JS/TS, Python, Go, Ruby, Java, PHP. Each finding
carries file, line, severity, and a one or two sentence fix. No vague warnings.

- Command injection (high): `child_process.exec` / `execSync` / `spawn` with
  shell true and concatenated input, `os.system`, `os.popen`, `subprocess`
  with `shell=True`, `Runtime.exec`, PHP `shell_exec` / `passthru` on
  variables, Ruby backticks / `system` on interpolated strings.
- SQL injection (high): query strings built by concatenation or interpolation
  (`+`, template literals, f-strings, `%` formatting) passed to a query call.
- Unsafe deserialization (high): `pickle.loads` / `yaml.load` without
  SafeLoader, Java `ObjectInputStream.readObject`, PHP `unserialize`, Ruby
  `Marshal.load`, `JSON.parse` is fine and is never flagged.
- Weak crypto (medium): MD5 / SHA1 used for passwords, `Math.random` /
  `random.random` used for tokens or secrets, hardcoded IV, DES / RC4.
- Path traversal (medium): file paths built from user input without
  sanitizing `..` (`open(userPath)`, `readFile(req.params...)`,
  `path.join(base, userInput)`).
- SSRF sinks (medium): `fetch` / `requests.get` / `http.get` called with a
  URL built from user input.

Rules for the detectors: flag the sink plus the tainted input in the same
statement. A bare `exec(` with a constant string is not a finding. Test
fixtures must prove both the hit and the clean case.

### 2. GitHub Actions hardening (extend posture in scan.ts)

- Third party actions not pinned to a full commit SHA (high): `uses: foo/bar@v4`
  is a finding, `uses: foo/bar@abc123...` is clean. First party actions
  (`actions/*`, `github/*`) pinned to a major version are clean.
- `pull_request_target` combined with a checkout (high): code from a fork runs
  with repo secrets.
- Script injection (high): `${{ ... }}` interpolated inside a `run:` block.
- Secrets passed to third party actions (medium): `secrets.*` in a `with:`
  block of a non first party action.

### 3. Container hardening (extend infra.ts)

- Runs as root (medium): Dockerfile with no `USER` instruction, or
  `USER root`; K8s `runAsUser: 0` / `runAsNonRoot: false`.
- `ADD` with a remote URL (low): use `COPY` for local files, `curl` for
  remote ones, so the layer cache stays honest.
- `latest` tag (low): base image or Compose image pinned to `latest`.
- No HEALTHCHECK (low): Dockerfile with a long running service and no
  `HEALTHCHECK`.
- Capabilities (medium): `cap_add` with `SYS_ADMIN` / `ALL`, or
  `securityContext.capabilities.add` with the same.

### 4. Exposed files (extend scan.ts)

- Committed private keys, `.sql` dumps, `.bak` / `.orig` / `.swp` backup
  files, Terraform state (`.tfstate`), `.terraform` directories, committed
  SQLite / database files (`.sqlite`, `.db`). Severity high for keys and
  dumps, medium for the rest. `.env` committed already exists and stays.

### 5. Install script supply chain (extend scan.ts)

- `postinstall` / `preinstall` / `prepare` scripts in package.json (medium):
  arbitrary code runs on install. The finding names the script and its
  command. No finding when the scripts are absent or empty.

### 6. Web config (fold into code-risks.ts)

- CORS wide open (medium): `Access-Control-Allow-Origin: *` or
  `cors({ origin: "*" })` in server code.
- Cookies without flags (low): `Set-Cookie` without `HttpOnly`, `Secure`,
  `SameSite`.
- JWT `none` algorithm (high): `algorithms: ["none"]` or
  `algorithm: "none"`.

## Scoring

New findings feed the existing score through score.ts. Reuse the existing
deduction scale: high findings deduct like existing high findings, medium
like medium, low like low. No new weight invented without a reason in the
code. wouldBeScore keeps working alongside. Baselines get re-measured live
and reported honestly: TechDirect, self-scan, and awesome-python scores may
move if the new checks find real issues. A move is reported, never forced
back to the old number. The self-scan must stay 100/A by the detectors being
right, not by carving the repo out: if a new check fires on GitSecure itself,
fix the code or tune the detector, and say so in the report.

## Em dash sweep (standing rule, this phase)

Replace every U+2014 in the shipped app with a hyphen. Scope: everything
under src/, the shipped text files under public/ (robots.txt, llms.txt,
sitemap.xml), README.md, SECURITY.md, GITSECURE.md, the layout metadata and
JSON-LD, and the GitHub repo description (already set with an em dash, fix
it in the same pass). Regenerate public/og.png with a hyphen in its text.
Update every test expectation that asserts copy containing an em dash, so the
suite stays green. Leave test-results/ alone: those are historical records,
not shipped copy. The title becomes "GitSecure - is this repo safe?".

## Copy rule (standing rule, this phase)

Findings say what is wrong, where, and the fix, in one or two short
sentences. No intro that restates the finding. No "This check looks for..."
lines. No filler sentences that add nothing a user could act on. Apply to
all new copy and trim the worst offenders in existing copy while touching
those files anyway. Do not cut disclaimers (the Advanced Security line, the
"never stored after the scan finishes" line) or anything the user needs to
trust the result.

## Map representation (added 2026-11-27, Freddy: the new checks need some sort
of official representation like the map, or on the map, and the map should improve)

The new categories are not list-only. They render on the dynamic visual plane
alongside secrets, so the map is the official picture of the whole report.

- Every new finding is a node on the plane, grouped by category: code risks,
  Actions hardening, container hardening, exposed files, install scripts, web
  config, plus the existing secrets. Nodes carry the category (label or shape,
  not color alone) and the severity. A legend on the plane explains the
  categories.
- Edges: code risk nodes link to the file they are in ("found in"); posture
  nodes link to the file they come from (workflow file, Dockerfile,
  package.json); the existing usage edges (used in code, used in tests,
  lives in) stay for secrets. Every edge stays labelled and clickable with
  a plain English detail.
- Category filter: toggles on the plane show or hide each category. Filtering
  never changes the report counts, only what the plane shows.
- Rendering caps: the current caps (12 findings, 24 nodes) hide too much once
  six categories exist. Raise them and keep the cap label honest, or cluster
  by category with counts. The cap is stated on the plane either way.
- Existing interactions stay: pan, wheel and pinch zoom, +/- and reset
  buttons, click a node to centre and open its detail, pin nodes, drag nodes,
  traversal with breadcrumb, keyboard shortcuts, mobile first at 360px, dark
  mode, secrets fragment only.
- Verify the known cosmetic limitation from Phase 18 against the current
  code: labels landing on neighbouring nodes or captions. The second pass
  collision pass was built to fix it; the builder re-measures and fixes it
  if it is still present, and says so in the report either way.

## Verification

- Full offline suite green plus tsc, build exit 0, no test skipped.
- Fixture repo with planted findings for every new detector, plus a clean
  fixture proving the no-false-positive cases (constant string exec, JSON.parse,
  SHA pinned action, USER set, no install scripts).
- Live proof on a real vulnerable repo (OWASP NodeGoat or WrongSecrets):
  the new code checks must fire on real code, not only on fixtures.
- Live baselines re-measured and reported: TechDirect, self-scan (100/A or
  the honest reason it moved), awesome-python.
- Live verification of the em dash sweep: grep the served home HTML and a
  report page for U+2014, expect zero; og.png serves with the new text.
- Map verification headlessly against the local server: new category nodes
  render, filter toggles work, caps are labelled, existing interactions
  still pass. No real iPhone tap test is required for this phase; Freddy
  tap tested the map on 2026-11-27.
- Map, MCP, resume, and accumulation paths untouched unless a change forces
  it; if touched, their suites re-run.

## Out of scope

- Branch protection and repo settings: the token is Contents read only and
  cannot read them. Do not claim to check them. A future phase with a wider
  token could add them.
- The history chunk no-progress loop (chunk timing out inside git clone and
  retrying forever with an identical cursor). Still open, separate pipeline
  fix, not a security feature.
- Paid features. The tool stays free (Freddy, 2026-11-27).

## Outcome (2026-11-27, converge)

- Built as scoped. Three workers (code risks, posture, map) plus integration.
- Baselines: TechDirect 83/B to 73/C, honest move (real script injection in
  network-validation.yml, verified by hand). Self-scan 100/A, 39 secrets, all
  likely-test-key. Awesome-python not re-measured in this run; parent verifies.
- Em dash sweep done in shipped content (51 files, zero U+2014 left); GitHub
  repo description still has one (browser session dead, see report).
- Map worker closed before its recheck rounds finished; label-collision
  re-measurement not reported back. Open item, not a blocker.
- Hero copy fix: posture issues are no longer called "small" when a high
  exists (postureHigh threaded through ReportView, report-markdown, ScoreDial).
