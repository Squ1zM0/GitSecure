# Security Policy

## What GitSecure is

GitSecure scans a public GitHub repository and reports on its security:
leaked secrets, known flaws in the frameworks and dependencies it uses,
and security-posture gaps (missing SECURITY.md, no Dependabot, risky
workflow patterns, and similar). It only scans public repos, it never
shows a secret in full (redacted fragments only), and it never stores
a report or a secret - every scan is fresh.

## How to report a vulnerability

If you find a security problem in GitSecure itself - the scanner, the
website, or this repository - please report it by email:

**motdhvacr@gmail.com**

Please include:

- What the problem is, in plain words, and what an attacker could do with it.
- Where it is (file, route, or scan input that triggers it).
- Steps to reproduce it, if you have them.
- Whether you believe it is already being exploited.

Please do not open a public GitHub issue for a vulnerability, and do not
try to prove it by accessing other people's data, running a scan that
hammers GitHub's API, or live-validating a credential you find in a
report. A report that stays in email until it is fixed protects everyone
who uses the tool.

## What to expect

- **Acknowledgement within 3 business days.** You will hear back that
  the report was received and whether it looks like a real issue.
- **A fix, or a plan for one, within 30 days** for anything that puts
  users or scanned repos at real risk. Lower-severity issues are fixed
  in the normal development flow and the reporter is told when the fix
  ships.
- **Credit if you want it.** Say so in your report and you will be
  credited in the fix notes; say nothing and you stay anonymous.
- **No bounty program.** GitSecure is a small solo project and does not
  pay bounties. Reports are still welcome and still answered.

## Scope

In scope:

- The GitSecure scanner (`src/lib/`), the website (`src/app/`), and the
  MCP server (`src/app/mcp/`, `src/app/api/mcp/`).
- The deployed site at gitsecure.vercel.app.
- Anything in this repository that would let an attacker see a full
  secret, store one, validate one against a live service, or scan a
  private repo without the owner's consent.

Out of scope:

- Vulnerabilities in the repositories GitSecure *scans* - those belong
  to the owner of that repo, not to this project. (GitSecure reports
  them; it does not fix them.)
- Findings in GitSecure's own test fixtures (`tests/fixtures/`) - those
  files deliberately contain fake secrets and old, vulnerable versions
  so the scanner's detection can be tested. They are placeholders, not
  real credentials, and the old versions are kept on purpose.
- Rate limits, timeouts, or incomplete scans on very large repos -
  those are known limits, stated in the scan report, not vulnerabilities.
- Reports that need a GitHub token, a Vercel login, or access to
  someone else's account to reproduce.

## Safe harbor

Good-faith security research on GitSecure, reported through the email
above and kept private until fixed, will not be treated as abuse.
Do not access, modify, or delete data that is not yours, do not disrupt
the live site for other users, and do not publish details before a fix
is available.
