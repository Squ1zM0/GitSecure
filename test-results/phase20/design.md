# Phase 20 design - wider CI plus the next three categories

Approved by Freddy 2026-11-27 11:11 AM MST, as planned in chat. Cobalt
orchestrates directly, no coordinator, no recheck rounds. Budget: under
an hour, one verification pass.

## Why

Phase 19 added CI, but only GitHub Actions, six checks. Every other CI
system is unchecked, and the deeper Actions risks (artifact and cache
poisoning, reusable workflow trust, OIDC, self-hosted runners) are not
covered. This phase closes that gap and adds the next three code
categories.

## New checks

### 1. CI everywhere (new src/lib/ci-risks.ts, category "ci")

One scanner, file path dispatch, line based like code-risks.ts.
GitLab CI (.gitlab-ci.yml), CircleCI (.circleci/config.yml),
Azure Pipelines (azure-pipelines.yml, azure-pipelines*.yml),
Bitbucket Pipelines (bitbucket-pipelines.yml), Jenkins
(Jenkinsfile, *.jenkinsfile, Jenkinsfile.*).

Shared checks, every system:
- curl or wget piped straight into a shell in a script step (high).
- A secret echoed into logs (echo of a CI secret variable or a
  masked variable, high).
- A container image with no tag or :latest (medium).
- An unpinned external reference (GitLab include: from a remote URL
  with no pinned ref, CircleCI orb with no version, Azure template
  with no ref, Jenkins shared library with no version, medium).
- A user-controlled value interpolated into a script step
  (merge request variables, trigger payloads, high). System
  variables that the pipeline itself sets are not flagged.

Jenkins only: `sh` with a GString interpolating params or env
(high, same shape as script injection).

### 2. Deeper GitHub Actions (extend buildPosture in scan.ts, category "actions")

- Artifact poisoning: actions/download-artifact in a workflow that
  triggers on pull_request (medium).
- Cache poisoning: actions/cache with a key containing a PR
  controlled value (github.event.pull_request, github.head_ref)
  (high).
- Reusable workflow trust: uses of another owner's reusable
  workflow pinned to a branch or tag instead of a full SHA (medium).
- Self-hosted runner: runs-on self-hosted (medium).
- NOT added as separate checks because Phase 19 already covers
  them: workflow_dispatch inputs interpolated in a run: block are
  caught by actions-script-injection, and a static cloud key handed
  to a third-party action is caught by actions-secret-third-party
  (or by the secret detectors when it is hardcoded).

### 3. TLS and network (extend RULES in code-risks.ts, category "tls")

- Certificate validation disabled: rejectUnauthorized false (JS),
  verify False (Python), InsecureSkipVerify true (Go),
  ssl._create_unverified_context (Python) (high).
- Plain HTTP in a client call (fetch, axios, requests, http.Get)
  to a non-local host (medium). localhost and 127.0.0.1 are clean.
- Weak TLS: PROTOCOL_TLSv1, TLSv1_0, TLSv1_1, ssl.PROTOCOL_SSLv23
  without a minimum version (medium).

### 4. Secrets in logs and errors (extend RULES, category "logging")

- Logging a value whose name says secret, password, token, apiKey,
  or credential (medium).
- Sending an error or stack trace back in an HTTP response
  (res.send(err), res.status(500).send(err), raise with traceback
  in a response body) (medium).
- Debug mode on: Flask debug=True, Django DEBUG = True,
  app.debug = True (medium).

### 5. Frontend XSS sinks (extend RULES, category "xss")

- dangerouslySetInnerHTML with a tainted value (high).
- innerHTML assigned a tainted value (high).
- document.write with a tainted value (high).
- eval with a tainted value (high).
Same taint rule as Phase 19: a sink with only a constant string is
never a finding.

## Scoring, map, copy

Scoring reuses the existing deduction scale (score.ts sums posture
by severity), so no score change. New map categories "ci", "tls",
"xss", "logging" get entries in MAP_CATEGORY_META, MAP_CATEGORY_ORDER,
and POSTURE_CATEGORIES, plus the types.ts union. New findings are
nodes on the plane like Phase 19. Copy rule stands: findings say
what is wrong, where, and the fix, in one or two short sentences.

## Verification (one pass)

- New suite scripts/test-phase20.ts: planted hit plus clean case
  for every new check, fixtures assembled from fragments so no
  literal sink plus tainted input sits in the file.
- Full offline suite green plus tsc plus build exit 0, no test
  skipped. If it is red on a small obvious fix, fix once; if it
  is bigger, cut the check and say so.
- Live proof on a real repo for the CI checks (a repo with a
  .gitlab-ci.yml or CircleCI config that trips one), plus live
  baselines re-measured (TechDirect, self-scan).

## Out of scope

Branch protection and repo settings (token is Contents read only).
Paid features (stays free). The live file-count progress fix stays
its own follow-up (design in test-results/phase19/
live-progress-next-phase.md). The history chunk no-progress loop
stays its own pipeline fix.
