# Phase 21 design: frictionless on the existing infrastructure

Freddy, 2026-11-28: "Stick to the existing infrastructure get creative
if you have to, but make it happen please." No new host. Vercel
serverless plus Upstash only. Goal: thousands of concurrent users,
no API ceiling, no login, no waiting, no 429.

## Outcome (integration, 2026-11-28)

Workstream A as designed here was WRONG on its central premise and
was reverted during integration. The design said "the scan never
covers more than the newest 1000 commits anyway (the existing
cap)"; that is false for the git path. Phase 8 deliberately removed
the 1000 cap on the git path, proven by the 1005-commit test in
test-history.ts, and `depth: MAX_HISTORY_COMMITS` capped it at 1000,
breaking 3 tests including one that misattributed a finding to the
wrong commit. Measured: depth-1000 fixed DefinitelyTyped's pack
(69.9 MB, under the 150 MB bound) but the log parse still took
~47.7 min on this VM and the chunk scanned 0 commits; torvalds/linux
still fails to clone outright (ECONNRESET at ~6.5 s, and depth-1
alone already exceeds 150 MB). So depth bought nothing in practice
and regressed coverage. Reverted. What shipped instead: the loop
fix (a failed chunk advances its cursor to assemble instead of
throwing with no cursor) and workstream B's compare pre-filter
(about 14 calls for a clean 1000-commit scan), which is what
actually covers huge repos. Measurements preserved in
test-results/phase21/measurements/measurements.md.

## The problem, restated with the code behind it

The scan already avoids the API on the happy path. History runs
through isomorphic-git, a pure JavaScript git client, and the live
TechDirect scan proves it (62 commits, git protocol, zero API
calls). The quota burns only when the clone fails and the scan falls
through to the API path at about one call per commit.

Why the clone fails, from the code (`src/lib/history.ts`):

- The clone is `singleBranch: true, noCheckout: true` but with NO
  depth: it downloads the full history pack. `PACK_MAX_BYTES` is
  150 MB, so any repo whose pack exceeds that fails the clone by
  design (`PackTooLargeError`) and falls to the API path.
- isomorphic-git buffers the whole pack in memory before writing
  it, so the bound exists to keep a 1 GB function from OOM-crashing.
- The clone sits outside the 30 s walk budget
  (`GIT_HISTORY_CHUNK_BUDGET_MS`) and aborts at the route deadline
  (45 s history timeout, 60 s route ceiling). A slow clone is the
  one part of the chunk no budget reaches.
- The no-progress loop (flagged since Phase 18): a chunk timing out
  inside the clone persists no progress and retries forever with a
  byte-identical cursor. The chunk handler does fall back to the API
  path when the git path returns not-ok (`src/lib/chunks.ts`), so
  the loop bites when the API path is ALSO unavailable, which at
  scale means rate-limited. Fixing the clone and the API cost both
  attack the loop.

## Workstream A: make the git path hold (shallow clone)

Add `depth: MAX_HISTORY_COMMITS` (1000) to the isomorphic-git clone
in `scanHistoryViaGit`. The scan never covers more than the newest
1000 commits anyway (the existing cap), so a depth-1000 clone loses
nothing and the pack shrinks to what the scan actually reads.

- Verify against the installed isomorphic-git version that `clone`
  accepts `depth` with `singleBranch` (it should; prove it, do not
  assume).
- Measure before and after on the repos that fail today: clone time
  and pack bytes for torvalds/linux and DefinitelyTyped, plus a
  mid-size repo. The win is the clone fitting inside the chunk
  budget and under the 150 MB pack bound.
- If depth-1000 Linux still exceeds 150 MB, report it honestly:
  the compare pre-filter (workstream B) covers it, and the bound
  stays, because the pack is buffered in memory and the function is
  1 GB.
- Resume must still work: the chunk protocol resumes after a SHA,
  and the resume SHA is always inside the newest 1000, so depth
  1000 is consistent with the cap. Prove it with a multi-chunk
  resume test, not by reasoning.
- Fix the no-progress loop at its root: dig into the exact
  mechanism (chunk handler, driver retry, cursor encoding) and make
  a timed-out clone advance the cursor through the API fallback
  instead of retrying byte-identical. If the API path is also
  unavailable, the chunk must surface an honest, non-retryable
  error with the reset time, not a retryable identical cursor.

## Workstream B: make the API fallback cheap (compare pre-filter)

`scanHistoryApiChunk` currently fetches each commit's patch
individually (1 call per commit). Replace it with compare windows
as a pre-filter:

- One compare call per 250 commits (`/repos/{owner}/{repo}/
  compare/{base}...{head}`) returns the window's aggregate diff.
- Scan the aggregate diff for secret patterns. Most windows have
  no hits and cost exactly 1 call.
- Only for a window with a hit, fetch the individual commit patches
  in that window to attribute each finding to its exact commit.
  Attribution is preserved exactly; the per-commit fetch is the
  confirmation step, not the search step.
- Keep the per-commit path for windows where compare truncates the
  diff.

Verify the compare response shape live before building on it (the
`files[].patch` fields must match the per-commit endpoint's shape).
Expected cost: a 1,000-commit repo drops from about 1,010 calls to
about 5 plus attribution calls for windows with hits. Since secrets
are rare, the expected cost collapses. The token then covers
roughly 1,000 big-repo scans an hour instead of 5.

## Workstream C: tests and verification

- New tests: shallow clone respects depth and returns identical
  findings to a full clone on a fixture; compare pre-filter
  preserves attribution and the call count; resume across chunks
  with a depth-bounded clone; the no-progress loop case (a chunk
  that times out in the clone advances instead of retrying
  identical).
- Extend the existing suites where they touch history
  (test-history, test-history-git, test-zero-rest, test-techdirect).
  No change to the map, scoring, or triage suites is expected; if
  one breaks, fix the product, not the test.
- Full offline suite green (same bar as every phase; the zero-rest
  quota caveat is handled as before, verifying the cross-check fact
  independently via a bare clone when the shared-IP quota blocks
  the REST call).
- Live verification: baselines unchanged (self-scan 100/A,
  TechDirect 73/C, MCP 62/62), plus big-repo proof: torvalds/linux
  and DefinitelyTyped completing via the git path with 0 API calls,
  and a forced-API-fallback scan showing the reduced call count.

## Explicitly out of scope

- Report or commit-findings caching in Upstash. It changes the
  promise that finished reports are never stored, so it needs
  Freddy's word on its own. Name it in the final report, do not
  build it.
- Moving the scan worker to a host. Freddy ruled it out in this
  turn.
- Live-progress streaming (Phase 19 follow-up). Separate item.

## Verification bar (same as every phase)

tsc exit 0, build exit 0, full offline suite green, secret-pattern
grep clean, zero em dashes in changed app copy, live baselines
unchanged plus the big-repo proof above, docs push (GITSECURE.md
plus MEMORY.md), final report to Freddy with the honest residuals.
