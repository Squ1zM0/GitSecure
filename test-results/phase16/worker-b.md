# Phase 16 — Worker B: API ceiling-risk audit (other `runScanLoop` callers)

Date: 2026-11-26. Worker B scope only: every `runScanLoop` caller except
the report page (Worker A owns `src/app/[owner]/[repo]/page.tsx`, which
no longer awaits the loop at all — it renders the shell and the browser
drives chunks; that fix already landed in this tree while this audit ran).

## Verdict

**Yes, a single invocation could exceed ~55 s — confirmed by reasoning
and by measurement — so it was tightened.** The loop checked its deadline
only *after* each chunk returned, so a chunk that started at 49 s of a
50 s budget ran a full chunk past it. The fix threads the loop deadline
into every chunk (each chunk's own budgets are capped at the time left)
and refuses to *start* another chunk unless enough budget remains for
that chunk to land the invocation under ~55 s. The loop budget for the
API + MCP is cut 50 s → 40 s. The 202 + cursor contract is unchanged.

## 1. Callers found (complete grep of `src/`)

| Caller | Before | After |
|---|---|---|
| `GET /api/scan/[owner]/[repo]` (`src/app/api/scan/[owner]/[repo]/route.ts`) | `runScanLoop({ budgetMs: FAST_PATH_WAIT_MS })` = 50 s | `budgetMs: API_FAST_PATH_WAIT_MS` = **40 s** |
| MCP `scan_repo` / `get_report` (`src/lib/mcp.ts` `fullScan`) | 50 s | **40 s** |
| MCP `resume_scan` (`src/lib/mcp.ts` `resumeScan`) | 50 s | **40 s** |
| Report page | 50 s | **not a caller any more** (Worker A: shell + client-driven chunks) |

Not `runScanLoop` callers, therefore out of scope and unchanged
(no deadline passed, old fixed budgets apply): `POST /api/scan/chunk`
and `POST /api/scan/start` (Worker A's new route) — both drive exactly
one chunk via `advanceScan`. `GET /api/scan/[owner]/[repo]/tip` only
resolves the HEAD sha; no scan runs there. `FAST_PATH_WAIT_MS` (50 s)
is kept defined and unchanged — nothing in production imports it any
more; removing the export is Worker A's cleanup call, not this audit's.

## 2. Worst-case arithmetic (pre-fix)

`runScanLoop` set `deadline = now + budget` and checked it only after
each `advanceScan` returned. A chunk that started just before the
deadline ran to *its own* end, so:

```
total ≈ budget + (worst chunk started just before the deadline)
       + cold start (~1–3 s) + response serialisation
```

Per-chunk worst cases (read from `src/lib/scan.ts`, `src/lib/history.ts`,
`src/lib/osv.ts`, `src/lib/chunks.ts`):

- **HEAD chunk** (`scanHead`): `resolveRemoteHead` ≤ 12 s + tarball
  fetch abort 30 s (whole-buffer path) **or** streaming budget 50 s
  (+ 55 s abort timer, which used to be cleared once headers arrived,
  so a mid-body stall hung forever) + post-processing CPU over the
  retained files (unbounded, ~1–3 s typical). Worst ≈ 45–65 s alone.
- **Git history chunk** (`scanHistoryViaGit`, budget 30 s): the 30 s
  is the *walk* budget, measured from chunk start — but the clone (no
  timeout at all) + full `git.log` parse (no timeout) + the post-walk
  HEAD-usage corpus read (no timeout) all sit **outside** it.
- **API history chunk** (`scanHistoryApiChunk`): **no budget at all** —
  sequential, up to 12 fetches × 12 s abort = 144 s theoretical.
- **Assemble chunk**: `scanHead` again (≈ HEAD worst) + `fetchHeadSha`
  ≤ 12 s + `assembleReport` → OSV with `queryBudgetMs`/`detailBudgetMs`
  = null (unbounded; per-query 15 s abort, per-detail 8 s abort).

So with a 50 s budget a late chunk alone could add 30–60 s: total
80–110 s in theory, and live it was 52.8–63.6 s on
vinta/awesome-python with the stream cut at Vercel's 60 s ceiling
(`test-results/phase16/repro.md`).

## 3. Measurements (local VM — slow, conservative vs Vercel)

Pre-fix, live repos:

| Measurement | Result |
|---|---|
| TechDirect HEAD chunk (2,802 files) | 3.4–3.8 s |
| TechDirect git history chunk (62 commits) | 14.8 s |
| TechDirect `assembleReport` (OSV + build) | 1.7 s |
| awesome-python HEAD chunk (126 files) | 1.2 s |
| awesome-python git history chunk 1 | **39.9 s for 16 commits** — the 30 s walk budget fired, but clone + log parse had already eaten it |
| awesome-python clone / `git.log` (3,350 commits) / 16-commit blob reads, split | **11.6 s / 17.6 s / 0.2 s** — prefix P (clone + log) ≈ **29.2 s** |
| awesome-python history chunk 1, post-fix (no deadline passed) | 23.3 s for the full 200 commits (run-to-run clone variance; the pre-fix 39.9 s run was a slow clone) |

Post-fix, same repos, `runScanLoop` with the 40 s API budget:

| Measurement | Result |
|---|---|
| TechDirect full loop | **done in 20.4 s** — score 83, 2,802 files, 62 commits (fast path intact: 200 in one call) |
| awesome-python full loop | **partial in 32.2 s**, 200 commits scanned, cursor returned (pre-fix this invocation ran a second ~40 s chunk and was killed at 60 s) |

## 4. The fix (smallest + safest)

**`src/lib/chunks.ts`** — new constant `API_FAST_PATH_WAIT_MS = 40_000`
(API + MCP loop budget); `runScanLoop` passes its absolute `deadline`
into every chunk as new optional `deadlineMs` on `AdvanceInput`, and
does not start another chunk unless `budget − 21 s` remains once a
chunk has run and a cursor exists (the first chunk always runs — a
fresh scan must produce a cursor). Worst case for any budget is now
`budget − floor + ~32 s ≈ 53 s` (floor = `max(0, budget − 21 s)`).
At the 40 s production budget the floor is 19 s; TechDirect reaches
assemble with ~22 s left, so it still answers 200 in one call.

**`src/lib/chunks.ts` `advanceScan`** — threads the deadline:
git-history walk budget = `min(30 s, remaining)`; API-history chunk
gets `deadlineMs`; HEAD/`scanHead` gets `deadlineMs`; assemble passes
OSV budgets = remaining and `deadlineMs`. No deadline (chunk
endpoint, one-shot callers) keeps every old fixed value — behaviour
there is unchanged.

**`src/lib/scan.ts`** — new optional `ScanOptions.deadlineMs`:
`resolveRemoteHead` timeout `min(12 s, remaining)`; tarball download
abort `min(30 s, remaining)` (new `timeoutMs` param, default 30 s);
streaming budget = remaining, and its 55 s abort timer now stays
armed through the stream (capped at the caller's budget) instead of
being cleared after headers; per-file fallback budgets = remaining
(`fetchHeadFiles` gains a budget check; `fetchRaw` gains a timeout
param, default 10 s); whole-buffer parse loop throws the existing
timeout error every 256 files once past the deadline (the chunk
driver already turns that into a resumable head-stage partial);
`assembleReport` forwards `deadlineMs` to OSV.

**`src/lib/history.ts`** — `scanHistoryApiChunk` gains optional
`deadlineMs`: returns its unchanged position at once when no time is
left, checks before every fetch, and caps each fetch at the time
left. `scanHistoryViaGit` gains optional `deadlineMs`: the clone
aborts at the deadline via the git HTTP client's `AbortSignal`
(isomorphic-git's node client forwards `signal` — verified in
`node_modules/isomorphic-git/http/node/index.js`); the HEAD-usage
corpus read (`readHeadUsageCorpus`) gives up at the deadline and
returns null, so findings are triaged without usage exactly as when
the corpus is over its bounds.

**`src/lib/osv.ts`** — `checkDependencies` gains optional
`deadlineMs`: both phase deadlines are the earlier of their own
budget and the loop deadline, and each in-flight query/detail fetch
is capped at the time left (was a fixed 15 s / 8 s).

**Callers** — API route and both MCP tools pass
`API_FAST_PATH_WAIT_MS`. Response shapes, status codes, cursor
format, caps, scoring, and redaction are untouched.

### Residual risks (documented, not hidden)

- `git.log` parses the **whole** log per chunk with no abort
  (~5 ms/commit measured locally: 17.6 s for 3,350 commits). The
  clone abort caps the network half of the prefix, but a repo with a
  very large commit count and a pack under 150 MB could still push a
  chunk past the bound via log-parse alone. The bound as proven
  holds while the clone+log prefix P ≤ ~33 s (measured worst 29.2 s
  locally; Vercel runs faster). Follow-up if that ever binds:
  depth-paginated `git.log` — a history-semantics change, out of
  scope here.
- `scanHead` post-processing CPU (usage/triage/framework parsing
  over retained files, ≤ 100 MB retained) has no deadline check;
  measured ≤ ~2 s on the repos scanned. Deliberately left
  uninterruptible: throwing it away would discard a fully scanned
  HEAD that the loop can still return late-but-under-60 s.
- `fetchHeadSha` in the assemble chunk is one 12 s call with no
  deadline; it is inside the arithmetic (assemble worst ≈ 12 s +
  deadline-capped OSV ≈ 28 s from a ≥ 19 s start → ≤ ~48 s total).
- Single-chunk endpoints (`POST /api/scan/chunk`, `POST /api/scan/start`)
  pass no deadline, so one HEAD chunk on a giant repo can still
  approach the 60 s ceiling on its own — same exposure as before,
  needs its own deadline as a follow-up.

## 5. Files changed

- `src/lib/chunks.ts` — `API_FAST_PATH_WAIT_MS`, deadline threading,
  start floor in `runScanLoop`.
- `src/lib/scan.ts` — `ScanOptions.deadlineMs`, sub-step timeout
  caps, streaming-timer fix, parse-loop deadline check, assemble →
  OSV deadline.
- `src/lib/history.ts` — API-chunk deadline, clone abort, corpus
  deadline.
- `src/lib/osv.ts` — `deadlineMs` in `checkDependencies`.
- `src/lib/mcp.ts` — both tools use `API_FAST_PATH_WAIT_MS`.
- `src/app/api/scan/[owner]/[repo]/route.ts` — uses
  `API_FAST_PATH_WAIT_MS`.
- `package.json` — new `test:phase16-worker-b` script.
- `scripts/test-phase16-worker-b.ts` — new test (25 checks).
- `test-results/phase16/worker-b.md` — this file.

NOT changed: `src/app/[owner]/[repo]/page.tsx` (Worker A),
`src/app/api/scan/chunk/route.ts`, `src/app/api/scan/start/route.ts`,
`src/app/api/scan/[owner]/[repo]/tip/route.ts`, scan behaviour, caps,
scoring, redaction, API/MCP contracts. Nothing pushed.

## 6. Tests

New suite `npm run test:phase16-worker-b` — **25/25 PASS**:
budget arithmetic for 10/40/50 s budgets (worst 42/53/53 s ≤ 55 s);
slow API history mock (15 s/request): loop with a 2 s budget returns
partial + same-position cursor in **2,006 ms** (pre-fix: 12 s + 12 s
of per-fetch aborts, then threw); API-chunk deadline units (past
deadline: 0–1 ms, same position, never failed); slow git clone mock
(30 s stalled `git-upload-pack`): loop returns partial + cursor in
**2,014 ms** (pre-fix: waited out the 30 s clone, no timeout on it);
fast path still completes end to end (stubbed 1-file tarball + fast
mock API: done in 1,258 ms, 1 file + 1 commit); contract/source
checks (route 202 + `running` shape, MCP both tools, page untouched
by Worker B).

Existing suites (same tree, after the change):

| Suite | Result |
|---|---|
| `test:cursor-phase9` | **192 PASS, 0 FAIL** |
| `test:resilience-phase15` | **47 PASS, 0 FAIL** |
| `test:history` | **70 PASS, 0 FAIL** |
| `test:mcp` | **62 PASS, 0 FAIL** (one earlier run: 50 pass with live-scan failures, all `GitHub's request limit was hit` — the shared outbound IP's unauthenticated quota was exhausted at the time; a re-run with no code change passed 62/62) |
| `test:zero-rest` | **26 PASS, 0 FAIL, then crash** at the test-side tree cross-check: `tree cross-check fetch failed: 403`, body `API rate limit exceeded for 104.29.196.211` — the shared-IP quota, not the change. The scan portion itself passed, including `live full scan: no api.github.com fetch in total — 0 calls`. Quota reset is ~40 min out; not waited for. |

`npx tsc --noEmit`: clean. `npm run build` (output to
`/tmp/build-phase16-worker-b.log`): **exit 0**. Secret-pattern grep
over all changed files (Stripe/GitHub/AWS/private-key/webhook
patterns): **clean, no matches**. Test fixtures carry plain text
only; no secret-pattern strings were introduced.
