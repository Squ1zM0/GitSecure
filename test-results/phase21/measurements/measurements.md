# Phase 21 Workstream A measurements

Date: 2026-11-28. Driver: `drive-history.mts` (calls the real
`scanHistoryViaGit`, `maxCommits: 1` so the walk is negligible and the
number is clone + `git.log` parse). Pack bytes are the `.pack` file
size polled in the clone dir while the run is live; a clone that fails
before writing the pack reports 0 on disk, so the byte-bound abort
count (150,014,588 etc.) comes from the `PackTooLargeError` probe
runs instead. Probe: `probe-linux-clone.mts` (same bounded HTTP
client, same clone call, raw error surfaced). Depth proof:
`verify-depth.mts`. Loop-fix proof: `verify-loop-fix.mts`.

Caveat: this VM downloads from GitHub at ~3 MB/s, so absolute clone
times do NOT transfer to Vercel (far faster egress). Pack bytes DO
transfer - bytes are bytes. The `scanHistoryViaGit` totals also
include the `git.log` parse with `includeChanges`, which is the
uncapped residual documented in `chunks.ts` (it has no budget check).

## isomorphic-git 1.44.19: `clone` accepts `depth` with `singleBranch` - PROVED

Real clone, DefinitelyTyped, `depth: 1000, singleBranch: true,
noCheckout: true`: log has exactly 1000 entries, `.git/shallow`
present, only `master` locally and remotely. `depth` is respected
and `singleBranch` still holds.

## BEFORE (no depth) vs AFTER (`depth: MAX_HISTORY_COMMITS` = 1000)

### Squ1zM0/GitSecure (main, <1000 commits - control)

| | ok | wall ms | pack bytes on disk |
|---|---|---|---|
| BEFORE | true | 27,502 | 77,931,497 |
| AFTER | true | 21,528 | 77,931,496 |

Identical pack (1-byte run-to-run jitter). Depth changes nothing
here, as expected: the repo fits entirely inside 1000 commits.

### DefinitelyTyped/DefinitelyTyped (master, ~92k commits)

| | ok | wall ms | pack bytes |
|---|---|---|---|
| BEFORE | false (`PackTooLargeError`) | 50,993 | >150,000,000 (aborted at the 150 MB bound; 150,014,588 bytes read in the probe) |
| AFTER (clone, probe) | true | 46,447 | 69,877,238 (69.9 MB, under the bound) |
| AFTER (`scanHistoryViaGit` driver) | true (0 commits - see note) | 2,908,995 | 69,877,238 on disk |

Depth-1000 FIXES DefinitelyTyped on the git path: the pack drops
from over 150 MB to 69.9 MB. The `scanHistoryViaGit` driver run
finished at 2,908,995 ms wall (~48.5 min): clone ~46 s, then the
pure-JS `git.log` + `includeChanges` parse over 1000 DT commits with
enormous trees took ~47.7 min on this 1.5-CPU VM. The walk itself
scanned 0 commits: the 300 s walk budget had expired long before
the log parse finished, so the first file check stopped the chunk
(`chunkStopped`, honest empty chunk) - the budget works, but the
log parse sits outside it, which is the pre-existing uncapped
residual documented in `chunks.ts`. The wall time is therefore a
VM artifact of the log parse, not of the depth change; the
transferable numbers are the clone time (~46 s) and pack bytes
(69.9 MB).

### torvalds/linux (master)

| | ok | wall ms | pack bytes |
|---|---|---|---|
| BEFORE | false (generic clone failure) | 6,565 | 0 on disk (no pack written) |
| AFTER | false (generic clone failure) | 7,071 (separate run) / 6,725 (clean rerun, 0 B on disk) | 0 on disk (no pack written) |

Depth-1000 does NOT fix Linux, for two independent reasons:

1. The clone never gets far enough for the pack bound to matter:
   full and depth-1000 clones both die at ~6.5-6.7 s with
   `ECONNRESET "aborted"` (3 observations: full x2, depth-1000 x2),
   before any pack bytes flow. Depth 1/10/100 stream fine to the
   150 MB bound (43 s / 67 s / 71 s), so the reset is specific to
   deep Linux clones - most plausibly GitHub taking >6 s to start
   the pack stream for a 1M+ commit graph while the connection is
   reset. It is not the byte bound and not a timeout in our code.
2. Even without the reset, Linux cannot fit: depth-1 alone already
   passes 150 MB (150,014,588 bytes read, 43 s). The tip tree by
   itself exceeds the bound, so no depth >= 1 fits under
   `PACK_MAX_BYTES`.

Linux stays on the API fallback (workstream B's compare pre-filter)
either way. The bound is NOT raised: the pack is buffered in memory
and the function is 1 GB.

## Verdict for the depth question

- DefinitelyTyped: fixed by depth-1000 (69.9 MB < 150 MB).
- Linux: not fixed by depth-1000 (reset + depth-1 already >150 MB).
- GitSecure: unchanged.

See the parent report for the depth-vs-coverage assessment
(recommendation: option (b), condition the depth on the chunk staying
inside the first 1000 commits).
