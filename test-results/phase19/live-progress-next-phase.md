# Live HEAD progress - next phase design (measured 2026-11-27)

## The problem (Freddy, on his phone)

Scanning torvalds/linux, the progress screen sat at "0 files scanned so
far" while the scan ran. Measured live against git-secure.com: POST
/api/scan/start for torvalds/linux took 53.6 seconds for the first chunk
and returned filesScanned 60,053, filesTotal 0, stage still head. The
count only moves between server calls, never during one. Two
consequences: the UI reads as stuck on big repos, and 53.6 seconds is
dangerously close to the 60 second maxDuration, so on a slower day that
chunk times out and the client retries from 0 - the same no-progress
shape as the known history-chunk loop.

Acceptance bar: during a torvalds/linux scan the files-scanned count
must visibly climb, not sit at 0 and jump.

## Measurement (2026-11-27, this VM)

Counting-only stream of the torvalds/linux tarball (download + gunzip +
tar parse, no secret scanning, no retention):

- 10,000 files at 6.2s
- 20,000 files at 7.8s
- 30,000 files at 10.3s
- 40,000 files at 19.8s
- 50,000 files at 24.3s
- 60,000 files at 40.9s
- aborted at the 55s stream timer before finishing (the tail past 60k
  files was still arriving)

The full production scanHead for the same repo took 53.6s including
secret scanning. Conclusion: the DOWNLOAD dominates. Secret scanning
adds only a few seconds on top of download + gunzip + parse.

## Why skip-forward batching cannot meet the bar

The first design considered was subdividing the HEAD stage into
multiple chunk calls, each resuming where the last stopped by
re-downloading the tarball and skipping already-scanned entries.
The measurement kills it: skipping costs the same as counting
(download + gunzip up to the resume point), so every chunk would pay
~50s of re-download before doing its own batch. Chunks would land
every ~10-25s (not every few seconds) and the whole scan would run
~60 percent slower. That is not the bar, and it is not honest to
ship it as if it were.

The accumulated HEAD state (retained manifests, findings, triage
context) is small for linux, so state carriage is not the blocker.
The re-download is.

## Option A (recommended for the next phase): streaming progress in the chunk

Keep one HEAD chunk call, but answer it as a newline-delimited JSON
stream instead of a single JSON body. scanHead already emits
onProgress per file (progress.filesScanned climbs live inside the
server); the start route forwards those events, throttled to one per
~250 files or ~500ms, and the final event carries today's partial +
cursor shape unchanged. The client (ScanProgress.tsx) reads the
stream incrementally and sets progress per event; history and
assemble chunks stay plain JSON.

- Count climbs every second or so. No server state, no polling, no
  re-download, no resume machinery.
- filesTotal: fetch the recursive tree when the tarball trips the
  100MB buffer switch (streaming branch only, big repos only), so the
  total is known a few seconds in and the count climbs against it.
  The happy path (small repos, whole-buffer tarball) pays nothing.
- Residual risk, stated plainly: the single chunk still runs ~53s
  against a 60s ceiling. On a slower day it can still time out and
  the client retries from 0 - but the user will have SEEN the count
  climb before the retry, instead of 0 the whole time. The timeout
  itself needs Option B.

## Option B (true batching, larger): zip-range resume

codeload also serves a zipball. A zip central directory (fetched with
one trailing Range request) lists every entry with its byte offset,
so entries can be fetched in batches with Range requests and each
entry decompressed independently - no re-download of scanned entries.
Each HEAD chunk fetches one contiguous batch of entries, scans them,
and returns a cursor carrying the next byte offset. Chunks land every
~5s, each well under 60s, and a timeout resumes instead of
restarting. This is the only design that fixes BOTH the stuck count
and the timeout risk. It is a full phase: a new zip reader, range
fetching, new cursor fields, new chunk stages, and tests against a
big repo.

## Option C (not recommended): server-side progress state + client polling

The server would hold per-scan progress in the Upstash store and the
client would poll it. It meets the bar, but it adds a store write per
progress tick, a polling endpoint, and a new failure mode (stale
progress after a redeploy) for a result Option A delivers with no
state at all.

## Recommendation

Next phase: Option A (streaming progress + filesTotal in the
streaming branch). Option B follows only if the 60s timeout on huge
repos becomes a real failure instead of a risk. Option C is not
needed.
