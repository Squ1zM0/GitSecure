# Scope: move the GitSecure scan worker to a host with git

Freddy, 2026-11-28: "Yes" to scoping the host move properly, costs and
shape, before deciding. This is the scope. No build yet.

## The problem, with corrected numbers

Cobalt overstated the API cost in chat before this scope and corrects
it here. History on Vercel usually costs zero API calls already: it
runs through isomorphic-git, a pure JavaScript git client, and the
live TechDirect scan proves it (full history, 62 commits, git
protocol, zero API calls). The quota burns only when that clone
fails, which is what happens on big or slow repos, and then the scan
falls through to the API path at about one call per commit. The
earlier "79 scans an hour" was the fallback case, not the typical
case.

So the host does not remove an API cost that every scan pays. It
fixes the git path itself, which is slow and fragile on serverless:

- isomorphic-git buffers the whole pack in memory before writing
  it, so a big pack OOM-crashes a 1 GB function. The code carries a
  streaming byte bound and a 500 MB memory guard because of this.
- The clone plus log parse sits outside the 30 s walk budget and
  aborts at the route deadline. The local self-scan history stall
  (bare clone 102.9 s vs the 30 s budget) and the no-progress loop
  (a chunk timing out inside the clone persists nothing and retries
  forever) are both this failure mode.
- The route ceiling is 60 s (maxDuration = 60 on start and chunk).
  HISTORY_TIMEOUT_MS is 45 s per chunk. Big repos crawl in chunks.

A real git binary on a persistent host removes all three: native
clone is far faster than the JavaScript client, no whole-pack
buffering, no 60 s ceiling. The git path stops failing on big repos,
so the API fallback almost never triggers, and the 5,000/hr shared
token stops being a ceiling at all. The token stays, but as an
emergency fallback, not the thing every big scan leans on.

## What moves, what stays

Stays on Vercel, unchanged: the whole Next.js app, the report pages,
the MCP server, the Upstash scan-state (per-scan accumulation, deleted
at assemble), the GITHUB_TOKEN (fallback paths only).

Moves: scan execution only, meaning `advanceScan` and everything it
calls (scan.ts, history.ts, osv.ts, deps, triage). The chunk protocol
is already stateless (the cursor carries the repo and stage, the
accumulated findings live with the caller), so the worker needs no
shared state between chunks and no client changes.

Two shapes for the cutover. Recommended: the proxy first.

### Shape 1 (recommended first step): thin proxy

The Vercel routes `POST /api/scan/start` and `POST /api/scan/chunk`
keep their URLs and instead of calling `advanceScan` locally, they
fetch the worker with the same body and return its response. The
frontend, the driver, and MCP change nothing. The worker runs the
same code, with the same chunk boundaries, so the 60 s Vercel ceiling
still bounds each proxy call, but the worker itself is fast enough
that chunks complete well inside it.

- Smallest change, fewest surfaces, easiest to verify live.
- Fallback is trivial: if the worker is unreachable, the route runs
  `advanceScan` locally exactly as today (API fallback intact).
- Cost: one extra hop per chunk, and the 60 s ceiling stays on the
  proxy call.

### Shape 2 (end state): direct

The frontend and MCP call the worker directly at
scan.git-secure.com with the same `/api/scan/*` paths. Removes the
Vercel hop and the 60 s ceiling entirely, so chunks can be bigger
and scans finish in fewer round trips, and the worker can stream
progress events, which also fixes the Phase 19 live-progress gap
(files-scanned count stuck at 0 on the first chunk) properly instead
of with a poll.

- Needs CORS, a subdomain plus DNS, and the MCP server re-pointed.
- More moving parts. Do it after the proxy is proven live, not in
  the same change.

## The bare-clone cache (the big perf lever)

The worker keeps bare clones on a disk volume, keyed by repo. A
repeat scan runs `git fetch` instead of a full clone, seconds
instead of minutes. This is what makes thousands of users scanning
the same popular repos nearly free: the first scan of a repo pays
the clone, every scan after it pays a fetch. Needs a size cap and
LRU eviction (torvalds/linux is about 4 GB; a 20 GB volume holds a
handful of big repos or many small ones). The cache holds public
repo data only, no secrets beyond what is already public in the
repos, and the scan's redaction rules still apply to findings.

## Capacity, honestly

One 1 vCPU / 2 GB machine runs a handful of concurrent clones
comfortably; the clone is the bottleneck, not the file scan. Exact
throughput is not claimed here because it was not measured; the
levers are the bare-clone cache (repeat scans skip the clone), a
queue with a depth cap (extra scans wait in line with honest
progress instead of failing), and horizontal scaling (add a second
machine behind the same proxy when the queue is the bottleneck).
None of that needs building up front; the proxy plus cache is the
first step, and the queue depth is the signal for when to add
capacity.

## Reliability and security

- If the worker is down or unreachable, Vercel runs the scan
  locally as today. Scans degrade to the API fallback, never fail
  outright. The worker is an accelerator, not a hard dependency.
- The worker only accepts requests from Vercel (shared secret
  header), with per-IP rate limiting for abuse. It fetches arbitrary
  public repos, so the existing size gates stay (tarball streaming
  bound, history pack bound, MAX_HISTORY_COMMITS 1000, 50 MB patch
  cap), plus a disk quota per clone.
- No token needed on the worker: the git protocol is unauthenticated
  for public repos. The GITHUB_TOKEN stays in Vercel for the fallback
  paths only.
- Health check plus auto-restart on the host. Uptime monitoring of
  the worker is an open decision, not assumed: Freddy declined paid
  monitoring for the site itself.

## Costs (verified live 2026-11-28, sources in the pricing note)

Fit is 1-2 vCPU, 2 GB RAM, always-on, us-east. Downloads from
GitHub are ingress (free everywhere); egress is scan results sent
back.

| Provider | Fitting size (us-east) | Monthly | Notes |
|---|---|---|---|
| Fly.io | shared-cpu-1x, 1 shared vCPU, 2 GB, Ashburn (iad) | $12.70 list, ~$7.70 after the documented $5/mo Free-plan usage credit | Cheapest in us-east. Docker image, git in the Dockerfile. Must set auto-stop off or the worker sleeps. Shared vCPU throttles to about 6% of a core with a burst balance. The $5 credit needs confirming at signup. |
| DigitalOcean | Basic Droplet, 1 vCPU, 2 GB, 50 GB SSD, NYC | $12.00 flat, 2 TB transfer included | Runner-up. Fixed price, no surprises. Full VM, you own OS patching. |
| Hetzner (US) | CPX11, 2 vCPU, 2 GB, 40 GB NVMe, Ashburn | $21.09 incl. IPv4 | The cheap EU box (about EUR 5.99) is EU-only and restricted for new customers since Jun 2026. |
| Render | Standard, 1 CPU, 2 GB | $25.00 | Paid instances never sleep. Steepest egress overage ($0.15/GB past 5 GB on Hobby). |
| Railway | 1 vCPU + 2 GB, metered | $40 at full tilt | Bill drops when the worker idles (only option that does). Most expensive at full tilt. Region choice may be Pro-only. |

Plus a disk volume for the bare-clone cache: Fly.io $0.15/GB/mo,
so a 20 GB volume is about $3/mo. All-in for the recommended
option: roughly $11-16/mo on Fly.io, or $12-15/mo on DigitalOcean.

Vercel itself cannot host this worker: no git binary in functions,
no persistent disk, 4.5 MB request/response cap. That is the
blocker, not duration.

## What the build looks like

A phase-sized piece of work, in the usual shape: Docker image with
git plus the scan code, deploy to the host, Vercel routes proxy to
it, verify live. Verification bar: tsc and build clean, full offline
suite green, live baselines unchanged (self-scan 100/A, TechDirect
73/C, MCP 62/62), plus a big-repo scan that currently falls through
to the API (torvalds/linux or DefinitelyTyped) proving the git path
holds end to end on the worker, and a repeat scan proving the
bare-clone cache is hit. Then the docs push.

## Open decisions for Freddy

1. Host: Fly.io (~$8-13/mo after credit) or DigitalOcean ($12/mo
   flat). Recommendation: Fly.io, cheapest in us-east, with
   DigitalOcean as the fixed-price fallback.
2. Shape: proxy first, direct later. Recommendation: yes, proxy
   first.
3. Report cache (repeat scans of the same repo plus HEAD cost
   zero): not in this scope. It changes the current promise that
   finished reports are never stored, so it needs its own decision.
4. Uptime monitoring for the worker: not assumed, needs a word.
