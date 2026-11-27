# GitSecure Phase 17, Part 1 — History-findings accumulation: design

**Status:** design only (Worker A). No `src/` changed, nothing provisioned,
no dependency added, no credential created. Remote head at time of writing:
`2707ff21` (per task brief; working tree is not a git checkout, so the head
was not re-verified locally).

**The hole, in one sentence:** for a scan whose history spans more than one
serverless invocation, every history finding found before the *last*
invocation is silently dropped from the finished report — the report still
claims the full history was checked, and the score is wrong (too high).

**Files read:** `src/lib/chunks.ts` (`runScanLoop`, `advanceScan`, assemble
exemption), `src/lib/cursor.ts`, `src/lib/mcp.ts` (`scan_repo`, `resumeScan`),
`src/app/api/scan/[owner]/[repo]/route.ts` (GET), `src/app/api/scan/chunk/route.ts`
(POST), `src/app/api/scan/start/route.ts`, `src/app/api/scan/[owner]/[repo]/tip/route.ts`,
`src/lib/resume.ts`, `src/lib/history.ts` (per-commit cache), `src/lib/scan.ts`
(`assembleReport`, `buildLimits`), `src/lib/types.ts`, `README.md`
("Scan cursors"), `GITSECURE.md` (Phases 9/16).

---

## 1. The hole, verified — repro numbers

### 1.1 Mechanism (read from the code, then proved by running it)

- `runScanLoop()` (`src/lib/chunks.ts`) accumulates `historyFindings` in a
  local variable, seeded only from `opts.historyFindings`. A fresh call
  starts from `[]`.
- The GET route calls `runScanLoop(owner, repo, { cursor, budgetMs:
  API_FAST_PATH_WAIT_MS })` — no `historyFindings`, no `head` — and its 202
  body returns only `{ cursor, partial, progress, note }`. The loop's
  returned `historyFindings` are discarded. (`src/app/api/scan/[owner]/[repo]/route.ts`)
- `mcp.ts` `fullScan` / `resumeScan` call `runScanLoop` the same way and keep
  only progress + cursor in the still-running text. Same discard.
- `advanceScan`'s assemble stage takes `historyFindings` from its *caller*
  (`input.historyFindings`, default `[]`). Only the POST-chunk caller ever
  supplies them, because only that caller is handed `chunkFindings` per chunk
  and told to accumulate them (`src/app/api/scan/chunk/route.ts`, and the
  browser driver via `sessionStorage`, `src/lib/resume.ts`).
- The cursor must NEVER carry findings or fragments (`src/lib/cursor.ts`
  header + `decodeCursor` — no findings field exists, and that rule stands),
  so findings have no ride across invocations today.
- Phase 16's assemble exemption (`src/lib/chunks.ts`, comment at ~line 547:
  the loop does not apply the start floor when the next stage is `assemble`)
  only saves the case where history *and* assemble fit in ONE invocation.
  It is the reason mid-size repos are fine and huge ones are not.

### 1.2 Runnable repro

`test-results/phase17/loss-repro/loss-repro.ts` (run:
`npx tsx test-results/phase17/loss-repro/loss-repro.ts`; results in
`test-results/phase17/loss-repro/results.json`). Mock GitHub API server on
localhost, 6-commit repo, one commit per history chunk, a distinct fake
Discord webhook planted in chunks 1, 3 and 5 (fake secrets assembled from
fragments, never a literal secret-pattern string; `noFullSecretLeaked: true`
in the output).

| | Path A — POST-chunk caller | Path B — GET / MCP caller |
|---|---|---|
| Driver | `advanceScan` per chunk, caller accumulates `chunkFindings` | Invocation 1: **genuine** `runScanLoop({cursor, budgetMs: 40000, apiBase, chunkCommits: 1})` — the exact GET-route / `mcp.ts` call shape — against a mock whose detail responses sleep 8 s, so the Phase 16 start floor stops it after 3 chunks; invocation 2 resumes from the cursor with a fresh accumulation and runs the remaining chunks via `advanceScan` (the exact primitive `runScanLoop` calls) |
| Chunks run | 6 | 3 + 3 |
| Invocation 1 wall time | — | **24,016 ms**, floor-stopped after 3 chunks (histScanned 3) |
| Invocation 1 returned `historyFindings` | — | `discord-webhook-app-js-1@3333333`, `discord-webhook-config-js-1@4444444` — **then discarded, as the GET route and MCP do** |
| Findings supplied at assemble | 3/3 | 1/3 (only chunk 5's `discord-webhook-keys-txt-1@6666666`) |
| **Report secrets** | **3** | **1** |
| **Report score / grade** | **23 / F** | **73 / C** |
| History commits claimed | 6 | 6 |
| Limits line (both) | `History checked: 6 commits, newest first (GitHub API — no git binary in this runtime).` | identical — the count is honest, the findings are silently gone |
| **Lost** | — | **`discord-webhook-app-js-1@3333333:http…56`, `discord-webhook-config-js-1@4444444:http…56`** |

Assemble in both paths is `assembleReport()` directly — the exact function
`advanceScan`'s assemble stage calls — because that stage also calls
`fetchHeadSha()` against the real `api.github.com`, which cannot answer for a
mock repo. The loss is decided *before* assemble, in what `historyFindings`
the caller can supply. Same substitution as `scripts/test-cursor-phase9.ts`
§4 (synthetic HEAD, zero dependencies, no OSV network).

Repro exit code 0; verdict `lossReproduced: true`. One deliberate design
choice in the repro: Path B uses a genuine `runScanLoop` call for invocation 1
rather than simulating the boundary, so the floor-stop and the discard are
both real code paths, not a hand simulation. (A 1 ms budget was tried first
and does not work: the chunk's own deadline check returns empty before doing
any work — the loop deadline is threaded into every chunk, which is itself a
useful confirmation of the Phase 16 deadline threading.)

### 1.3 Measured payload facts (ground the storage sizing)

- 3 accumulated history findings serialise to **2,957 bytes JSON,
  ~986 bytes per finding** (includes triage annotation; API-path findings
  carry no usage annotation; git-path findings may carry usage and be
  slightly larger — budget **~1 KB per finding**).
- Worst case observed live (Phase 5): DefinitelyTyped, **403 secrets** →
  ~400 KB accumulated payload. Fits every option below except none (all maxima
  are ≥ 1 MB per value/record).
- Live chunk counts (Phase 16): awesome-python 3,350 commits → 16 chunk calls
  + 2 resumes; TechDirect 62 commits → 1 call; self-scan 35 commits → 1 call.
  Git path is 200 commits/chunk (≈17 history chunks for awesome-python);
  API path is 10/chunk. A "huge" scan is therefore ~17–50 chunks, not
  hundreds.

### 1.4 Volume model (GitSecure has no analytics — scenarios, not claims)

Assume a scan costs the store **1 write per invocation boundary + 1 read at
resume + 1 delete at assemble** (see §4.3 — the store is touched at invocation
boundaries, *not* per chunk; chunks inside one invocation already accumulate
in-process). That is ~2–4 store operations per multi-invocation scan; small
scans that finish in one invocation cost **zero** store operations.

| Scenario | Scans/day | Store ops/day | What it means |
|---|---|---|---|
| Today-ish (Freddy + a few visitors) | 10 | ~10–40 | trivial for every option |
| Busy | 100 | ~100–400 | trivial for every option except Blob's op cap (§2.3) |
| Viral day | 1,000 | ~1,000–4,000 | binds Upstash's stricter free-tier reading (§2.2) and Cloudflare KV's write cap (§2.4); still $0–$0.14/mo elsewhere |
| Sustained DefinitelyTyped-scale | 1,000/day × 400 KB | 400 MB/day written, TTL-bounded | storage, not ops, becomes the constraint on Upstash 256 MB (§2.2) — unrealistic sustained load for a personal scanner; flagged, not designed for |

Steady-state storage is near zero by design: a scan's record lives minutes
(it is deleted at assemble) and the TTL only covers abandoned scans.

---

## 2. Storage options — decision matrix

Common to all server-side options: the stored value is **redacted fragments
only** (the same `SecretFinding` objects the report already returns —
`fragment` is first 4 chars … last 2, never the full secret; see
`src/lib/secrets.ts` `redactSecret` and `src/lib/redact.ts` `leaksSecret`).
No option may store a full secret, a file's contents, or a live credential.
Every option is validated on read with the same shape filter `advanceScan`'s
assemble stage already applies (object with string `type`/`file`/`fragment`),
plus a `headSha` match against the cursor. A corrupt/oversized/unexpected
value is treated as "no stored state", never a crash, never trusted.

### 2.1 Vercel KV — does not exist any more

- **Status: dead product. Do not design for it.** The `vercel/storage` README
  states: *"The packages `@vercel/postgres` and `@vercel/kv` have been
  deprecated and the associated products Vercel Postgres and Vercel KV no
  longer exist."* Source:
  `https://github.com/vercel/storage/blob/main/README.md`. The Vercel docs
  storage page lists only Blob and Global Config as first-party stores;
  Redis/Postgres are Marketplace (Upstash/Neon) now. Legacy free tier was
  256 MB, 3K commands/day (per a 2026 setup doc) — historical only.
- Any design that says "Vercel KV" must be re-read as "Upstash Redis via the
  Vercel Marketplace" (§2.2). The old README line *"no paid KV store"* (§5)
  is doubly stale: KV no longer exists *and* the fix needs a store.

### 2.2 Upstash Redis direct (REST API, plain `fetch` — no SDK)

- **Free tier (sources conflict — plan against the tighter figure):**
  Upstash's pricing table says **500K commands/month**; its FAQ says
  **10,000 commands/day**. Both are live on Upstash's own surfaces as of
  7 Nov 2026 (documented contradiction:
  `https://stackwrite.com/blog/upstash-free-tier-limits-2026/`). Storage
  **250 MB** (256 MB on one table cell), **1 database** on Free,
  **10 GB bandwidth/month**, max request **10 MB**, max record **100 MB**,
  10,000 commands/sec throughput ceiling. Paid (pay-as-you-go):
  **$0.20 per 100K commands**. Sources: `https://upstash.com/pricing/redis`
  (via the pages above), Upstash docs `https://upstash.com/docs/redis/features/restapi`.
- **Cost at realistic volume:** 10 scans/day ≈ 40 cmds/day → **$0** under
  either reading. 100 scans/day ≈ 400 cmds/day → **$0** under either reading
  (4% of the 10K/day figure). 1,000 scans/day ≈ 4,000 cmds/day → **$0** under
  the 10K/day reading; under the 500K/mo reading 120K/mo is also $0. The
  binding case is only if *every* scan were huge *and* chunk-writes were
  per-chunk rather than per-boundary — with the §4.3 boundary design it does
  not bind. Worst honest overage: 1,000 scans/day × 19 cmds (per-chunk-write
  design, if the boundary design were abandoned) = 570K cmds/mo → ~70K over
  the 500K figure × $0.20/100K = **$0.14/month**. Free-tier overage behaviour
  is a hard exception, not a bill (per the stackwrite re-check), so the
  failure mode is degraded scans, not a surprise charge.
- **Storage headroom:** 256 MB holds ~260,000 findings at 1 KB. Steady state
  is ~0 (delete at assemble). Only a sustained flood of abandoned
  DefinitelyTyped-scale scans (400 KB each) could fill it — ~640 abandoned
  huge scans inside the 7-day TTL window. Not a realistic risk; the TTL
  bounds it.
- **Provisioning (Freddy does dashboard steps):** two routes.
  *A — Vercel Marketplace (no new account):* Vercel Dashboard → GitSecure
  project → Storage → Browse Marketplace → Upstash Redis → Create →
  plan Free → region **us-east-1** (same region as the Vercel functions'
  `iad1`; a single-region database is what makes read-your-writes hold —
  do NOT pick Global/multi-region replication for this use) → env vars are
  auto-injected as `KV_REST_API_URL` / `KV_REST_API_TOKEN` → redeploy.
  *B — Upstash console (if Marketplace's plan is unclear):* upstash.com →
  sign up (no card for Free) → Create Database → Redis → name
  `gitsecure-scan-state` → region us-east-1 → plan Free → Create → Details
  page → copy REST URL + REST token → Vercel Dashboard → GitSecure →
  Settings → Environment Variables → add `UPSTASH_REDIS_REST_URL` and
  `UPSTASH_REDIS_REST_TOKEN` (Production; Preview too if previews should
  scan) → redeploy.
  **Verify at provisioning:** whether the Marketplace database lands on
  Upstash's Free plan (10K/day) or a Marketplace-specific allowance, and
  whether Freddy already has an Upstash free database — Free allows **1**,
  so an existing one means either sharing one DB under the `gs:scan:` key
  prefix (acceptable fallback, weaker isolation) or pay-as-you-go.
- **TTL/expiry:** native, second granularity: `SET key value EX 604800`
  (body-style REST: `POST /` with `["SET","k","v","EX","604800"]`,
  `Authorization: Bearer <token>`). No sweeper needed.
- **Latency:** REST round trip, typically tens of ms; 2–4 calls per scan
  against chunks that cost seconds. Negligible.
- **Redaction:** value is JSON of already-redacted findings; the adapter
  never writes `fragment`'s source material, never writes file contents.
  The token is a Bearer token with full access to *one* single-purpose DB
  that holds only scan state — blast radius is scan state, not user data.
- **Store absent/unavailable:** env vars unset → `NoopStore` (all calls
  no-op); REST 5xx/timeout/over-quota → caught, scan continues with
  in-process accumulation only, and the final report carries an honest
  limits note (§4.5). The scan never fails *because* of the store.
- **Consistency:** single-region Redis is strongly consistent for
  read-your-writes — the property this fix actually needs (write at the end
  of invocation N, read at the start of invocation N+1, possibly on a
  different instance, seconds later). This is the decisive technical reason
  it beats Cloudflare KV (§2.4).
- **Dependencies:** **none.** Plain `fetch` to the REST API (documented at
  `https://upstash.com/docs/redis/features/restapi`; body-style example in
  Upstash's own skill docs). The `@upstash/redis` SDK is optional and NOT
  needed.

### 2.3 Vercel Blob (first-party, current)

- **Free tier (Hobby):** **1 GB storage, 10 GB data transfer/month,
  10,000 simple operations/month, 2,000 advanced operations/month**
  (sources: `https://vercel.com/docs/blob/pricing` via
  `https://temps.sh/blog/vercel-pricing-complete-guide-2026` and
  `https://www.pandacodegen.com/blog/nextjs-hosting-zero-cost`, both
  re-checked Oct 2026). `put()` counts as **advanced**; `head()`/URL access
  on cache miss is simple; `del()` is free. **Over a Hobby limit Blob is
  blocked for 30 days, not billed** — a hard outage of the feature, not a
  charge. Pro: storage $0.023/GB-mo, transfer $0.05/GB, advanced ops
  $5.00/1M (i.e. the $20/mo Pro seat is the real price of exceeding).
- **Cost at realistic volume — FAILS the $0 test above trivial volume:**
  per multi-invocation scan ≈ 2 advanced ops per invocation (one `put` +
  one TTL op) — ~3 per scan at ~1.5 invocations on average. 10 scans/day → ~900 advanced ops/mo —
  **$0** (under 2,000). 100 scans/day → ~9,000/mo — **over the free cap**,
  Blob blocked 30 days. Per-chunk writes would be far worse. The cap is a
  cliff, and the cliff disables the fix for a month.
- **Provisioning:** Vercel Dashboard → GitSecure project → Storage → Create
  Blob Store → name `gitsecure-scan-state` → creates `BLOB_READ_WRITE_TOKEN`
  env var → redeploy. No new account, no card.
- **TTL/expiry:** **now exists** — `ttlDays` 1–730 on `put()` (announced
  17–18 Nov 2026, `https://vercel.com/changelog/vercel-blob-now-supports-ttls-for-automatic-deletion`;
  needs `@vercel/blob@2.9.0`). A 7-day TTL costs **1 extra advanced
  operation per put** (1 per started 60 days). Minimum TTL is 1 day — fine
  for scans (the design uses 7 days). Note this is brand-new (days old at
  time of writing); treat the exact behaviour as verify-at-build.
- **Private access:** private blobs GA 30 Jun 2026 (`access: 'private'`);
  server-side reads go through the Blob SDK with the store token, not a
  public URL. Exact private-read call shape was **not** verified by a live
  call in this pass — verify at build time.
- **Latency:** object PUT/GET, typically 100–300 ms; fine against
  seconds-long chunks.
- **Redaction:** same as §2.2 (redacted fragments only). Private access is
  required — a `public` blob would put findings at a guessable URL.
- **Store absent/unavailable:** same degradation as §2.2 (Noop + honest
  note). Over-cap = 30-day Blob blockout, during which *every*
  multi-invocation scan degrades — the worst failure mode of any option.
- **Dependencies:** **needs `@vercel/blob`** (new dependency — the only
  option here that cannot be done with raw `fetch` alone).
- **Verdict:** credible runner-up, killed as first choice by the 2,000
  advanced-ops/month cliff and the new-dependency requirement. If Freddy's
  volume stays at ~10 scans/day it would work — but the design should not
  bet the fix on staying tiny.

### 2.4 Cloudflare KV

- **Free tier (official docs, updated 24 Nov 2026):** **100,000 reads/day,
  1,000 writes/day** (to different keys), 1,000 deletes/day, 1,000 list/day,
  **1 GB storage**, value ≤ **25 MB**, `expirationTtl` minimum **60 s**.
  Paid: $0.50/1M reads, $5.00/1M writes. Sources:
  `https://developers.cloudflare.com/kv/platform/limits/` and
  `https://developers.cloudflare.com/kv/platform/pricing/`.
- **Cost at realistic volume:** 10 scans/day ≈ 20–40 writes/day → **$0**.
  100 scans/day ≈ 200–400 writes/day → **$0**. 1,000 scans/day ≈ 2,000–4,000
  writes/day → **over the 1,000/day cap**; writes then fail with an error
  (hard fail, not billed). The write cap is the tightest of any option.
  Additional tripwire: **1 write/second per key** — two concurrent scans of
  the same repo+HEAD, or a retry within a second, get a 429.
- **Provisioning:** Freddy **already has a Cloudflare account**
  (git-secure.com DNS is on Cloudflare nameservers) — no new account.
  Dashboard → Workers & Pages → KV → Create namespace `gitsecure-scan-state`
  → create an API token (My Profile → API Tokens → Custom token, permission
  `Workers KV Storage: Edit`, or the account-level token) → Vercel env vars
  `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_KV_NAMESPACE_ID`,
  `CLOUDFLARE_API_TOKEN` → redeploy. Writes/reads go through the Cloudflare
  REST API (`/client/v4/accounts/{id}/storage/kv/namespaces/{ns}/values/{key}`),
  plain `fetch`, no SDK. (A Workers binding would be the native path, but
  GitSecure runs on Vercel, not Workers — the REST API is the only route.)
- **TTL/expiry:** native `expiration_ttl` (seconds, min 60) on PUT. Fine.
- **Latency:** REST API round trip, tens of ms; fine.
- **Redaction:** same as §2.2. The API token must be scoped to KV only.
- **Consistency — the disqualifier:** KV is **eventually consistent**.
  Official docs (`https://developers.cloudflare.com/kv/concepts/how-kv-works/`):
  *"KV achieves high performance by caching … which makes reads
  eventually-consistent with writes. Changes may take up to 60 seconds or
  more to be visible in other global network locations."* A resume seconds
  after a write, landing in another location, can read the *old* value (or a
  cached "key does not exist") — the same hole, wearing a different cause.
  Community/JSR docs claim REST-API reads go to the central store and see a
  write at once, but **Cloudflare's own docs do not guarantee that** — it is
  unverified for this design. A correctness fix cannot rest on an
  unverified consistency claim.
- **Store absent/unavailable:** same degradation as §2.2. Over the write cap
  the failure is silent-ish (write returns an error; the scan continues
  degraded) — acceptable only if the honest-note path (§4.5) fires.
- **Verdict:** wrong shape for this job despite the existing account:
  tightest write budget, per-key write rate limit, and eventual consistency
  that can re-create the loss it is meant to fix.

### 2.5 Cloudflare R2

- **Free tier (official docs, updated 30 Oct 2026):** **10 GB-month storage,
  1 million Class A operations/month** (PUT/LIST/DELETE), **10 million
  Class B/month** (GET/HEAD), **egress $0**. Paid: $0.015/GB-mo,
  $4.50/1M Class A, $0.36/1M Class B. Source:
  `https://developers.cloudflare.com/r2/pricing/`.
- **Cost at realistic volume:** 100 scans/day ≈ 9,000 Class A ops/mo →
  **$0** with huge headroom; even 1,000 scans/day is $0. The most generous
  free tier here by an order of magnitude.
- **Provisioning:** Cloudflare Dashboard (existing account) → R2 → Create
  bucket `gitsecure-scan-state` → **requires a payment method on file to
  enable R2, even for the free tier** (per third-party verification of the
  checkout flow) → create an API token (R2 Object Read & Write, scoped to
  the bucket) → Vercel env vars (`R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`,
  `R2_SECRET_ACCESS_KEY`, bucket name) → redeploy. This is the only option
  that asks Freddy for a payment method — say so plainly when presenting it.
- **TTL/expiry:** **no per-object TTL API verified in this pass.** Expiry
  would need either object lifecycle rules (whether R2 supports expiry
  rules was not verified from the docs here — verify at build time) or an
  explicit delete at assemble plus a sweeper for abandoned scans. The
  design's primary cleanup is delete-at-assemble anyway (§4.4), so this is
  a gap, not a blocker — but it is a gap the other options do not have.
- **Consistency:** R2's read-after-write consistency was **not verified
  from the docs in this pass** — do not assume it; check at build time.
- **Latency:** S3-API round trip, tens of ms; fine.
- **Redaction:** same as §2.2. Objects must be private (no public bucket,
  no public URL); access is by signed request only.
- **Access mechanics:** S3-compatible API needs SigV4 signing — either
  hand-rolled signing over raw `fetch` (~100 lines, no dep) or
  `@aws-sdk/client-s3` (new dependency). Both are heavier than the
  one-call REST of §2.2/§2.4.
- **Store absent/unavailable:** same degradation as §2.2.
- **Verdict:** cheapest at scale and generous, but object storage for a
  key-value job, with a payment-method requirement, unverified TTL and
  consistency, and the heaviest access code. Not recommended.

### 2.6 Supabase (Freddy already uses it for VPT)

- **Free tier (pricing page, checked Nov 2026):** **$0, 2 active projects,
  500 MB database per project, 1 GB file storage, 5 GB egress/month,
  50,000 MAU, 500,000 edge-function invocations/month, unlimited API
  requests.** Pro is $25/mo + usage. Sources: `https://supabase.com/pricing`
  via `https://www.cloudzero.com/blog/supabase-pricing/` and
  `https://fastero.com/blog/supabase-pricing` (Nov 2026 checks).
- **Cost at realistic volume:** unlimited API requests → **$0 at any
  volume** in this design (500 MB holds ~500,000 findings at 1 KB; egress
  is KBs per scan). The only free-tier cost that can bite is the *project*
  count, not usage.
- **The coupling question (asked honestly, not assumed):** Freddy's VPT
  project already exists (`suxaftwvyzeqrthzfqof`, per MEMORY.md). Two
  shapes:
  *A — new table in the VPT project:* zero new projects, zero new accounts.
  Cost: **GitSecure's server would hold the VPT project's `service_role`
  key in Vercel env vars.** That key bypasses RLS and can read/write
  Freddy's entire voice-business database (contacts, cards, obligations).
  A leak or bug in GitSecure's server code becomes a VPT breach. The table
  itself is low-risk (redacted fragments of public repos); the *credential*
  is the coupling. Mitigation (Postgres role with access to only that table)
  is possible but is real DBA work, not a default.
  *B — second free project for GitSecure:* isolated credential, isolated
  data. Cost: it consumes Freddy's **2nd and last free active-project slot**;
  a third project later (for anything) means paying or pausing one. And
  **free projects auto-pause after 1 week of inactivity** — GitSecure scans
  are bursty, so after a quiet week the first scan would hit a paused
  project and degrade (or fail) until someone resumes it from the dashboard.
  That pause behaviour is the single worst operational wart of this option:
  the store meant to make scans reliable would itself need waking up.
- **Provisioning:** Supabase Dashboard → (A) VPT project → SQL Editor, or
  (B) New project → name `gitsecure-scan-state`, region, Free plan → SQL
  Editor → run the migration (table `scan_state`, columns `key text primary
  key, head_sha text, hist_scanned int, findings jsonb, updated_at
  timestamptz`; **mandatory** per the standing AGENTS.md rule for post-2026-10-30
  tables: `REVOKE ALL` from `anon`/`authenticated`, `ENABLE ROW LEVEL
  SECURITY`, explicit least-privilege grants — never `GRANT ALL`) → copy the
  `service_role` key (A) or the new project's key (B) → Vercel env vars
  `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` → redeploy.
- **TTL/expiry:** no native row TTL. Expiry = `updated_at` + a `DELETE ...
  WHERE updated_at < now() - interval '7 days'` — either a scheduled
  cleanup (needs a cron, new moving part) or lazy expiry (reads ignore rows
  older than 7 days; a periodic manual delete). The design's primary cleanup
  is delete-at-assemble; TTL is a backstop, so lazy expiry + occasional
  manual delete is acceptable but is still a job nobody owns.
- **Latency:** PostgREST round trip, ~50–200 ms from Vercel; fine.
- **Redaction:** same as §2.2, *plus* RLS must deny `anon`/`authenticated`
  entirely — the findings table must never be readable with the anon key
  (which ships in frontend bundles elsewhere). Server-side only, service
  role only.
- **Store absent/unavailable:** same degradation as §2.2, with one extra
  mode: **paused project** (free-tier idle pause) behaves as "store
  unavailable" and must degrade the same way, not fail the scan. First-scan-
  after-pause is exactly when a user is most likely to be watching.
- **Dependencies:** **none** — raw `fetch` to PostgREST (`/rest/v1/scan_state`),
  same as the VPT code already does.
- **Verdict:** the only option that is $0 at *any* volume with no new
  vendor — but it spends Freddy's last free project slot *or* couples a
  public no-auth scanner to his business database's crown-jewel credential,
  pauses when idle, and needs a migration with RLS care plus an expiry
  story. Second choice. Prefer it only if Freddy explicitly prefers one
  fewer vendor over isolation.

### 2.7 GitHub-native options

- **Actions cache:** 10 GB per repo default, 7-day retention since last
  access, LRU eviction (sources: GitHub changelog 20 Nov 2025,
  `https://github.blog/changelog/2025-11-20-github-actions-cache-size-can-now-exceed-10-gb-per-repository/`).
  **Not usable:** it is only accessible from Actions runs via an
  Actions-scoped token. A Vercel function has no such token, and the
  `GITHUB_TOKEN` PAT in Vercel is Contents **read-only** (per MEMORY.md) —
  it cannot write a cache entry. Even if it could, silent LRU eviction is
  the exact failure mode being fixed.
- **Contents API (commit scan state to a repo/branch):** the PAT cannot
  write (read-only, above). Even with a write-scoped token it would mean a
  commit per invocation into some state repo, a new credential with write
  scope, and polluting git history with machine state. Reject.
- **Gist:** needs a new PAT with `gist` scope; public gists are public,
  "secret" gists are URL-guessable; wrong tool for ephemeral state. Reject.
- **Verdict:** no GitHub-native option works from the Vercel runtime with
  the credentials GitSecure holds. Do not pursue.

### 2.8 In-memory (the status quo ante)

- What exists today: `historyCache` in `src/lib/history.ts` — a module-level
  `Map` of per-commit findings, *"In-memory only … a serverless instance
  that restarts just re-walks cold."* It helps only when consecutive chunks
  land on the **same warm instance**, which is luck: Vercel routes each
  invocation independently, functions freeze between invocations, and a
  redeploy wipes all of them. There is no shared memory between instances,
  no persistence, and 1 GB function RAM bounds what one instance could hold
  anyway (DefinitelyTyped-scale state would be fine in RAM; surviving is
  the problem, not size).
- **Verdict:** this is the thing that fails. It is not a design option; it
  is the bug. (Note the per-commit cache still has value *within* one
  invocation — re-walks are cheaper when warm — and the store design keeps
  it; it just stops pretending it is a resume mechanism.)

### 2.9 Decision matrix (at a glance)

| Option | Free-tier headroom | $0 at 10/day | $0 at 100/day | TTL | Read-your-writes | New dep? | New account / credential? | Degrades gracefully? |
|---|---|---|---|---|---|---|---|---|
| Upstash Redis direct (§2.2) | 10K cmds/day (or 500K/mo — sources conflict), 256 MB, 1 DB | ✅ | ✅ | native, seconds | ✅ strong (single-region) | ❌ none (raw fetch) | Marketplace: no new account; console: Upstash account | ✅ |
| Vercel Blob (§2.3) | 1 GB, 2K advanced ops/mo | ✅ (~900/mo) | ❌ (~9K/mo → 30-day block) | native, days (new, Nov 2026) | ✅ | ✅ `@vercel/blob` | no | ✅, but over-cap = 30-day blockout |
| Cloudflare KV (§2.4) | 100K reads/day, **1K writes/day**, 1 GB | ✅ | ✅ | native, seconds | ❌ eventual (≤60 s+) | ❌ none (raw fetch) | no new account (CF exists); new API token | ✅ |
| Cloudflare R2 (§2.5) | 10 GB-mo, 1M Class A/mo | ✅ | ✅ | ❌ not verified | ❓ not verified | SigV4 hand-roll or `@aws-sdk/client-s3` | no new account; **payment method required** | ✅ |
| Supabase (§2.6) | 500 MB, unlimited requests, 2 projects | ✅ | ✅ | ❌ manual/lazy | ✅ (Postgres) | ❌ none (raw fetch) | no new account; **couples to VPT credential or burns last free slot**; pauses after 1 wk idle | ✅ (incl. paused-project mode) |
| GitHub-native (§2.7) | — | ❌ not usable from Vercel | ❌ | — | — | — | new write-scoped PAT would be needed | — |
| In-memory (§2.8) | — | ❌ the bug | ❌ | — | ❌ | — | — | — |

---

## 3. No-new-service fallback: caller-carried accumulation

If Freddy says no to every store, the hole can be *narrowed* — not closed —
by making the callers that today drop findings carry them instead. This is
additive and backward-compatible, and it is worth shipping *as well as* the
store (it helps MCP callers even with the store, and it is the only fix
available if the store is down). It is not a substitute for the store.

### 3.1 Contract shape

- **MCP `resume_scan`:** add an **optional** `historyFindings` input
  (array of `SecretFinding`, same shape the chunk endpoint already accepts).
  `resumeScan` passes it to `runScanLoop({ cursor, historyFindings })`.
  The still-running text must then **echo the accumulated findings back**
  (or a pointer the model can re-send) so the model has something to pass
  on the next call — today the text carries only the cursor + counts.
  `scan_repo` / `get_report` need no change (fresh scans start empty).
  Backward-compatible: old callers omit the field and get today's behaviour.
- **GET `/api/scan/[owner]/[repo]`:** accept an optional `historyFindings`
  query parameter — base64url JSON, same encoding family as the cursor.
  `runScanLoop` already accepts `historyFindings`; the route just has to
  read and validate it (same shape filter as the chunk route) and pass it
  through. Backward-compatible: omitted → today's behaviour.
- **POST `/api/scan/chunk`:** no change — it already accepts
  `historyFindings` and is the working reference implementation.
- **Browser page:** no change — `sessionStorage` already carries findings
  (`src/lib/resume.ts`); the page is the one caller that never had the hole.

### 3.2 What it fixes

- MCP scans, when the model faithfully copies the accumulated findings from
  the still-running text into the next `resume_scan` call: the findings
  survive across invocations with no server state at all.
- Small GET resumes (a handful of findings, a few KB) via the query param.

### 3.3 What it still loses (be honest about these)

- **GET with a large findings set cannot work.** A URL has practical length
  limits (browsers ~2–8 KB, proxies/CDNs often less; Vercel/Next will
  reject absurdly long URLs). DefinitelyTyped's 403 findings (~400 KB) can
  never ride in a query string. The GET fallback caps out at a few findings
  — exactly the scans that least need it.
- **MCP depends on the model as a storage medium.** The still-running text
  grows ~1 KB per finding per round trip (token cost on every resume), and a
  model that summarises, truncates, or paraphrases the findings array
  corrupts it. There is no checksum the server can check beyond the shape
  filter — a silently altered fragment is undetectable. This is not a
  storage contract; it is a hope.
- **A bare `curl …?cursor=` resume — the documented public API — still
  loses everything.** The README's own example (`curl
  "https://gitsecure.vercel.app/api/scan/torvalds/linux?cursor=<cursor>"`)
  is the case the fallback cannot fix, because nothing in that call carries
  findings.
- **No fix for concurrent/resumed-by-a-stranger scans.** Whoever holds the
  cursor but not the findings gets a silently incomplete report.

### 3.4 Recommendation on the fallback

Ship it *with* the store (MCP param + GET param, both optional), because it
costs little and helps MCP callers when the store is unavailable. Do **not**
ship it *instead of* the store and call Phase 17 done — the public curl
resume, the case the README documents, would still lose findings.

---

## 4. Recommendation

### 4.1 Recommended option: Upstash Redis direct via the REST API (§2.2)

Reasons, in order: (1) it is the only option whose consistency model matches
the job — single-region Redis gives read-your-writes across instances,
seconds apart, which is the exact property the fix needs, and Cloudflare KV
fails it; (2) $0 at realistic volume under *both* published readings of its
free tier, with a $0.14/month worst-case overage, not a cliff; (3) no new npm
dependency — plain `fetch`, so nothing to install, audit, or keep current;
(4) no new account if provisioned through the Vercel Marketplace, and the
token's blast radius is one single-purpose database holding only redacted
fragments of public repos; (5) native second-granularity TTL, so expiry is a
one-argument feature, not a sweeper; (6) latency is tens of ms against
seconds-long chunks; (7) degradation is clean (Noop + honest note, §4.5).

### 4.2 Exact provisioning steps (Freddy does the dashboard steps)

Preferred route — Vercel Marketplace (no new account):

1. Vercel Dashboard → open the **GitSecure** project → **Storage** tab →
   **Browse Marketplace** → **Upstash Redis** → **Create**.
2. Plan: **Free**. Region: **us-east-1** (single region — do not pick Global
   / multi-region replication; read-your-writes is the point). Name: anything
   (suggested `gitsecure-scan-state`).
3. Confirm the created database shows plan **Free**. (Verify at this step:
   does the Marketplace database carry Upstash's Free allowance — 10K
   commands/day — or a Marketplace-specific allowance? If the dashboard does
   not say, use route B below instead; do not guess.)
4. The integration injects `KV_REST_API_URL` and `KV_REST_API_TOKEN` into the
   project env vars automatically. Redeploy (or let the integration trigger
   one).
5. Tell Cobalt it is done; Cobalt verifies with a live multi-invocation
   scan (§4.6) and reports the result.

Fallback route — Upstash console (use if the Marketplace plan is unclear, or
if Freddy already has an Upstash account):

1. upstash.com → sign in (no card for Free) → **Create Database** → type
   **Redis** → name `gitsecure-scan-state` → region **us-east-1** → plan
   **Free** → Create.
2. On the database **Details** page copy **REST URL** and **REST Token**.
3. Vercel Dashboard → GitSecure → Settings → Environment Variables → add
   `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` (Production;
   Preview too if preview deployments should scan) → redeploy.
4. Pre-checks before this route: (a) Freddy has no other Upstash free
   database — Free allows **1**; if he does, share that DB under the
   `gs:scan:` key prefix (acceptable) or accept pay-as-you-go ($0.20/100K
   commands, still ~$0 at this volume); (b) the token is server-side only —
   never put it in client code, never commit it (same handling as the
   existing `GITHUB_TOKEN`).

No step here creates an account, a credential, or a charge on Cobalt's side —
all of the above are Freddy's dashboard clicks, deliberately left for him.

### 4.3 Exact $0 cost proof (scenario arithmetic, from §1.3–1.4)

- Per-finding payload ~1 KB (measured: 986 B). Per-scan store ops with the
  boundary design (§4.4): 1 write per invocation boundary + 1 read at resume
  + 1 delete at assemble ≈ 2–4 ops; one-invocation scans cost 0.
- 10 scans/day → ~40 cmds/day = **$0** (0.4% of the 10K/day FAQ figure;
  0.24% of 500K/mo).
- 100 scans/day → ~400 cmds/day = **$0** (4% of 10K/day; 2.4% of 500K/mo).
- 1,000 scans/day → ~4,000 cmds/day = **$0** under the 10K/day reading;
  120K cmds/mo = **$0** under the 500K/mo reading.
- Storage: steady state ≈ 0 (delete at assemble); worst realistic transient
  is a handful of in-flight scans × ~400 KB (DefinitelyTyped-scale) — orders
  of magnitude under 256 MB. Only ~640 *abandoned* huge scans inside one
  7-day TTL window would fill the DB; the TTL bounds it and the delete at
  assemble prevents it.
- Overage, if the boundary design were abandoned and every chunk wrote:
  1,000 scans/day × 19 cmds = 570K cmds/mo → ~70K over × $0.20/100K =
  **$0.14/month**. Free-tier overage is a hard exception, not a bill.

### 4.4 TTL design (key format, expiry, never a permanent record)

- **Key:** `gs:scan:v1:{owner}:{repo}:{headSha}` — all three components
  come from the cursor (already validated: `NAME_RE` owner/repo, 40-hex
  headSha). The headSha in the key means a scan whose repo moved can never
  read another HEAD's findings; a moved HEAD starts a fresh key.
- **Value (JSON, one document per scan):**
  `{ v: 1, headSha, histScanned, historyFindings: SecretFinding[] }`.
  Findings only — **no head partial** in v1 (see below). `histScanned` is
  the monotonic guard (§4.5).
- **Write:** at each `runScanLoop` partial return (invocation boundary),
  `SET key <json> EX 604800` — **one write per invocation, not per chunk**
  (chunks inside an invocation already accumulate in-process). Overwrite is
  whole-document (the in-process array is the truth at that point).
- **Read:** at `runScanLoop` entry when a cursor is supplied, `GET key`;
  seed `historyFindings` with the stored array (deduped against any
  `opts.historyFindings` the caller passed) **only if** `stored.headSha ===
  cursor.headSha` and `stored.histScanned <= cursor.histScanned`
  (a stored count ahead of the cursor means a newer invocation already
  wrote — take the stored array; a stored count behind means stale — ignore).
- **Delete (primary cleanup):** at the `done` return, `DEL key`. A finished
  scan leaves **nothing** in the store. The report is never stored — only
  in-progress findings are, transiently.
- **TTL (backstop only):** `EX 604800` (7 days). Covers abandoned scans
  (tab closed mid-scan, cursor lost, scan never resumed). 7 days is long
  enough for any realistic resume (a scan resumed after a week is against a
  probably-moved HEAD anyway and restarts) and short enough that the store
  can never become a permanent record.
- **Why no head partial in v1:** the hole is findings, not head. `head` is
  already re-derived at assemble time when the caller does not supply it
  (`advanceScan` assemble stage re-runs `scanHead`), which is today's
  behaviour for GET/MCP multi-invocation scans and is already exercised.
  Persisting `HeadPartial` too (frameworks, dependencies, HEAD secrets —
  potentially hundreds of KB for DefinitelyTyped) would grow the payload
  and the blast radius for a saving of one HEAD re-scan per
  multi-invocation scan. Note as a follow-up, not v1.
- **Concurrency:** two writers to the same key (two clients resuming the
  same cursor simultaneously) are last-write-wins on the whole document.
  The `histScanned` monotonic guard closes the common case: a write is
  applied only if its `histScanned >=` the stored value (checked via the
  read the resume path already did; a stale writer's smaller array cannot
  clobber a newer one). The residual race (two writers interleaving
  read-then-write) is real but narrow, and its worst case is the same
  silent loss the honest-note path (§4.5) is built to catch. True atomicity
  (server-side Lua / `EVAL`) is a possible hardening step — verify Upstash
  REST supports it at build time; do not assume it.

### 4.5 Code changes needed (design — not implemented here)

New file `src/lib/scan-state.ts` (name to confirm at build time):

```ts
export interface StoredScanState {
  v: 1;
  headSha: string;
  histScanned: number;
  historyFindings: SecretFinding[];
}
export interface ScanStateStore {
  load(key: string): Promise<StoredScanState | null>;
  save(key: string, state: StoredScanState, ttlSeconds: number): Promise<void>;
  del(key: string): Promise<void>;
}
```

- `UpstashRestStore` — plain `fetch`, no dependency. `load` = `POST /`
  `["GET", key]`; `save` = `["SET", key, json, "EX", "604800"]`;
  `del` = `["DEL", key]`. Bearer token from `UPSTASH_REDIS_REST_URL` /
  `UPSTASH_REDIS_REST_TOKEN`, falling back to Marketplace names
  `KV_REST_API_URL` / `KV_REST_API_TOKEN`. 5 s per-call timeout (well under
  the chunk budgets; a slow store must never eat a scan's budget).
  Validates on read: object, `v === 1`, `headSha` 40-hex, `histScanned`
  integer ≥ 0, `historyFindings` array filtered by the assemble-stage shape
  filter (string `type`/`file`/`fragment`).
- `NoopStore` — used when env vars are absent: every method resolves
  immediately. The scan behaves exactly as today.
- `MemoryScanStateStore` — test-only, for the suites below (never wired in
  production).
- Wiring — `runScanLoop` only; `advanceScan` and the chunk route are
  untouched (POST-chunk callers already carry their own findings):
  1. On entry with a cursor: if a store is configured, `load` and seed
     `historyFindings` per §4.4 (merge with `opts.historyFindings` via
     `dedupeSecrets`).
  2. On every partial return (both the floor-stop and the post-chunk
     deadline return): best-effort `save` of the current accumulation.
     **Never throw** — a store failure is caught, recorded on a local flag,
     and the loop continues with in-process accumulation.
  3. On the `done` return: best-effort `del` (a failed delete is harmless —
     the TTL cleans it in 7 days).
  4. Head-moved / error exits: no delete needed (TTL covers it); do not add
     cleanup paths that can throw.
- **Honest degradation (the part that makes a store failure visible instead
  of silent):** track `stateRecovered: boolean` through the loop. If a scan
  resumes from a cursor with `histScanned > 0` but the load returned
  nothing (store unconfigured, expired, or failed) *and* the caller passed
  no `historyFindings`, the finished report gets a limits line (via
  `assembleReport` input or a post-step in `runScanLoop`'s done path):
  *"History findings from earlier parts of this scan could not be
  recovered, so this report may be missing secrets from the first
  {histScanned} commits checked — the history count above is how far the
  scan walked, not how many findings survived."* The same line fires if any
  boundary `save` failed. This turns the hole from a silent misreport into
  a stated limitation even when the store is absent — and it is shippable
  on its own, before any store exists.
- **Fallback (§3) shipped alongside:** optional `historyFindings` on MCP
  `resume_scan` (+ echo in the still-running text) and optional
  `?historyFindings=` (base64url JSON) on the GET route. Both validated with
  the assemble-stage shape filter; both ignored when the store already
  seeded findings (store wins; dedupe merges).
- **No changes to:** scoring, caps, redaction, the cursor format
  (no new cursor fields — a scan id in the cursor is *not* needed for v1),
  `advanceScan`, the chunk route, the browser driver, or the per-commit
  in-memory cache (kept as a within-invocation optimisation).

### 4.6 Tests to prove it (for the Phase 17 build)

1. **Loss repro with store (extends the §1.2 repro):** wire the
   `MemoryScanStateStore` into the Path B driver and re-run — must report
   **3/3** findings (was 1/3 without the store). This is the acceptance test.
2. **Store absent:** Path B with `NoopStore` → 1/3 findings **and** the
   honest limits line from §4.5 present in the report.
3. **Store write fails mid-scan:** failing store (throws on `save`) → scan
   still completes, report carries the honest line, no throw, no 500.
4. **TTL expiry:** seed state, advance a fake clock past 7 days (or use a
   1-second TTL in the test store), resume → load returns null → honest
   line, no crash.
5. **Head moved:** stored state under headSha X, cursor pinned to headSha Y
   → state ignored (no cross-HEAD contamination), scan restarts cleanly.
6. **Monotonic guard:** write state with `histScanned` 10, then attempt a
   write with `histScanned` 5 → stored value unchanged.
7. **Shape validation:** stored JSON with a finding missing `fragment`, a
   non-object entry, an oversized array → treated as no state, never a crash.
8. **Regression:** existing suites pass unmodified — `test:cursor-phase9`
   (181 checks), `test:mcp` (62), `test:history`, `test:public-full`,
   `test:zero-rest`, `test:history-git` (live). No suite may gain a network
   dependency on the store.
9. **Live verification (after provisioning, Freddy's word for the push):**
   multi-invocation GET scan of a huge repo *with* history secrets via
   `curl` + `?cursor=` (DefinitelyTyped is the candidate: 403 secrets,
   huge history) — finished report must list the secrets found in early
   chunks, not just the last invocation's. Also re-run the Phase 16 live
   checks (TechDirect 83/B, self-scan 100/A, awesome-python 91/A) to prove
   nothing regressed for single-invocation scans.

### 4.7 Copy that must change (the public promise)

Any server-side store — even a 7-day TTL one holding only redacted fragments
— contradicts the current unqualified promise. These locations must change
with the store; the replacement wording keeps the true promise (fragments
only, never full, never a permanent record, finished reports never stored)
and drops the false one (nothing ever stored, even transiently).

| Location | Current copy | Must become (exact replacement) |
|---|---|---|
| `src/lib/mcp.ts:140` (`LIST_CHECKS_TEXT`) | *"The server holds no scan state, so a restart never loses a scan; GitSecure never stores reports on disk or in a database."* | *"A scan in progress keeps its partial findings in a short-lived server store (redacted fragments only), deleted when the scan finishes or after 7 days; a restart never loses a scan. Finished reports are never stored."* |
| `src/lib/mcp.ts:178` (`get_report` description) | *"It runs a fresh live scan — GitSecure never stores reports on disk or in a database, so the result is always current."* | *"It runs a fresh live scan — finished reports are never stored, so the result is always current."* |
| `README.md:60` | *"Secrets are **never shown in full** …, **never stored**, and **never live-validated** …"* | *"Secrets are **never shown in full** …, **never stored after the scan finishes** (in-progress findings are kept only as redacted fragments, deleted at finish or after 7 days), and **never live-validated** …"* |
| `README.md:111–113` ("Scan cursors") | *"the server holds **no scan-state** between them — no job, no database, no paid KV store, no new env var"* | *"the server holds **no scan job** between chunks. The cursor carries the resume position; the partial findings of a scan in progress are kept in a short-lived store (redacted fragments only, deleted when the scan finishes or after 7 days) so a resume on another instance loses nothing."* |
| `README.md:252–253` (design bullets) | *"**The server holds no scan state.** No durable store, no paid service, no database, no in-memory job map."* | *"**The server holds no scan job.** A short-lived store holds in-progress findings only (redacted fragments, 7-day expiry, deleted at finish). No database of reports, no in-memory job map."* |
| `README.md:191` (MCP section) | *"It runs a fresh live scan — GitSecure never stores reports on …"* | Same replacement as `mcp.ts:178`. |
| `src/app/page.tsx:116`, `src/app/layout.tsx:22` (home-page footer) | *"Secrets are never shown in full, never stored, and never live-validated."* | *"Secrets are never shown in full, never stored after the scan finishes, and never live-validated."* |
| `src/lib/scan.ts:486` (`buildLimits`) | *"Public repos only. No secret is ever stored, logged, or shown in full."* | *"Public repos only. No secret is ever stored after the scan finishes, logged, or shown in full."* |
| `src/lib/types.ts:6` (header comment) | *"fragment only, never stored, never live-validated"* | *"fragment only, never stored after the scan finishes, never live-validated"* |
| `src/lib/chunks.ts` header, `src/lib/cursor.ts:6`, `src/lib/resume.ts:3`, `src/lib/scan.ts:810`, `src/lib/types.ts:136` (code comments) | *"The server holds NO state between chunks" / "holds NO scan state on the server at all" / "the server never stores it"* | Reword to *"the server holds no scan job; in-progress findings live in the short-lived store (see scan-state.ts)"* — comments must not keep asserting a property the code no longer has. |
| `GITSECURE.md:298,401,751,966` + Phase 9/16 status sections | *"GitSecure never stores reports"*, *"never stored, never live-validated"*, *"server holds NO scan state"* | Update in the Phase 17 status entry: record the change as a deliberate, dated decision (as Phases 9/16 record theirs), not a silent edit. |

Note the honest framing for Freddy: the findings were *already public*
(they come from public repos, and the finished report already returns them
to anyone). What changes is *where a copy sits for minutes*: from "only in
the caller's memory" to "also in a 7-day TTL store, as fragments". The
promise that matters — no full secret, no permanent record, no report
retention — survives intact; the sentence that must die is the unqualified
"never stored".

---

## 5. What I could not verify

- **GitSecure's real traffic volume.** No analytics in the repo; §1.4 is
  scenario arithmetic, not measured traffic. The $0 proof holds at 10× and
  100× today's plausible volume; re-check before claiming it at 1,000
  scans/day sustained.
- **Whether Freddy already has an Upstash account / free database.**
  Free allows 1 DB. Check at provisioning (§4.2, step 3 / pre-check a).
- **Whether the Vercel Marketplace Upstash integration lands on the Free
  plan** (10K commands/day) or a Marketplace-specific allowance. Verify in
  the dashboard at provisioning; fall back to the Upstash console route if
  it is unclear.
- **Upstash's free-tier command figure.** Pricing table (500K/mo) and FAQ
  (10K/day) contradict each other on Upstash's own surfaces (re-checked
  7 Nov 2026 by the cited source). The design plans against the tighter
  figure; either way the cost is $0 at realistic volume.
- **Vercel Blob private-read server-side call shape** and the exact
  behaviour of the brand-new (17–18 Nov 2026) `ttlDays` feature — not
  verified by a live call. Irrelevant to the recommendation, relevant if
  Blob is ever revisited.
- **Cloudflare R2 read-after-write consistency and lifecycle-rule expiry** —
  not verified from R2 docs in this pass. Same for the community claim that
  Cloudflare KV REST-API reads see writes at once (official docs do not
  guarantee it).
- **Supabase free-project pause/resume behaviour** — how a paused project
  answers its first API call after a week idle, and how long a dashboard
  resume takes. Only matters if Supabase is chosen.
- **No live provisioning was done** (per task constraints): no store, account,
  or credential was created; no `src/` was changed; no dependency was added.
  The repro and this design are the deliverables. The build (store adapter,
  wiring, tests, copy changes, live verification) is Phase 17 implementation
  work, not done here.

---

## Appendix — evidence index

- Repro: `test-results/phase17/loss-repro/loss-repro.ts`,
  `test-results/phase17/loss-repro/results.json` (exit 0, `lossReproduced: true`).
- Mechanism: `src/lib/chunks.ts` (`runScanLoop`, `advanceScan`, assemble
  exemption ~line 547), `src/app/api/scan/[owner]/[repo]/route.ts` (202 body),
  `src/lib/mcp.ts` (`fullScan`, `resumeScan`), `src/lib/cursor.ts` (never
  carries findings), `src/app/api/scan/chunk/route.ts` (the working
  caller-carried path), `src/lib/resume.ts` (browser path).
- Pricing sources (all fetched 26 Nov 2026): Upstash contradiction —
  `https://stackwrite.com/blog/upstash-free-tier-limits-2026/`; Vercel KV
  deprecation — `https://github.com/vercel/storage/blob/main/README.md`;
  Blob Hobby limits — `https://temps.sh/blog/vercel-pricing-complete-guide-2026`,
  `https://www.pandacodegen.com/blog/nextjs-hosting-zero-cost`; Blob TTL —
  `https://vercel.com/changelog/vercel-blob-now-supports-ttls-for-automatic-deletion`;
  Cloudflare KV limits/pricing —
  `https://developers.cloudflare.com/kv/platform/limits/`,
  `https://developers.cloudflare.com/kv/platform/pricing/`; KV consistency —
  `https://developers.cloudflare.com/kv/concepts/how-kv-works/`; R2 pricing —
  `https://developers.cloudflare.com/r2/pricing/`; Supabase pricing —
  `https://www.cloudzero.com/blog/supabase-pricing/`,
  `https://fastero.com/blog/supabase-pricing`; Actions cache —
  `https://github.blog/changelog/2025-11-20-github-actions-cache-size-can-now-exceed-10-gb-per-repository/`;
  Upstash REST API — `https://upstash.com/docs/redis/features/restapi`.
