// GitSecure Phase 17, Part 1 (Worker C) — history-findings
// accumulation tests.
//
// Proves, against the same mock GitHub server as the loss repro
// (test-results/phase17/loss-repro/loss-repro.ts — 6 commits, one
// commit per history chunk, a distinct fake Discord webhook planted
// in chunks 1, 3 and 5), that:
//   1. a store round-trips the accumulation across simulated fresh
//      invocations: the loss-repro Path B now reports 3/3 findings
//      (was 1/3), with no honest-limits line;
//   2. with no store (NoopStore) a multi-invocation scan still
//      completes but the finished report carries the honest limits
//      line — the hole becomes a stated limitation, never a silent
//      misreport — while a single-invocation scan behaves exactly
//      as today (no line);
//   3. a failing store never fails a scan (report carries the line,
//      scan still completes, no throw);
//   4. the caller-carried fallback works: MCP resume_scan with
//      historyFindings, and the GET ?historyFindings= parser, both
//      carry the accumulation without a store;
//   5. the store contract itself: activation rule, monotonic guard,
//      TTL expiry, head-mismatch rejection, shape validation, and
//      the Upstash REST adapter against a fake Upstash server.
//
// Timing: the mock's detail responses sleep 1 s, so one API history
// chunk costs ~1 s. Invocation 1 uses a 3.5 s budget, so the loop's
// deadline return stops it after chunk 3 or 4 (chunk 4 is clean —
// either stop leaves findings A+B in hand, and the test asserts on
// the actual cursor, never on an assumed chunk count).
//
// Fixture discipline (Phase 14): every secret value below is
// assembled at runtime from a short prefix plus a repeated
// single-character filler — no literal secret-pattern string is
// committed anywhere in this file. The values are invented and
// never worked.
//
// Run: npm run test:phase17-worker-c

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { advanceScan, runScanLoop, historyFindingsMissingLine } from "../src/lib/chunks";
import { encodeCursor, initialHistoryCursor, decodeCursor } from "../src/lib/cursor";
import { assembleReport } from "../src/lib/scan";
import { leaksSecret } from "../src/lib/redact";
import {
  getScanStateStore,
  scanStateKey,
  validateStoredState,
  MemoryScanStateStore,
  NoopStore,
  UpstashRestStore,
  SCAN_STATE_MAX_BYTES,
  type ScanStateStore,
  type StoredScanState,
} from "../src/lib/scan-state";
import { createMcpServer, resumeScan, stillRunningText } from "../src/lib/mcp";
import { parseHistoryFindingsParam, MAX_GET_HISTORY_FINDINGS_BYTES } from "../src/app/api/scan/[owner]/[repo]/route";
import type { HeadPartial, SecretFinding } from "../src/lib/types";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

let failures = 0;
let checks = 0;
function check(name: string, ok: boolean, extra = "") {
  checks++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// --- Fake secrets, assembled in memory only. ---
const FAKE = "FAKE";
const sha = (c: string) => c.repeat(40);
const SHA_NEW = sha("3"); // chunk 1 — webhook A
const SHA_C2 = sha("2"); // chunk 2 — clean
const SHA_C3 = sha("4"); // chunk 3 — webhook B
const SHA_C4 = sha("5"); // chunk 4 — clean
const SHA_C5 = sha("6"); // chunk 5 — webhook C
const SHA_OLD = sha("1"); // chunk 6 — clean
const SHAS = [SHA_NEW, SHA_C2, SHA_C3, SHA_C4, SHA_C5, SHA_OLD];
const webhook = (id: string) =>
  "https://discord.com/api/webhooks/" + id + "/" + FAKE.repeat(6) + "123456";
const HOOK_A = webhook("111111111111111111");
const HOOK_B = webhook("222222222222222222");
const HOOK_C = webhook("333333333333333333");
const ALL_HOOKS = [HOOK_A, HOOK_B, HOOK_C];

const PATCHES: Record<string, { filename: string; patch: string }[]> = {
  [SHA_NEW]: [{ filename: "app.js", patch: `@@ -0,0 +1,2 @@\n+const HOOK = "${HOOK_A}";\n+module.exports = { HOOK };\n` }],
  [SHA_C2]: [{ filename: "notes.txt", patch: "@@ -1,1 +1,2 @@\n context\n+unrelated change\n" }],
  [SHA_C3]: [{ filename: "config.js", patch: `@@ -0,0 +1,1 @@\n+const HOOK = "${HOOK_B}";\n` }],
  [SHA_C4]: [{ filename: "notes.txt", patch: "@@ -1,1 +1,2 @@\n context\n+another unrelated change\n" }],
  [SHA_C5]: [{ filename: "keys.txt", patch: `@@ -0,0 +1,1 @@\n+const HOOK = "${HOOK_C}";\n` }],
  [SHA_OLD]: [{ filename: "readme.md", patch: "@@ -0,0 +1,1 @@\n+# hello\n" }],
};

let detailDelayMs = 1000;

// Mock GitHub API server (same shape as the loss repro).
const ghServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  if (url.pathname === "/repos/testowner/testrepo/commits") {
    if (url.searchParams.get("per_page") === "1") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify([{ sha: SHA_NEW }])); // HEAD check
      return;
    }
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(SHAS.map((s) => ({ sha: s }))));
    return;
  }
  const m = /^\/repos\/testowner\/testrepo\/commits\/([0-9a-f]+)$/.exec(url.pathname);
  if (m) {
    if (detailDelayMs > 0) await sleep(detailDelayMs);
    if (res.writableEnded) return;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ sha: m[1], files: PATCHES[m[1]] ?? [] }));
    return;
  }
  res.statusCode = 404;
  res.end("not found");
});

// Fake Upstash REST server: body-style commands over a Map, with
// knobs for failure modes. The store under test talks to this over
// real fetch — no live Upstash, no network.
const upstashData = new Map<string, string>();
let upstashFailStatus: number | null = null;
let upstashHang = false;
const upstashServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  if (upstashHang) return; // never respond: the client's timeout must fire
  if (upstashFailStatus) {
    res.statusCode = upstashFailStatus;
    res.end("error");
    return;
  }
  let body = "";
  for await (const chunk of req) body += chunk;
  let args: unknown[];
  try {
    args = JSON.parse(body) as unknown[];
  } catch {
    res.statusCode = 400;
    res.end(JSON.stringify({ error: "bad json" }));
    return;
  }
  const [cmd, key, ...rest] = args as [string, string, ...unknown[]];
  res.setHeader("Content-Type", "application/json");
  if (cmd === "GET") {
    res.end(JSON.stringify({ result: upstashData.get(key) ?? null }));
    return;
  }
  if (cmd === "SET") {
    upstashData.set(key, String(rest[0]));
    res.end(JSON.stringify({ result: "OK" }));
    return;
  }
  if (cmd === "DEL") {
    const had = upstashData.delete(key);
    res.end(JSON.stringify({ result: had ? 1 : 0 }));
    return;
  }
  res.statusCode = 400;
  res.end(JSON.stringify({ error: "unknown command" }));
});

// Synthetic HEAD: zero secrets, zero dependencies (no OSV network),
// one posture item so the score has something besides secrets.
const HEAD: HeadPartial = {
  owner: "testowner", repo: "testrepo", branch: "main", headSha: SHA_NEW,
  filesScanned: 3, filesTotal: 3, treeTruncated: false, tarballFallback: false,
  secrets: [], frameworks: [], dependencies: [],
  posture: [{ id: "no-security-md", title: "No SECURITY.md", severity: "low", detail: "No SECURITY.md.", fix: "Add one." }],
  unpinnedCount: 0, historyMethod: "api", retainedIncomplete: false,
};

const ids = (fs: SecretFinding[]) =>
  fs.map((f) => `${f.id}@${(f.commit ?? "?").slice(0, 7)}:${f.fragment}`).sort();
const HONEST_LINE = "could not be recovered";
const hasHonestLine = (limits: string[]) => limits.some((l) => l.includes(HONEST_LINE));

// The assembled report outputs, for the redaction check at the end.
const outputsForRedaction: string[] = [];

// Store that throws on every call (store-down simulation).
class FailingStore implements ScanStateStore {
  async load(_key: string): Promise<StoredScanState | null> {
    throw new Error("store down");
  }
  async save(_key: string, _state: StoredScanState, _ttlSeconds?: number): Promise<void> {
    throw new Error("store down");
  }
  async del(_key: string): Promise<void> {
    throw new Error("store down");
  }
}

// runScanLoop's assemble stage calls fetchHeadSha() against
// api.github.com, which cannot answer for a mock repo. Route those
// calls to the mock server instead (test-only, restored in
// finally). The mock already answers the HEAD check (per_page=1).
const realFetch = globalThis.fetch;
function patchFetchForMock(apiBase: string) {
  globalThis.fetch = ((input: unknown, init?: unknown) => {
    const url = typeof input === "string" ? input : (input as { url: string }).url;
    if (typeof url === "string" && url.startsWith("https://api.github.com/")) {
      return realFetch(apiBase + url.slice("https://api.github.com".length), init as RequestInit);
    }
    return realFetch(input as string, init as RequestInit);
  }) as typeof fetch;
}

async function main() {
  await new Promise<void>((resolve) => ghServer.listen(0, "127.0.0.1", resolve));
  await new Promise<void>((resolve) => upstashServer.listen(0, "127.0.0.1", resolve));
  const apiBase = `http://127.0.0.1:${(ghServer.address() as { port: number }).port}`;
  const upstashUrl = `http://127.0.0.1:${(upstashServer.address() as { port: number }).port}`;
  const startCursor = encodeCursor(
    initialHistoryCursor({ owner: "testowner", repo: "testrepo", branch: "main", headSha: SHA_NEW, historyMethod: "api" }),
  );
  const key = scanStateKey("testowner", "testrepo", SHA_NEW);

  try {
    // ================= 1. Activation rule =================
    check("activation: no env vars → NoopStore", getScanStateStore({}) instanceof NoopStore);
    check("activation: URL without token → NoopStore", getScanStateStore({ KV_REST_API_URL: upstashUrl }) instanceof NoopStore);
    check("activation: token without URL → NoopStore", getScanStateStore({ KV_REST_API_TOKEN: "t" }) instanceof NoopStore);
    check(
      "activation: KV pair → UpstashRestStore",
      getScanStateStore({ KV_REST_API_URL: upstashUrl, KV_REST_API_TOKEN: "t" }) instanceof UpstashRestStore,
    );
    check(
      "activation: Upstash pair → UpstashRestStore",
      getScanStateStore({ UPSTASH_REDIS_REST_URL: upstashUrl, UPSTASH_REDIS_REST_TOKEN: "t" }) instanceof UpstashRestStore,
    );
    const bothPairs = getScanStateStore({
      UPSTASH_REDIS_REST_URL: "https://upstash.example",
      UPSTASH_REDIS_REST_TOKEN: "u",
      KV_REST_API_URL: "https://kv.example",
      KV_REST_API_TOKEN: "k",
    });
    check(
      "activation: Upstash pair wins over KV pair",
      bothPairs instanceof UpstashRestStore &&
        (bothPairs as unknown as { config: { url: string } }).config.url === "https://upstash.example",
    );
    const noop = new NoopStore();
    check("NoopStore: load is null", (await noop.load("k")) === null);
    await noop.save("k", { v: 1, headSha: SHA_NEW, histScanned: 1, historyFindings: [] });
    await noop.del("k");
    check("NoopStore: save/del resolve without throwing", true);

    // ================= 2. Stored-state validation =================
    const goodFinding = {
      id: "discord-webhook-app-js-1", type: "discord-webhook", title: "Discord webhook",
      severity: "critical" as const, confidence: "high" as const, file: "app.js", line: 1,
      commit: SHA_NEW, fragment: "http…56", fix: "Revoke it.", plainEnglish: "A webhook.",
    };
    const goodState = { v: 1, headSha: SHA_NEW, histScanned: 3, historyFindings: [goodFinding] };
    const validated = validateStoredState(goodState);
    check("validation: well-formed state passes", validated !== null && validated.histScanned === 3 && validated.historyFindings.length === 1);
    check("validation: wrong version → null", validateStoredState({ ...goodState, v: 2 }) === null);
    check("validation: bad headSha → null", validateStoredState({ ...goodState, headSha: "xyz" }) === null);
    check("validation: negative histScanned → null", validateStoredState({ ...goodState, histScanned: -1 }) === null);
    check("validation: non-integer histScanned → null", validateStoredState({ ...goodState, histScanned: 1.5 }) === null);
    check("validation: findings not an array → null", validateStoredState({ ...goodState, historyFindings: "nope" }) === null);
    check("validation: non-object → null", validateStoredState("nope") === null);
    const withBadEntry = validateStoredState({
      ...goodState,
      historyFindings: [goodFinding, { type: "discord-webhook", file: "x.js" }, "junk", null],
    });
    check("validation: malformed finding entries are dropped, good ones kept", withBadEntry !== null && withBadEntry.historyFindings.length === 1);
    check(
      "validation: oversized array → null",
      validateStoredState({ ...goodState, historyFindings: new Array(10_001).fill(goodFinding) }) === null,
    );
    const hugeState = { ...goodState, historyFindings: [{ ...goodFinding, fragment: "x".repeat(SCAN_STATE_MAX_BYTES) }] };
    check("validation: oversized value → null", validateStoredState(hugeState) === null);

    // ================= 3. MemoryStore =================
    const mem = new MemoryScanStateStore();
    check("MemoryStore: load missing → null", (await mem.load(key)) === null);
    await mem.save(key, { v: 1, headSha: SHA_NEW, histScanned: 3, historyFindings: [goodFinding] });
    const memLoaded = await mem.load(key);
    check("MemoryStore: round-trip", memLoaded !== null && memLoaded.histScanned === 3 && memLoaded.historyFindings.length === 1);
    await mem.save(key, { v: 1, headSha: SHA_NEW, histScanned: 10, historyFindings: [goodFinding, goodFinding] });
    check("MemoryStore: newer write replaces", (await mem.load(key))?.histScanned === 10);
    await mem.save(key, { v: 1, headSha: SHA_NEW, histScanned: 5, historyFindings: [] });
    check("MemoryStore: monotonic guard — stale write (5) cannot clobber newer (10)", (await mem.load(key))?.histScanned === 10);
    await mem.del(key);
    check("MemoryStore: delete at assemble leaves nothing", (await mem.load(key)) === null);
    const memTtl = new MemoryScanStateStore(1);
    await memTtl.save(key, { v: 1, headSha: SHA_NEW, histScanned: 3, historyFindings: [goodFinding] });
    check("MemoryStore: state present before TTL", (await memTtl.load(key)) !== null);
    await sleep(1200);
    check("MemoryStore: TTL expiry → load null", (await memTtl.load(key)) === null);

    // ================= 4. UpstashRestStore vs fake server =================
    const up = new UpstashRestStore({ url: upstashUrl, token: "test-token" });
    check("Upstash: load missing → null", (await up.load(key)) === null);
    await up.save(key, { v: 1, headSha: SHA_NEW, histScanned: 3, historyFindings: [goodFinding] });
    const upLoaded = await up.load(key);
    check("Upstash: round-trip over real fetch", upLoaded !== null && upLoaded.histScanned === 3 && upLoaded.historyFindings[0]?.fragment === "http…56");
    await up.save(key, { v: 1, headSha: SHA_NEW, histScanned: 10, historyFindings: [goodFinding] });
    await up.save(key, { v: 1, headSha: SHA_NEW, histScanned: 5, historyFindings: [] });
    check("Upstash: monotonic guard — stale write (5) cannot clobber newer (10)", (await up.load(key))?.histScanned === 10);
    upstashData.set(key, "not json{");
    check("Upstash: corrupt stored value → load null, never a crash", (await up.load(key)) === null);
    upstashData.set(key, JSON.stringify({ v: 2, headSha: SHA_NEW, histScanned: 1, historyFindings: [] }));
    check("Upstash: wrong-version stored value → load null", (await up.load(key)) === null);
    upstashData.delete(key);
    await up.save(key, { v: 1, headSha: SHA_NEW, histScanned: 3, historyFindings: [goodFinding] });
    await up.del(key);
    check("Upstash: delete at assemble leaves nothing", (await up.load(key)) === null);
    let oversizedThrew = false;
    try {
      await up.save(key, { v: 1, headSha: SHA_NEW, histScanned: 1, historyFindings: [{ ...goodFinding, fragment: "x".repeat(SCAN_STATE_MAX_BYTES) }] });
    } catch {
      oversizedThrew = true;
    }
    check("Upstash: oversized save throws (caller degrades, never stores it)", oversizedThrew);
    check("Upstash: oversized save stored nothing", (await up.load(key)) === null);
    upstashFailStatus = 500;
    let loadThrew = false;
    try {
      await up.load(key);
    } catch {
      loadThrew = true;
    }
    check("Upstash: non-2xx load throws (caller degrades)", loadThrew);
    let saveThrew = false;
    try {
      await up.save(key, { v: 1, headSha: SHA_NEW, histScanned: 1, historyFindings: [] });
    } catch {
      saveThrew = true;
    }
    check("Upstash: non-2xx save throws (caller degrades)", saveThrew);
    upstashFailStatus = null;
    upstashHang = true;
    const hanging = new UpstashRestStore({ url: upstashUrl, token: "t", timeoutMs: 100 });
    const hangStarted = Date.now();
    let hangThrew = false;
    try {
      await hanging.load(key);
    } catch {
      hangThrew = true;
    }
    const hangMs = Date.now() - hangStarted;
    check("Upstash: hanging store times out instead of hanging the scan", hangThrew && hangMs < 5000, `${hangMs}ms`);
    upstashHang = false;

    // ================= 5. Loop tests (mock GitHub) =================
    patchFetchForMock(apiBase);

    // Helper: drive Path B (GET / MCP shape) with a given store.
    // Invocation 1: genuine runScanLoop, production shape, small
    // budget so the deadline return stops it after chunk 3 or 4.
    // Invocation 2: fresh runScanLoop from the cursor.
    async function runPathB(store: ScanStateStore, inv2Findings?: SecretFinding[]) {
      const inv1 = await runScanLoop("testowner", "testrepo", {
        cursor: startCursor, head: HEAD, budgetMs: 3500, apiBase, chunkCommits: 1, store,
      });
      if (inv1.status !== "partial" || !inv1.cursor) throw new Error(`inv1: expected partial, got ${inv1.status}`);
      const scanned1 = decodeCursor(inv1.cursor, "testowner", "testrepo").histScanned;
      const inv1Findings = inv1.historyFindings ?? [];
      const inv2 = await runScanLoop("testowner", "testrepo", {
        cursor: inv1.cursor, head: HEAD, apiBase, chunkCommits: 1, store,
        historyFindings: inv2Findings,
      });
      if (inv2.status !== "done" || !inv2.report) throw new Error(`inv2: expected done, got ${inv2.status}`);
      return { inv1, inv1Findings, scanned1, report: inv2.report };
    }

    // --- 5a. Round-trip with a store: the loss-repro scenario, fixed. ---
    const memStore = new MemoryScanStateStore();
    const fixed = await runPathB(memStore);
    outputsForRedaction.push(JSON.stringify(fixed.report));
    check("round-trip: inv1 returns findings A+B", JSON.stringify(ids(fixed.inv1Findings)) === JSON.stringify(["discord-webhook-app-js-1@3333333:http…56", "discord-webhook-config-js-1@4444444:http…56"]));
    check("round-trip: report has 3/3 secrets (was 1/3)", fixed.report.counts.secrets === 3, `${fixed.report.counts.secrets} secrets`);
    check("round-trip: score 23/F, as the caller-carried Path A", fixed.report.score === 23 && fixed.report.grade === "F", `${fixed.report.score}/${fixed.report.grade}`);
    check("round-trip: no honest-limits line (findings recovered)", !hasHonestLine(fixed.report.limits));
    check("round-trip: delete at assemble leaves nothing in the store", (await memStore.load(key)) === null);

    // --- 5b. NoopStore default: single-invocation scan is exactly today's behaviour. ---
    const noopStore = new NoopStore();
    const single = await runScanLoop("testowner", "testrepo", {
      cursor: startCursor, head: HEAD, apiBase, chunkCommits: 1, store: noopStore,
    });
    if (single.status !== "done" || !single.report) throw new Error(`single-invocation: expected done, got ${single.status}`);
    outputsForRedaction.push(JSON.stringify(single.report));
    check("noop single-invocation: 3/3 secrets", single.report.counts.secrets === 3);
    check("noop single-invocation: no honest-limits line", !hasHonestLine(single.report.limits));

    // --- 5c. NoopStore default: multi-invocation scan degrades honestly. ---
    const degraded = await runPathB(new NoopStore());
    outputsForRedaction.push(JSON.stringify(degraded.report));
    check("noop multi-invocation: report has 1/3 secrets (today's loss)", degraded.report.counts.secrets === 1, `${degraded.report.counts.secrets} secrets`);
    check("noop multi-invocation: score 73/C (today's inflation)", degraded.report.score === 73 && degraded.report.grade === "C", `${degraded.report.score}/${degraded.report.grade}`);
    const expectedLine = historyFindingsMissingLine(degraded.scanned1);
    check("noop multi-invocation: honest limits line present, exact wording", degraded.report.limits.includes(expectedLine), degraded.report.limits.join(" | "));
    check("noop multi-invocation: line names the walked count", degraded.report.limits.some((l) => l.includes(`first ${degraded.scanned1} commits`)));

    // --- 5d. Failing store: scan still completes, line present, no throw. ---
    const failing = await runPathB(new FailingStore());
    outputsForRedaction.push(JSON.stringify(failing.report));
    check("failing store: scan completes (no throw, no 500)", failing.report.counts.secrets === 1);
    check("failing store: honest limits line present", hasHonestLine(failing.report.limits));

    // --- 5e. Caller-carried fallback at the loop level (no store). ---
    const inv1fb = await runScanLoop("testowner", "testrepo", {
      cursor: startCursor, head: HEAD, budgetMs: 3500, apiBase, chunkCommits: 1, store: new NoopStore(),
    });
    if (inv1fb.status !== "partial" || !inv1fb.cursor) throw new Error("fallback inv1: expected partial");
    const fb = await runScanLoop("testowner", "testrepo", {
      cursor: inv1fb.cursor, head: HEAD, apiBase, chunkCommits: 1, store: new NoopStore(),
      historyFindings: inv1fb.historyFindings ?? [],
    });
    if (fb.status !== "done" || !fb.report) throw new Error("fallback inv2: expected done");
    outputsForRedaction.push(JSON.stringify(fb.report));
    check("fallback (opts.historyFindings): report has 3/3 secrets", fb.report.counts.secrets === 3);
    check("fallback (opts.historyFindings): no honest-limits line (caller carried them)", !hasHonestLine(fb.report.limits));

    // --- 5f. Head-mismatch stored state is ignored, never trusted. ---
    const memMismatch = new MemoryScanStateStore();
    await memMismatch.save(key, { v: 1, headSha: sha("9"), histScanned: 3, historyFindings: [goodFinding] });
    const inv1mm = await runScanLoop("testowner", "testrepo", {
      cursor: startCursor, head: HEAD, budgetMs: 3500, apiBase, chunkCommits: 1, store: new NoopStore(),
    });
    if (inv1mm.status !== "partial" || !inv1mm.cursor) throw new Error("head-mismatch inv1: expected partial");
    const mm = await runScanLoop("testowner", "testrepo", {
      cursor: inv1mm.cursor, head: HEAD, apiBase, chunkCommits: 1, store: memMismatch,
    });
    if (mm.status !== "done" || !mm.report) throw new Error("head-mismatch inv2: expected done");
    outputsForRedaction.push(JSON.stringify(mm.report));
    check("head-mismatch: stored state under another HEAD is ignored (1/3)", mm.report.counts.secrets === 1);
    check("head-mismatch: honest limits line present", hasHonestLine(mm.report.limits));
    check("head-mismatch: the mismatched finding never enters the report", mm.report.secrets.length === 1 && mm.report.secrets[0]?.file === "keys.txt");

    // --- 5g. TTL expiry at the loop level. ---
    // runScanLoop always passes the production 7-day TTL, so a
    // short TTL has to come from the store side: this wrapper
    // honours a 1-second TTL whatever the loop asks for.
    class ShortTtlStore extends MemoryScanStateStore {
      override async save(key: string, state: StoredScanState, _ttlSeconds?: number): Promise<void> {
        return super.save(key, state, 1);
      }
    }
    const memShortTtl = new ShortTtlStore();
    const ttl1 = await runScanLoop("testowner", "testrepo", {
      cursor: startCursor, head: HEAD, budgetMs: 3500, apiBase, chunkCommits: 1, store: memShortTtl,
    });
    if (ttl1.status !== "partial" || !ttl1.cursor) throw new Error("ttl inv1: expected partial");
    await sleep(1200); // the saved state expires
    const ttl2 = await runScanLoop("testowner", "testrepo", {
      cursor: ttl1.cursor, head: HEAD, apiBase, chunkCommits: 1, store: memShortTtl,
    });
    if (ttl2.status !== "done" || !ttl2.report) throw new Error("ttl inv2: expected done");
    outputsForRedaction.push(JSON.stringify(ttl2.report));
    check("ttl expiry: expired state → 1/3 secrets", ttl2.report.counts.secrets === 1);
    check("ttl expiry: honest limits line present", hasHonestLine(ttl2.report.limits));

    // --- 5h. The loss-repro control: advanceScan + assembleReport
    // directly (the POST-chunk caller shape) still reports 3/3 —
    // advanceScan is untouched, and the fix did not change it. ---
    detailDelayMs = 0;
    let cursorA: string | null = startCursor;
    const accumulated: SecretFinding[] = [];
    let chunksA = 0;
    while (cursorA) {
      chunksA++;
      const r = await advanceScan({ owner: "testowner", repo: "testrepo", cursor: cursorA, apiBase, chunkCommits: 1 });
      if (r.status === "done") throw new Error("Path A: unexpected done before assemble stage");
      accumulated.push(...r.chunkFindings);
      if (decodeCursor(r.cursor, "testowner", "testrepo").stage === "assemble") break;
      cursorA = r.cursor;
      if (chunksA > 10) throw new Error("Path A: did not reach assemble");
    }
    const reportA = await assembleReport(HEAD, {
      findings: accumulated, commitsScanned: 6, ok: true, method: "api", note: null,
    });
    outputsForRedaction.push(JSON.stringify(reportA));
    check("advanceScan untouched: caller-carried Path A still 3/3", reportA.counts.secrets === 3 && reportA.score === 23);
    detailDelayMs = 1000;

    // ================= 6. MCP fallback =================
    // --- 6a. tools/list: resume_scan takes an optional historyFindings. ---
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const mcpServer = createMcpServer();
    await mcpServer.connect(serverTransport);
    const mcpClient = new Client({ name: "gitsecure-test", version: "0.1.0" }, { capabilities: {} });
    await mcpClient.connect(clientTransport);
    const toolList = await mcpClient.listTools();
    const resumeTool = toolList.tools.find((t) => t.name === "resume_scan");
    const resumeProps = (resumeTool?.inputSchema as { properties?: Record<string, unknown> } | undefined)?.properties ?? {};
    check("mcp tools/list: resume_scan exists", !!resumeTool);
    check("mcp tools/list: resume_scan takes a cursor", "cursor" in resumeProps);
    check("mcp tools/list: resume_scan takes optional historyFindings", "historyFindings" in resumeProps);
    check("mcp tools/list: resume_scan description mentions passing findings back", /historyFindings/i.test(resumeTool?.description ?? ""));
    await mcpClient.close();
    await mcpServer.close();

    // --- 6b. stillRunningText echoes the accumulation. ---
    const echoText = stillRunningText("testowner", "testrepo", {
      status: "partial",
      cursor: "CURSOR-STRING",
      historyFindings: [goodFinding, { ...goodFinding, id: "discord-webhook-config-js-1", file: "config.js" }],
      progress: { step: "history", filesScanned: 3, filesTotal: 3, commitsScanned: 3, depsChecked: 0, depsTotal: 0, advisoriesDetailed: 0, advisoriesTotal: 0 },
    }, "Call resume_scan again with this cursor to continue it from the last finished chunk.");
    check("mcp echo: still-running text carries the cursor", echoText.includes("CURSOR-STRING"));
    check("mcp echo: still-running text echoes both findings", echoText.includes("discord-webhook-app-js-1") && echoText.includes("discord-webhook-config-js-1"));
    check("mcp echo: text tells the model to pass them back verbatim as historyFindings", /pass these back verbatim as historyFindings/i.test(echoText));
    const quietText = stillRunningText("testowner", "testrepo", {
      status: "partial",
      cursor: "CURSOR-STRING",
      historyFindings: [],
      progress: { step: "history", filesScanned: 3, filesTotal: 3, commitsScanned: 0, depsChecked: 0, depsTotal: 0, advisoriesDetailed: 0, advisoriesTotal: 0 },
    }, "Call resume_scan again with this cursor to continue it from the last finished chunk.");
    check("mcp echo: no findings → no accumulation block", !quietText.includes("Accumulated history findings"));

    // --- 6c. resume_scan end-to-end: with the fallback, 3/3. ---
    const mcpInv1 = await runScanLoop("testowner", "testrepo", {
      cursor: startCursor, head: HEAD, budgetMs: 3500, apiBase, chunkCommits: 1, store: new NoopStore(),
    });
    if (mcpInv1.status !== "partial" || !mcpInv1.cursor) throw new Error("mcp inv1: expected partial");
    const mcpResumed = await resumeScan(mcpInv1.cursor, { historyFindings: mcpInv1.historyFindings ?? [], apiBase, head: HEAD });
    const mcpText = (mcpResumed.content[0] as { text: string }).text;
    const mcpReport = JSON.parse(mcpText) as { counts: { secrets: number }; score: number; grade: string; limits: string[] };
    outputsForRedaction.push(mcpText);
    check("mcp resume_scan with historyFindings: 3/3 secrets", mcpReport.counts.secrets === 3, `${mcpReport.counts.secrets} secrets`);
    check("mcp resume_scan with historyFindings: 23/F, no honest line", mcpReport.score === 23 && mcpReport.grade === "F" && !hasHonestLine(mcpReport.limits));
    const mcpBare = await resumeScan(mcpInv1.cursor, { apiBase, head: HEAD });
    const mcpBareText = (mcpBare.content[0] as { text: string }).text;
    const mcpBareReport = JSON.parse(mcpBareText) as { counts: { secrets: number }; limits: string[] };
    outputsForRedaction.push(mcpBareText);
    check("mcp resume_scan without historyFindings: 1/3 + honest line (control)", mcpBareReport.counts.secrets === 1 && hasHonestLine(mcpBareReport.limits));
    const mcpBad = await resumeScan("!!!not-a-cursor!!!");
    check("mcp resume_scan with a bogus cursor is still a plain-English error", !!mcpBad.isError);

    // ================= 7. GET ?historyFindings= parser =================
    const toParam = (findings: unknown) => Buffer.from(JSON.stringify(findings), "utf8").toString("base64url");
    check("get param: null → []", parseHistoryFindingsParam(null).length === 0);
    check("get param: valid base64url JSON round-trips", JSON.stringify(parseHistoryFindingsParam(toParam([goodFinding]))) === JSON.stringify([goodFinding]));
    check("get param: malformed base64 → []", parseHistoryFindingsParam("!!!not-base64!!!").length === 0);
    check("get param: valid base64, non-JSON → []", parseHistoryFindingsParam(Buffer.from("hello", "utf8").toString("base64url")).length === 0);
    check("get param: valid JSON, non-array → []", parseHistoryFindingsParam(toParam({ x: 1 })).length === 0);
    const parsedMixed = parseHistoryFindingsParam(toParam([goodFinding, { type: "x", file: "y.js" }, "junk"]));
    check("get param: malformed entries dropped, good ones kept", parsedMixed.length === 1 && parsedMixed[0]?.id === goodFinding.id);
    const many = Array.from({ length: 30 }, (_, i) => ({ ...goodFinding, id: `f-${i}`, fragment: "x".repeat(400) }));
    check(
      "get param: oversized decoded JSON (>8 KB) → [] (URL-length limit, documented in the route)",
      parseHistoryFindingsParam(toParam(many)).length === 0,
      `${Buffer.byteLength(JSON.stringify(many), "utf8")} bytes decoded`,
    );
    check("get param: byte cap is 8192", MAX_GET_HISTORY_FINDINGS_BYTES === 8192);

    // ================= 8. Redaction =================
    const allOut = outputsForRedaction.join("\n");
    for (const hook of ALL_HOOKS) {
      check(`redaction: full invented secret never appears in any report output (${hook.slice(0, 18)}…)`, !leaksSecret(allOut, hook));
    }
    check("redaction: every stored/echoed fragment is redacted (< 12 chars)", outputsForRedaction.every((o) => {
      const parsed = JSON.parse(o) as { secrets?: { fragment: string }[] };
      return (parsed.secrets ?? []).every((f) => f.fragment.length < 12);
    }));
  } finally {
    globalThis.fetch = realFetch;
    upstashServer.closeAllConnections?.();
    ghServer.closeAllConnections?.();
    await new Promise<void>((resolve) => ghServer.close(() => resolve()));
    await new Promise<void>((resolve) => upstashServer.close(() => resolve()));
  }
}

main()
  .then(() => {
    console.log(failures === 0 ? `\nAll ${checks} Phase 17 Worker C checks passed.` : `\n${failures} of ${checks} check(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
