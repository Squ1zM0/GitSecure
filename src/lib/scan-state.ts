// GitSecure Phase 17, Part 1 - short-lived server store for
// in-progress history findings (see
// test-results/phase17/accumulation-design.md §4).
//
// THE HOLE IT CLOSES: runScanLoop() accumulates history findings
// in-process only. A scan whose history spans more than one
// serverless invocation silently drops every finding found before
// the last invocation - the finished report still claims the full
// history was checked, and the score is wrong (too high). The
// cursor must never carry findings (cursor.ts), and the GET / MCP
// callers discard the loop's returned findings, so findings need a
// ride across invocations. This store is that ride.
//
// INERT UNTIL PROVISIONED: the store activates ONLY when a
// Upstash Redis REST pair is present in the environment -
// UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN (Upstash
// console route), falling back to KV_REST_API_URL +
// KV_REST_API_TOKEN (Vercel Marketplace route, auto-injected).
// With no pair set, getScanStateStore() returns NoopStore and the
// scan behaves exactly as today, plus the honest limits line
// (chunks.ts) when earlier findings could not be recovered. No
// store, account, credential, or env var is created by this code -
// provisioning is Freddy's dashboard clicks (design §4.2).
//
// WHAT IS STORED: one document per scan, redacted fragments only -
// the same SecretFinding objects the finished report already
// returns (fragment is first 4 chars … last 2, never the full
// secret). Never a full secret, never file contents, never a live
// credential, never a finished report. Key:
//   gs:scan:v1:{owner}:{repo}:{headSha}
// The headSha in the key means a scan whose repo moved can never
// read another HEAD's findings. Value:
//   { v: 1, headSha, histScanned, historyFindings: SecretFinding[] }
// The store is touched at INVOCATION BOUNDARIES, not per chunk:
// one read at resume, one write per partial return, one delete at
// assemble. A finished scan leaves NOTHING in the store (delete at
// assemble is the primary cleanup); the 7-day TTL (EX 604800) is a
// backstop for abandoned scans only.
//
// DEGRADATION: a store failure (network error, non-2xx, timeout,
// over-quota) must NEVER fail a scan. Every store call inside the
// loop is best-effort (see chunks.ts): the loop catches, records
// the failure, and continues with in-process accumulation only -
// and the finished report carries the honest limits line saying
// earlier findings may be missing. A store that is absent or down
// degrades to today's behaviour with a stated limitation, never a
// silent misreport and never a 500.
//
// MONOTONIC GUARD: two writers to the same key (two clients
// resuming the same cursor) are last-write-wins on the whole
// document. save() closes the common case: a write is applied only
// if its histScanned >= the stored value, so a stale writer's
// smaller array cannot clobber a newer one. The check costs one
// extra read per save (still per invocation boundary, not per
// chunk). Findings are deterministic per (HEAD, commit set), so a
// further-along state's findings are the same findings the
// resuming scan would find by walking those commits itself. The
// residual race (two writers interleaving read-then-write) is real
// but narrow, and its worst case is the same silent loss the
// honest-note path is built to catch. True atomicity (server-side
// Lua / EVAL) is a possible hardening step - verify Upstash REST
// supports it before assuming it.
//
// CALLER-CARRIED FALLBACK (NOT a replacement for this store): the
// MCP resume_scan tool and the GET route also accept
// historyFindings from the caller (see mcp.ts, route.ts). That
// helps MCP callers when the store is unavailable and is the only
// fix available if the store is down - but a bare
// curl …?cursor= resume carries nothing, and a large findings set
// can never ride in a URL, so the fallback narrows the hole, it
// does not close it. The store is the fix; the fallback is additive.

import type { SecretFinding } from "./types";

/** 7-day TTL, in seconds - backstop only; delete at assemble is the
 *  primary cleanup, so a finished scan leaves nothing behind. */
export const SCAN_STATE_TTL_SECONDS = 604800;
/** Per-call timeout: a slow store must never eat a scan's budget
 *  (chunks cost seconds; the store costs tens of ms). */
export const SCAN_STATE_STORE_TIMEOUT_MS = 5000;
/** Safety bounds for a stored value. Worst case observed live
 *  (Phase 5): DefinitelyTyped, 403 secrets ≈ 400 KB. Both bounds
 *  sit far above that; anything past them is treated as "no stored
 *  state", never trusted, never a crash. */
export const SCAN_STATE_MAX_FINDINGS = 10_000;
export const SCAN_STATE_MAX_BYTES = 5_000_000;

export interface StoredScanState {
  v: 1;
  headSha: string;
  histScanned: number;
  historyFindings: SecretFinding[];
}

export interface ScanStateStore {
  load(key: string): Promise<StoredScanState | null>;
  save(key: string, state: StoredScanState, ttlSeconds?: number): Promise<void>;
  del(key: string): Promise<void>;
}

const SHA_RE = /^[0-9a-f]{40}$/;

/** Key for one scan's in-progress state. Owner/repo come from the
 *  cursor (already validated: NAME_RE) and headSha is 40-hex, so
 *  the key is safe to use verbatim. */
export function scanStateKey(owner: string, repo: string, headSha: string): string {
  return `gs:scan:v1:${owner}:${repo}:${headSha}`;
}

/** The assemble-stage shape filter (chunks.ts): an object with
 *  string type/file/fragment. Anything else is dropped, never
 *  trusted. Exported so the MCP / GET fallback params use the same
 *  filter as the store read path. */
export function filterHistoryFindings(value: unknown): SecretFinding[] {
  if (!Array.isArray(value)) return [];
  return (value as unknown[]).filter(
    (f): f is SecretFinding =>
      typeof f === "object" &&
      f !== null &&
      typeof (f as SecretFinding).type === "string" &&
      typeof (f as SecretFinding).file === "string" &&
      typeof (f as SecretFinding).fragment === "string",
  );
}

/** Validate a stored value on read. A corrupt, oversized, or
 *  unexpected value is "no stored state" - never a crash, never
 *  trusted. Malformed finding entries are dropped individually;
 *  the rest of the document still counts as recovered state. */
export function validateStoredState(value: unknown): StoredScanState | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const v = value as Record<string, unknown>;
  if (v.v !== 1) return null;
  if (typeof v.headSha !== "string" || !SHA_RE.test(v.headSha)) return null;
  if (typeof v.histScanned !== "number" || !Number.isInteger(v.histScanned) || v.histScanned < 0) return null;
  if (!Array.isArray(v.historyFindings)) return null;
  if (v.historyFindings.length > SCAN_STATE_MAX_FINDINGS) return null;
  if (Buffer.byteLength(JSON.stringify(value), "utf8") > SCAN_STATE_MAX_BYTES) return null;
  return {
    v: 1,
    headSha: v.headSha,
    histScanned: v.histScanned,
    historyFindings: filterHistoryFindings(v.historyFindings),
  };
}

/** Default when no env vars are set: every method resolves
 *  immediately. The scan behaves exactly as today (plus the honest
 *  limits line when a resume has nothing to recover from). */
export class NoopStore implements ScanStateStore {
  async load(_key: string): Promise<StoredScanState | null> {
    return null;
  }
  async save(_key: string, _state: StoredScanState, _ttlSeconds?: number): Promise<void> {
    return;
  }
  async del(_key: string): Promise<void> {
    return;
  }
}

/** Test-only in-memory store (never wired in production). Stores
 *  the JSON round-tripped, like a real store, so validation is
 *  exercised; honours TTL so expiry can be tested with a short
 *  default TTL. */
export class MemoryScanStateStore implements ScanStateStore {
  private map = new Map<string, { json: string; expiresAtMs: number }>();
  constructor(private defaultTtlSeconds: number = SCAN_STATE_TTL_SECONDS) {}
  async load(key: string): Promise<StoredScanState | null> {
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return null;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(entry.json) as unknown;
    } catch {
      return null;
    }
    return validateStoredState(parsed);
  }
  async save(key: string, state: StoredScanState, ttlSeconds?: number): Promise<void> {
    // Monotonic guard (see header): a stale writer's smaller array
    // must not clobber a newer one.
    const current = await this.load(key);
    if (current && current.histScanned > state.histScanned) return;
    this.map.set(key, {
      json: JSON.stringify(state),
      expiresAtMs: Date.now() + (ttlSeconds ?? this.defaultTtlSeconds) * 1000,
    });
  }
  async del(key: string): Promise<void> {
    this.map.delete(key);
  }
}

export interface UpstashRestConfig {
  url: string;
  token: string;
  timeoutMs?: number;
}

/** Upstash Redis via the REST API, plain fetch - no SDK, no new
 *  dependency. Body-style commands (POST / with a JSON array):
 *  ["GET", key], ["SET", key, json, "EX", ttl], ["DEL", key].
 *  Any non-2xx, error field, or timeout throws - the caller treats
 *  that as "store unavailable" and degrades, never as a scan
 *  failure. The token is a Bearer token with full access to one
 *  single-purpose database holding only redacted fragments; it is
 *  server-side only - never in client code, never committed. */
export class UpstashRestStore implements ScanStateStore {
  constructor(private config: UpstashRestConfig) {}

  private async command<T>(args: unknown[]): Promise<T> {
    const timeoutMs = this.config.timeoutMs ?? SCAN_STATE_STORE_TIMEOUT_MS;
    let res: Response;
    try {
      res = await fetch(this.config.url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.config.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(args),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      throw new Error(`Scan-state store unreachable: ${err instanceof Error ? err.message : "fetch failed"}`);
    }
    if (!res.ok) throw new Error(`Scan-state store answered ${res.status}`);
    let body: unknown;
    try {
      body = (await res.json()) as unknown;
    } catch {
      throw new Error("Scan-state store answered with unreadable JSON");
    }
    if (typeof body === "object" && body !== null && "error" in body && (body as { error?: unknown }).error != null) {
      throw new Error(`Scan-state store error: ${String((body as { error: unknown }).error)}`);
    }
    if (typeof body !== "object" || body === null || !("result" in body)) {
      throw new Error("Scan-state store answered without a result");
    }
    return (body as { result: T }).result;
  }

  async load(key: string): Promise<StoredScanState | null> {
    const result = await this.command<string | null>(["GET", key]);
    if (result == null) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(result) as unknown;
    } catch {
      return null;
    }
    return validateStoredState(parsed);
  }

  async save(key: string, state: StoredScanState, ttlSeconds: number = SCAN_STATE_TTL_SECONDS): Promise<void> {
    // Monotonic guard (see header): a stale writer's smaller array
    // must not clobber a newer one. Costs one extra read per save -
    // still per invocation boundary, not per chunk.
    const current = await this.load(key);
    if (current && current.histScanned > state.histScanned) return;
    const json = JSON.stringify(state);
    if (Buffer.byteLength(json, "utf8") > SCAN_STATE_MAX_BYTES) {
      throw new Error("Scan-state value too large to store");
    }
    const result = await this.command<string>(["SET", key, json, "EX", String(ttlSeconds)]);
    if (result !== "OK") throw new Error(`Scan-state store did not confirm the write (got ${String(result)})`);
  }

  async del(key: string): Promise<void> {
    await this.command<number>(["DEL", key]);
  }
}

/** Resolve the store for this process. Activates ONLY when a
 *  complete REST pair is present: prefer the Upstash-console names
 *  (UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN); fall back
 *  to the Vercel Marketplace names (KV_REST_API_URL /
 *  KV_REST_API_TOKEN, auto-injected). A half pair (URL without
 *  token, or vice versa) is the same as no pair - NoopStore.
 *  `env` is injectable so tests can prove the activation rule
 *  without touching process.env. */
export function getScanStateStore(env: NodeJS.ProcessEnv = process.env): ScanStateStore {
  const upstashUrl = env.UPSTASH_REDIS_REST_URL;
  const upstashToken = env.UPSTASH_REDIS_REST_TOKEN;
  if (upstashUrl && upstashToken) return new UpstashRestStore({ url: upstashUrl, token: upstashToken });
  const kvUrl = env.KV_REST_API_URL;
  const kvToken = env.KV_REST_API_TOKEN;
  if (kvUrl && kvToken) return new UpstashRestStore({ url: kvUrl, token: kvToken });
  return new NoopStore();
}
