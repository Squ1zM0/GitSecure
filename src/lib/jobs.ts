// Async scan jobs (Phase 8).
//
// Why: a Vercel serverless invocation ends after 60 s, but a big repo
// (DefinitelyTyped: ~30 s on the API alone, more with a cold history)
// does not fit in one invocation — and the old answer, a 55 s race
// that killed the scan with a 504, is gone. So a scan now runs as a
// JOB: the API (or the report page, or MCP) starts one, waits up to
// ~50 s for it (the fast path — TechDirect still answers in a single
// request, ~12 s), and if it is still running answers 202 with a job
// ID. The client polls GET /api/scan/jobs/{id} for live progress and
// the finished report.
//
// Job ID: crypto.randomUUID() — random, unguessable, and it carries no
// owner, repo, or secret fragment in it. A job ID can be shared
// freely; the worst it reveals is that a scan of some repo exists.
//
// Store: IN-MEMORY only (a Map in this module). No durable store, no
// paid service, no database — that is a deliberate Phase 8 choice, and
// it has a real limit you must know about: a job does NOT survive a
// cold start, a redeploy, or a poll that lands on a different serverless
// instance than the one that started the job. A poll for an unknown ID
// answers 404 with plain English ("that scan is no longer running here
// — start it again"), and the client restarts the scan. Finished jobs
// are kept for JOB_TTL_MS (10 minutes) so the report page can reload
// once the job is done without re-scanning, then dropped. That is the
// only sense in which GitSecure "stores" a report: in memory, for
// minutes, never on disk, never in a database. Secrets in a finished
// report are redacted fragments only, as always.
//
// Dedupe: one running job per owner/repo. Starting a scan while one
// is already running (or recently finished) returns the same job — so
// MCP get_report picks up a running scan instead of starting a second
// one, and a report-page reload does not re-scan.
//
// Background execution: the job's promise is started immediately and
// kept alive with Next.js after() by the route/page that started it
// (after() runs after the response, inside the same invocation). If
// after() is unavailable the detached promise still runs on a warm
// local server; on Vercel the after() registration is what keeps the
// job alive past the 202 response.

import { randomUUID } from "node:crypto";
import { scanRepo, validateOwnerRepo } from "./scan";
import type { ScanProgress } from "./progress";
import type { FullReport } from "./types";

export type JobStatus = "running" | "done" | "error";

export interface JobError {
  message: string;
  kind: string;
  status: number;
}

export interface ScanJob {
  id: string;
  owner: string;
  repo: string;
  status: JobStatus;
  progress: ScanProgress;
  startedAt: string;
  updatedAt: string;
  report?: FullReport;
  error?: JobError;
  /** The in-flight scan promise. Never serialised, never sent to a client. */
  promise: Promise<FullReport>;
}

/** Public snapshot of a job — what the poll endpoint returns. The
 *  report is included only when the job is done. */
export interface JobSnapshot {
  jobId: string;
  owner: string;
  repo: string;
  status: JobStatus;
  progress: ScanProgress;
  startedAt: string;
  updatedAt: string;
  report?: FullReport;
  error?: JobError;
}

export const FAST_PATH_WAIT_MS = 50_000;
const JOB_TTL_MS = 10 * 60_000;
const POLL_INTERVAL_MS = 250;

const jobs = new Map<string, ScanJob>();
const jobsByRepo = new Map<string, string>();

/** Test-only override for the finished-job TTL (scripts/test-jobs-phase8.ts). */
let ttlOverrideMs: number | null = null;
export function setJobTtlForTests(ms: number | null): void {
  ttlOverrideMs = ms;
}
function ttlMs(): number {
  return ttlOverrideMs ?? JOB_TTL_MS;
}

function evictExpired(): void {
  for (const [id, job] of jobs) {
    if (job.status !== "running" && Date.now() - new Date(job.updatedAt).getTime() > ttlMs()) {
      jobs.delete(id);
      if (jobsByRepo.get(`${job.owner}/${job.repo}`) === id) jobsByRepo.delete(`${job.owner}/${job.repo}`);
    }
  }
}

export function getJob(id: string): ScanJob | undefined {
  evictExpired();
  return jobs.get(id);
}

export function jobSnapshot(job: ScanJob): JobSnapshot {
  const snap: JobSnapshot = {
    jobId: job.id,
    owner: job.owner,
    repo: job.repo,
    status: job.status,
    progress: { ...job.progress },
    startedAt: job.startedAt,
    updatedAt: job.updatedAt,
  };
  if (job.status === "done" && job.report) snap.report = job.report;
  if (job.status === "error" && job.error) snap.error = job.error;
  return snap;
}

export type ScanRunner = (
  owner: string,
  repo: string,
  onProgress: (p: ScanProgress) => void,
) => Promise<FullReport>;

function defaultRunner(owner: string, repo: string, onProgress: (p: ScanProgress) => void): Promise<FullReport> {
  // Phase 8: no OSV budgets — every pinned dep is queried and every
  // advisory gets full detail inside the background job.
  return scanRepo(owner, repo, { onProgress, osv: { queryBudgetMs: null, detailBudgetMs: null } });
}

/** Start a scan job for owner/repo, or return the job already running
 *  (or recently finished) for it. `runner` exists only so tests can
 *  drive the job/poll path without the network; production callers
 *  never pass it. Throws ScanError (400) for a bad owner/repo name. */
export function getOrStartJob(owner: string, repo: string, runner: ScanRunner = defaultRunner): ScanJob {
  validateOwnerRepo(owner, repo);
  evictExpired();
  const key = `${owner}/${repo}`;
  const existingId = jobsByRepo.get(key);
  if (existingId) {
    const existing = jobs.get(existingId);
    if (existing) return existing;
    jobsByRepo.delete(key);
  }
  const job: ScanJob = {
    id: randomUUID(),
    owner,
    repo,
    status: "running",
    progress: { step: "files", filesScanned: 0, filesTotal: 0, commitsScanned: 0, depsChecked: 0, depsTotal: 0, advisoriesDetailed: 0, advisoriesTotal: 0 },
    startedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    promise: Promise.resolve() as unknown as Promise<FullReport>,
  };
  job.promise = runner(owner, repo, (p) => {
    job.progress = { ...p };
    job.updatedAt = new Date().toISOString();
  }).then(
    (report) => {
      job.status = "done";
      job.report = report;
      job.progress = { ...job.progress, step: "done", filesScanned: report.counts.filesScanned, commitsScanned: report.counts.historyCommitsScanned };
      job.updatedAt = new Date().toISOString();
      return report;
    },
    (err: unknown) => {
      const e = err as { message?: string; kind?: string; status?: number };
      job.status = "error";
      job.error = {
        message: typeof e?.message === "string" ? e.message : "Scan failed. Try again in a bit.",
        kind: typeof e?.kind === "string" ? e.kind : "unknown",
        status: typeof e?.status === "number" ? e.status : 500,
      };
      job.updatedAt = new Date().toISOString();
      throw err;
    },
  );
  // The promise's rejection is handled by waiters; keep an empty catch
  // attached so an un-awaited job does not surface as unhandled.
  job.promise.catch(() => undefined);
  jobs.set(job.id, job);
  jobsByRepo.set(key, job.id);
  return job;
}

/** Wait for a job to reach a terminal state, up to waitMs. Returns the
 *  job as it stands when the wait ends — running, done, or error. */
export async function waitForJob(job: ScanJob, waitMs: number): Promise<ScanJob> {
  const deadline = Date.now() + waitMs;
  for (;;) {
    if (job.status !== "running") return job;
    if (Date.now() >= deadline) return job;
    await new Promise((r) => setTimeout(r, Math.min(POLL_INTERVAL_MS, Math.max(0, deadline - Date.now()))));
  }
}
