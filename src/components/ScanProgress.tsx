// Live scan progress (Phase 9) — client component.
//
// The report page renders this when a scan is still running after the
// ~50 s server fast path. It drives the scan chunk by chunk through
// POST /api/scan/chunk, carrying the cursor forward — the server holds
// no state, so a restart, cold start, or a chunk landing on a
// different instance loses nothing. After every chunk it saves the
// cursor + accumulated results in sessionStorage (see resume.ts), so
// a reload or a closed tab resumes from the last completed chunk and
// says so plainly ("Resumed — picked up where it left off"). When the
// HEAD chunk is done the provisional HEAD report renders above the
// progress card, and history streams in underneath it — live counts,
// secrets found so far — until the assemble chunk returns the finished
// report, which swaps in without a reload.
//
// There is no lost-scan dead-end any more:
// a bad cursor or a moved HEAD restarts cleanly from the beginning
// (saved progress is discarded and the page reloads once), and any
// other failure offers a retry from the same cursor.
"use client";

import { useEffect, useRef, useState } from "react";
import { stepLabel, type ScanProgress as ScanProgressType } from "@/lib/progress";
import { rateLimitPausedBody } from "@/lib/rate-limit";
import { buildProvisionalReport } from "@/lib/provisional";
import {
  clearProgress,
  clearReport,
  loadProgress,
  loadReport,
  resumedLine,
  saveProgress,
  saveReport,
} from "@/lib/resume";
import ReportView from "@/components/ReportView";
import type { FullReport, HeadPartial, SecretFinding } from "@/lib/types";

function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}

/** Phase 15 (finding 3): a chunk failure must say WHY it failed and
 *  how far the scan got — a generic "try again" with no reason and no
 *  progress is a retry loop with no information. The driver already
 *  holds the numbers; the card shows them. */
type ChunkErrorKind = "rate-limit" | "network" | "other";
// The network/other copies are fixed; the rate-limit copy is computed
// at fail time from GitHub's reset time when the chunk route knew it
// (rateLimitPausedBody) — this entry is only the fallback when the
// reset time could not be read.
const CHUNK_ERROR_COPY: Record<ChunkErrorKind, string> = {
  "rate-limit": "GitHub's request limit was hit, so the scan paused here. The limit resets within the hour — retry then, and the scan picks up from the last finished chunk.",
  network: "The scan couldn't be reached — check your connection and try again. Nothing was lost: the scan picks up from the last finished chunk.",
  other: "GitHub didn't answer as expected. Try again in a bit — the scan picks up from the last finished chunk.",
};

function dedupeKey(s: SecretFinding): string {
  return `${s.type}:${s.file}:${s.line}:${s.fragment}:${s.commit}`;
}

function dedupeFindings(list: SecretFinding[]): SecretFinding[] {
  const seen = new Set<string>();
  return list.filter((s) => {
    const key = dedupeKey(s);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Lenient cursor read, just to learn the pinned HEAD sha for the
 *  saved-report check. Any failure means "unknown" — never a crash. */
function cursorHeadSha(cursor: string): string | null {
  try {
    const b64 = cursor.replace(/-/g, "+").replace(/_/g, "/");
    const json = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    const parsed = JSON.parse(json) as { headSha?: unknown };
    return typeof parsed.headSha === "string" ? parsed.headSha : null;
  } catch {
    return null;
  }
}

/** Lenient cursor read for the stage ("history" | "assemble"), so a
 *  resumed provisional report says whether history was already done. */
function cursorStage(cursor: string): string | null {
  try {
    const b64 = cursor.replace(/-/g, "+").replace(/_/g, "/");
    const json = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    const parsed = JSON.parse(json) as { stage?: unknown };
    return typeof parsed.stage === "string" ? parsed.stage : null;
  } catch {
    return null;
  }
}

type ChunkResponse =
  | { status: "partial"; cursor: string; partial: { head: HeadPartial | null; historyScanned: number; historyComplete: boolean; historyStopped: string | null }; chunkFindings: SecretFinding[]; progress: ScanProgressType; note: string | null }
  | { status: "done"; report: FullReport };

export default function ScanProgress({
  owner,
  repo,
  cursor: initialCursor,
  head: initialHead,
  historyFindings: initialFindings,
  historyScanned: initialScanned,
  initial,
  provisional: initialProvisional,
}: {
  owner: string;
  repo: string;
  cursor: string;
  head: HeadPartial | null;
  historyFindings: SecretFinding[];
  historyScanned: number;
  initial: ScanProgressType;
  provisional: FullReport | null;
}) {
  const [progress, setProgress] = useState<ScanProgressType>(initial);
  const [provisional, setProvisional] = useState<FullReport | null>(initialProvisional);
  const [finalReport, setFinalReport] = useState<FullReport | null>(null);
  const [resumed, setResumed] = useState<string | null>(null);
  const [secretsFound, setSecretsFound] = useState<number>(() => dedupeFindings([...(initialHead?.secrets ?? []), ...initialFindings]).length);
  const [error, setError] = useState<{ kind: ChunkErrorKind; message: string } | null>(null);
  const [retryKey, setRetryKey] = useState(0);
  const startedRef = useRef(false);

  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    let stopped = false;

    const drive = async () => {
      // 1. A finished report saved from an earlier visit, for the same
      // HEAD, renders immediately — no re-scan.
      const savedReport = loadReport(sessionStorage, owner, repo);
      const headSha = cursorHeadSha(initialCursor);
      if (savedReport && headSha && savedReport.headSha === headSha) {
        const report = savedReport.report as FullReport;
        if (!stopped) setFinalReport(report);
        return;
      }
      // 2. Saved progress further ahead than the server's fresh
      // partial wins — resume from it, and say so.
      let cursor = initialCursor;
      let head: HeadPartial | null = initialHead;
      let findings: SecretFinding[] = dedupeFindings(initialFindings);
      let scanned = initialScanned;
      const saved = loadProgress(sessionStorage, owner, repo);
      if (saved && saved.historyScanned > initialScanned) {
        const savedHead = saved.head as HeadPartial;
        if (typeof savedHead === "object" && savedHead !== null && typeof (savedHead as HeadPartial).headSha === "string") {
          cursor = saved.cursor;
          head = savedHead;
          findings = dedupeFindings(saved.historyFindings as SecretFinding[]);
          scanned = saved.historyScanned;
          if (!stopped) {
            setResumed(resumedLine(scanned, findings.length));
            setSecretsFound(dedupeFindings([...(head.secrets ?? []), ...findings]).length);
            setProvisional(buildProvisionalReport(head, findings, scanned, cursorStage(cursor) === "assemble"));
          }
        }
      } else {
        saveProgress(sessionStorage, owner, repo, { cursor, head, historyFindings: findings, historyScanned: scanned });
      }

      // 3. Drive chunks until the assemble chunk returns the report.
      let failures = 0;
      // A failure is terminal once it has failed 3 times — except a
      // rate limit, which no quick retry will clear, so it fails
      // fast on the first 429 instead of burning three attempts.
      // `message` overrides the fixed copy (the rate-limit copy is
      // computed from GitHub's reset time when the route knew it).
      const fail = (kind: ChunkErrorKind, message?: string): boolean => {
        failures++;
        if (kind === "rate-limit" || failures >= 3) {
          if (!stopped) setError({ kind, message: message ?? CHUNK_ERROR_COPY[kind] });
          return true;
        }
        return false;
      };
      for (;;) {
        if (stopped) return;
        let res: Response;
        try {
          res = await fetch("/api/scan/chunk", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            cache: "no-store",
            body: JSON.stringify({ cursor, head, historyFindings: findings }),
          });
        } catch {
          if (fail("network")) return;
          await new Promise((r) => setTimeout(r, 2000));
          continue;
        }
        if (res.status === 400 || res.status === 409) {
          // Bad cursor, or the repo moved: discard saved progress and
          // start a fresh scan for the current HEAD.
          clearProgress(sessionStorage, owner, repo);
          clearReport(sessionStorage, owner, repo);
          window.location.reload();
          return;
        }
        if (!res.ok) {
          if (res.status === 429) {
            // Phase 15 (rate-limit recovery): the chunk route carries
            // GitHub's reset time when it knew it — read it so the
            // card can say honestly how long to wait ("in about N
            // minutes") instead of a vague "few minutes". An
            // unreadable body falls back to the hourly wording.
            let resetAtMs: number | null = null;
            try {
              const data = (await res.json()) as { resetAtMs?: unknown };
              if (typeof data.resetAtMs === "number") resetAtMs = data.resetAtMs;
            } catch {
              // Fall through with resetAtMs null.
            }
            if (fail("rate-limit", rateLimitPausedBody(resetAtMs))) return;
          } else {
            if (fail("other")) return;
          }
          await new Promise((r) => setTimeout(r, 2000));
          continue;
        }
        failures = 0;
        const data = (await res.json()) as ChunkResponse;
        if (stopped) return;
        if (data.status === "done") {
          saveReport(sessionStorage, owner, repo, data.report, data.report.commit);
          clearProgress(sessionStorage, owner, repo);
          setFinalReport(data.report);
          return;
        }
        cursor = data.cursor;
        if (data.partial.head) head = data.partial.head;
        findings = dedupeFindings([...findings, ...data.chunkFindings]);
        scanned = data.partial.historyScanned;
        setProgress(data.progress);
        setSecretsFound(dedupeFindings([...(head?.secrets ?? []), ...findings]).length);
        if (head) {
          setProvisional(buildProvisionalReport(head, findings, scanned, data.partial.historyComplete));
        }
        saveProgress(sessionStorage, owner, repo, { cursor, head, historyFindings: findings, historyScanned: scanned });
      }
    };
    void drive();
    return () => {
      stopped = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [retryKey]);

  if (finalReport) {
    return <ReportView report={finalReport} />;
  }

  if (error) {
    // Phase 15 (finding 3): the card names the failure reason and the
    // progress reached — files / commits / secrets so far — so the
    // user can judge whether retrying will help. The provisional
    // report below renders with its banner switched to "paused"
    // (finding 3a), never "still running".
    const progressBits: string[] = [];
    if (progress.filesScanned > 0) {
      progressBits.push(
        progress.filesTotal > 0
          ? `${formatCount(progress.filesScanned)} of ${formatCount(progress.filesTotal)} files scanned`
          : `${formatCount(progress.filesScanned)} files scanned`,
      );
    }
    if (progress.commitsScanned > 0) progressBits.push(`${formatCount(progress.commitsScanned)} history commits checked`);
    if (secretsFound > 0) progressBits.push(`${formatCount(secretsFound)} possible leaked secret${secretsFound === 1 ? "" : "s"} found so far`);
    return (
      <div>
        <p className="back-link"><a href="/">← Scan another repo</a></p>
        <h1>Couldn&apos;t scan {owner}/{repo}</h1>
        <div className="card error-card" role="alert">
          <p>{error.message}</p>
          {progressBits.length > 0 ? <p>So far: {progressBits.join(" · ")}.</p> : null}
          <p>
            <button
              className="button-link"
              type="button"
              onClick={() => {
                setError(null);
                startedRef.current = false;
                setRetryKey((k) => k + 1);
              }}
            >
              Retry from where it left off
            </button>{" "}
            <a className="button-link" href="/">Scan another repo</a>
          </p>
        </div>
        {provisional ? <ReportView report={provisional} paused /> : null}
      </div>
    );
  }

  return (
    <div>
      {provisional ? <ReportView report={provisional} /> : (
        <>
          <p className="back-link"><a href="/">← Scan another repo</a></p>
          <h1>Scanning {owner}/{repo}…</h1>
        </>
      )}
      <div className="card" role="status" aria-live="polite">
        {resumed ? <p><b>{resumed}</b></p> : null}
        <p className="scan-status">
          <span className="spinner" aria-hidden="true" />
          <span><b>{stepLabel(progress.step)}…</b></span>
        </p>
        <ul className="loading-steps">
          <li>
            <span className="step-dot" aria-hidden="true" />
            {progress.filesTotal > 0
              ? `${formatCount(progress.filesScanned)} of ${formatCount(progress.filesTotal)} files scanned`
              : `${formatCount(progress.filesScanned)} files scanned so far`}
          </li>
          <li>
            <span className="step-dot" aria-hidden="true" />
            {progress.commitsScanned > 0
              ? `${formatCount(progress.commitsScanned)} history commits checked`
              : "History not checked yet"}
          </li>
          <li>
            <span className="step-dot" aria-hidden="true" />
            {secretsFound > 0
              ? `${formatCount(secretsFound)} possible leaked secret${secretsFound === 1 ? "" : "s"} found so far`
              : "No leaked secrets found so far"}
          </li>
          <li>
            <span className="step-dot" aria-hidden="true" />
            {progress.depsTotal > 0
              ? `${formatCount(progress.depsChecked)} of ${formatCount(progress.depsTotal)} dependencies checked for known flaws`
              : progress.step === "dependencies"
                ? "Checking dependencies for known flaws"
                : "Dependencies not checked yet"}
          </li>
        </ul>
        <p className="muted">
          This is a big repo, so the scan continues chunk by chunk — the report will appear here as soon as it is done. If you close this page, the scan picks up where it left off when you come back. There is nothing to click.
        </p>
      </div>
    </div>
  );
}
