// Live scan progress (Phase 9) - client component.
//
// Phase 16: the report page renders this shell immediately, with no
// cursor - the page no longer awaits any scan server-side (that wait
// hit Vercel's 60 s ceiling on big repos and Safari reported "This
// page couldn't load"). This driver starts the scan itself through
// POST /api/scan/start (the HEAD chunk) and then drives it chunk by
// chunk through POST /api/scan/chunk, carrying the cursor forward -
// the server holds no state, so a restart, cold start, or a chunk
// landing on a different instance loses nothing. After every chunk it
// saves the cursor + accumulated results in sessionStorage (see
// resume.ts), so a reload or a closed tab resumes from the last
// completed chunk and says so plainly ("Resumed - picked up where it
// left off", with the counts so far). When the HEAD chunk is done the
// provisional HEAD report renders above the progress card, and history
// streams in underneath it - live counts, secrets found so far - until
// the assemble chunk returns the finished report, which swaps in
// without a reload.
//
// There is no lost-scan dead-end any more:
// a bad cursor or a moved HEAD restarts cleanly from the beginning
// (saved progress is discarded and the page reloads once), and any
// other failure offers a retry from the same cursor.
"use client";

import { useEffect, useRef, useState } from "react";
import { historyRatePerMin, stepLabel, type ScanProgress as ScanProgressType } from "@/lib/progress";
import { rateLimitPausedBody } from "@/lib/rate-limit";
import { scanErrorCopy, scanErrorRetryLabel, type ScanErrorKind } from "@/lib/scan-error-copy";
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
import RetryScanButton from "@/components/RetryScanButton";
import type { FullReport, HeadPartial, SecretFinding } from "@/lib/types";

function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}

/** Phase 15 (finding 3): a chunk failure must say WHY it failed and
 *  how far the scan got - a generic "try again" with no reason and no
 *  progress is a retry loop with no information. The driver already
 *  holds the numbers; the card shows them. */
type ChunkErrorKind = "rate-limit" | "network" | "other";
// The network/other copies are fixed; the rate-limit copy is computed
// at fail time from GitHub's reset time when the chunk route knew it
// (rateLimitPausedBody) - this entry is only the fallback when the
// reset time could not be read.
const CHUNK_ERROR_COPY: Record<ChunkErrorKind, string> = {
  "rate-limit": "GitHub's request limit was hit, so the scan paused here. The limit resets within the hour - retry then, and the scan picks up from the last finished chunk.",
  network: "The scan couldn't be reached - check your connection and try again. Nothing was lost: the scan picks up from the last finished chunk.",
  other: "GitHub didn't answer as expected. Try again in a bit - the scan picks up from the last finished chunk.",
};

/** Phase 16: kinds that end the scan with the full error page (same
 *  words the old server page used) instead of the retry card: the scan
 *  never got going, so there is no progress to resume from. Anything
 *  else - upstream / unknown, or a failure after progress was made -
 *  keeps the retry card, which says how far the scan got. */
const TERMINAL_ERROR_KINDS = ["not-found", "private", "rate-limit", "timeout", "bad-format", "head-moved"] as const;

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

/** Progress counts for a resumed scan, from the saved HEAD partial and
 *  the commits checked so far - so the card shows the retained
 *  progress the moment the page reloads, instead of zeros until the
 *  next chunk answers. Same step mapping the server uses for a
 *  partial (see progressFor in chunks.ts). */
function progressFromSaved(head: HeadPartial | null, commitsScanned: number, stage: string | null): ScanProgressType {
  return {
    step: head ? (stage === "assemble" ? "dependencies" : "history") : "files",
    filesScanned: head?.filesScanned ?? 0,
    filesTotal: head?.filesTotal ?? 0,
    commitsScanned,
    depsChecked: 0,
    depsTotal: 0,
    advisoriesDetailed: 0,
    advisoriesTotal: 0,
  };
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
  /** Null on a fresh visit (Phase 16: the page renders the shell with
   *  no cursor and the driver starts the scan itself). A non-null
   *  cursor resumes from it; "" is treated as null. */
  cursor: string | null;
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
  // Phase 16: a scan that failed before anything was scanned gets the
  // full error page (same words the old server page used), not the
  // retry card - there is no progress to resume from.
  const [terminalError, setTerminalError] = useState<{ kind: ScanErrorKind; resetAtMs: number | null } | null>(null);
  const [retryKey, setRetryKey] = useState(0);
  const startedRef = useRef(false);
  // Phase 16 - honest timing: when this browser session started
  // driving chunks, and how many history commits were already checked
  // at that point. The live rate below is the DELTA over the elapsed
  // driving time - never the server's pre-mount work divided by the
  // client-side clock, which would overstate the pace.
  const startedAtRef = useRef(Date.now());
  const baseCommitsRef = useRef(initial.commitsScanned);

  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    let stopped = false;

    const drive = async () => {
      // The shell carries no cursor any more (Phase 16: the page
      // renders immediately), so saved progress from this tab is
      // further ahead by definition whenever it exists - resume from
      // it and say so. The old "further ahead than the server's fresh
      // partial" comparison is gone with the server wait, and so is
      // the else branch that saved the empty initial state over real
      // saved progress whenever the saved scan had 0 history commits
      // (HEAD done, history not started): nothing is saved until the
      // first chunk answers now.
      let cursor: string | null = initialCursor || null;
      let head: HeadPartial | null = initialHead;
      let findings: SecretFinding[] = dedupeFindings(initialFindings);
      let scanned = initialScanned;
      const saved = loadProgress(sessionStorage, owner, repo);
      if (saved) {
        const savedHead = saved.head as HeadPartial;
        // A saved head is trusted only with its full shape: the chunk
        // route re-derives a bad head server-side, but a head missing
        // its arrays must never be sent at all - an older-build saved
        // head once reached assemble without them and the scan 500ed
        // at the dependencies step (live TechDirect, 2026-11-27). A
        // head that fails this check falls through to a fresh scan.
        const savedHeadUsable =
          typeof savedHead === "object" && savedHead !== null && typeof (savedHead as HeadPartial).headSha === "string" &&
          Array.isArray((savedHead as HeadPartial).secrets) && Array.isArray((savedHead as HeadPartial).dependencies) &&
          Array.isArray((savedHead as HeadPartial).frameworks) && Array.isArray((savedHead as HeadPartial).posture);
        if (savedHeadUsable) {
          cursor = saved.cursor;
          head = savedHead;
          findings = dedupeFindings(saved.historyFindings as SecretFinding[]);
          scanned = saved.historyScanned;
          // A finished report saved for this same HEAD renders
          // immediately - no re-scan.
          const savedReport = loadReport(sessionStorage, owner, repo);
          if (savedReport && savedReport.headSha === savedHead.headSha) {
            if (!stopped) setFinalReport(savedReport.report as FullReport);
            return;
          }
          if (!stopped) {
            // Show the retained progress at once - commits checked so
            // far, current stage, and the explicit resume line - so a
            // reload never sits on a bare spinner. The history pace
            // below must measure only THIS session's driving, so the
            // already-checked commits become the new baseline (see
            // baseCommitsRef).
            setResumed(resumedLine(scanned, findings.length));
            setSecretsFound(dedupeFindings([...(head.secrets ?? []), ...findings]).length);
            setProvisional(buildProvisionalReport(head, findings, scanned, cursorStage(cursor) === "assemble"));
            setProgress(progressFromSaved(head, scanned, cursorStage(cursor)));
            baseCommitsRef.current = scanned;
          }
        }
      } else {
        // No saved progress: a finished report from an earlier visit
        // still renders immediately - but only if the repo's HEAD has
        // not moved since it was saved (cheap tip check, one round
        // trip). A failed tip check never blocks the scan: it just
        // means the saved report cannot be proven current, so a fresh
        // scan starts below.
        const savedReport = loadReport(sessionStorage, owner, repo);
        if (savedReport) {
          try {
            const tipRes = await fetch(`/api/scan/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/tip`, { cache: "no-store" });
            if (tipRes.ok) {
              const tip = (await tipRes.json()) as { headSha?: unknown };
              if (typeof tip.headSha === "string" && tip.headSha === savedReport.headSha) {
                if (!stopped) setFinalReport(savedReport.report as FullReport);
                return;
              }
            } else if (tipRes.status === 404 || tipRes.status === 400) {
              // The repo is gone, private, or malformed: say so with
              // the same error page a fresh scan would show, instead
              // of re-scanning a repo that cannot be scanned.
              const data = (await tipRes.json().catch(() => null)) as { kind?: unknown } | null;
              const kind = typeof data?.kind === "string" && (TERMINAL_ERROR_KINDS as readonly string[]).includes(data.kind)
                ? (data.kind as ScanErrorKind)
                : "not-found";
              if (!stopped) setTerminalError({ kind, resetAtMs: null });
              return;
            }
          } catch {
            // Network failure on the tip check: fall through to a
            // fresh scan, which surfaces the real error if any.
          }
        }
      }

      let failures = 0;
      // A failure is terminal once it has failed 3 times - except a
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
      // Drive chunks until the assemble chunk returns the report. The
      // first chunk of a fresh scan runs through POST /api/scan/start
      // (the HEAD chunk - the chunk endpoint only continues a scan
      // from a cursor); every chunk after that through
      // POST /api/scan/chunk. Both answer the same partial shape, so
      // the loop treats them identically.
      for (;;) {
        if (stopped) return;
        let res: Response;
        const isStart = cursor === null;
        try {
          res = await fetch(isStart ? "/api/scan/start" : "/api/scan/chunk", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            cache: "no-store",
            body: JSON.stringify(isStart ? { owner, repo } : { cursor, head, historyFindings: findings }),
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
          // Read the error body once: the kind decides between the
          // full error page and the retry card. A terminal failure
          // before anything was scanned gets the error page, with the
          // same words the old server page used - a missing repo must
          // not masquerade as a transient retry. A failure after
          // progress was made keeps the retry card, which says how
          // far the scan got.
          let kind: string | null = null;
          let resetAtMs: number | null = null;
          try {
            const data = (await res.json()) as { kind?: unknown; resetAtMs?: unknown };
            if (typeof data.kind === "string") kind = data.kind;
            if (typeof data.resetAtMs === "number") resetAtMs = data.resetAtMs;
          } catch {
            // Unreadable body: fall through to the generic retry path.
          }
          const noProgressYet = head === null && scanned === 0 && findings.length === 0;
          if (kind !== null && noProgressYet && (TERMINAL_ERROR_KINDS as readonly string[]).includes(kind)) {
            if (!stopped) setTerminalError({ kind: kind as ScanErrorKind, resetAtMs });
            return;
          }
          if (res.status === 429) {
            // Phase 15 (rate-limit recovery): the chunk route carries
            // GitHub's reset time when it knew it - read it so the
            // card can say honestly how long to wait ("in about N
            // minutes") instead of a vague "few minutes". An
            // unreadable body falls back to the hourly wording.
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

  if (terminalError) {
    // Phase 16: the scan failed before anything was scanned, so there
    // is no progress to resume from - the full error page, with the
    // same words the old server page used, instead of the retry card.
    const { title, body } = scanErrorCopy(terminalError.kind, owner, repo, terminalError.resetAtMs);
    return (
      <div>
        <p className="back-link"><a href="/">← Scan another repo</a></p>
        <h1>{title}</h1>
        <div className="card error-card" role="alert">
          <p>{body}</p>
          <p><RetryScanButton label={scanErrorRetryLabel(terminalError.kind)} />{" "}<a className="button-link" href="/">Scan another repo</a></p>
        </div>
      </div>
    );
  }

  if (error) {
    // Phase 15 (finding 3): the card names the failure reason and the
    // progress reached - files / commits / secrets so far - so the
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

  // Phase 16 - live history pace, measured, never invented: commits
  // checked since this session started driving, over the seconds
  // spent driving. Null until enough has been measured (see
  // historyRatePerMin) - then the card says "large repos take
  // longer" with no number instead of guessing.
  const elapsedSec = Math.max(0, Math.floor((Date.now() - startedAtRef.current) / 1000));
  const historyRate = historyRatePerMin(progress.commitsScanned - baseCommitsRef.current, elapsedSec);

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
        {progress.step === "history" ? (
          <p className="muted">
            {historyRate !== null
              ? `History is the slow part on a big repo: ${formatCount(progress.commitsScanned)} commits checked so far, about ${formatCount(historyRate)} a minute - a repo with thousands of commits takes several minutes.`
              : "History is the slow part on a big repo - a repo with thousands of commits takes several minutes."}
          </p>
        ) : null}
        <p className="muted">
          This is a big repo, so the scan continues chunk by chunk - the report will appear here as soon as it is done. If you close this page, the scan picks up where it left off when you come back. There is nothing to click.
        </p>
      </div>
    </div>
  );
}
