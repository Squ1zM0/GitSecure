// Live scan progress - the shared shape for a running scan job.
//
// Client-safe on purpose: this module imports NOTHING (no scan.ts,
// no history.ts, no node: built-ins). The progress component runs in
// the browser, so importing scan.ts here would drag node:child_process
// (history.ts) into the client bundle and break the build. scan.ts
// and jobs.ts both import these types from here instead.
export type ScanStep = "files" | "history" | "dependencies" | "done";

/** One step of a running scan, for the job progress a client polls.
 *  Counts are exact counts of work actually done so far - never
 *  estimates, never a spinner pretending to know. `commitsScanned`
 *  stays 0 while the history step runs (history.ts has no progress
 *  callback yet) and jumps to the true count when that step returns. */
export interface ScanProgress {
  step: ScanStep;
  filesScanned: number;
  filesTotal: number;
  commitsScanned: number;
  depsChecked: number;
  depsTotal: number;
  advisoriesDetailed: number;
  advisoriesTotal: number;
}

export function emptyProgress(): ScanProgress {
  return { step: "files", filesScanned: 0, filesTotal: 0, commitsScanned: 0, depsChecked: 0, depsTotal: 0, advisoriesDetailed: 0, advisoriesTotal: 0 };
}

/** Plain-English label for a step, for the live progress line. */
export function stepLabel(step: ScanStep): string {
  switch (step) {
    case "files": return "Checking the current files for leaked secrets";
    case "history": return "Checking the full history, newest first";
    case "dependencies": return "Checking dependencies for known flaws";
    case "done": return "Scan complete";
  }
}

/** Phase 16 - honest history pace, from measured numbers only.
 *  `commitsDelta` is how many history commits this browser session
 *  has watched get checked, over `elapsedSec` seconds of driving the
 *  chunks. Returns commits/minute, or null when too little has been
 *  measured for the number to mean anything (under 100 commits or
 *  under 20 s - the early chunks include HEAD setup time, so an early
 *  rate would overstate the pace). Callers show the no-number wording
 *  ("large repos take longer") when this returns null - never an
 *  invented estimate. No total commit count exists before the scan
 *  finishes, so there is no ETA to compute, only the observed rate. */
export function historyRatePerMin(commitsDelta: number, elapsedSec: number): number | null {
  if (commitsDelta < 100 || elapsedSec < 20) return null;
  return Math.round((commitsDelta / elapsedSec) * 60);
}
