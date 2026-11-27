// Browser progress persistence (Phase 9) - client-safe, imports nothing.
//
// The server holds no scan job, so the BROWSER is where a scan's
// partial results live between requests: the cursor, the HEAD partial,
// and the history findings accumulated so far are saved in
// sessionStorage after every chunk. A page reload, a closed tab, or a
// server restart loses nothing - the report page resumes from the last
// completed chunk instead of starting over, and says so plainly:
// "Resumed - picked up where it left off".
//
// sessionStorage (not localStorage) is deliberate: a scan belongs to
// this tab's visit. Closing the tab ends the visit; reopening the repo
// later starts a fresh scan for the repo's current HEAD. The finished
// report is saved too, so a reload after a completed scan shows the
// finished report immediately without re-scanning.
//
// This module only knows shapes, never the scanner: `head` and
// `historyFindings` are opaque JSON (validated as object/array on load).
// Anything malformed in storage is treated as "no saved progress" -
// storage is untrusted input, never a crash.

export interface SavedProgress {
  cursor: string;
  head: unknown;
  historyFindings: unknown[];
  historyScanned: number;
  savedAt: string;
}

export interface SavedReport {
  report: unknown;
  headSha: string;
  savedAt: string;
}

export function progressKey(owner: string, repo: string): string {
  return `gitsecure:progress:${owner}/${repo}`;
}

export function reportKey(owner: string, repo: string): string {
  return `gitsecure:report:${owner}/${repo}`;
}

/** Minimal Storage shape, so tests can pass a fake. */
export interface ProgressStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export function saveProgress(
  storage: ProgressStorage,
  owner: string,
  repo: string,
  data: Omit<SavedProgress, "savedAt">,
): void {
  try {
    storage.setItem(progressKey(owner, repo), JSON.stringify({ ...data, savedAt: new Date().toISOString() }));
  } catch {
    // Storage full or unavailable (private mode): the scan still works,
    // it just won't survive a reload. Never crash the page for this.
  }
}

export function loadProgress(storage: ProgressStorage, owner: string, repo: string): SavedProgress | null {
  let raw: string | null;
  try {
    raw = storage.getItem(progressKey(owner, repo));
  } catch {
    return null;
  }
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (typeof parsed.cursor !== "string" || parsed.cursor.length === 0) return null;
    if (typeof parsed.head !== "object" || parsed.head === null) return null;
    if (!Array.isArray(parsed.historyFindings)) return null;
    if (typeof parsed.historyScanned !== "number" || parsed.historyScanned < 0) return null;
    return {
      cursor: parsed.cursor,
      head: parsed.head,
      historyFindings: parsed.historyFindings,
      historyScanned: parsed.historyScanned,
      savedAt: typeof parsed.savedAt === "string" ? parsed.savedAt : "",
    };
  } catch {
    return null;
  }
}

export function clearProgress(storage: ProgressStorage, owner: string, repo: string): void {
  try {
    storage.removeItem(progressKey(owner, repo));
  } catch {
    // Ignore - clearing is best-effort.
  }
}

export function saveReport(
  storage: ProgressStorage,
  owner: string,
  repo: string,
  report: unknown,
  headSha: string,
): void {
  try {
    storage.setItem(reportKey(owner, repo), JSON.stringify({ report, headSha, savedAt: new Date().toISOString() }));
  } catch {
    // Storage full or unavailable: the report is still on screen.
  }
}

export function loadReport(storage: ProgressStorage, owner: string, repo: string): SavedReport | null {
  let raw: string | null;
  try {
    raw = storage.getItem(reportKey(owner, repo));
  } catch {
    return null;
  }
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (typeof parsed.report !== "object" || parsed.report === null) return null;
    if (typeof parsed.headSha !== "string") return null;
    return {
      report: parsed.report,
      headSha: parsed.headSha,
      savedAt: typeof parsed.savedAt === "string" ? parsed.savedAt : "",
    };
  } catch {
    return null;
  }
}

export function clearReport(storage: ProgressStorage, owner: string, repo: string): void {
  try {
    storage.removeItem(reportKey(owner, repo));
  } catch {
    // Ignore - clearing is best-effort.
  }
}

/** The plain-English resume line the page shows when it picks up saved
 *  progress: what was already done, so the user can see nothing was
 *  lost. Pure function of the counts, so tests can prove the copy. */
export function resumedLine(historyScanned: number, historyFindings: number): string {
  const commits =
    historyScanned === 1 ? "1 history commit" : `${historyScanned.toLocaleString("en-US")} history commits`;
  const findings =
    historyFindings === 1 ? "1 secret found so far" : `${historyFindings.toLocaleString("en-US")} secrets found so far`;
  return `Resumed - picked up where it left off (${commits} checked, ${findings}).`;
}
