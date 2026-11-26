// GitSecure report types.
// Phase 4: every caller gets the full report — the site only scans
// public repos, so the detail is information already public in the
// repo. There is no public-only report shape and no login flow.
// Hard rule (unchanged): a secret is never shown in full — redacted
// fragment only, never stored, never live-validated.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Phase 10 triage verdicts. A finding is never removed — the verdict
 *  only annotates it. */
export type TriageVerdict = "likely-test-key" | "likely-genuine-leak" | "uncertain";

export interface SecretTriage {
  verdict: TriageVerdict;
  /** Signal ids that produced the verdict (see src/lib/triage.ts). */
  signals: string[];
  /** Plain-English explanation of the verdict, naming the signals. */
  explanation: string;
  /** The severity/confidence the triage assesses — the finding's own
   *  `severity`/`confidence` (the detector's) never change, and the
   *  score is always computed from the detector severity (see
   *  GITSECURE.md: triage must never inflate the score). */
  adjustedSeverity: Severity;
  adjustedConfidence: "high" | "medium" | "low";
  /** The Fix to show for this finding: the test-key Fix for a
   *  likely-test finding, the detector's Fix otherwise. */
  fix: string;
}

export interface SecretFinding {
  id: string;
  type: string; // e.g. "discord-webhook"
  title: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  file: string;
  line: number;
  commit: string | null; // "HEAD" or a commit sha
  /** Redacted fragment only — first 4 chars + ellipsis + last 2, never full. */
  fragment: string;
  fix: string;
  plainEnglish: string;
  /** Phase 10 triage annotation — present on every finding a scan
   *  produces (HEAD and history alike). */
  triage?: SecretTriage;
}

export interface Framework {
  name: string;
  ecosystem: string; // "js" | "python" | "rust" | "go" | "ruby" | "php" | "java" | "dotnet" | "config" | "docker" | "kubernetes" | "terraform" | "actions"
  version: string | null; // null = could not be determined (never guessed)
  versionSource: "lockfile" | "manifest" | "config" | "unknown";
  unpinned: boolean;
  sourceFile: string;
}

export interface Dependency {
  name: string;
  ecosystem: "npm" | "pypi" | "crates" | "go" | "ruby" | "php" | "java" | "dotnet" | "actions";
  version: string | null;
  direct: boolean;
  sourceFile: string;
}

export interface Vulnerability {
  id: string; // CVE / GHSA / OSV / RUSTSEC id
  packageName: string;
  ecosystem: string;
  installedVersion: string | null;
  fixedVersion: string | null;
  severity: Severity;
  summary: string;
  plainEnglish: string;
  upgrade: string;
}

export interface PostureIssue {
  id: string;
  title: string;
  severity: Severity;
  detail: string;
  fix: string;
}

export interface ReportCounts {
  secrets: number;
  /** Phase 10: of counts.secrets, how many triaged as likely-test-key.
   *  They are still counted in `secrets` and still deduct their
   *  detector severity from the score — this is the honest split, not
   *  a discount. */
  testKeySecrets: number;
  vulnerabilities: number;
  frameworks: number;
  dependencies: number;
  postureIssues: number;
  filesScanned: number;
  historyCommitsScanned: number;
}

/** The HEAD chunk's result (Phase 9). Everything the scan learns from
 *  the current files, before history or the dependency flaw check run:
 *  HEAD secrets, frameworks, dependencies, posture (without the
 *  OSV-unavailable item — assemble adds that), and the counts the
 *  report needs. The client keeps this in sessionStorage between
 *  chunks; the server never stores it. */
export interface HeadPartial {
  owner: string;
  repo: string;
  branch: string;
  headSha: string;
  filesScanned: number;
  filesTotal: number;
  treeTruncated: boolean;
  tarballFallback: boolean;
  secrets: SecretFinding[];
  frameworks: Framework[];
  dependencies: Dependency[];
  posture: PostureIssue[];
  unpinnedCount: number;
  repoSizeKb: number;
  /** Which history path the scan will use ("git" for repos small enough
   *  to clone, "api" for repos above the clone size gate). */
  historyMethod: "git" | "api";
  /** Streaming HEAD mode only: true when some retainable config files
   *  could not be kept in memory (retained-bytes budget) — framework
   *  detection may be incomplete, though every file was still checked
   *  for secrets. The report says so. */
  retainedIncomplete: boolean;
}

export interface FullReport {
  kind: "full";
  repo: string;
  owner: string;
  branch: string;
  commit: string;
  score: number;
  grade: string;
  counts: ReportCounts;
  summary: string;
  scannedAt: string;
  historyDepth: string;
  limits: string[];
  secrets: SecretFinding[];
  frameworks: Framework[];
  dependencies: Dependency[];
  vulnerabilities: Vulnerability[];
  posture: PostureIssue[];
  /** Phase 9: true on the provisional report the page shows while
   *  history / dependency checks are still streaming in — the score
   *  counts HEAD secrets + posture only and will change when the rest
   *  lands. Absent (or false) on a finished report. */
  provisional?: boolean;
}
