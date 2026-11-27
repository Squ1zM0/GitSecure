// GitSecure report types.
// Phase 4: every caller gets the full report - the site only scans
// public repos, so the detail is information already public in the
// repo. There is no public-only report shape and no login flow.
// Hard rule (unchanged): a secret is never shown in full - redacted
// fragment only, never stored after the scan finishes, never live-validated.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Phase 10 triage verdicts. A finding is never removed - the verdict
 *  only annotates it. */
export type TriageVerdict = "likely-test-key" | "likely-genuine-leak" | "uncertain";

export interface SecretTriage {
  verdict: TriageVerdict;
  /** Signal ids that produced the verdict (see src/lib/triage.ts). */
  signals: string[];
  /** Plain-English explanation of the verdict, naming the signals. */
  explanation: string;
  /** The severity/confidence the triage assesses - the finding's own
   *  `severity`/`confidence` (the detector's) never change. Phase 12:
   *  the score IS computed from the triage verdict (test keys deduct
   *  nothing, uncertain deduct half, genuine / untriaged deduct full)
   *  - the Phase 10 rule that triage never changes the score was
   *  overturned by Freddy, 2026-11-26. */
  adjustedSeverity: Severity;
  adjustedConfidence: "high" | "medium" | "low";
  /** The Fix to show for this finding: the test-key Fix for a
   *  likely-test finding, the detector's Fix otherwise. */
  fix: string;
}

export interface SecretUsage {
  /** Non-test code that references this finding's identifier
   *  (variable/env name, key filename, or config key) - first 10. */
  referencedBy: { file: string; line: number }[];
  /** True total of non-test references (the list above is capped). */
  referencedByTotal: number;
  /** Test code that references the identifier - first 10. Test-only
   *  references do NOT count as "in use". */
  referencedByTests: { file: string; line: number }[];
  /** True total of test references (the list above is capped). */
  referencedByTestsTotal: number;
  /** True when an identifier was found to search for and nothing
   *  anywhere in the repo references it. False when references exist
   *  OR when no usable identifier could be extracted (then the lists
   *  are empty and nothing about liveness was determined). */
  deadEnd: boolean;
  /** History finding: usage was computed from the HEAD files only -
   *  the old commit's files are gone, so a reference that existed
   *  then but not now is not counted. */
  historyOnly?: boolean;
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
  /** Redacted fragment only - first 4 chars + ellipsis + last 2, never full. */
  fragment: string;
  fix: string;
  plainEnglish: string;
  /** Phase 10 triage annotation - present on every finding a scan
   *  produces (HEAD and history alike). */
  triage?: SecretTriage;
  /** Phase 11 usage annotation - whether anything in the repo still
   *  references this finding's identifier (see SecretUsage). Present
   *  when the scan could compute it; absent when no HEAD files were
   *  available to search (API / patch-fallback history paths). */
  usage?: SecretUsage;
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
  ecosystem: "npm" | "pypi" | "crates" | "go" | "ruby" | "php" | "java" | "dotnet" | "actions" | "pub";
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
  /** Phase 19: which check family produced this issue. */
  category?: "code-risk" | "actions" | "container" | "exposed-file" | "install-script" | "web-config" | "hygiene";
  /** Phase 19: file the issue was found in, when it comes from a file. */
  file?: string;
  /** Phase 19: 1-based line in that file, when known. */
  line?: number;
}

export interface ReportCounts {
  secrets: number;
  /** Phase 10: of counts.secrets, how many triaged as likely-test-key.
   *  They are still counted in `secrets`; Phase 12: they deduct
   *  nothing from the score (see ScoreDetail), uncertain findings
   *  deduct at half weight, genuine / untriaged findings at full
   *  weight. This number is the honest split, not a discount. */
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
 *  OSV-unavailable item - assemble adds that), and the counts the
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
  /** Which history path the scan starts on: "git" (git protocol).
   *  The chunked driver flips the cursor to "api" if the git path
   *  fails (e.g. a history pack too large to clone). Phase 15
   *  (worker D): no repo size is carried any more - the gates that
   *  needed it are streaming bounds now, so the scan no longer reads
   *  the REST repo-info call. */
  historyMethod: "git" | "api";
  /** Streaming HEAD mode only: true when some retainable config files
   *  could not be kept in memory (retained-bytes budget) - framework
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
  /** Phase 12: the full scoring breakdown - per-component deductions,
   *  per-verdict finding counts, and the would-be score under the old
   *  full-weight rule. Carried on every report (finished and
   *  provisional) so the API, report page, and MCP can never show a
   *  score that disagrees with the sections. */
  scoreDetail: import("./score").ScoreDetail;
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
   *  history / dependency checks are still streaming in - the score
   *  counts HEAD secrets + posture only and will change when the rest
   *  lands. Absent (or false) on a finished report. */
  provisional?: boolean;
}
