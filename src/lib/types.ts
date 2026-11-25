// GitSecure report types.
// Hard rule: a PublicReport contains score + counts ONLY. No file names,
// no line numbers, no secret fragments, no vulnerability IDs, no framework
// names/versions. A FullReport adds the detail, and is only served in
// owner mode (see src/lib/owner.ts).

export type Severity = "critical" | "high" | "medium" | "low" | "info";

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
}

export interface Framework {
  name: string;
  ecosystem: string; // "js" | "python" | "rust" | "config"
  version: string | null; // null = could not be determined (never guessed)
  versionSource: "lockfile" | "manifest" | "config" | "unknown";
  unpinned: boolean;
  sourceFile: string;
}

export interface Dependency {
  name: string;
  ecosystem: "npm" | "pypi" | "crates";
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
  vulnerabilities: number;
  frameworks: number;
  dependencies: number;
  postureIssues: number;
  filesScanned: number;
  historyCommitsScanned: number;
}

export interface PublicReport {
  kind: "public";
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
}

export interface FullReport extends Omit<PublicReport, "kind"> {
  kind: "full";
  secrets: SecretFinding[];
  frameworks: Framework[];
  dependencies: Dependency[];
  vulnerabilities: Vulnerability[];
  posture: PostureIssue[];
}

export type AnyReport = PublicReport | FullReport;
