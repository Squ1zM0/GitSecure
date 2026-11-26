// GitSecure report types.
// Phase 4: every caller gets the full report — the site only scans
// public repos, so the detail is information already public in the
// repo. There is no public-only report shape and no login flow.
// Hard rule (unchanged): a secret is never shown in full — redacted
// fragment only, never stored, never live-validated.

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
  vulnerabilities: number;
  frameworks: number;
  dependencies: number;
  postureIssues: number;
  filesScanned: number;
  historyCommitsScanned: number;
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
}
