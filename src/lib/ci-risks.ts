// CI pipeline risks beyond GitHub Actions (Phase 20).
// Line based, same shape as code-risks.ts: a detector flags a
// dangerous pattern in a script step, with file, line, severity,
// and a short fix. A constant or a system variable the pipeline
// itself sets is never a finding; only values a merge request or
// trigger author can control count as tainted input.

import type { PostureIssue, Severity } from "./types";

type CiSystem = "gitlab" | "circleci" | "azure" | "bitbucket" | "jenkins";

function systemOf(path: string): CiSystem | null {
  const base = path.split("/").pop() ?? path;
  if (base === ".gitlab-ci.yml" || base === ".gitlab-ci.yaml") return "gitlab";
  if (path.includes(".circleci/config.yml") || path.includes(".circleci/config.yaml")) return "circleci";
  if (/^azure-pipelines[^/]*\.ya?ml$/.test(base)) return "azure";
  if (base === "bitbucket-pipelines.yml" || base === "bitbucket-pipelines.yaml") return "bitbucket";
  if (base === "Jenkinsfile" || base.endsWith(".jenkinsfile") || base.startsWith("Jenkinsfile.")) return "jenkins";
  return null;
}

const SECRET_NAME = /(TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)/i;

// Values a merge request or trigger author can control, per system.
const USER_CONTROLLED: Record<CiSystem, RegExp> = {
  gitlab: /\$CI_MERGE_REQUEST_[A-Z_]+|\$\{CI_MERGE_REQUEST_[A-Z_]+\}/,
  circleci: /<<\s*pipeline\.parameters\.[^>]+>>/,
  azure: /\$\{\{\s*parameters\.[^}]+\}\}|\$\(\s*parameters\.[^)]+\)/,
  bitbucket: /\$BITBUCKET_PR_[A-Z_]+|\$\{BITBUCKET_PR_[A-Z_]+\}/,
  jenkins: /\$\{\s*params\.[^}]+\}|\$\{\s*env\.CHANGE_[A-Z_]+\}/,
};

/** True when the line sits inside a script step. YAML CI keeps
 *  script lines under script:, run:, bash:, pwsh:, or command:
 *  keys; Jenkins runs shell in sh "..." lines. */
function scriptLines(lines: string[], system: CiSystem): Set<number> {
  const out = new Set<number>();
  if (system === "jenkins") {
    lines.forEach((line, idx) => {
      if (/\bsh\s+["']/.test(line)) out.add(idx + 1);
    });
    return out;
  }
  let scriptIndent: number | null = null;
  lines.forEach((line, idx) => {
    if (/^\s*(#.*)?$/.test(line)) return;
    const indent = line.match(/^ */)?.[0].length ?? 0;
    if (scriptIndent !== null && indent <= scriptIndent) scriptIndent = null;
    if (/^\s*(script|run|bash|pwsh|command)\s*:/.test(line)) {
      scriptIndent = indent;
      const after = line.split(":").slice(1).join(":");
      if (after.trim().length > 0) out.add(idx + 1);
      return;
    }
    if (scriptIndent !== null) out.add(idx + 1);
  });
  return out;
}

interface CiRule {
  id: string;
  title: string;
  severity: Severity;
  fix: string;
  detail: string;
  match: (line: string, lineNo: number, system: CiSystem, script: Set<number>) => boolean;
}

const RULES: CiRule[] = [
  {
    id: "curl-pipe-shell",
    title: "CI step pipes a download straight into a shell",
    severity: "high",
    fix: "Download the script to a file, verify its checksum or signature, then run the file - never pipe a download into a shell.",
    detail: "A CI step downloads a script and pipes it straight into a shell, so whatever the server returns runs with the pipeline's permissions.",
    match: (line, lineNo, _system, script) =>
      script.has(lineNo) && /(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:sh|bash)\b/.test(line),
  },
  {
    id: "secret-echo",
    title: "CI step prints a secret to the logs",
    severity: "high",
    fix: "Never echo secrets. Mask them and pass them only to the step that needs them.",
    detail: "A CI step prints a secret value, which leaks it into the build logs.",
    match: (line, lineNo, _system, script) => {
      if (!script.has(lineNo)) return false;
      if (/\bprintenv\b/.test(line)) return true;
      if (/\becho\b/.test(line) && SECRET_NAME.test(line)) return true;
      return false;
    },
  },
  {
    id: "image-latest",
    title: "CI container image has no pinned tag",
    severity: "medium",
    fix: "Pin the image to an exact version tag, never latest and never untagged.",
    detail: "A CI job runs a container image with no tag or the latest tag, so a future image change can alter the build or smuggle in new code.",
    match: (line) => {
      const m = /^\s*(?:-\s*)?image\s*:\s*["']?([^\s"']+)/.exec(line);
      if (!m) return false;
      const ref = m[1];
      return !ref.includes(":") || ref.endsWith(":latest");
    },
  },
  {
    id: "script-injection",
    title: "CI script interpolates a user-controlled value",
    severity: "high",
    fix: "Pass the value through an environment variable instead of interpolating it into the script.",
    detail: "A CI script interpolates a value a merge request or trigger author controls, so they can inject shell commands that run with the pipeline's permissions.",
    match: (line, lineNo, system, script) =>
      script.has(lineNo) && USER_CONTROLLED[system].test(line),
  },
  {
    id: "unpinned-ref",
    title: "CI step uses an unpinned external reference",
    severity: "medium",
    fix: "Pin the reference to an exact version or a full commit SHA.",
    detail: "A CI step pulls an external reference with no pinned version, so a future change to that reference can alter the build.",
    match: (line, _lineNo, system) => {
      if (system === "gitlab") {
        const m = /^\s*(?:-\s*)?remote\s*:\s*["']?(https?:\/\/[^\s"']+)/.exec(line);
        return !!m && !m[1].includes("@");
      }
      if (system === "circleci") {
        if (/^\s*(?:-\s*)?image\s*:/.test(line)) return false;
        const m = /:\s*["']?([a-z0-9][a-z0-9_-]*\/[a-z0-9][a-z0-9_-]*)["']?\s*$/.exec(line);
        return !!m;
      }
      if (system === "azure") {
        const m = /^\s*(?:-\s*)?task\s*:\s*["']?([^@\s"']+)(@([^\s"']+))?/.exec(line);
        return !!m && !m[2];
      }
      if (system === "jenkins") {
        const m = /library\s*\(?\s*["']([^"']+)["']/i.exec(line);
        return !!m && !m[1].includes("@");
      }
      return false;
    },
  },
  {
    id: "static-cloud-key",
    title: "CI step uses a static cloud key",
    severity: "high",
    fix: "Use OIDC federation or a role instead of a long-lived static key.",
    detail: "A CI step authenticates to a cloud provider with a static key, which lives forever until someone rotates it and leaks like any other secret.",
    match: (line, lineNo, _system, script) => {
      if (!script.has(lineNo)) return false;
      return /(AWS_ACCESS_KEY_ID|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET)\s*=/.test(line);
    },
  },
];

/** Scan one file for CI pipeline risks. Returns no findings for
 *  files that are not a recognised CI config. One finding per rule
 *  per line. */
export function scanTextForCiRisks(file: { path: string; content: string }): PostureIssue[] {
  const findings: PostureIssue[] = [];
  if (!file.content) return findings;
  const system = systemOf(file.path);
  if (!system) return findings;
  const lines = file.content.split("\n");
  const script = scriptLines(lines, system);
  const seen = new Set<string>();
  lines.forEach((line, idx) => {
    const lineNo = idx + 1;
    for (const rule of RULES) {
      if (!rule.match(line, lineNo, system, script)) continue;
      const key = `${rule.id}:${lineNo}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: `ci-${rule.id}-${file.path.replace(/[^A-Za-z0-9]/g, "-")}-${lineNo}`,
        title: rule.title,
        severity: rule.severity,
        detail: rule.detail,
        fix: rule.fix,
        category: "ci",
        file: file.path,
        line: lineNo,
      });
    }
  });
  return findings;
}
