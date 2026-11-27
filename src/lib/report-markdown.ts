// "Roll all into report" (Freddy, 2026-11-26) - the whole current
// scan as one downloadable Markdown document.
//
// Pure module: takes the FullReport the page already has and returns
// a string + a filename. No DOM, no network, no API route - the
// download itself (Blob + anchor click) lives in the RollAllButton
// component. Unit-testable with tsx alone (scripts/test-report-markdown.ts).
//
// Hard rule, same as the page: secrets are fragment-only, exactly as
// in the report - the builder only ever reads `fragment`, never any
// other field that could hold a secret value. No truncation anywhere:
// every secret, vulnerability, posture issue, dependency, and
// framework in the report is listed, even when the on-page lists are
// collapsed or filtered - the builder reads the report arrays, not
// the page state.

import { adjustedExplainScore, adjustedVerdict, scoreExplanationText, type ScoreDetail } from "@/components/ScoreDial";
import { gradeWord } from "@/lib/score";
import type { FullReport, SecretFinding, Vulnerability } from "@/lib/types";
import { recommendedFixVersions } from "@/lib/versions";

const safe = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, "-");

/** `gitsecure-report-{owner}-{repo}-{short-sha}.md`. The short sha is
 *  the first 7 of the report commit; "unknown" when there is none. */
export function reportMarkdownFilename(report: FullReport): string {
  const sha = report.commit ? String(report.commit).slice(0, 7) : "unknown";
  return `gitsecure-report-${safe(report.owner)}-${safe(report.repo)}-${safe(sha)}.md`;
}

function triageLabel(s: SecretFinding): string {
  switch (s.triage?.verdict) {
    case "likely-test-key":
      return "Likely test key";
    case "likely-genuine-leak":
      return "Likely genuine leak";
    case "uncertain":
      return "Uncertain - needs a human check";
    default:
      return "Untriaged";
  }
}

/** The Fix line for one vulnerability, reconciled the same way the
 *  on-page list reconciles it (Phase 15 finding 15): one recommended
 *  version per package, covering all its advisories. */
function vulnFix(v: Vulnerability, reconciled: Map<string, { recommended: string; advisoryCount: number }>): string {
  if (!v.fixedVersion) return v.upgrade;
  const rec = reconciled.get(`${v.packageName}@${v.installedVersion ?? ""}`);
  if (!rec) return v.upgrade;
  return `Upgrade ${v.packageName} to ${rec.recommended} or later - this covers all ${rec.advisoryCount} advisories for this version.`;
}

function secretSection(s: SecretFinding, i: number): string {
  const lines = [
    `### ${i + 1}. ${s.title}`,
    ``,
    `- Severity: ${s.severity} · Confidence: ${s.confidence} · Triage: ${triageLabel(s)}`,
    `- Location: \`${s.file}:${s.line}\` · Commit: \`${s.commit ?? "HEAD"}\``,
    // Fragment only - never a full secret value.
    `- Fragment (redacted - never the full secret): \`${s.fragment}\``,
    ``,
    s.plainEnglish,
    ``,
  ];
  if (s.triage) {
    lines.push(`Triage: ${s.triage.explanation} (Assessed severity: ${s.triage.adjustedSeverity}, confidence: ${s.triage.adjustedConfidence}.)`, ``);
  }
  if (s.usage) {
    if (s.usage.deadEnd) {
      lines.push(`Usage: nothing in this repo references this key - a true dead end.${s.usage.historyOnly ? " (Usage checked against the current files only.)" : ""}`, ``);
    } else {
      const total = s.usage.referencedByTotal + s.usage.referencedByTestsTotal;
      if (total > 0) {
        const refs = [
          ...s.usage.referencedBy.map((r) => `${r.file}:${r.line}`),
          ...s.usage.referencedByTests.map((r) => `${r.file}:${r.line} (test)`),
        ];
        lines.push(`Usage: used by ${refs.join(", ")}${total > refs.length ? ` (+${total - refs.length} more)` : ""}.${s.usage.historyOnly ? " (Usage checked against the current files only.)" : ""}`, ``);
      }
    }
  }
  lines.push(`Fix: ${s.triage?.fix ?? s.fix}`, ``);
  return lines.join("\n");
}

/** The whole report as Markdown. `paused` is the page's chunk-driver
 *  state (ReportView prop): a provisional report whose driver errored
 *  says "paused" instead of "still running". */
export function buildReportMarkdown(report: FullReport, opts?: { paused?: boolean }): string {
  const detail: ScoreDetail | undefined = (report as { scoreDetail?: ScoreDetail }).scoreDetail;
  const counts = {
    secrets: report.counts.secrets,
    vulnerabilities: report.counts.vulnerabilities,
    postureIssues: report.counts.postureIssues,
    postureHigh: report.posture.filter((p) => p.severity === "high" || p.severity === "critical").length,
  };
  const reconciled = recommendedFixVersions(report.vulnerabilities);
  const out: string[] = [];

  out.push(`# GitSecure report: ${report.owner}/${report.repo}`, ``);
  if (report.provisional) {
    out.push(
      `> **Provisional report** - the current files are scanned, but history and dependency checks are ${opts?.paused ? "paused - history and dependency checks stopped here" : "still running"}. The score below counts what the current files show so far; it will update when the scan finishes. The lists show exactly what has been checked so far - nothing is half-reported.`,
      ``,
    );
  }
  out.push(
    `- Repo: ${report.owner}/${report.repo}`,
    `- Branch: ${report.branch}`,
    `- Commit: ${report.commit}`,
    `- Scanned: ${report.scannedAt}`,
    `- Files scanned: ${report.counts.filesScanned}`,
    `- History commits scanned: ${report.counts.historyCommitsScanned} (${report.historyDepth})`,
    ``,
  );

  out.push(`## Score`, ``);
  out.push(`**${report.score} out of 100 (grade ${report.grade} - ${gradeWord(report.grade)})**`, ``);
  out.push(`${adjustedVerdict(detail, counts)}`, ``);
  out.push(`${report.summary}`, ``);
  out.push(`${adjustedExplainScore(report.score, report.grade, detail, counts)}`, ``);
  if (detail) out.push(`${scoreExplanationText(detail)}`, ``);
  out.push(
    `- Possible leaked secrets: ${report.counts.secrets}${report.counts.testKeySecrets > 0 ? ` (of which ${report.counts.testKeySecrets} look like test keys)` : ""}`,
    // Phase 16: on a provisional report the dependency check has not
    // run yet, so the count must not render as a checked 0 - same
    // contradiction as the page's vulnerabilities section.
    `- Dependency vulnerabilities: ${report.provisional ? "not checked yet" : report.counts.vulnerabilities}`,
    `- Frameworks detected: ${report.counts.frameworks}`,
    `- Dependencies checked: ${report.counts.dependencies}`,
    `- Posture issues: ${report.counts.postureIssues}`,
    ``,
  );

  out.push(`## Leaked secrets (${report.secrets.length})`, ``);
  if (report.secrets.length === 0) {
    out.push(`No leaked secrets were found in the files and recent history scanned.`, ``);
  } else {
    if (report.provisional) out.push(`Secrets found in the current files so far - history has not been checked yet.`, ``);
    report.secrets.forEach((s, i) => out.push(secretSection(s, i)));
  }

  out.push(`## Frameworks (${report.frameworks.length})`, ``);
  if (report.frameworks.length === 0) {
    out.push(`No frameworks were fingerprinted in this repo.`, ``);
  } else {
    for (const f of report.frameworks) {
      out.push(`- **${f.name}** - ${f.version ?? "version could not be determined"} (${f.versionSource})${f.unpinned ? " · unpinned version" : ""} · \`${f.sourceFile}\``);
    }
    out.push(``);
  }

  out.push(`## Dependencies (${report.dependencies.length})`, ``);
  if (report.dependencies.length === 0) {
    out.push(`No dependencies were found in this repo.`, ``);
  } else {
    if (report.provisional) out.push(`Dependency checks are still running - the list below is what has been checked so far.`, ``);
    for (const d of report.dependencies) {
      out.push(`- **${d.name}** ${d.version ?? "(no version)"} · ${d.ecosystem} · ${d.direct ? "direct" : "transitive"} · \`${d.sourceFile}\``);
    }
    out.push(``);
  }

  out.push(`## Dependency vulnerabilities${report.provisional ? " (not checked yet)" : ` (${report.vulnerabilities.length})`}`, ``);
  if (report.vulnerabilities.length === 0) {
    out.push(report.provisional ? `Dependency checks are still running - no vulnerabilities listed yet.` : `No known vulnerabilities were found in the dependencies checked.`, ``);
  } else {
    report.vulnerabilities.forEach((v, i) => {
      out.push(
        `### ${i + 1}. ${v.id} - ${v.packageName} ${v.installedVersion ?? ""}`,
        ``,
        `- Severity: ${v.severity}${v.fixedVersion ? ` · Fixed in: ${v.fixedVersion}` : ` · No fixed version listed`}`,
        ``,
        `${v.plainEnglish}`,
        ``,
        `Fix: ${vulnFix(v, reconciled)}`,
        ``,
      );
    });
  }

  out.push(`## Security posture (${report.posture.length})`, ``);
  if (report.posture.length === 0) {
    out.push(`No posture issues were found in the basic checks.`, ``);
  } else {
    report.posture.forEach((p, i) => {
      out.push(`### ${i + 1}. ${p.title}`, ``, `- Severity: ${p.severity}`, ``, `${p.detail}`, ``, `Fix: ${p.fix}`, ``);
    });
  }

  out.push(`## About this scan`, ``);
  for (const l of report.limits) out.push(`- ${l}`);
  out.push(
    ``,
    `Secrets are shown as redacted fragments only, never in full. Full JSON report: \`/api/scan/${report.owner}/${report.repo}\`. Report page: https://git-secure.com/${report.owner}/${report.repo}`,
    ``,
    `Generated by GitSecure - swap github.com for git-secure.com to scan any public repo.`,
    ``,
  );
  return out.join("\n");
}
