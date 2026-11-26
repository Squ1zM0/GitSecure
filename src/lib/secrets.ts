// Secret detectors. Each detector is a regex + human-readable metadata.
// The scanner never returns, logs, or renders a raw match — only
// redactSecret(match) (see redact.ts). No detector ever calls the service
// the credential belongs to (no live validation).

import { redactSecret } from "./redact";
import type { SecretFinding, Severity } from "./types";

export interface Detector {
  id: string;
  title: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  pattern: RegExp;
  fix: string;
  plainEnglish: string;
  /** Literal substrings every match must contain. If set and NONE of
   *  them occurs in the file, the detector cannot match and is skipped
   *  without running its regex — a cheap `includes` (native memmem)
   *  instead of a full regex pass. This is what makes scanning a
   *  97k-file repo affordable: most files contain none of these
   *  literals at all. Each literal is a NECESSARY condition of the
   *  pattern above it — verified by inspection, never a heuristic. */
  prefilter?: string[];
}

export const DETECTORS: Detector[] = [
  {
    id: "discord-webhook",
    title: "Discord webhook URL",
    severity: "critical",
    confidence: "high",
    pattern: /https:\/\/(?:discord\.com|discordapp\.com)\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{20,}/g,
    prefilter: ["discord.com/api/webhooks", "discordapp.com/api/webhooks"],
    fix: "Delete this webhook in Discord Server Settings > Integrations, create a fresh one, and store it as a secret — never commit it. The URL in git history still works until the webhook is deleted.",
    plainEnglish: "Anyone with this link can post messages to your Discord server with no login. This is the exact leak that hit a repo in November 2026.",
  },
  {
    id: "slack-webhook",
    title: "Slack webhook URL",
    severity: "critical",
    confidence: "high",
    pattern: /https:\/\/hooks\.slack\.com\/(?:services|triggers)\/[A-Za-z0-9/_-]{20,}/g,
    prefilter: ["hooks.slack.com/"],
    fix: "Revoke this webhook in Slack, create a fresh one, and store it as a secret — never commit it.",
    plainEnglish: "Anyone with this link can post messages into your Slack workspace with no login.",
  },
  {
    id: "slack-token",
    title: "Slack API token",
    severity: "critical",
    confidence: "high",
    pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
    prefilter: ["xox"],
    fix: "Revoke this token in Slack and issue a new one stored as a secret.",
    plainEnglish: "This token can act in Slack as the app or user it belongs to.",
  },
  {
    id: "aws-access-key",
    title: "AWS access key ID",
    severity: "high",
    confidence: "high",
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    prefilter: ["AKIA", "ASIA", "ABIA", "ACCA"],
    fix: "Deactivate and delete this key in AWS IAM, create a new one, and store it in a secrets manager — never in code.",
    plainEnglish: "This is half of an AWS credential pair. Paired with its secret key it can use your AWS account.",
  },
  {
    id: "github-token",
    title: "GitHub personal access token",
    severity: "critical",
    confidence: "high",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
    prefilter: ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
    fix: "Revoke this token at github.com/settings/tokens and create a new fine-grained token with only the scopes it needs.",
    plainEnglish: "This token can act on GitHub as the account that created it, including reading and writing repos.",
  },
  {
    id: "stripe-secret-key",
    title: "Stripe secret key",
    severity: "critical",
    confidence: "high",
    pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    prefilter: ["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
    fix: "Roll this key in the Stripe dashboard and store the replacement as a server-side secret only.",
    plainEnglish: "A live Stripe secret key can move real money. It must never be in client code or a public repo.",
  },
  {
    id: "openai-api-key",
    title: "OpenAI API key",
    severity: "critical",
    confidence: "high",
    pattern: /\bsk-proj-[A-Za-z0-9_-]{20,}\b|\bsk-[A-Za-z0-9]{20,}\b/g,
    prefilter: ["sk-"],
    fix: "Revoke this key at platform.openai.com and create a new one stored as a server-side secret.",
    plainEnglish: "This key can spend money on your OpenAI account.",
  },
  {
    id: "private-key",
    title: "Private key",
    severity: "critical",
    confidence: "high",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
    prefilter: ["PRIVATE KEY-----"],
    fix: "Treat this key as compromised: generate a new key pair, replace it everywhere it was used, and remove the old one from git history.",
    plainEnglish: "A private key in a public repo is no longer private. Anyone can impersonate whatever it unlocks.",
  },
  {
    id: "database-url",
    title: "Database URL with credentials",
    severity: "high",
    confidence: "high",
    pattern: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/g,
    prefilter: ["postgres://", "postgresql://", "mysql://", "mongodb", "redis://"],
    fix: "Rotate the database password, move the URL into an environment variable / secrets manager, and never commit it.",
    plainEnglish: "This URL contains a username and password for a database, in plain text.",
  },
  {
    id: "jwt-token",
    title: "JSON Web Token (JWT)",
    severity: "medium",
    confidence: "medium",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    prefilter: ["eyJ"],
    fix: "Check whether this token is still valid; if so, revoke the session / rotate the signing secret.",
    plainEnglish: "This looks like a signed login token. If it is still valid, it may let someone act as that user.",
  },
  {
    id: "hardcoded-password",
    title: "Hardcoded password / secret assignment",
    severity: "medium",
    confidence: "medium",
    pattern: /\b(?:password|passwd|pwd|api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    fix: "Move this value into an environment variable or a secrets manager and reference it by name.",
    plainEnglish: "A password or secret is written directly in the code instead of being loaded from a safe place.",
  },
  {
    id: "generic-high-entropy-secret",
    title: "Possible high-entropy secret",
    severity: "low",
    confidence: "low",
    pattern: /\b(?:token|secret|key)\s*[:=]\s*['"][A-Za-z0-9+/=_-]{32,}['"]/gi,
    fix: "Confirm whether this is a real credential. If it is, rotate it and move it to a secrets manager.",
    plainEnglish: "This looks like a long random secret, but it could also be a harmless hash or test value. Worth a human check.",
  },
];

export interface ScannedFile {
  path: string;
  content: string;
  commit: string | null;
}

export interface ScannedLine {
  line: number;
  text: string;
}

/** Scan explicit (line number, text) pairs — the form history diffs arrive
 *  in, where line numbers come from hunk headers rather than a position in
 *  a whole file. scanTextForSecrets is a thin wrapper over this. */
export function scanLinesForSecrets(file: { path: string }, lines: ScannedLine[], commit: string | null): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const seen = new Set<string>();
  for (const detector of DETECTORS) {
    const re = new RegExp(detector.pattern.source, detector.pattern.flags);
    for (const { line: lineNo, text } of lines) {
      if (!text) continue;
      // No blanket "EXAMPLE" skip: a specific credential pattern (AKIA…,
      // ghp_…, a webhook URL) is worth flagging even on a line that says
      // "example" — a human can dismiss it, a scanner must not hide it.
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const raw = m[0];
        const key = `${detector.id}:${file.path}:${lineNo}:${redactSecret(raw)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          id: `${detector.id}-${file.path.replace(/[^A-Za-z0-9]/g, "-")}-${lineNo}`,
          type: detector.id,
          title: detector.title,
          severity: detector.severity,
          confidence: detector.confidence,
          file: file.path,
          line: lineNo,
          commit,
          fragment: redactSecret(raw),
          fix: detector.fix,
          plainEnglish: detector.plainEnglish,
        });
        if (m[0].length === 0) break;
      }
    }
  }
  return findings;
}

/** Scan a whole file's content for secrets.
 *
 *  Runs each detector regex ONCE over the whole content — not once per
 *  line, as the old implementation did. The old per-line loop cost
 *  ~56 s on torvalds/linux (97k files, ~30M lines: 12 detectors x
 *  every line). Line numbers come from the match offset via a
 *  forward cursor over the newlines, so a file with no matches costs
 *  only the regex passes, and a file with matches costs one extra
 *  forward pass at most.
 *
 *  Results are IDENTICAL to the old per-line scan (guarded by an
 *  equivalence test in scripts/test-scanner.ts that compares this
 *  function against scanLinesForSecrets line for line):
 *  - A match can only cross a line boundary by consuming the "\n"
 *    itself, and any match whose text contains "\n" is re-scanned
 *    line by line with the exact old method, so a value split across
 *    lines is never reported — and a real match hiding inside the
 *    spanned lines is never swallowed by the cross-line match.
 *  - `\b` behaves the same at a line edge in whole-content mode,
 *    because "\n" is a non-word character, exactly like a string
 *    boundary. No detector uses ^ or $.
 *  Detectors with a `prefilter` are skipped entirely when none of
 *  their literals occurs in the file (see Detector.prefilter). */
export function scanTextForSecrets(file: ScannedFile): SecretFinding[] {
  const { path, content, commit } = file;
  const findings: SecretFinding[] = [];
  if (!content) return findings;
  const seen = new Set<string>();
  const push = (detector: Detector, raw: string, lineNo: number) => {
    const key = `${detector.id}:${path}:${lineNo}:${redactSecret(raw)}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({
      id: `${detector.id}-${path.replace(/[^A-Za-z0-9]/g, "-")}-${lineNo}`,
      type: detector.id,
      title: detector.title,
      severity: detector.severity,
      confidence: detector.confidence,
      file: path,
      line: lineNo,
      commit,
      fragment: redactSecret(raw),
      fix: detector.fix,
      plainEnglish: detector.plainEnglish,
    });
  };
  for (const detector of DETECTORS) {
    if (detector.prefilter && !detector.prefilter.some((lit) => content.includes(lit))) continue;
    const re = new RegExp(detector.pattern.source, detector.pattern.flags);
    // Line cursor: matches arrive in ascending offset order, so one
    // forward pass over the newlines serves every match of this
    // detector.
    let cursorPos = 0;
    let cursorLine = 1;
    const lineAt = (index: number): number => {
      let pos = cursorPos;
      for (;;) {
        const nl = content.indexOf("\n", pos);
        if (nl === -1 || nl >= index) break;
        cursorLine++;
        pos = nl + 1;
      }
      cursorPos = pos;
      return cursorLine;
    };
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) {
      const raw = m[0];
      if (raw.length === 0) break;
      if (raw.includes("\n")) {
        // Cross-line match: the old per-line scan could never have
        // found this match, but it may have found matches on the
        // lines this match spans — re-scan exactly those lines with
        // the per-line method so nothing is lost or invented.
        const startLine = lineAt(m.index);
        lineAt(m.index + raw.length); // advance the cursor past the spanned lines
        const regionStart = content.lastIndexOf("\n", m.index - 1) + 1;
        let regionEnd = content.indexOf("\n", m.index + raw.length);
        if (regionEnd === -1) regionEnd = content.length;
        const regionLines = content.slice(regionStart, regionEnd).split("\n");
        const lineRe = new RegExp(detector.pattern.source, detector.pattern.flags);
        regionLines.forEach((text, i) => {
          if (!text) return;
          lineRe.lastIndex = 0;
          let lm: RegExpExecArray | null;
          while ((lm = lineRe.exec(text)) !== null) {
            if (lm[0].length === 0) break;
            push(detector, lm[0], startLine + i);
          }
        });
        continue;
      }
      push(detector, raw, lineAt(m.index));
    }
  }
  return findings;
}

export function envFileFinding(path: string, commit: string | null): SecretFinding {
  return {
    id: `env-file-${path.replace(/[^A-Za-z0-9]/g, "-")}`,
    type: "env-file",
    title: "Committed .env file",
    severity: "high",
    confidence: "high",
    file: path,
    line: 1,
    commit,
    fragment: "••••••",
    fix: "Remove the file from the repo and from git history, add .env to .gitignore, and rotate every credential that was in it.",
    plainEnglish: "Environment files hold real credentials. This one is committed to the repo, so anyone can read it.",
  };
}
