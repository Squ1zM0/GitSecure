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
}

export const DETECTORS: Detector[] = [
  {
    id: "discord-webhook",
    title: "Discord webhook URL",
    severity: "critical",
    confidence: "high",
    pattern: /https:\/\/(?:discord\.com|discordapp\.com)\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{20,}/g,
    fix: "Delete this webhook in Discord Server Settings > Integrations, create a fresh one, and store it as a secret — never commit it. The URL in git history still works until the webhook is deleted.",
    plainEnglish: "Anyone with this link can post messages to your Discord server with no login. This is the exact leak that hit a repo in November 2026.",
  },
  {
    id: "slack-webhook",
    title: "Slack webhook URL",
    severity: "critical",
    confidence: "high",
    pattern: /https:\/\/hooks\.slack\.com\/(?:services|triggers)\/[A-Za-z0-9/_-]{20,}/g,
    fix: "Revoke this webhook in Slack, create a fresh one, and store it as a secret — never commit it.",
    plainEnglish: "Anyone with this link can post messages into your Slack workspace with no login.",
  },
  {
    id: "slack-token",
    title: "Slack API token",
    severity: "critical",
    confidence: "high",
    pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
    fix: "Revoke this token in Slack and issue a new one stored as a secret.",
    plainEnglish: "This token can act in Slack as the app or user it belongs to.",
  },
  {
    id: "aws-access-key",
    title: "AWS access key ID",
    severity: "high",
    confidence: "high",
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    fix: "Deactivate and delete this key in AWS IAM, create a new one, and store it in a secrets manager — never in code.",
    plainEnglish: "This is half of an AWS credential pair. Paired with its secret key it can use your AWS account.",
  },
  {
    id: "github-token",
    title: "GitHub personal access token",
    severity: "critical",
    confidence: "high",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
    fix: "Revoke this token at github.com/settings/tokens and create a new fine-grained token with only the scopes it needs.",
    plainEnglish: "This token can act on GitHub as the account that created it, including reading and writing repos.",
  },
  {
    id: "stripe-secret-key",
    title: "Stripe secret key",
    severity: "critical",
    confidence: "high",
    pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    fix: "Roll this key in the Stripe dashboard and store the replacement as a server-side secret only.",
    plainEnglish: "A live Stripe secret key can move real money. It must never be in client code or a public repo.",
  },
  {
    id: "openai-api-key",
    title: "OpenAI API key",
    severity: "critical",
    confidence: "high",
    pattern: /\bsk-proj-[A-Za-z0-9_-]{20,}\b|\bsk-[A-Za-z0-9]{20,}\b/g,
    fix: "Revoke this key at platform.openai.com and create a new one stored as a server-side secret.",
    plainEnglish: "This key can spend money on your OpenAI account.",
  },
  {
    id: "private-key",
    title: "Private key",
    severity: "critical",
    confidence: "high",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
    fix: "Treat this key as compromised: generate a new key pair, replace it everywhere it was used, and remove the old one from git history.",
    plainEnglish: "A private key in a public repo is no longer private. Anyone can impersonate whatever it unlocks.",
  },
  {
    id: "database-url",
    title: "Database URL with credentials",
    severity: "high",
    confidence: "high",
    pattern: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/g,
    fix: "Rotate the database password, move the URL into an environment variable / secrets manager, and never commit it.",
    plainEnglish: "This URL contains a username and password for a database, in plain text.",
  },
  {
    id: "jwt-token",
    title: "JSON Web Token (JWT)",
    severity: "medium",
    confidence: "medium",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
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

export function scanTextForSecrets(file: ScannedFile): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = file.content.split("\n");
  const seen = new Set<string>();
  for (const detector of DETECTORS) {
    const re = new RegExp(detector.pattern.source, detector.pattern.flags);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      // No blanket "EXAMPLE" skip: a specific credential pattern (AKIA…,
      // ghp_…, a webhook URL) is worth flagging even on a line that says
      // "example" — a human can dismiss it, a scanner must not hide it.
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        const raw = m[0];
        const key = `${detector.id}:${file.path}:${i + 1}:${redactSecret(raw)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          id: `${detector.id}-${file.path.replace(/[^A-Za-z0-9]/g, "-")}-${i + 1}`,
          type: detector.id,
          title: detector.title,
          severity: detector.severity,
          confidence: detector.confidence,
          file: file.path,
          line: i + 1,
          commit: file.commit,
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
