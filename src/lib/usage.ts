// Secret usage analysis (Phase 11) — for every secret finding,
// determine from the repo's own files what the value depends on and
// whether anything else uses it.
//
// The search is IDENTIFIER-ONLY. A finding's identifier is the
// variable / env name, the key filename, or the config key it was
// assigned to — never the secret value itself, never the redacted
// fragment. The value string is never searched for, never stored,
// and never leaves this module: a file that contains the secret
// value but never names it is NOT a reference (proved by the
// regression test in scripts/test-usage-phase11.ts).
//
// The identifier is anchored to the detector match, not to the
// line: the name whose assignment's value IS the matched secret
// (the name inside the match itself for the password-style
// detectors, or the `NAME =` immediately before the value for the
// rest). A bare URL line has no such name — its scheme (`postgres`)
// is not an identifier — and a line whose match sits inside a
// string (a test that builds a fake secret in memory) yields the
// name inside the string, never the test's own variable. When the
// line has no detector match at all, the fallback is the assignment
// at the start of the line, with a URL-scheme guard.
//
// What counts as a reference: the identifier appears in another
// file (never the file the finding came from), bounded by
// non-identifier characters, so `MY_KEY` does not match inside
// `MY_API_KEY`. References in test files are recorded separately
// (referencedByTests) and do NOT count as "in use" — only a
// reference from non-test code makes a finding live. Test files are
// classified with the Phase 10 test-path detection (isTestFilePath
// in triage.ts).
//
// What does NOT count: the finding's own file; ignore-files
// (.gitignore, .gitattributes, .dockerignore, .npmignore — they
// name files to exclude, they do not use the value); matches on
// the secret value itself; and generic names (`key`, `token`,
// `password`, …) which are too common to mean anything — a finding
// whose line yields no usable identifier gets an empty usage
// annotation with deadEnd: false, i.e. "liveness undetermined",
// never a false dead end. Test files are classified with the Phase
// 10 test-path detection (isTestFilePath in triage.ts). A bare
// `.env` basename is NOT an identifier for an .env-file finding:
// every repo mentions ".env" in prose ("committed .env files",
// "add .env to .gitignore"), and none of those mentions loads the
// file — an .env file's identifiers are its variable names only.
//
// Lists are capped at 10 entries each with true totals. The search
// is one prefilter pass per file (a single alternation regex over
// all identifiers) plus exact per-identifier attribution only for
// files that pass the prefilter, so a repo with hundreds of
// findings does not pay findings × files full scans.
//
// Pure functions of (findings, files) — no I/O, no crypto, no
// secret values. The caller supplies the file corpus (a Map of
// path -> content) and, per finding, the context the identifier is
// extracted from (the finding's line text and, for .env files, the
// whole file content so its variable names can be read).

import { isProductionPath, isTestFilePath } from "./triage";
import { DETECTORS } from "./secrets";
import { redactSecret } from "./redact";
import type { SecretFinding, SecretUsage } from "./types";

/** Entries kept per reference list (first 10, in file order). */
export const USAGE_LIST_CAP = 10;

/** Basenames that name files to exclude — they never "use" a value. */
const IGNORE_FILE_BASENAMES = new Set([
  ".gitignore",
  ".gitattributes",
  ".dockerignore",
  ".npmignore",
]);

/** Variable names too generic to identify anything: matching them
 *  would call nearly every file in a repo a "reference". Compared
 *  case-insensitively, exact match only — `db_password` and
 *  `security-password` are specific enough to keep. */
const GENERIC_NAMES = new Set([
  "key", "token", "secret", "password", "passwd", "pwd", "value",
  "auth", "data", "name", "id", "code", "hash", "text", "string",
  "var", "config", "setting", "env", "url", "uri", "api",
]);

/** Shell-generic variable names an .env file may define that do not
 *  identify the file's own secrets. */
const GENERIC_ENV_VARS = new Set([
  "PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "TZ", "PWD",
  "OLDPWD", "TERM",
]);

/** Key-filename stems too generic to search for on their own
 *  (`prod` in `prod/db.conf` is a directory, not the key). */
const GENERIC_STEMS = new Set([
  "test", "tests", "key", "keys", "secret", "secrets", "private",
  "public", "cert", "certs", "default", "config", "master", "main",
  "prod", "dev", "app", "data",
]);

export interface FindingContext {
  /** The text of the finding's own line (for value findings: the
   *  assignment the value sits in). */
  lineText?: string | null;
  /** The finding file's whole content (for .env files: the variable
   *  names it defines). */
  content?: string | null;
}

function isWordChar(ch: string | undefined): boolean {
  return ch !== undefined && /[A-Za-z0-9_]/.test(ch);
}

/** A finding file's basename, e.g. `sign_key.pem`. */
function basename(path: string): string {
  return path.split("/").pop() ?? path;
}

/** Is `name` usable as an identifier? Long enough and not generic. */
function usableName(name: string): boolean {
  const n = name.trim();
  if (n.length < 4) return false;
  if (GENERIC_NAMES.has(n.toLowerCase())) return false;
  return true;
}

/** The name inside a detector match itself, for the password-style
 *  detectors whose pattern includes the assignment (`password =
 *  "…"`, `security-password="…"`). Null when the match does not
 *  start with a name — including a bare URL, whose scheme
 *  (`postgres:`) looks like a name but is not one. */
function matchName(match: string): string | null {
  const m = /^\s*["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]/.exec(match);
  if (!m) return null;
  if (m[0].endsWith(":") && match.slice(m[0].length).startsWith("//")) return null;
  return normalizeName(m[1]);
}

/** The assignment name immediately before a detector match: the
 *  `NAME =` / `NAME:` at the end of the text preceding the value
 *  (`const SHARED_KEY_NAME = "AKIA…"`, `"api_key": "ghp_…"`).
 *  Null when the value has no assignment in front of it (a bare
 *  URL, a bare token on its own line). */
function prefixName(prefix: string): string | null {
  const m = /["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]\s*["']?\s*$/.exec(prefix);
  return m ? normalizeName(m[1]) : null;
}

/** The left-hand name a value is assigned to, anchored to the
 *  detector match on the line: the name whose assignment's value IS
 *  the matched secret. The finding's fragment identifies the exact
 *  match when a line holds several (same rule as triage's raw-value
 *  recovery); otherwise the first match of the finding's detector
 *  type is used. Returns undefined when the line holds no detector
 *  match at all (the caller then falls back to the line-start
 *  name); null when a match exists but no usable name is attached
 *  to it — that answer is definitive, and no fallback runs. */
function matchAnchoredName(finding: SecretFinding, lineText: string): string | null | undefined {
  const detector = DETECTORS.find((d) => d.id === finding.type);
  if (!detector) return undefined;
  const re = new RegExp(detector.pattern.source, detector.pattern.flags);
  let m: RegExpExecArray | null;
  let first: RegExpExecArray | null = null;
  while ((m = re.exec(lineText)) !== null) {
    if (m[0].length === 0) break;
    if (!first) first = m;
    if (redactSecret(m[0]) === finding.fragment) {
      return matchName(m[0]) ?? prefixName(lineText.slice(0, m.index));
    }
  }
  if (!first) return undefined;
  return matchName(first[0]) ?? prefixName(lineText.slice(0, first.index));
}

/** Fallback when the line holds no detector match (a hand-built
 *  finding, or a value the detectors cannot re-match): the
 *  assignment at the start of the line, ignoring leading keywords
 *  (`const`, `export`, …) and an optional list bullet. A name
 *  followed by `://` is a URL scheme, not an assignment — a bare
 *  URL line yields no identifier. */
function lineStartName(lineText: string): string | null {
  const m = /^\s*(?:[-*]\s+)?(?:(?:export|const|let|var|public|private|static|readonly|final)\s+)*["'`]?([A-Za-z_][A-Za-z0-9_.\-]*)["'`]?\s*[:=]/.exec(lineText);
  if (!m) return null;
  // URL scheme guard: `postgres://…` is a value, not `postgres = …`.
  const after = lineText.slice(m.index + m[0].length);
  if (m[0].endsWith(":") && after.startsWith("//")) return null;
  return normalizeName(m[1]);
}

/** The left-hand name a value is assigned to on one line, e.g.
 *  `AWS_ACCESS_KEY_ID` from `AWS_ACCESS_KEY_ID=AKIA…`, `api_key`
 *  from `"api_key": "…"`, `MY_KEY` from `process.env.MY_KEY = "…"`.
 *  Null when the line yields no usable name. */
function assignmentName(finding: SecretFinding, lineText: string): string | null {
  const anchored = matchAnchoredName(finding, lineText);
  if (anchored !== undefined) return anchored;
  return lineStartName(lineText);
}

/** Strip an `env.`/`process.env.`/`os.environ.` prefix (the name
 *  that matters is the last segment) and normalise. */
function normalizeName(raw: string): string | null {
  let name = raw.trim().replace(/^["']|["']$/g, "");
  for (const prefix of ["process.env.", "os.environ.", "os.environ[", "environ.", "env."]) {
    if (name.startsWith(prefix)) name = name.slice(prefix.length);
  }
  // Dotted config keys keep their full form (`database.url`) —
  // except an env access, whose last segment is the variable.
  // (The prefixes above already handled the env case.)
  name = name.replace(/\]$/, "");
  return usableName(name) ? name : null;
}

/** Variable names defined in an .env file's content
 *  (`NAME=value` lines, skipping shell-generic names). */
function envVarNames(content: string): string[] {
  const out: string[] = [];
  for (const line of content.split("\n")) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
    if (!m) continue;
    const name = m[1];
    if (GENERIC_ENV_VARS.has(name)) continue;
    if (name.length < 4) continue;
    if (!out.includes(name)) out.push(name);
  }
  return out;
}

/** Extract the identifiers for one finding. Never the secret value,
 *  never the fragment — only names: the key filename (private keys),
 *  the variable names an .env file defines (.env files — never the
 *  bare `.env` basename, which every repo mentions in prose), or
 *  the assignment name on the finding's line (everything else). */
export function extractIdentifiers(finding: SecretFinding, ctx: FindingContext = {}): string[] {
  if (finding.type === "private-key") {
    const base = basename(finding.file);
    const ids = [base];
    // The stem too, when it is specific enough to mean the file
    // (`sign_key` in a Makefile) — never a generic stem (`prod`).
    const dot = base.lastIndexOf(".");
    const stem = dot > 0 ? base.slice(0, dot) : base;
    if (stem !== base && stem.length >= 5 && !GENERIC_STEMS.has(stem.toLowerCase())) {
      ids.push(stem);
    }
    return ids;
  }
  if (finding.type === "env-file") {
    if (ctx.content) return envVarNames(ctx.content);
    return [];
  }
  if (ctx.lineText) {
    const name = assignmentName(finding, ctx.lineText);
    if (name) return [name];
  }
  return [];
}

// Test-file classification is the Phase 10 detection, reused from
// triage.ts (isTestFilePath: test path segment or test filename
// token). isProductionPath is also reused from triage.ts — it is the
// Phase 11 upgrade rule's production-path definition, used here only
// to order the capped reference list (production references first).
// Both are imported above; neither is redefined here.

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Line numbers (1-based) of every bounded occurrence of
 *  `identifier` in `content`. Bounded means the character before
 *  and after the match is not [A-Za-z0-9_], so `MY_KEY` never
 *  matches inside `MY_API_KEY`. */
export function findIdentifierOccurrences(content: string, identifier: string): number[] {
  const lines: number[] = [];
  if (!identifier) return lines;
  // Line starts, computed once: occurrence offsets -> line numbers.
  let starts: number[] | null = null;
  const lineAt = (index: number): number => {
    if (!starts) {
      starts = [0];
      for (let i = 0; i < content.length; i++) {
        if (content.charCodeAt(i) === 10) starts.push(i + 1);
      }
    }
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  let from = 0;
  for (;;) {
    const idx = content.indexOf(identifier, from);
    if (idx === -1) break;
    from = idx + identifier.length;
    const before = idx > 0 ? content[idx - 1] : undefined;
    const after = idx + identifier.length < content.length ? content[idx + identifier.length] : undefined;
    if (!isWordChar(before) && !isWordChar(after)) lines.push(lineAt(idx));
  }
  return lines;
}

/** Compute usage for every finding, in place (same array back — the
 *  list never changes, so a usage pass can never drop a finding).
 *
 *  `files` is the corpus to search: the scanned HEAD files. `getContext`
 *  supplies, per finding, the line text / file content its identifier
 *  is extracted from; when it yields nothing (e.g. a history finding
 *  whose added lines are gone), only filename identifiers are used.
 *
 *  `historyOnly` marks the annotation as computed from HEAD files
 *  only (history findings). */
export function computeUsageForFindings(
  findings: SecretFinding[],
  files: Map<string, string>,
  getContext?: (finding: SecretFinding) => FindingContext,
  opts?: { historyOnly?: boolean },
): SecretFinding[] {
  // One identifier set per finding, deduped across findings so a
  // shared name is searched once, not once per finding.
  const perFinding = new Map<SecretFinding, string[]>();
  const allIdentifiers = new Set<string>();
  for (const f of findings) {
    const ctx = getContext ? getContext(f) : {};
    const ids = extractIdentifiers(f, ctx);
    perFinding.set(f, ids);
    for (const id of ids) allIdentifiers.add(id);
  }

  // Prefilter: one alternation regex over all identifiers. A file
  // that matches no identifier at all is skipped without any
  // per-identifier work. The prefilter is deliberately a superset
  // (no word boundaries): it can only admit files, never hide one —
  // attribution below applies the strict bounded match.
  const sorted = [...allIdentifiers].sort((a, b) => b.length - a.length);
  const prefilter = sorted.length > 0 ? new RegExp(sorted.map(escapeRegExp).join("|")) : null;

  // Reference lists per finding, in deterministic (sorted-path) order.
  const refs = new Map<SecretFinding, { code: { file: string; line: number }[]; tests: { file: string; line: number }[] }>();
  for (const f of findings) refs.set(f, { code: [], tests: [] });

  if (prefilter) {
    const paths = [...files.keys()].sort();
    for (const path of paths) {
      const base = basename(path);
      if (IGNORE_FILE_BASENAMES.has(base)) continue;
      const content = files.get(path);
      if (content === undefined || !prefilter.test(content)) continue;
      const isTest = isTestFilePath(path);
      for (const f of findings) {
        if (f.file === path) continue; // never the finding's own file
        const ids = perFinding.get(f) ?? [];
        if (ids.length === 0) continue;
        const bucket = refs.get(f)!;
        for (const id of ids) {
          for (const line of findIdentifierOccurrences(content, id)) {
            (isTest ? bucket.tests : bucket.code).push({ file: path, line });
          }
        }
      }
    }
  }

  for (const f of findings) {
    const bucket = refs.get(f)!;
    // Non-test references are listed production-path-first, then by
    // file/line: the capped list keeps the references triage cares
    // about (a production-path reference past the cap would otherwise
    // be invisible to the upgrade rule).
    const dedupedCode = dedupeRefs(bucket.code).sort((a, b) => {
      const pa = isProductionPath(a.file) ? 0 : 1;
      const pb = isProductionPath(b.file) ? 0 : 1;
      return pa - pb || (a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1);
    });
    const dedupedTests = dedupeRefs(bucket.tests);
    const hasIdentifier = (perFinding.get(f) ?? []).length > 0;
    f.usage = {
      referencedBy: dedupedCode.slice(0, USAGE_LIST_CAP),
      referencedByTotal: dedupedCode.length,
      referencedByTests: dedupedTests.slice(0, USAGE_LIST_CAP),
      referencedByTestsTotal: dedupedTests.length,
      // A dead end needs a searched identifier and zero references
      // anywhere. No identifier means undetermined, never dead-end.
      deadEnd: hasIdentifier && dedupedCode.length === 0 && dedupedTests.length === 0,
      ...(opts?.historyOnly ? { historyOnly: true } : {}),
    };
  }
  return findings;
}

/** Dedupe (file, line) pairs, sorted by file then line. Two
 *  identifiers matching the same spot (basename + stem) count once. */
function dedupeRefs(list: { file: string; line: number }[]): { file: string; line: number }[] {
  const seen = new Set<string>();
  const out: { file: string; line: number }[] = [];
  for (const r of [...list].sort((a, b) => (a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1))) {
    const key = `${r.file}:${r.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out;
}
