// Secret triage (Phase 10) — a layered post-processing pipeline that
// annotates every secret finding WITHOUT changing the detectors, the
// findings list, the counts, or the score.
//
// The problem it solves: GitSecure cried CRITICAL on intentional test
// keys — the Linux kernel's SGX self-test signing key
// (tools/testing/selftests/sgx/sign_key.pem) and the device-tree test
// data in drivers/of/unittest-data/tests-phandle.dtsi are not leaks,
// they are test fixtures. But a scanner must never hide a real leak,
// so triage NEVER removes a finding: it annotates it with a verdict,
// the signals that produced it, and an adjusted severity/confidence,
// and the report shows the triage label, a plain-English explanation,
// and a different Fix for likely-test findings. A likely-test finding
// still counts in counts.secrets and still deducts its detector
// severity from the score (see the scoring rule in GITSECURE.md) —
// relabelling a finding must never inflate the score.
//
// The three layers (Freddy's direction, 2026-11-25):
//   1. Static context — path, filename, and content signals.
//   2. Cryptographic inspection — parse the key/value where the format
//      allows: type and size, fingerprint against a small built-in list
//      of famous published test keys (FINGERPRINTS ONLY — never the
//      keys themselves), known example values (hashes only), weak/short
//      keys, and whether the key's public half is committed in the
//      same repo. No credential is ever live-validated, stored, or
//      logged; triage only ever sees the file content the scanner
//      already held, and only redacted fragments leave the scanner.
//   3. The scanner's own evidence — the detector result (type,
//      confidence, fragment) is an input, not the verdict: a
//      high-confidence match in a production path stays high; the same
//      match in a self-test path with matching test signals is
//      downgraded.
//
// Verdict model (points; see triageFinding):
//   decisive: fingerprint matches a known published test key, or the
//     value matches a published example value -> likely-test-key.
//   >= +4 points -> likely-test-key.
//   <= -2 points -> likely-genuine-leak.
//   high-confidence detector, no test signals at all, <= 0 points
//     -> likely-genuine-leak (a specific credential pattern with
//     nothing suggesting a test is most likely real).
//   otherwise -> uncertain (keeps detector severity, says so).

import { createHash } from "node:crypto";
import { DETECTORS } from "./secrets";
import { redactSecret } from "./redact";
import type { SecretFinding, SecretTriage, Severity, TriageVerdict } from "./types";
import type { ScannedLine } from "./secrets";

// ---------------------------------------------------------------------------
// Known published test keys / example values.
//
// FINGERPRINTS AND HASHES ONLY. Never a key, never a full value. A
// fingerprint is the SHA-256 of the key's DER bytes (the exact bytes
// the scanner sees when it reads the committed file); an example-value
// hash is the SHA-256 of the published example string. Both are
// one-way: neither can be turned back into the key or the value.
// To add an entry: fetch the published test key, hash its DER (or the
// example string), and record the hash with a comment naming the
// source. Never paste the key itself.
// ---------------------------------------------------------------------------

/** Published test keys, by SHA-256 of their DER bytes. */
export const KNOWN_TEST_KEY_FINGERPRINTS: { sha256: string; name: string }[] = [
  {
    // Linux kernel SGX self-test signing key — the key Freddy's
    // screenshot flagged as CRITICAL. It signs SGX test enclaves and
    // nothing else (tools/testing/selftests/sgx/sign_key.pem, RSA
    // 3072, PKCS#1). Verified 2026-11-25 by fetching the file from
    // torvalds/linux and hashing its DER.
    sha256: "739756e08012f17a899b05995ed88295c68e434b8680d7d8a1219347a07cb7b1",
    name: "Linux kernel SGX self-test signing key",
  },
];

/** Published example credential values, by SHA-256 of the value. */
export const KNOWN_EXAMPLE_VALUE_HASHES: { sha256: string; name: string }[] = [
  {
    // The AWS documentation's example access key ID, printed in
    // every AWS guide (the textbook example). It is not a real
    // credential — it is the textbook example. Hash verified
    // 2026-11-25 against the assembled string.
    sha256: "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3",
    name: "AWS documentation example access key ID",
  },
];

function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

// ---------------------------------------------------------------------------
// Layer 1 — static context signals
// ---------------------------------------------------------------------------

/** Path segments that say "this lives with the tests". A segment
 *  matches exactly, or by the substring rules below ("unittest-data"
 *  contains "unittest"; "tests-phandle.dtsi" is a filename, handled
 *  by the filename rule). Substring matching is deliberately narrow:
 *  a bare "test" substring would also match "latest" and "contest". */
const TEST_PATH_SEGMENTS = new Set([
  "test", "tests", "testing", "selftest", "selftests", "unittest", "unittests",
  "fixture", "fixtures", "mock", "mocks", "example", "examples", "sample",
  "samples", "demo", "demos", "spec", "specs", "testdata", "test-data",
  "doctest", "doctests", "e2e",
]);
export function isTestPathSegment(seg: string): boolean {
  const s = seg.toLowerCase();
  if (TEST_PATH_SEGMENTS.has(s)) return true;
  if (s.startsWith("test-") || s.startsWith("test_") || s.startsWith("tests-") || s.startsWith("tests_")) return true;
  if (s.endsWith("-test") || s.endsWith("_test") || s.endsWith("-tests") || s.endsWith("_tests")) return true;
  if (s.includes("unittest") || s.includes("selftest")) return true;
  return false;
}

/** Filename tokens that say "test fixture" ("tests-phandle.dtsi" ->
 *  tokens tests/phandle/dtsi). Token-based, never substring, so
 *  "latest.pem" does not match. */
const TEST_FILENAME_TOKENS = new Set([
  "test", "tests", "testing", "selftest", "selftests", "unittest", "unittests",
  "fixture", "fixtures", "mock", "mocks", "example", "examples", "sample",
  "samples", "dummy", "fake", "placeholder", "stub", "testdata",
]);
function filenameTestTokens(base: string): string[] {
  return base
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => TEST_FILENAME_TOKENS.has(t));
}

/** Content phrases that say "test / example / not for production".
 *  Word-boundary regexes, so "latest" and "contest" do not match. */
const TEST_CONTENT_PHRASES: { re: RegExp; label: string }[] = [
  { re: /\bfor testing only\b/i, label: "for testing only" },
  { re: /\bdo not use in production\b/i, label: "do not use in production" },
  { re: /\btest fixture\b/i, label: "test fixture" },
  { re: /\btest data\b/i, label: "test data" },
  { re: /\bselftest\b/i, label: "selftest" },
  { re: /\bunittest\b/i, label: "unittest" },
  { re: /\btestcase\b/i, label: "testcase" },
  { re: /\btesting\b/i, label: "testing" },
  { re: /\btests?\b/i, label: "test" },
  { re: /\bexample\b/i, label: "example" },
  { re: /\bdummy\b/i, label: "dummy" },
  { re: /\bfake\b/i, label: "fake" },
  { re: /\bsample\b/i, label: "sample" },
];

/** Path segments that say "this lives with production". */
const PROD_PATH_SEGMENTS = new Set(["prod", "production", "deploy", "deployment", "live"]);
const PROD_FILENAME_TOKENS = new Set(["prod", "production", "live"]);

// ---------------------------------------------------------------------------
// Layer 2 — cryptographic inspection (minimal DER parsing)
//
// Only the shapes the detectors can produce: RSA / EC private keys
// (PKCS#1, PKCS#8, SEC1) and RSA / EC public keys (SPKI, X.509 cert).
// A parse failure is not a signal either way — the finding simply gets
// no crypto signals, and the other layers decide.
// ---------------------------------------------------------------------------

function readLength(buf: Buffer, i: number): { length: number; next: number } {
  let len = buf[i];
  i++;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let k = 0; k < n; k++) len = (len << 8) | buf[i++];
  }
  return { length: len, next: i };
}

function readTlv(buf: Buffer, i: number): { tag: number; value: Buffer; next: number } | null {
  if (i >= buf.length) return null;
  const tag = buf[i];
  const { length, next } = readLength(buf, i + 1);
  if (next + length > buf.length) return null;
  return { tag, value: buf.subarray(next, next + length), next: next + length };
}

function readChildren(buf: Buffer): Buffer[] {
  const out: Buffer[] = [];
  let i = 0;
  while (i < buf.length) {
    const tlv = readTlv(buf, i);
    if (!tlv) break;
    out.push(buf.subarray(i, tlv.next));
    i = tlv.next;
  }
  return out;
}

/** Parse an OID's dotted form from its DER value bytes. */
function parseOid(value: Buffer): string {
  if (value.length === 0) return "";
  const parts: number[] = [Math.floor(value[0] / 40), value[0] % 40];
  let cur = 0;
  for (let i = 1; i < value.length; i++) {
    cur = (cur << 7) | (value[i] & 0x7f);
    if ((value[i] & 0x80) === 0) {
      parts.push(cur);
      cur = 0;
    }
  }
  return parts.join(".");
}

const EC_CURVE_BITS: Record<string, { name: string; bits: number }> = {
  "1.2.840.10045.3.1.1": { name: "P-192", bits: 192 },
  "1.3.132.0.33": { name: "P-224", bits: 224 },
  "1.2.840.10045.3.1.7": { name: "P-256", bits: 256 },
  "1.3.132.0.34": { name: "P-384", bits: 384 },
  "1.3.132.0.35": { name: "P-521", bits: 521 },
};

export interface ParsedKey {
  kind: "rsa" | "ec" | "unknown";
  /** RSA modulus bits, or EC curve bits. Null when it could not be read. */
  bits: number | null;
  /** Human label, e.g. "RSA 3072" or "EC P-256". */
  label: string;
  /** SHA-256 of the DER bytes (the key's fingerprint). */
  fingerprint: string;
  /** SHA-256 of the public material (RSA modulus / EC public point),
   *  or null when the key carries no public part. Two halves of one
   *  pair share an identity: a private key whose identity matches a
   *  committed public key / certificate is far more likely to be a
   *  test fixture than a leaked production secret. */
  identity: string | null;
}

function parseRsaPublicKeyDer(der: Buffer): { bits: number; identity: string } | null {
  const top = readTlv(der, 0);
  if (!top || top.tag !== 0x30) return null;
  const first = readTlv(top.value, 0);
  if (!first || first.tag !== 0x02) return null;
  const modulus = first.value;
  // Strip a leading zero byte (DER pads a modulus whose top bit is set).
  const trimmed = modulus.length > 0 && modulus[0] === 0 ? modulus.subarray(1) : modulus;
  return { bits: trimmed.length * 8, identity: sha256Hex(trimmed) };
}

/** Parse an SPKI (SubjectPublicKeyInfo) DER: SEQ { SEQ algId, BIT STRING }. */
function parseSpkiDer(der: Buffer): ParsedKey | null {
  const top = readTlv(der, 0);
  if (!top || top.tag !== 0x30) return null;
  const alg = readTlv(top.value, 0);
  const bitString = alg ? readTlv(top.value, alg.next) : null;
  if (!alg || !bitString || bitString.tag !== 0x03 || bitString.value.length < 2) return null;
  const algChildren = readChildren(alg.value);
  const oidTlv = algChildren.length > 0 ? readTlv(algChildren[0], 0) : null;
  const oid = oidTlv && oidTlv.tag === 0x06 ? parseOid(oidTlv.value) : "";
  const keyBytes = bitString.value.subarray(1); // skip the unused-bits byte
  if (oid === "1.2.840.113549.1.1.1") {
    // RSA: the BIT STRING holds an RSAPublicKey SEQ { n, e }.
    const rsa = parseRsaPublicKeyDer(keyBytes);
    if (!rsa) return null;
    return { kind: "rsa", bits: rsa.bits, label: `RSA ${rsa.bits}`, fingerprint: sha256Hex(der), identity: rsa.identity };
  }
  if (oid === "1.2.840.10045.2.1") {
    // EC: the BIT STRING holds the uncompressed point 0x04 || x || y.
    const curveTlv = algChildren.length > 1 ? readTlv(algChildren[1], 0) : null;
    const curve = curveTlv && curveTlv.tag === 0x06 ? EC_CURVE_BITS[parseOid(curveTlv.value)] : undefined;
    if (!curve) return null;
    return { kind: "ec", bits: curve.bits, label: `EC ${curve.name}`, fingerprint: sha256Hex(der), identity: sha256Hex(keyBytes) };
  }
  return null;
}

/** Parse a private-key DER (PKCS#1 RSA, PKCS#8, or SEC1 EC). */
function parsePrivateKeyDer(der: Buffer): ParsedKey | null {
  const fingerprint = sha256Hex(der);
  const top = readTlv(der, 0);
  if (!top || top.tag !== 0x30) return null;
  const first = readTlv(top.value, 0);
  if (!first) return null;
  // PKCS#1 RSA: SEQ { INT version, INT n, INT e, ... } — the second
  // child is the modulus.
  if (first.tag === 0x02) {
    const second = readTlv(top.value, first.next);
    if (second && second.tag === 0x02) {
      const modulus = second.value;
      const trimmed = modulus.length > 0 && modulus[0] === 0 ? modulus.subarray(1) : modulus;
      const bits = trimmed.length * 8;
      return { kind: "rsa", bits, label: `RSA ${bits}`, fingerprint, identity: sha256Hex(trimmed) };
    }
    return null;
  }
  // PKCS#8: SEQ { INT version, SEQ algId, OCTET STRING privateKey }.
  // The OCTET STRING holds PKCS#1 (RSA) or SEC1 (EC).
  if (first.tag === 0x30) {
    const second = readTlv(top.value, first.next);
    if (!second || second.tag !== 0x04) return null;
    const inner = parsePrivateKeyDer(second.value);
    if (inner) return { ...inner, fingerprint };
    return null;
  }
  return null;
}

/** Parse a SEC1 EC private key DER: SEQ { INT version, OCTET STRING
 *  private, [0] curve OID, [1] BIT STRING public }. Only reached for
 *  "BEGIN EC PRIVATE KEY" blocks, which PKCS#8 does not cover. */
function parseEcPrivateKeyDer(der: Buffer): ParsedKey | null {
  const fingerprint = sha256Hex(der);
  const top = readTlv(der, 0);
  if (!top || top.tag !== 0x30) return null;
  let i = 0;
  let curve: { name: string; bits: number } | undefined;
  let identity: string | null = null;
  while (i < top.value.length) {
    const tlv = readTlv(top.value, i);
    if (!tlv) break;
    if (tlv.tag === 0xa0) {
      const oidTlv = readTlv(tlv.value, 0);
      if (oidTlv && oidTlv.tag === 0x06) curve = EC_CURVE_BITS[parseOid(oidTlv.value)];
    }
    if (tlv.tag === 0xa1) {
      const bitString = readTlv(tlv.value, 0);
      if (bitString && bitString.tag === 0x03 && bitString.value.length > 1) {
        identity = sha256Hex(bitString.value.subarray(1));
      }
    }
    i = tlv.next;
  }
  if (!curve) return null;
  return { kind: "ec", bits: curve.bits, label: `EC ${curve.name}`, fingerprint, identity };
}

/** Extract the first PEM block of the given kinds from text, starting
 *  at (or just after) a line number when one is given. Returns the
 *  decoded DER bytes plus the block's header label. */
export function extractPemBlock(
  content: string,
  lineNo?: number,
  kinds: string[] = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY"],
): { der: Buffer; label: string } | null {
  const lines = content.split("\n");
  // The line number is the file line (HEAD) — but for history diffs
  // the content is only the added lines, so the number can point past
  // the end. In that case, and when no block is found at/after it,
  // scan from the start: the BEGIN line of a private key is the
  // finding's own line, and it is always present in the content.
  const startIdx = lineNo != null && lineNo - 1 < lines.length ? Math.max(0, lineNo - 1) : 0;
  for (let attempt = 0; attempt < 2; attempt++) {
    const from = attempt === 0 ? startIdx : 0;
    for (let i = from; i < lines.length; i++) {
      const m = /-----BEGIN ([A-Z0-9 ]+)-----/.exec(lines[i]);
      if (!m) continue;
      if (!kinds.includes(m[1])) continue;
      const b64: string[] = [];
      for (let j = i + 1; j < lines.length; j++) {
        if (lines[j].includes("-----END ")) break;
        b64.push(lines[j].trim());
      }
      try {
        return { der: Buffer.from(b64.join(""), "base64"), label: m[1] };
      } catch {
        return null;
      }
    }
  }
  return null;
}

/** Parse the private key in `content` (a whole file, or the added
 *  lines of a history diff — either way the PEM block is in there).
 *  Returns null when there is no parseable private key. */
export function parsePrivateKeyInContent(content: string, lineNo?: number): ParsedKey | null {
  const block = extractPemBlock(content, lineNo);
  if (!block) return null;
  if (block.label === "EC PRIVATE KEY") return parseEcPrivateKeyDer(block.der);
  if (block.label === "OPENSSH PRIVATE KEY" || block.label === "PGP PRIVATE KEY") {
    // Formats this parser does not read: no crypto signals, and the
    // fingerprint is still recorded so a future known-key entry can
    // match it by DER hash alone.
    return { kind: "unknown", bits: null, label: block.label, fingerprint: sha256Hex(block.der), identity: null };
  }
  return parsePrivateKeyDer(block.der);
}

/** Collect the public-key identities committed in one file's content:
 *  every "BEGIN PUBLIC KEY" block and every X.509 certificate's
 *  SubjectPublicKeyInfo. Used repo-wide (HEAD only — history commits
 *  cannot see the repo's other files) so a private key whose public
 *  half ships with it can be recognised as a fixture. */
export function collectPublicKeyIdentities(content: string): Set<string> {
  const identities = new Set<string>();
  if (!content.includes("BEGIN PUBLIC KEY") && !content.includes("BEGIN CERTIFICATE")) return identities;
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /-----BEGIN (PUBLIC KEY|CERTIFICATE)-----/.exec(lines[i]);
    if (!m) continue;
    const b64: string[] = [];
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].includes("-----END ")) break;
      b64.push(lines[j].trim());
    }
    let der: Buffer;
    try {
      der = Buffer.from(b64.join(""), "base64");
    } catch {
      continue;
    }
    if (m[1] === "PUBLIC KEY") {
      const parsed = parseSpkiDer(der);
      if (parsed?.identity) identities.add(parsed.identity);
      continue;
    }
    // Certificate: SEQ { tbs SEQ { ... SPKI ... }, ... }. The SPKI is
    // the SEQ child of the tbs whose first child is a SEQ (the
    // algorithm id) and whose second child is a BIT STRING.
    const outer = readTlv(der, 0);
    const tbs = outer ? readTlv(outer.value, 0) : null;
    if (!tbs || tbs.tag !== 0x30) continue;
    for (const child of readChildren(tbs.value)) {
      const parsed = parseSpkiDer(child);
      if (parsed?.identity) identities.add(parsed.identity);
    }
  }
  return identities;
}

// ---------------------------------------------------------------------------
// Triage context + verdict
// ---------------------------------------------------------------------------

export interface TriageContext {
  /** Full file content (HEAD) or the added lines of a history diff.
   *  The triage layer only ever reads content the scanner already
   *  held for detection; it never fetches anything itself. */
  content?: string;
  /** The added lines around the finding (history path), each with its
   *  file line number — used for the raw-value recovery and the
   *  nearby-lines content signals. */
  lines?: ScannedLine[];
  /** Public-key identities committed anywhere in the repo (HEAD only). */
  repoPublicKeyIdentities?: Set<string>;
  /** True when the key file is referenced only from test files. */
  referencedByTestOnly?: boolean;
  /** True when the key file is referenced from production code. */
  referencedByProd?: boolean;
  /** Extra known-test-key fingerprints (tests use this to plant a
   *  fingerprint without touching the built-in list). */
  extraKnownFingerprints?: { sha256: string; name: string }[];
}

interface Signal {
  id: string;
  points: number;
  /** Human phrase used in the explanation, e.g. "it lives in
   *  tools/testing/selftests/". */
  text: string;
}

const TEST_KEY_FIX =
  "Confirm this key is only used by tests and never signs real artifacts; if it does, rotate it.";
const TEST_VALUE_FIX =
  "Confirm this value is only used by tests or examples and is not a real credential. If it is real, rotate it and move it to a secrets manager.";

function lineTextFor(finding: SecretFinding, ctx: TriageContext): string | null {
  if (ctx.lines) {
    const hit = ctx.lines.find((l) => l.line === finding.line);
    if (hit) return hit.text;
  }
  if (ctx.content) {
    const lines = ctx.content.split("\n");
    return lines[finding.line - 1] ?? null;
  }
  return null;
}

/** Recover the raw matched value for a finding, from the line it sits
 *  on — needed for the example-value hash and the Stripe test-mode
 *  check. The raw value never leaves this function except as a hash:
 *  it is never stored, logged, or put on the finding. */
function recoverRawValue(finding: SecretFinding, ctx: TriageContext): string | null {
  const detector = DETECTORS.find((d) => d.id === finding.type);
  if (!detector) return null;
  const text = lineTextFor(finding, ctx);
  if (!text) return null;
  const re = new RegExp(detector.pattern.source, detector.pattern.flags);
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) break;
    if (redactSecret(m[0]) === finding.fragment) return m[0];
  }
  return null;
}

export interface TriageResult {
  triage: SecretTriage;
  /** The parsed key's public identity, when one was read — the caller
   *  (HEAD scan) uses it for the repo-wide counterpart check. */
  keyIdentity: string | null;
}

/** Triage one finding. Pure except for the crypto hash (node:crypto,
 *  no I/O). Every input finding gets an output annotation — triage
 *  never drops a finding. */
export function triageFinding(finding: SecretFinding, ctx: TriageContext = {}): TriageResult {
  const signals: Signal[] = [];
  let decisiveTest: string | null = null;
  let keyIdentity: string | null = null;

  const segments = finding.file.split("/");
  const base = segments[segments.length - 1] ?? "";
  // The path shown in an explanation runs through the LAST test /
  // production segment, so it names the test (or prod) part of the
  // path instead of stopping at the first one ("tools/testing" would
  // hide the "selftests" that actually matters).
  const pathThroughLast = (pred: (s: string) => boolean): string | null => {
    let last = -1;
    segments.forEach((s, i) => {
      if (pred(s)) last = i;
    });
    return last >= 0 ? segments.slice(0, last + 1).join("/") : null;
  };

  // --- Layer 1: static context ---
  const testSeg = segments.find((s) => isTestPathSegment(s));
  if (testSeg) {
    signals.push({ id: `test-path:${testSeg}`, points: 4, text: `it lives in a test path (${pathThroughLast(isTestPathSegment)})` });
  }
  const testTokens = filenameTestTokens(base);
  if (testTokens.length > 0) {
    signals.push({ id: `filename-test:${testTokens[0]}`, points: 2, text: `its file name looks like a test fixture (${base})` });
  }
  const contentText = ctx.content ?? (ctx.lines ? ctx.lines.map((l) => l.text).join("\n") : "");
  const contentHit = TEST_CONTENT_PHRASES.find((p) => p.re.test(contentText));
  if (contentHit && contentText) {
    signals.push({ id: `content-test:${contentHit.label}`, points: 2, text: `the surrounding lines talk about testing (${contentHit.label})` });
  }
  const prodSeg = segments.find((s) => PROD_PATH_SEGMENTS.has(s.toLowerCase()));
  if (prodSeg) {
    signals.push({ id: `prod-path:${prodSeg}`, points: -4, text: `it sits in a production path (${pathThroughLast((s) => PROD_PATH_SEGMENTS.has(s.toLowerCase()))})` });
  }
  const prodTokens = base.toLowerCase().split(/[^a-z0-9]+/).filter((t) => PROD_FILENAME_TOKENS.has(t));
  if (prodTokens.length > 0) {
    signals.push({ id: `prod-filename:${prodTokens[0]}`, points: -2, text: `its file name looks production (${base})` });
  }
  if (ctx.referencedByTestOnly) {
    signals.push({ id: "usage-test-only", points: 2, text: "it is only referenced from test files" });
  }
  if (ctx.referencedByProd) {
    signals.push({ id: "usage-prod", points: -2, text: "it is referenced from production code" });
  }

  // --- Layer 2: cryptographic inspection ---
  const raw = recoverRawValue(finding, ctx);
  if (raw) {
    if ((finding.type === "stripe-secret-key" && (raw.startsWith("sk_test_") || raw.startsWith("rk_test_")))) {
      signals.push({ id: "stripe-test-mode", points: 3, text: "it is a Stripe test-mode key, which can never move real money" });
    }
    const example = KNOWN_EXAMPLE_VALUE_HASHES.find((e) => e.sha256 === sha256Hex(raw));
    if (example) {
      decisiveTest = `it matches a published example value (${example.name})`;
      // 0 points: the match is decisive on its own, so it must not
      // double-count — but it IS a signal that produced the verdict,
      // so it belongs in the recorded list.
      signals.push({ id: "known-example-value", points: 0, text: decisiveTest });
    }
  }
  if (finding.type === "private-key" && contentText) {
    const parsed = parsePrivateKeyInContent(contentText, finding.line);
    if (parsed) {
      keyIdentity = parsed.identity;
      const known = [...KNOWN_TEST_KEY_FINGERPRINTS, ...(ctx.extraKnownFingerprints ?? [])].find(
        (k) => k.sha256 === parsed.fingerprint,
      );
      if (known) {
        decisiveTest = `its fingerprint matches a published test key (${known.name})`;
        // 0 points: decisive on its own — but recorded, because it is
        // the signal that produced the verdict.
        signals.push({ id: "known-test-key", points: 0, text: decisiveTest });
      }
      if (parsed.kind === "rsa" && parsed.bits != null && parsed.bits < 2048) {
        signals.push({ id: `weak-key:${parsed.label}`, points: 2, text: `the key is weak for production use (${parsed.label})` });
      }
      if (parsed.kind === "ec" && parsed.bits != null && parsed.bits < 256) {
        signals.push({ id: `weak-key:${parsed.label}`, points: 2, text: `the key is weak for production use (${parsed.label})` });
      }
      if (parsed.kind === "rsa" && parsed.bits != null && parsed.bits >= 4096) {
        signals.push({ id: `strong-key:${parsed.label}`, points: -2, text: `the key itself looks production-grade (${parsed.label})` });
      }
      if (parsed.kind === "ec" && parsed.bits != null && parsed.bits >= 384) {
        signals.push({ id: `strong-key:${parsed.label}`, points: -2, text: `the key itself looks production-grade (${parsed.label})` });
      }
      if (keyIdentity && ctx.repoPublicKeyIdentities?.has(keyIdentity)) {
        signals.push({ id: "public-counterpart-in-repo", points: 3, text: "its public half is committed in the same repo" });
      }
    }
  }

  // --- Layer 3: the detector's own evidence (used in the verdict) ---
  const points = signals.reduce((a, s) => a + s.points, 0);
  const hasTestSignal = signals.some((s) => s.points > 0);

  let verdict: TriageVerdict;
  if (decisiveTest) {
    verdict = "likely-test-key";
  } else if (points >= 4) {
    verdict = "likely-test-key";
  } else if (points <= -2) {
    verdict = "likely-genuine-leak";
  } else if (finding.confidence === "high" && points <= 0 && !hasTestSignal) {
    verdict = "likely-genuine-leak";
  } else {
    verdict = "uncertain";
  }

  // --- Annotation ---
  const testReasons = signals.filter((s) => s.points > 0).map((s) => s.text);
  if (decisiveTest) testReasons.unshift(decisiveTest);
  const prodReasons = signals.filter((s) => s.points < 0).map((s) => s.text);
  let explanation: string;
  let fix: string;
  let adjustedSeverity: Severity = finding.severity;
  let adjustedConfidence: "high" | "medium" | "low" = finding.confidence;
  if (verdict === "likely-test-key") {
    explanation =
      `This looks like an intentional test key: ${testReasons.join("; ")}.` +
      ` It is still listed and still counted — if it ever signs real artifacts or grants real access, treat it as compromised and rotate it.`;
    fix = finding.type === "private-key" || finding.type === "env-file" ? TEST_KEY_FIX : TEST_VALUE_FIX;
    adjustedSeverity = "low";
    adjustedConfidence = "low";
  } else if (verdict === "likely-genuine-leak") {
    explanation =
      prodReasons.length > 0
        ? `This looks like a genuine leak: ${prodReasons.join("; ")} with no test signals.`
        : `This looks like a genuine leak: a high-confidence ${finding.title.toLowerCase()} match with no test signals.`;
    fix = finding.fix;
  } else {
    const mixed = [...testReasons, ...prodReasons].join("; ");
    explanation =
      mixed.length > 0
        ? `This could be a test key or a real leak: ${mixed} — not enough evidence either way, so a human should check it.`
        : `Not enough evidence to tell whether this is a test value or a real leak — a human should check it.`;
    fix = finding.fix;
  }

  return {
    triage: {
      verdict,
      signals: signals.map((s) => s.id),
      explanation,
      adjustedSeverity,
      adjustedConfidence,
      fix,
    },
    keyIdentity,
  };
}

/** Annotate every finding in place. Returns the same array — the
 *  length never changes, so a triage pass can never drop a finding
 *  (proved by the Phase 10 regression test). */
export function triageFindings(
  findings: SecretFinding[],
  getCtx: (finding: SecretFinding) => TriageContext,
): SecretFinding[] {
  for (const f of findings) {
    f.triage = triageFinding(f, getCtx(f)).triage;
  }
  return findings;
}

/** Fill in a triage annotation for any finding that lacks one (a
 *  history finding that arrived from an older client/cursor, or a
 *  finding built before triage existed). Path + detector signals only
 *  — no content is available — but the invariant "every finding
 *  carries a triage annotation" holds for every report. */
export function ensureTriage(findings: SecretFinding[]): SecretFinding[] {
  for (const f of findings) {
    if (!f.triage) f.triage = triageFinding(f, {}).triage;
  }
  return findings;
}

/** Triage findings from added diff lines (history paths). The joined
 *  added lines are the content: path/filename signals come from the
 *  file path, content signals from the added lines, and a PEM block
 *  added by the commit is fully present in them. */
export function triageHistoryFindings(
  findings: SecretFinding[],
  path: string,
  lines: ScannedLine[],
): SecretFinding[] {
  const content = lines.map((l) => l.text).join("\n");
  return triageFindings(findings, (f) => ({ content, lines }));
}
