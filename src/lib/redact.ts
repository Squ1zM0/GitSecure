// Redaction: the ONLY way a secret value ever leaves the scanner.
// Never return the full value. For a value longer than 6 chars show the
// first 4 + an ellipsis + the last 2; shorter values are fully masked.
// Callers must never log or render the raw match.

export function redactSecret(value: string): string {
  const v = value.trim();
  if (v.length <= 6) return "••••••";
  return `${v.slice(0, 4)}…${v.slice(-2)}`;
}

/** True if `text` still contains `secret` verbatim — used by tests to prove
 *  no full secret leaks into a report. */
export function leaksSecret(text: string, secret: string): boolean {
  if (!secret || secret.length < 8) return false;
  return text.includes(secret);
}
