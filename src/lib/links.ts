// Direct links for findings (Phase 5 navigation).
//
// Every finding gets two ways to reach it:
//   1. A GitHub blob link to the exact file and line - the primary
//      "go fix this" action. HEAD findings link to the scanned branch;
//      history findings link to the commit that introduced them (the
//      short sha GitHub accepts in a blob URL), because the line may no
//      longer exist on the branch.
//   2. An in-page anchor (#secret-12, #vuln-3, ...) so one finding can
//      be linked to and shared. The index is the finding's position in
//      the report's full list, so it is stable across renders.
//
// Redaction rule (unchanged): a link never carries a secret value -
// only the file path, line, and the already-redacted fragment appear
// anywhere near a finding, including in tooltips and link labels.

export type FindingKind = "secret" | "vuln" | "posture" | "dep";

/** Stable in-page anchor id for the Nth finding of a kind (0-based). */
export function findingAnchorId(kind: FindingKind, index: number): string {
  return `${kind}-${index}`;
}

/** github.com/{owner}/{repo}/blob/{ref}/{file}#L{line}, with each path
 *  segment URL-encoded. `commit` is "HEAD" for current files, or the
 *  short sha for a history finding. */
export function githubBlobUrl(
  owner: string,
  repo: string,
  branch: string,
  file: string,
  line: number,
  commit: string | null,
): string {
  const ref = commit && commit !== "HEAD" ? commit : branch;
  const encodedPath = file
    .split("/")
    .map((seg) => encodeURIComponent(seg))
    .join("/");
  return `https://github.com/${owner}/${repo}/blob/${encodeURIComponent(ref)}/${encodedPath}#L${line}`;
}

/** Direct link to an advisory's page on OSV.dev - the "go fix this"
 *  link for a dependency vulnerability, which has no file/line. */
export function osvAdvisoryUrl(id: string): string {
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}
