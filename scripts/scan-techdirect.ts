// Live test: scan the real public repo Squ1zM0/TechDirect via the scanner
// (GitHub API, no auth). Saves the FULL report to
// test-results/techdirect-full-phase4-2026-11-25.json and prints a summary.
// Run: npm run test:techdirect
//
// Phase 4: the file scan is UNLIMITED — every file in the HEAD tree is
// scanned. This script proves it by counting the tree itself (via the
// GitHub tree API, same skip rules as the scanner) and asserting
// counts.filesScanned equals that count. TechDirect has 2,802 files in
// the tree; the only skips are binary / dist / node_modules / .next
// paths, which are not source files to scan. Also asserts the known
// score stays 83/B and that the limits line says the whole tree was
// scanned. History: 62 commits via the ephemeral clone (Phase 2).

import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { scanRepo } from "../src/lib/scan";
import { isSkippablePath } from "../src/lib/paths";

async function treeBlobCount(owner: string, repo: string, branch: string): Promise<number> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    { headers: { Accept: "application/vnd.github+json", "User-Agent": "GitSecure-test" } },
  );
  if (!res.ok) throw new Error(`tree fetch failed: ${res.status}`);
  const data = (await res.json()) as { tree?: { path: string; type: string }[]; truncated?: boolean };
  if (data.truncated) throw new Error("tree was truncated by GitHub — cannot prove the count");
  return (data.tree ?? []).filter((t) => t.type === "blob" && !isSkippablePath(t.path)).length;
}

async function main() {
  console.log("Scanning Squ1zM0/TechDirect (live, public GitHub API + ephemeral clone)...");
  const started = Date.now();
  const full = await scanRepo("Squ1zM0", "TechDirect");
  mkdirSync(join(process.cwd(), "test-results"), { recursive: true });
  writeFileSync(
    join(process.cwd(), "test-results/techdirect-full-phase4-2026-11-25.json"),
    JSON.stringify(full, null, 2),
  );
  console.log(`Total scan time: ${((Date.now() - started) / 1000).toFixed(1)}s`);
  console.log(JSON.stringify({ score: full.score, grade: full.grade, counts: full.counts, summary: full.summary }, null, 2));

  const expected = await treeBlobCount("Squ1zM0", "TechDirect", full.branch);
  console.log(`Tree check: ${expected} scannable files in the tree, filesScanned=${full.counts.filesScanned}`);
  if (full.counts.filesScanned !== expected) {
    throw new Error(`filesScanned mismatch: got ${full.counts.filesScanned}, tree says ${expected} — the scan did not cover the whole tree`);
  }
  if (full.score !== 83 || full.grade !== "B") {
    throw new Error(`score changed: got ${full.score}/${full.grade}, expected 83/B`);
  }
  if (!full.limits.some((l) => /Scanned all \d+ files in the tree/.test(l))) {
    throw new Error(`limits do not say the whole tree was scanned: ${JSON.stringify(full.limits)}`);
  }

  console.log("Dependencies:");
  for (const d of full.dependencies) console.log(`  - ${d.name} ${d.version ?? "(no version)"} [${d.ecosystem}, ${d.direct ? "direct" : "transitive"}] from ${d.sourceFile}`);
  console.log("Frameworks:");
  for (const f of full.frameworks) console.log(`  - ${f.name} ${f.version ?? "(version unknown)"} [${f.versionSource}] from ${f.sourceFile}`);
  console.log(`Secrets: ${full.secrets.length} | Vulnerabilities: ${full.vulnerabilities.length} | Posture issues: ${full.posture.length}`);
  for (const p of full.posture) console.log(`  posture: [${p.severity}] ${p.title}`);
  for (const v of full.vulnerabilities.slice(0, 10)) console.log(`  vuln: [${v.severity}] ${v.id} ${v.packageName} ${v.installedVersion} -> fixed ${v.fixedVersion ?? "?"}`);
  console.log("History depth:", full.historyDepth);
  console.log("Limits:", full.limits);
  console.log("UNLIMITED scan proven: filesScanned matches the full scannable tree.");
}

main().catch((err) => {
  console.error("TechDirect scan failed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
