// Live test: scan the real public repo Squ1zM0/TechDirect via the scanner
// (GitHub API, no auth). Saves the PUBLIC report to
// test-results/techdirect-public-2026-11-25.json and prints a summary.
// Run: npm run test:techdirect

import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { scanRepo, toPublicReport } from "../src/lib/scan";

async function main() {
  console.log("Scanning Squ1zM0/TechDirect (live, public GitHub API)...");
  const full = await scanRepo("Squ1zM0", "TechDirect");
  const pub = toPublicReport(full);
  mkdirSync(join(process.cwd(), "test-results"), { recursive: true });
  writeFileSync(join(process.cwd(), "test-results/techdirect-public-2026-11-25.json"), JSON.stringify(pub, null, 2));
  console.log(JSON.stringify({ score: pub.score, grade: pub.grade, counts: pub.counts, summary: pub.summary }, null, 2));
  console.log("Dependencies (owner detail, printed for the test only):");
  for (const d of full.dependencies) console.log(`  - ${d.name} ${d.version ?? "(no version)"} [${d.ecosystem}, ${d.direct ? "direct" : "transitive"}] from ${d.sourceFile}`);
  console.log("Frameworks (owner detail, printed for the test only):");
  for (const f of full.frameworks) console.log(`  - ${f.name} ${f.version ?? "(version unknown)"} [${f.versionSource}] from ${f.sourceFile}`);
  console.log(`Secrets: ${full.secrets.length} | Vulnerabilities: ${full.vulnerabilities.length} | Posture issues: ${full.posture.length}`);
  for (const p of full.posture) console.log(`  posture: [${p.severity}] ${p.title}`);
  for (const v of full.vulnerabilities.slice(0, 10)) console.log(`  vuln: [${v.severity}] ${v.id} ${v.packageName} ${v.installedVersion} -> fixed ${v.fixedVersion ?? "?"}`);
  console.log("Limits:", pub.limits);
}

main().catch((err) => {
  console.error("TechDirect scan failed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
