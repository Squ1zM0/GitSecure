// Public-full test for Phase 4. Run: npm run test:public-full
//
// Phase 4 flipped the model: the site only scans public repos, so
// EVERY caller gets the full report — no login flow, no owner gate.
// This script proves, with no network:
//   1. No sign-in / owner-gate copy or code remains anywhere in src or
//      on the human pages (no "Honest limits" section, no "owner only",
//      no "sign in", no auth route, no next-auth dependency).
//   2. No file-count cap remains in the scanner (no MAX_FILES, no
//      per-file/total size cap, no "250 files" anywhere in scan.ts).
//   3. A full report carries the detail (file names, framework names,
//      vulnerability IDs) AND still never contains a full fake secret
//      (redaction rule unchanged).

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { scanTextForSecrets } from "../src/lib/secrets";
import { leaksSecret } from "../src/lib/redact";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

const ROOT = process.cwd();
const src = (p: string) => readFileSync(join(ROOT, p), "utf8");

// --- 1. No login flow, no owner gate, no Honest limits anywhere ---
check("src/lib/auth.ts is gone", !existsSync(join(ROOT, "src/lib/auth.ts")));
check("src/lib/owner.ts is gone", !existsSync(join(ROOT, "src/lib/owner.ts")));
check("src/app/api/auth route is gone", !existsSync(join(ROOT, "src/app/api/auth")));
check("no auth/owner module is imported anywhere in src", (() => {
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const f of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, f.name);
      if (f.isDirectory()) walk(p);
      else if (/\.(ts|tsx)$/.test(f.name)) files.push(p);
    }
  };
  walk(join(ROOT, "src"));
  const bad = files.filter((f) => /from\s+["']@\/lib\/(auth|owner)["']|lib\/(auth|owner)/.test(readFileSync(f, "utf8")));
  if (bad.length > 0) console.log(`  imports auth/owner: ${bad.join(", ")}`);
  return bad.length === 0;
})());

const home = src("src/app/page.tsx");
check("home page has no 'Honest limits' section", !/Honest limits/i.test(home));
check("home page has no 'owner only' copy", !/owner only/i.test(home));
check("home page has no sign-in copy", !/sign in/i.test(home));
check("home page says everyone gets the full report", /everyone gets the .*full report/i.test(home));

const reportPage = src("src/app/[owner]/[repo]/page.tsx");
check("report page has no sign-in copy", !/sign in/i.test(reportPage));
check("report page has no 'Owner view' banner", !/Owner view/i.test(reportPage));
check("report page has no 'Public view' banner", !/Public view/i.test(reportPage));
check("report page has no canViewFull / owner gate", !/canViewFull|isOwner|ownerMode/i.test(reportPage));

const layout = src("src/app/layout.tsx");
check("layout footer has no 'owner only' copy", !/owner only/i.test(layout));
check("layout metadata has no 'owner-only' copy", !/owner-only/i.test(layout));

const pkg = JSON.parse(src("package.json")) as { dependencies?: Record<string, string>; scripts?: Record<string, string> };
check("next-auth dependency is gone", !pkg.dependencies?.["next-auth"]);
check("test:owner-gate script is gone", !pkg.scripts?.["test:owner-gate"]);
check("test:public-full script exists", pkg.scripts?.["test:public-full"] === "tsx scripts/test-public-full.ts");

const scanSrc = src("src/lib/scan.ts");
check("scanner has no MAX_FILES constant", !/MAX_FILES/.test(scanSrc));
check("scanner has no per-file/total size cap", !/MAX_FILE_BYTES|MAX_TOTAL_BYTES/.test(scanSrc));
check("scanner mentions no '250 files' limit", !/250 files/.test(scanSrc));
check("scanner mentions no '200 KB' / '3 MB' cap", !/200 KB|3 MB/.test(scanSrc));

// --- 2. No file-count cap: scan.ts fetches the whole chosen tree ---
check("scanner fetches the whole tree (no slice cap on chosen)", /const chosen = sorted;/.test(scanSrc));

// --- 2b. Phase 5: no result-count caps anywhere ---
check("Phase 5: scanner has no 100-secret slice", !/slice\(0, 100\)/.test(scanSrc));
check("Phase 5: scanner has no secretOverflow / truncation bookkeeping", !/secretOverflow/.test(scanSrc));
check("Phase 5: scanner has no secret-findings cap copy", !/Secret findings capped/i.test(scanSrc));
check("Phase 5: scanner lists every dependency (no 200 slice)", !/slice\(0, 200\)/.test(scanSrc));
const osvSrc = src("src/lib/osv.ts");
check("Phase 5: OSV has no advisory list cap (VULN_CAP)", !/VULN_CAP/.test(osvSrc));
check("Phase 5: OSV has no fixed 50-detail cap constant (DETAIL_CAP)", !/DETAIL_CAP/.test(osvSrc));
check("Phase 5: OSV queries every pinned dep (no 60 slice)", !/slice\(0, 60\)/.test(osvSrc));
const mcpSrc = src("src/lib/mcp.ts");
check("Phase 5: MCP notes state no 100-finding cap", !/At most 100 secret findings/.test(mcpSrc));
check("Phase 5: MCP notes state no 50-detail cap", !/up to 50 advisories per scan/i.test(mcpSrc));
check("Phase 5: report page renders lists progressively (Show more)", /Show more/.test(reportPage) || /ReportLists/.test(reportPage));
check("Phase 5: report page lists dependencies, not just counts", /DependenciesList/.test(reportPage));
check("Phase 5: report page passes owner/repo/branch to the secrets list (GitHub links)", /SecretsList secrets=\{full\.secrets\} owner=\{full\.owner\} repo=\{full\.repo\} branch=\{full\.branch\}/.test(reportPage));

// --- 2c. Phase 5 navigation: groups, filters, map, anchors, GitHub links ---
const listsSrc = src("src/components/ReportLists.tsx");
const linksSrc = src("src/lib/links.ts");
check("nav: secrets list groups by type and file", /Group by/.test(listsSrc) && /Secret type/.test(listsSrc) && /File/.test(listsSrc));
check("nav: secrets list filters by type, severity, and file name", /Filter by secret type/.test(listsSrc) && /Filter by severity/.test(listsSrc) && /Filter by file name/.test(listsSrc));
check("nav: vulnerabilities group by advisory/package with severity filter", /Group vulnerabilities by/.test(listsSrc) && /Advisory/.test(listsSrc));
check("nav: posture groups + filters exist", /Group posture issues by/.test(listsSrc));
check("nav: dependencies filter by ecosystem and name", /Filter by ecosystem/.test(listsSrc) && /Filter by dependency name/.test(listsSrc));
check("nav: file map view exists (SVG spider, top files by count)", /FileMap/.test(listsSrc) && /MAP_NODES/.test(listsSrc) && /<svg/.test(listsSrc));
check("nav: map aggregates by file (one node per file, no node per finding)", /byFile/.test(listsSrc) && !/findings\.map\(\(s, i\) => \(\s*<g/.test(listsSrc));
check("nav: every secret row links to the exact GitHub file + line", /githubBlobUrl\(owner, repo, branch, s\.file, s\.line, s\.commit\)/.test(listsSrc) && /View on GitHub/.test(listsSrc));
check("nav: every finding has an in-page anchor + copy-link button", /findingAnchorId\("secret", entry\.idx\)/.test(listsSrc) && /CopyLinkButton/.test(listsSrc) && /findingAnchorId\("vuln", entry\.idx\)/.test(listsSrc));
check("nav: link helper builds blob URLs with file + line", /blob\//.test(linksSrc) && /#L\$\{line\}/.test(linksSrc));
check("nav: link helper uses the commit for history findings", /commit !== "HEAD"/.test(linksSrc));
check("nav: map tooltips carry only file + count, never a fragment", /\$\{f\.file\} — \$\{f\.count\} finding/.test(listsSrc));

// --- 3. Full report carries detail AND redaction still holds ---
// Fake secrets assembled from fragments at runtime (never literal —
// GitHub push protection blocks literal secret-pattern values).
const FAKE = "FAKE";
const FAKE_SECRETS = [
  "https://discord.com/api/webhooks/" + "123456789012345678/" + FAKE.repeat(6) + "123456",
  "AKIA" + "IOSFODNN7EXAMPLE",
  "ghp_" + FAKE.repeat(8) + "1234",
  "sk_live_" + FAKE.repeat(6) + "12",
  "sk-proj-" + FAKE.repeat(7),
  "postgres://fakeuser:FAKEPASSWORD123@localhost:5432/fakedb",
  FAKE.repeat(8) + "12345678",
];
const PRIVATE_KEY_FAKE =
  "-----BEGIN RSA " + "PRIVATE KEY-----\nFAKEFAKEFAKE\n-----END RSA PRIVATE KEY-----";
const configRaw = readFileSync(join(ROOT, "tests/fixtures/fake-repo/config.js"), "utf8");
const config = FAKE_SECRETS.reduce(
  (text, secret, i) => text.split(`__SECRET_${i}__`).join(secret),
  configRaw,
).split("__SECRET_7__").join(PRIVATE_KEY_FAKE);
const findings = scanTextForSecrets({ path: "config.js", content: config, commit: "HEAD" });
const findingsJson = JSON.stringify(findings);
check("fixture scan still finds the planted secrets", findings.length >= 8, `${findings.length} found`);
for (const secret of FAKE_SECRETS) {
  check(`redaction: full fake secret never appears (${secret.slice(0, 18)}…)`, !leaksSecret(findingsJson, secret));
}
check("full report detail includes file names", findingsJson.includes("config.js"));
check("full report detail includes secret fragments (redacted)", findings.every((f) => f.fragment.length < 12));

console.log(failures === 0 ? "\nAll public-full tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
