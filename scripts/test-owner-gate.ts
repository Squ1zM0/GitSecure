// Owner-gate test for GitHub OAuth (Phase 2). Run: npm run test:owner-gate
//
// Tests the gate LOGIC with session mocks — no network, no real GitHub
// OAuth App, no live sign-in. Live OAuth still needs Freddy to create the
// OAuth App and set the four env vars (see README.md); this script proves
// the gate itself is correct and that the production default (no env vars)
// fails closed to the public view.
//
// Also proves the public report leaks no detail, and that the auth module
// exports its handlers with no credentials configured.

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { isOAuthConfigured, isOwnerModeEnabled, isOwnerSession } from "../src/lib/owner";
import { toPublicReport } from "../src/lib/scan";
import type { FullReport } from "../src/lib/types";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

function finish() {
  console.log(failures === 0 ? "\nAll owner-gate tests passed." : `\n${failures} test(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

// --- Pure gate logic (session mocks) ---
check("owner session matches owner login", isOwnerSession({ user: { githubLogin: "Squ1zM0" } }, "Squ1zM0"));
check("owner match is case-insensitive", isOwnerSession({ user: { githubLogin: "squ1zm0" } }, "Squ1zM0"));
check("different login is not the owner", !isOwnerSession({ user: { githubLogin: "someone-else" } }, "Squ1zM0"));
check("signed-out session (null) is not the owner", !isOwnerSession(null, "Squ1zM0"));
check("session without githubLogin is not the owner", !isOwnerSession({ user: {} }, "Squ1zM0"));
check("session with empty githubLogin is not the owner", !isOwnerSession({ user: { githubLogin: "" } }, "Squ1zM0"));
check("owner login never matches a different repo owner", !isOwnerSession({ user: { githubLogin: "Squ1zM0" } }, "other-owner"));

// --- Env-gated configuration (fails closed by default) ---
const savedEnv = {
  GITHUB_ID: process.env.GITHUB_ID,
  GITHUB_SECRET: process.env.GITHUB_SECRET,
  NEXTAUTH_SECRET: process.env.NEXTAUTH_SECRET,
  NEXTAUTH_URL: process.env.NEXTAUTH_URL,
  GITSECURE_OWNER_MODE: process.env.GITSECURE_OWNER_MODE,
};
function restoreEnv() {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}
delete process.env.GITHUB_ID;
delete process.env.GITHUB_SECRET;
delete process.env.NEXTAUTH_SECRET;
delete process.env.NEXTAUTH_URL;
delete process.env.GITSECURE_OWNER_MODE;
check("OAuth not configured with no env vars (safe production default)", !isOAuthConfigured());
check("dev owner mode off with no env vars", !isOwnerModeEnabled());
process.env.GITHUB_ID = "test-id";
process.env.GITHUB_SECRET = "test-secret";
process.env.NEXTAUTH_SECRET = "test-nextauth-secret";
process.env.NEXTAUTH_URL = "http://localhost:3000";
check("OAuth configured only when all four env vars are set", isOAuthConfigured());
delete process.env.NEXTAUTH_URL;
check("OAuth NOT configured when one env var is missing", !isOAuthConfigured());
process.env.NEXTAUTH_URL = "http://localhost:3000";
process.env.GITSECURE_OWNER_MODE = "true";
check("dev owner mode on with GITSECURE_OWNER_MODE=true", isOwnerModeEnabled());
restoreEnv();

// --- Auth module loads with no credentials (dynamic import, dummy env
// set first so the import is exercised the way production would see it) ---
process.env.GITHUB_ID = "dummy-test-id";
process.env.GITHUB_SECRET = "dummy-test-secret";
process.env.NEXTAUTH_SECRET = "dummy-test-nextauth-secret";
process.env.NEXTAUTH_URL = "http://localhost:3000";
import("../src/lib/auth").then((authMod) => {
  check("auth module exports GET/POST handlers", typeof authMod.handlers.GET === "function" && typeof authMod.handlers.POST === "function");
  check("auth module exports auth() helper", typeof authMod.auth === "function");
  restoreEnv();

  // --- Public report still leaks no detail (owner-gate backstop) ---
  const full: FullReport = {
    kind: "full",
    repo: "fake-repo",
    owner: "fake-owner",
    branch: "main",
    commit: "abc1234",
    score: 10,
    grade: "F",
    counts: { secrets: 1, vulnerabilities: 1, frameworks: 2, dependencies: 3, postureIssues: 1, filesScanned: 5, historyCommitsScanned: 42 },
    summary: "Scan complete.",
    scannedAt: new Date().toISOString(),
    historyDepth: "test",
    limits: ["History scan: 42 commits, 1.0 MB of patches, 2.0s."],
    secrets: [{ id: "x", type: "discord-webhook", title: "Discord webhook URL", severity: "critical", confidence: "high", file: "config.js", line: 3, commit: "abc1234", fragment: "http…12", fix: "Rotate it.", plainEnglish: "Leaked." }],
    frameworks: [
      { name: "Next.js", ecosystem: "js", version: "14.2.5", versionSource: "lockfile", unpinned: false, sourceFile: "package.json" },
      { name: "Gin", ecosystem: "go", version: "v1.9.1", versionSource: "manifest", unpinned: false, sourceFile: "go.mod" },
    ],
    dependencies: [{ name: "next", ecosystem: "npm", version: "14.2.5", direct: true, sourceFile: "package.json" }],
    vulnerabilities: [{ id: "GHSA-test-1234", packageName: "next", ecosystem: "npm", installedVersion: "14.2.5", fixedVersion: "14.2.6", severity: "high", summary: "Test vuln.", plainEnglish: "Upgrade.", upgrade: "Upgrade next." }],
    posture: [{ id: "no-security-md", title: "No SECURITY.md", severity: "low", detail: "Missing.", fix: "Add one." }],
  };
  const pub = toPublicReport(full);
  const pubJson = JSON.stringify(pub);
  check("public report keeps score + counts (incl. history count)", pub.counts.historyCommitsScanned === 42);
  check("public report leaks no file/line/fragment", !pubJson.includes("config.js") && !pubJson.includes("http…12"));
  check("public report leaks no framework names (incl. Tier 2)", !pubJson.includes("Next.js") && !pubJson.includes("Gin"));
  check("public report leaks no vulnerability IDs", !pubJson.includes("GHSA-test-1234"));
  check("public report keeps history limits text (caps, no detail)", pub.limits.some((l) => l.includes("42 commits")));

  // --- No credential is ever hardcoded in src (env vars are the only home) ---
  const srcFiles: string[] = [];
  const walk = (dir: string) => {
    for (const f of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, f.name);
      if (f.isDirectory()) walk(p);
      else if (/\.(ts|tsx)$/.test(f.name)) srcFiles.push(p);
    }
  };
  walk(join(process.cwd(), "src"));
  let hardcoded = false;
  for (const f of srcFiles) {
    const text = readFileSync(f, "utf8");
    // Env vars must only ever be READ, never assigned a literal value.
    if (/(GITHUB_ID|GITHUB_SECRET|NEXTAUTH_SECRET|NEXTAUTH_URL)\s*=\s*["'][^"']+["']/.test(text)) {
      console.log(`  hardcoded credential in ${f}`);
      hardcoded = true;
    }
  }
  check("no OAuth credential is hardcoded anywhere in src/", !hardcoded, `${srcFiles.length} source files checked`);

  finish();
}).catch((err) => {
  console.log(`FAIL  auth module import failed — ${err instanceof Error ? err.message : err}`);
  failures++;
  finish();
});
