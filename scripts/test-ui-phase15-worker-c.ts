// Phase 15 worker C tests. Run: npm run test:ui-phase15c
//
// Covers findings 6, 10, 11, 14 - no network:
//   6.  Branded 404 (src/app/not-found.tsx): explains the owner/repo
//       shape, links home, role="alert", Phase 7 error-card styling.
//   10. MCP section: one plain-English line saying what MCP is, the
//       four JSON snippets collapsed behind a <details>, the canonical
//       URL https://git-secure.com/mcp everywhere it is hardcoded
//       in code/docs (mcp-config.ts, the /mcp route comment, README),
//       and a mobile fade/scroll hint on the snippet code blocks.
//   11. Loading copy: "15–30 seconds" on loading.tsx and on the home
//       scan-status line; the "nothing to click" line is kept.
//       Phase 16: the claim is scoped to small repos - a large repo
//       with a long history takes several minutes (live evidence:
//       vinta/awesome-python took 16 minutes for 3,350 history
//       commits, ~400/min), so the unscoped "usually takes 15–30
//       seconds" must not appear anywhere.
//   14. Home scan input: a visible <label> wired to the input;
//       prefilled value and validation messages unchanged.
//
// No literal secret-pattern values anywhere in these checks.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { renderToString } from "react-dom/server";
import React from "react";
import NotFound from "../src/app/not-found";
import Loading from "../src/app/[owner]/[repo]/loading";
import McpSection from "../src/components/McpSection";
import { MCP_SNIPPETS, MCP_URL } from "../src/lib/mcp-config";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` - ${extra}` : ""}`);
  if (!ok) failures++;
}

const ROOT = process.cwd();
const src = (p: string) => readFileSync(join(ROOT, p), "utf8");

// --- 6. Branded 404 --------------------------------------------------
const notFound = renderToString(React.createElement(NotFound)).replace(/<!-- -->/g, "");
check("404 explains the owner/repo URL shape", notFound.includes("git-secure.com/owner/repo"));
check("404 gives the Squ1zM0/GitSecure example", notFound.includes("git-secure.com/Squ1zM0/GitSecure"));
check("404 links home to scan", notFound.includes('href="/"') && notFound.includes("Scan a repo"));
check("404 uses the error card with role=alert", notFound.includes('role="alert"') && notFound.includes("error-card"));
check("404 has no stock Next.js wording", !notFound.includes("This page could not be found"));

// --- 10. MCP section -------------------------------------------------
check("MCP canonical URL is git-secure.com/mcp", MCP_URL === "https://git-secure.com/mcp");
check("no vercel.app MCP URL in mcp-config", !src("src/lib/mcp-config.ts").includes("gitsecure.vercel.app"));
check("no vercel.app MCP URL in the /mcp route comment", !src("src/app/mcp/route.ts").includes("gitsecure.vercel.app"));
check("no vercel.app MCP URL in README", !src("README.md").includes("gitsecure.vercel.app/mcp"));
check("all four snippets are valid JSON with the canonical URL", MCP_SNIPPETS.length === 4 && MCP_SNIPPETS.every((s) => {
  const parsed = JSON.parse(s.json) as Record<string, unknown>;
  return JSON.stringify(parsed).includes("https://git-secure.com/mcp");
}));

const mcp = renderToString(React.createElement(McpSection)).replace(/<!-- -->/g, "");
check(
  "MCP section explains what MCP is in one plain line",
  mcp.includes("MCP lets an AI assistant like Claude call GitSecure for you - no account needed."),
);
check("MCP explainer line sits at the top of the section", mcp.indexOf("MCP lets an AI assistant") < mcp.indexOf("Server URL"));
check("MCP section renders the canonical URL", mcp.includes("https://git-secure.com/mcp"));
const detailsAt = mcp.indexOf("<details");
check("MCP snippets are collapsed behind a <details>", detailsAt >= 0);
check(
  "all four snippets sit inside the <details>",
  detailsAt >= 0 && ["Claude", "Cursor", "VS Code", "Windsurf"].every((c) => mcp.indexOf(c, detailsAt) >= 0),
);
check("MCP details summary names the four clients", mcp.includes("Setup snippets for Claude, Cursor, VS Code, and Windsurf/Cline"));
const mcpCompact = renderToString(React.createElement(McpSection, { compact: true })).replace(/<!-- -->/g, "");
check("compact MCP section keeps the canonical URL", mcpCompact.includes("https://git-secure.com/mcp"));
check("compact MCP section keeps one snippet visible", mcpCompact.includes("Claude") && !mcpCompact.includes("<details"));

const css = src("src/app/globals.css");
check("mobile CSS fades the right edge of snippet code blocks", css.includes(".snippet pre") && css.includes("mask-image: linear-gradient(to right"));

// --- 11. Loading copy ------------------------------------------------
const loading = renderToString(React.createElement(Loading)).replace(/<!-- -->/g, "");
check("loading screen says 15–30 seconds", loading.includes("15–30 seconds"));
check("loading screen scopes 15–30 seconds to small repos", loading.includes("A small repo usually takes 15–30 seconds"));
check("loading screen says large repos take several minutes", loading.includes("takes several minutes"));
check("loading screen never makes the unscoped 15–30 second claim", !loading.includes("A full scan usually takes 15–30 seconds"));
check("loading screen keeps the nothing-to-click line", loading.includes("there is nothing to click"));
check("loading screen no longer promises about 15 seconds", !loading.includes("about 15 seconds"));
const home = src("src/app/page.tsx");
check("home scan-status scopes 15–30 seconds to small repos", home.includes("Small repos usually take 15–30 seconds; a large repo with a long history takes several minutes."));
check("home scan-status never makes the unscoped 15–30 second claim", !home.includes("This usually takes 15–30 seconds."));
check("home scan-status no longer promises about 15 seconds", !home.includes("about 15 seconds"));

// --- 14. Visible scan label ------------------------------------------
check("home form has a visible label above the input", home.includes('<label htmlFor="scan-input">GitHub repo to scan</label>'));
check("label is wired to the input id", home.includes('id="scan-input"'));
check("label comes before the input in the form", home.indexOf("GitHub repo to scan") < home.indexOf('id="scan-input"'));
check("prefilled value unchanged", home.includes('useState("Squ1zM0/GitSecure")'));
check("empty-input validation message unchanged", home.includes("Enter a repo to scan, like Squ1zM0/GitSecure."));
check("bad-format validation message unchanged", home.includes("Enter owner/repo - for example Squ1zM0/GitSecure."));
check("scan-field label styled in the design system", css.includes(".scan-field label"));
check("no literal secret-pattern values in the changed UI files", !/(sk_live|ghp_|AKIA|discord\.com\/api\/webhooks\/\d+\/)[A-Za-z0-9]/.test(
  src("src/app/not-found.tsx") + src("src/components/McpSection.tsx") + src("src/app/page.tsx") + src("src/app/[owner]/[repo]/loading.tsx"),
));

console.log(failures === 0 ? "\nAll Phase 15 worker-C checks passed." : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
