// GitSecure MCP server — lets an LLM ask GitSecure about a public repo
// over the Model Context Protocol (Streamable HTTP transport, stateless).
//
// HARD RULE: MCP returns PUBLIC reports only, always. Every tool response
// goes through toPublicReport, so no file names, line numbers, secret
// fragments, vulnerability IDs, or framework versions ever leave over
// MCP. There is no `full` parameter and no owner-mode flag on any tool —
// full detail stays owner-only via the signed-in web flow. The scanner
// itself is unchanged: same scanRepo, same scores, same limits.
//
// Stateless by design: a fresh McpServer + transport is created per HTTP
// request (sessionIdGenerator: undefined), so nothing is held in memory
// between invocations and the endpoint works on the Vercel serverless
// runtime. No git binary is required — the scan path already falls back
// to API patches when git is unavailable.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import { ScanError, scanRepoWithTimeout, toPublicReport, validateOwnerRepo } from "./scan";

const NAME_RE = /^[A-Za-z0-9_.-]+$/;
const NAME_MESSAGE =
  "Owner and repo names can only use letters, numbers, dots, hyphens and underscores — check for typos or extra characters.";

/** The two repo tools share one input shape: exactly owner + repo.
 *  No `full` parameter exists on any MCP tool, by design. */
const repoInput = {
  owner: z.string().regex(NAME_RE, NAME_MESSAGE).describe("The GitHub owner (user or organisation) of the repo, for example Squ1zM0."),
  repo: z.string().regex(NAME_RE, NAME_MESSAGE).describe("The GitHub repo name, for example TechDirect."),
};

function toolError(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true,
  };
}

/** Run a live scan and return the PUBLIC report as JSON text.
 *  ScanError messages are already plain English; anything else gets a
 *  generic message — never a stack trace. */
async function publicScan(owner: string, repo: string) {
  try {
    validateOwnerRepo(owner, repo);
    const full = await scanRepoWithTimeout(owner, repo);
    return {
      content: [{ type: "text" as const, text: JSON.stringify(toPublicReport(full), null, 2) }],
    };
  } catch (err) {
    if (err instanceof ScanError) return toolError(err.message);
    return toolError("The scan failed. Try again in a bit.");
  }
}

const LIST_CHECKS_TEXT = `What GitSecure checks when it scans a public GitHub repo:

1. Leaked secrets — Discord and Slack webhooks, AWS keys, GitHub tokens, Stripe and OpenAI keys, database URLs, private keys, committed .env files, and hardcoded passwords. Checked in the current files AND in the full history (newest-first), because deleting a file does not delete the commit it was in.
2. Frameworks — what the repo is built with (Next.js, React, Vite, Django, Flask, FastAPI, Rust crates, Go, Rails, Laravel, Spring, ASP.NET Core and more), with exact versions taken from lockfiles where possible. Unpinned versions (* or latest) are flagged; when a version cannot be determined, the report says so instead of guessing.
3. Dependency flaws — known vulnerabilities in direct and transitive dependencies, checked against OSV.dev, a free public database of known software flaws. Each one comes with a plain summary, a severity score, and the version that fixes it.
4. Security posture — missing SECURITY.md, no Dependabot config, .gitignore gaps, and risky GitHub Actions patterns (pull_request_target, write-all permissions, secrets echoed into logs).

What you get back from a scan is the PUBLIC report only: a score from 0 to 100, a letter grade, counts, a one-paragraph summary, and the honest limits below. You do NOT get file names, line numbers, secret fragments, vulnerability IDs, or framework versions — that full detail is available only to the repo owner through the signed-in web flow.

Honest limits:
- History is scanned newest-first via an ephemeral clone, capped at 1,000 commits / 50 MB of patches / 45 seconds. A secret in a very old commit of a huge repo may still be missed, and the report says when a cap was hit. If the runtime has no git binary, the scan falls back to the 5 most recent commits and says so.
- At most 250 files per scan (manifests and configs first), 200 KB per file, 3 MB total; at most 100 secret findings and 100 advisories listed per report.
- Dependency detail is fetched for up to 50 advisories per scan; any beyond that are listed with their advisory ID only.
- Unauthenticated GitHub API is 60 requests/hour; a scan uses roughly 7 API calls plus raw file fetches. If GitHub's request limit is hit, scans fail with a plain-English rate-limit error — try again in a few minutes.
- GitSecure is not a replacement for GitHub Advanced Security.`;

export function createMcpServer(): McpServer {
  const server = new McpServer(
    { name: "gitsecure", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.registerTool(
    "scan_repo",
    {
      title: "Scan a repo",
      description:
        "Run a live security scan of a public GitHub repo and return its public report. " +
        "Use this when someone asks whether a repo is safe, or asks to scan or check a repo. " +
        "Give owner and repo separately (for example owner Squ1zM0, repo TechDirect). " +
        "Returns the public report only: a score from 0 to 100, a letter grade, counts of possible leaked secrets, " +
        "dependency vulnerabilities, frameworks, dependencies and posture issues, a one-paragraph summary, and the scan's honest limits. " +
        "It does NOT return file names, line numbers, secret fragments, vulnerability IDs, or framework versions — " +
        "that full detail is available only to the repo owner through the signed-in web flow. " +
        "A scan takes about 15 seconds and looks at current files plus full history. " +
        "If the repo does not exist or is private, or GitHub's request limit is hit, the tool returns a plain-English error instead of a result.",
      inputSchema: repoInput,
      annotations: { readOnlyHint: true },
    },
    async ({ owner, repo }) => publicScan(owner, repo),
  );

  server.registerTool(
    "get_report",
    {
      title: "Get a repo report",
      description:
        "Read (or refresh) the public security report for a public GitHub repo. " +
        "Use this when someone asks for the current score or report for a repo that may already have been scanned, or to check the latest result. " +
        "It runs a fresh live scan each time — GitSecure never stores reports — so the result is always current. " +
        "Returns the same public report as scan_repo: score, grade, counts, summary and limits. " +
        "It does NOT return file names, line numbers, secret fragments, vulnerability IDs, or framework versions; " +
        "full detail is owner-only via the signed-in web flow.",
      inputSchema: repoInput,
      annotations: { readOnlyHint: true },
    },
    async ({ owner, repo }) => publicScan(owner, repo),
  );

  server.registerTool(
    "list_checks",
    {
      title: "List what GitSecure checks",
      description:
        "List what GitSecure checks when it scans a repo, in plain English, plus the honest limits of each check. " +
        "Use this when someone asks what GitSecure looks for, what a scan covers, or what it cannot catch — before running a scan, or to explain a score. " +
        "Takes no arguments. Returns a description of the four checks (leaked secrets, frameworks, dependency flaws, security posture) and the limits. " +
        "It does not scan anything and returns no score.",
      annotations: { readOnlyHint: true },
    },
    async () => ({ content: [{ type: "text" as const, text: LIST_CHECKS_TEXT }] }),
  );

  return server;
}

/** Handle one MCP HTTP request (POST, GET, or DELETE) statelessly.
 *  A fresh server + transport is created per request, so no session
 *  state survives between invocations. JSON responses (not SSE) are
 *  used so a long scan (~15 s) comes back as one response, which fits
 *  the serverless runtime. GET is the SSE stream endpoint: in stateless
 *  mode the transport answers it with a 4xx (406 without an SSE Accept
 *  header), which is the correct behaviour for a server that holds no
 *  streams. Note: a GET that *does* ask for text/event-stream opens a
 *  standalone SSE stream the transport holds open — MCP clients use POST,
 *  so this is not probed in the test (it would hang). */
export async function handleMcpRequest(req: Request): Promise<Response> {
  const server = createMcpServer();
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  await server.connect(transport);
  try {
    return await transport.handleRequest(req);
  } catch {
    return new Response(
      JSON.stringify({ error: "The MCP request could not be handled. Try again." }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
}
