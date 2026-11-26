// GitSecure MCP server — lets an LLM ask GitSecure about a public repo
// over the Model Context Protocol (Streamable HTTP transport, stateless).
//
// Phase 4: MCP returns the FULL report, like the web flow — the site
// only scans public repos, so the detail is information already public
// in the repo, and there is no login flow. HARD RULE (unchanged): a
// secret is never shown in full — redacted fragment only, never
// stored, never live-validated. The scanner itself is unchanged: same
// scanRepo, same scores. Phase 8 runs the scan as a background job
// (see jobs.ts) and polls it server-side until it finishes, within
// MCP's own limits.
//
// Stateless by design: a fresh McpServer + transport is created per HTTP
// request (sessionIdGenerator: undefined), so nothing is held in memory
// between invocations and the endpoint works on the Vercel serverless
// runtime. Scan jobs themselves live in the in-memory job store
// (src/lib/jobs.ts) — a job does not survive a cold start, and a
// get_report call that lands on another instance starts a fresh scan.
// No git binary is required — the scan path already falls back
// to API patches when git is unavailable.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import { FAST_PATH_WAIT_MS, getOrStartJob, waitForJob } from "./jobs";
import { ScanError, validateOwnerRepo } from "./scan";

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

/** Run a live scan and return the FULL report as JSON text.
 *  ScanError messages are already plain English; anything else gets a
 *  generic message — never a stack trace. Secrets in the report are
 *  redacted fragments only, never full values.
 *  Phase 8: the scan runs as a background job and this tool polls it
 *  server-side until it finishes, within MCP's own limits (the ~50 s
 *  fast-path wait). A large repo that is still running after that
 *  comes back as a plain-English "still running" message with the
 *  live progress and the job ID — the scan continues in the
 *  background, and calling get_report again picks up the SAME job
 *  (jobs dedupe by owner/repo) instead of starting over. */
async function fullScan(owner: string, repo: string) {
  try {
    validateOwnerRepo(owner, repo);
    const job = getOrStartJob(owner, repo);
    const finished = await waitForJob(job, FAST_PATH_WAIT_MS);
    if (finished.status === "done" && finished.report) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify(finished.report, null, 2) }],
      };
    }
    if (finished.status === "error" && finished.error) {
      return toolError(finished.error.message);
    }
    const p = finished.progress;
    return {
      content: [
        {
          type: "text" as const,
          text:
            `The scan of ${owner}/${repo} is still running in the background (job ${finished.id}). ` +
            `So far: ${p.filesScanned} of ${p.filesTotal > 0 ? p.filesTotal : "the"} files scanned, ` +
            `${p.commitsScanned} history commits checked. ` +
            `Call get_report again for the same repo and it will pick up this same scan — do not start a new one.`,
        },
      ],
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

What you get back from a scan is the FULL report: a score from 0 to 100, a letter grade, counts, a one-paragraph summary, and the full detail — file names, line numbers, redacted secret fragments, framework versions, and vulnerability IDs with the version that fixes each one. Secrets are never shown in full, only as redacted fragments.

Scan notes:
- History is scanned newest-first via an ephemeral clone, or via the GitHub API when the runtime has no git binary. The report says which path was used and exactly how many commits were checked.
- Every file in the repo tree is scanned, manifests and configs first (binary, dist, node_modules and .next skipped — generated/vendored paths, not source files). Every secret finding and every advisory found is listed — there is no cap on the number of results in a report.
- Full advisory detail (a plain summary, a severity score, and the version that fixes it) is fetched for every advisory found, and the flaw check covers every pinned dependency. A scan runs as a background job: small repos answer in one call, about 15 seconds; a large repo keeps running and the tool says so with its live progress — call get_report again for the same repo and it picks up the same scan instead of starting over. A finished scan is kept in memory only for a few minutes so a repeat call does not re-scan; GitSecure never stores reports on disk or in a database.
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
        "Run a live security scan of a public GitHub repo and return its full report. " +
        "Use this when someone asks whether a repo is safe, or asks to scan or check a repo. " +
        "Give owner and repo separately (for example owner Squ1zM0, repo TechDirect). " +
        "Returns the full report: a score from 0 to 100, a letter grade, counts of possible leaked secrets, " +
        "dependency vulnerabilities, frameworks, dependencies and posture issues, a one-paragraph summary, " +
        "plus the full detail — file names, line numbers, redacted secret fragments, framework versions, " +
        "and vulnerability IDs with the version that fixes each one. Secrets are never shown in full. " +
        "A small repo takes about 15 seconds and looks at current files plus full history. " +
        "A large repo keeps running in the background — the tool says so with its live progress, and calling get_report again picks up the same scan. " +
        "If the repo does not exist or is private, or GitHub's request limit is hit, the tool returns a plain-English error instead of a result.",
      inputSchema: repoInput,
      annotations: { readOnlyHint: true },
    },
    async ({ owner, repo }) => fullScan(owner, repo),
  );

  server.registerTool(
    "get_report",
    {
      title: "Get a repo report",
      description:
        "Read (or refresh) the full security report for a public GitHub repo. " +
        "Use this when someone asks for the current score or report for a repo that may already have been scanned, or to check the latest result. " +
        "If a scan of the repo is already running, it picks up that same scan; if one finished in the last few minutes it returns that result from memory; otherwise it runs a fresh live scan — GitSecure never stores reports on disk or in a database, so the result is always current. " +
        "Returns the same full report as scan_repo: score, grade, counts, summary, limits, and the full detail " +
        "(file names, line numbers, redacted secret fragments, framework versions, vulnerability IDs). " +
        "Secrets are never shown in full.",
      inputSchema: repoInput,
      annotations: { readOnlyHint: true },
    },
    async ({ owner, repo }) => fullScan(owner, repo),
  );

  server.registerTool(
    "list_checks",
    {
      title: "List what GitSecure checks",
      description:
        "List what GitSecure checks when it scans a repo, in plain English, plus the notes on each check. " +
        "Use this when someone asks what GitSecure looks for, what a scan covers, or what it cannot catch — before running a scan, or to explain a score. " +
        "Takes no arguments. Returns a description of the four checks (leaked secrets, frameworks, dependency flaws, security posture) and the scan notes. " +
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
