// GitSecure MCP server — lets an LLM ask GitSecure about a public repo
// over the Model Context Protocol (Streamable HTTP transport, stateless).
//
// Phase 4: MCP returns the FULL report, like the web flow — the site
// only scans public repos, so the detail is information already public
// in the repo, and there is no login flow. HARD RULE (unchanged): a
// secret is never shown in full — redacted fragment only, never
// stored, never live-validated. The scanner itself is unchanged: same
// scanRepo, same scores. Phase 9 runs the scan as stateless CHUNKS
// (see chunks.ts) and polls them server-side with the cursor until the
// scan finishes, within MCP's own limits.
//
// Stateless by design: a fresh McpServer + transport is created per HTTP
// request (sessionIdGenerator: undefined), so nothing is held in memory
// between invocations and the endpoint works on the Vercel serverless
// runtime. The scan holds no server-side state either — the cursor the
// tools return carries the whole resume position, so a resume_scan call
// that lands on another instance simply continues from it. No git binary
// is required — the scan path already falls back to API patches when
// git is unavailable.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import { FAST_PATH_WAIT_MS, runScanLoop } from "./chunks";
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
 *  Phase 9: the scan runs as stateless chunks and this tool drives
 *  them server-side with the cursor until the scan finishes, within
 *  MCP's own limits (the ~50 s fast-path wait). A large repo that is
 *  still running after that comes back as a plain-English "still
 *  running" message with the live progress AND the cursor — the scan
 *  holds no server-side state, so calling resume_scan with that cursor
 *  continues it from the last finished chunk, on any instance. */
async function fullScan(owner: string, repo: string) {
  try {
    validateOwnerRepo(owner, repo);
    const result = await runScanLoop(owner, repo, { budgetMs: FAST_PATH_WAIT_MS });
    if (result.status === "done" && result.report) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result.report, null, 2) }],
      };
    }
    const p = result.progress;
    return {
      content: [
        {
          type: "text" as const,
          text:
            `The scan of ${owner}/${repo} is still running (cursor ${result.cursor}). ` +
            `So far: ${p ? `${p.filesScanned} of ${p.filesTotal > 0 ? p.filesTotal : "the"} files scanned, ` : ""}` +
            `${p ? `${p.commitsScanned} history commits checked. ` : ""}` +
            `Call resume_scan with this cursor to continue it from the last finished chunk — do not start a new scan.`,
        },
      ],
    };
  } catch (err) {
    if (err instanceof ScanError) return toolError(err.message);
    return toolError("The scan failed. Try again in a bit.");
  }
}

/** Continue a scan from a cursor returned by scan_repo / get_report /
 *  resume_scan. The cursor pins the repo; its owner/repo are read out
 *  of it (leniently — strict validation happens inside the driver). */
async function resumeScan(cursor: string) {
  try {
    let owner = "";
    let repo = "";
    try {
      const parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { owner?: unknown; repo?: unknown };
      if (typeof parsed.owner === "string") owner = parsed.owner;
      if (typeof parsed.repo === "string") repo = parsed.repo;
    } catch {
      // Falls through to the cursor error below.
    }
    if (!owner || !repo) {
      return toolError("That scan link doesn't look right — it may be from an older scan or pasted wrong. Starting a fresh scan instead.");
    }
    const result = await runScanLoop(owner, repo, { cursor, budgetMs: FAST_PATH_WAIT_MS });
    if (result.status === "done" && result.report) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result.report, null, 2) }],
      };
    }
    const p = result.progress;
    return {
      content: [
        {
          type: "text" as const,
          text:
            `The scan of ${owner}/${repo} is still running (cursor ${result.cursor}). ` +
            `So far: ${p ? `${p.filesScanned} of ${p.filesTotal > 0 ? p.filesTotal : "the"} files scanned, ` : ""}` +
            `${p ? `${p.commitsScanned} history commits checked. ` : ""}` +
            `Call resume_scan again with this cursor to continue it from the last finished chunk.`,
        },
      ],
    };
  } catch (err) {
    if (err instanceof ScanError) return toolError(err.message);
    return toolError("The scan failed. Try again in a bit.");
  }
}

const LIST_CHECKS_TEXT = `What GitSecure checks when it scans a public GitHub repo:

1. Leaked secrets — Discord and Slack webhooks, AWS keys, GitHub tokens, Stripe and OpenAI keys, database URLs, private keys, committed .env files, and hardcoded passwords. Checked in the current files AND in the full history (newest-first), because deleting a file does not delete the commit it was in. Every secret finding carries a triage annotation: likely-test-key (an intentional test key — still listed and still counted, with a test-key fix instead of "rotate it"), likely-genuine-leak, or uncertain. Triage looks at the file's path and contents, the key itself (type, size, whether its fingerprint matches a published test key, whether its public half is committed in the same repo), and the detector's own result — but it never removes a finding and never changes the score: a likely-test finding still counts in the secrets total and still deducts its detector severity, so relabelling one cannot inflate the score. Every secret finding also carries a secret usage note — in use vs dead end: whether anything in the repo still references the key, by the key's own name (its variable or env name, key filename, or config key) and never by the secret value itself. A reference from non-test code means the key is in use (and can upgrade a test-key verdict when it comes from production code); references from tests alone do not count as in use; a key nothing anywhere references is a dead end. For secrets found in history, usage is checked against the current files only.
2. Frameworks — what the repo is built with (Next.js, React, Vite, Django, Flask, FastAPI, Rust crates, Go, Rails, Laravel, Spring, ASP.NET Core and more), with exact versions taken from lockfiles where possible. Unpinned versions (* or latest) are flagged; when a version cannot be determined, the report says so instead of guessing.
3. Dependency flaws — known vulnerabilities in direct and transitive dependencies, checked against OSV.dev, a free public database of known software flaws. Each one comes with a plain summary, a severity score, and the version that fixes it.
4. Security posture — missing SECURITY.md, no Dependabot config, .gitignore gaps, and risky GitHub Actions patterns (pull_request_target, write-all permissions, secrets echoed into logs).

What you get back from a scan is the FULL report: a score from 0 to 100, a letter grade, counts, a one-paragraph summary, and the full detail — file names, line numbers, redacted secret fragments, framework versions, and vulnerability IDs with the version that fixes each one. Secrets are never shown in full, only as redacted fragments.

Scan notes:
- History is scanned newest-first via the git protocol, or via the GitHub API when the repo is too large to clone. The report says which path was used and exactly how many commits were checked.
- Every file in the repo tree is scanned, manifests and configs first (binary, dist, node_modules and .next skipped — generated/vendored paths, not source files). Every secret finding and every advisory found is listed — there is no cap on the number of results in a report.
- Full advisory detail (a plain summary, a severity score, and the version that fixes it) is fetched for every advisory found, and the flaw check covers every pinned dependency. A scan runs as stateless chunks: small repos answer in one call, about 15 seconds; a large repo keeps running and the tool says so with its live progress and a cursor — call resume_scan with that cursor to continue it from the last finished chunk. The server holds no scan state, so a restart never loses a scan; GitSecure never stores reports on disk or in a database.
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
        "A large repo keeps running in chunks — the tool says so with its live progress and a cursor, and calling resume_scan with that cursor continues it from the last finished chunk. " +
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
        "It runs a fresh live scan — GitSecure never stores reports on disk or in a database, so the result is always current. If a scan is already running, resume it with resume_scan and the cursor instead of starting over. " +
        "Returns the same full report as scan_repo: score, grade, counts, summary, limits, and the full detail " +
        "(file names, line numbers, redacted secret fragments, framework versions, vulnerability IDs). " +
        "Secrets are never shown in full.",
      inputSchema: repoInput,
      annotations: { readOnlyHint: true },
    },
    async ({ owner, repo }) => fullScan(owner, repo),
  );

  server.registerTool(
    "resume_scan",
    {
      title: "Resume a scan",
      description:
        "Continue a scan that is still running, from the cursor scan_repo or get_report returned. " +
        "Use this when a scan came back as still running instead of starting a new scan — the cursor carries the whole resume position, so the scan continues from the last finished chunk instead of starting over, even if the server restarted since. " +
        "Returns the full report when the scan finishes, or another still-running message with a fresh cursor when it needs more chunks. " +
        "If the cursor is bad or from an older scan, the tool returns a plain-English error instead of a result.",
      inputSchema: {
        cursor: z.string().describe("The cursor string a scan_repo or get_report call returned for the still-running scan."),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ cursor }) => resumeScan(cursor),
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
