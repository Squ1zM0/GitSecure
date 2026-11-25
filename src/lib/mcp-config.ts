// MCP config snippets shown on the human pages (home + report).
// Plain constants only — no server code — so the client-side copy
// component can import this file without pulling the scanner in.
// Every snippet is valid JSON; the test in scripts/test-mcp.ts parses
// each one. Canonical server URL is /mcp; /api/mcp is an alias.

export const MCP_URL = "https://gitsecure.vercel.app/mcp";

export interface McpSnippet {
  id: string;
  client: string;
  where: string;
  json: string;
}

export const MCP_SNIPPETS: McpSnippet[] = [
  {
    id: "claude",
    client: "Claude",
    where: "Claude Code / Claude Desktop config file",
    json: JSON.stringify(
      { mcpServers: { gitsecure: { url: MCP_URL } } },
      null,
      2,
    ),
  },
  {
    id: "cursor",
    client: "Cursor",
    where: "Cursor Settings → MCP → add a new server",
    json: JSON.stringify(
      { mcpServers: { gitsecure: { url: MCP_URL } } },
      null,
      2,
    ),
  },
  {
    id: "vscode",
    client: "VS Code",
    where: "Your workspace .vscode/mcp.json file",
    json: JSON.stringify(
      { servers: { gitsecure: { type: "http", url: MCP_URL } } },
      null,
      2,
    ),
  },
  {
    id: "windsurf",
    client: "Windsurf / Cline",
    where: "Windsurf or Cline MCP settings",
    json: JSON.stringify(
      { mcpServers: { gitsecure: { serverUrl: MCP_URL } } },
      null,
      2,
    ),
  },
];

/** One plain line, used on every human surface that mentions MCP. */
export const MCP_PLAIN_LINE =
  "Your AI assistant gets the full report — score, counts, file names, line numbers, and redacted secret fragments. Secrets are never shown in full, and there is no sign-up or login.";
