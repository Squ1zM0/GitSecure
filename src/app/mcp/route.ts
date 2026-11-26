// Canonical MCP endpoint: https://www.git-secure.com/mcp
// Streamable HTTP transport, stateless (a fresh server + transport per
// request — no session state, no git binary required). /api/mcp is an
// alias serving the same handler. Full reports to anyone — the site
// only scans public repos, and there is no login flow.
import { handleMcpRequest } from "@/lib/mcp";

export const maxDuration = 60;

export async function POST(req: Request) {
  return handleMcpRequest(req);
}

export async function GET(req: Request) {
  return handleMcpRequest(req);
}

export async function DELETE(req: Request) {
  return handleMcpRequest(req);
}
