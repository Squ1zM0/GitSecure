// Canonical MCP endpoint: https://gitsecure.vercel.app/mcp
// Streamable HTTP transport, stateless (a fresh server + transport per
// request — no session state, no git binary required). /api/mcp is an
// alias serving the same handler. Public reports only, always.
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
