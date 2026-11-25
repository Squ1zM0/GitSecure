// Alias for the canonical MCP endpoint (/mcp). Same handler, same
// stateless Streamable HTTP transport, public reports only. Document
// /mcp as canonical; this alias exists for clients that expect /api/*.
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
