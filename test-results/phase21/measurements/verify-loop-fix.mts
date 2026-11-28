// Phase 21 Workstream A verification: the no-progress loop fix.
// Local mocks only - no GitHub, no network beyond localhost.
// - Mock git server: 500s every smart-HTTP request, so the clone
//   fails and the chunk falls through to the API fallback.
// - Mock API server: behaviour per test (500 / 403 / empty-list OK).
// Asserts advanceScan RETURNS a terminal partial (stage assemble)
// instead of throwing the identical 502 with no cursor.
// Usage: npx tsx verify-loop-fix.mts
import http from "node:http";
import { advanceScan } from "../../../src/lib/chunks";
import { decodeCursor, encodeCursor, initialHistoryCursor } from "../../../src/lib/cursor";

const HEAD_SHA = "a".repeat(40);

type ApiMode = "500" | "403" | "ok-empty";
let apiMode: ApiMode = "500";

const server = http.createServer((req, res) => {
  const url = req.url ?? "";
  if (url.startsWith("/repos/")) {
    if (apiMode === "500") {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: "Internal Server Error" }));
      return;
    }
    if (apiMode === "403") {
      // Secondary limit shape: 403 WITHOUT x-ratelimit-remaining: 0,
      // so the API chunk reports it as an unexpected error, not
      // rateLimited.
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: "API rate limit exceeded" }));
      return;
    }
    // ok-empty: HEAD check sees the pinned tip; the list is empty
    // (repo with no commits on this page) so history is done.
    res.writeHead(200, { "content-type": "application/json" });
    if (url.includes("per_page=1&")) res.end(JSON.stringify([{ sha: HEAD_SHA }]));
    else res.end(JSON.stringify([]));
    return;
  }
  // Smart-HTTP git paths: fail the clone outright.
  res.writeHead(500, { "content-type": "text/plain" });
  res.end("mock git server down");
});

await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
const port = (server.address() as { port: number }).port;
const base = `http://127.0.0.1:${port}`;

function historyCursor() {
  return encodeCursor(
    initialHistoryCursor({ owner: "o", repo: "r", branch: "main", headSha: HEAD_SHA, historyMethod: "git" }),
  );
}

async function runCase(name: string, mode: ApiMode) {
  apiMode = mode;
  try {
    const result = await advanceScan({
      owner: "o",
      repo: "r",
      cursor: historyCursor(),
      cloneUrlOverride: `${base}/o/r.git`,
      apiBase: base,
    });
    if (result.status !== "partial") {
      console.log(JSON.stringify({ case: name, mode, outcome: "UNEXPECTED_DONE", report: "done" }));
      return;
    }
    const next = decodeCursor(result.cursor, "o", "r");
    console.log(
      JSON.stringify({
        case: name,
        mode,
        outcome: "returned-partial (no throw)",
        stage: next.stage,
        histStop: next.histStop,
        histDone: next.histDone,
        histScanned: next.histScanned,
        historyMethod: next.historyMethod,
        note: result.note,
      }),
    );
  } catch (e) {
    const err = e as Error & { status?: number; kind?: string };
    console.log(
      JSON.stringify({
        case: name,
        mode,
        outcome: "THREW (old loop behaviour)",
        status: err.status ?? null,
        kind: err.kind ?? null,
        message: err.message,
      }),
    );
  }
}

await runCase("git-fails + api-500", "500");
await runCase("git-fails + api-403-secondary-limit", "403");
await runCase("git-fails + api-ok-empty (fallback still works)", "ok-empty");
server.close();
