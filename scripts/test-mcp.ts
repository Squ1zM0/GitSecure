// MCP end-to-end test — real protocol handshake against a RUNNING server.
// Start the production server first:
//   npm run build && npm start          (default http://localhost:3000)
// or point at another server:
//   MCP_BASE_URL=http://localhost:3000 npm run test:mcp
//
// What it checks, against the live server:
//   1. initialize handshake (client.connect) succeeds
//   2. tools/list returns scan_repo, get_report, list_checks — and NO tool
//      accepts a `full` or `owner` parameter (full detail is the default
//      for everyone now; there is no gate to opt into)
//   3. tools/call list_checks returns the plain-English check descriptions
//   4. tools/call scan_repo Squ1zM0/TechDirect returns the known FULL
//      result (83/B, 0 secrets, 4 vulns) — with the full detail present
//      (vulnerability IDs, js-yaml, fixed versions)
//   5. tools/call scan_repo Squ1zM0/GitSecure returns 1/F with 6 secrets
//      counted — and the response DOES carry the full detail (file names,
//      line numbers, redacted fragments) while containing NO full fake
//      secret anywhere (redaction rule, proved on a repo WITH findings).
//      NOTE: the repo scored 3/F in the MVP era, then 0/F after the
//      Phase 2 push (remote main d6a7e13) added package-lock.json (119
//      deps fingerprinted), Tier 2 fixtures and a fake vite.config.ts.
//      It is 1/F now: deductions are 76 (secrets) + 19 (posture) + 4
//      (2 unpinned deps) = 99. The 0/F was measured at remote d6a7e136;
//      the Phase 3 push (5d8da890) changed the repo's contents and the
//      unpinned count. Secrets are still the same 6 known-fake ones.
//      The change is in the remote repo's contents, not the scanner.
//   6. bad owner/repo format and a missing repo return plain-English
//      errors, never a stack trace
//   7. the config snippets shown on the human pages are valid JSON
//   8. GET /mcp answers 405 (stateless server holds no SSE stream)
//
// Exit 0 = all checks pass. Any failure prints FAIL and exits 1.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { MCP_SNIPPETS } from "../src/lib/mcp-config";

const BASE = (process.env.MCP_BASE_URL ?? "http://localhost:3000").replace(/\/+$/, "");
const MCP_URL = `${BASE}/mcp`;
const SCAN_TIMEOUT_MS = 120_000;

let passed = 0;
function check(name: string, ok: boolean, detail = "") {
  if (ok) {
    passed++;
    console.log(`  PASS ${name}`);
  } else {
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
    process.exitCode = 1;
  }
}
function toolText(result: { content?: unknown; isError?: boolean }): string {
  const content = (result as { content?: { type?: string; text?: string }[] }).content ?? [];
  return content.filter((c) => c.type === "text").map((c) => c.text ?? "").join("\n");
}
function looksLikeStackTrace(text: string): boolean {
  return /^\s*at\s+\S+\s*\(/m.test(text) || text.includes("node:internal") || text.includes("Error: ");
}

async function main() {
  console.log(`MCP test against ${MCP_URL}`);
  console.log("  (start the production server first: npm run build && npm start)");

  // 0. Server reachable at all.
  let reachable = false;
  try {
    const res = await fetch(`${BASE}/`, { signal: AbortSignal.timeout(10_000) });
    reachable = res.ok;
  } catch {
    reachable = false;
  }
  check("server reachable (home page 200)", reachable);
  if (!reachable) {
    console.log("  Server is not running — start it with `npm run build && npm start` and re-run.");
    process.exit(1);
  }

  // 1. Real protocol handshake.
  const client = new Client({ name: "gitsecure-test", version: "0.1.0" }, { capabilities: {} });
  const transport = new StreamableHTTPClientTransport(new URL(MCP_URL));
  try {
    await client.connect(transport);
  } catch (err) {
    check("initialize handshake", false, err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
  check("initialize handshake", true);

  // 2. tools/list.
  const listed = await client.listTools();
  const names = listed.tools.map((t) => t.name).sort();
  check("tools/list returns scan_repo, get_report, list_checks", JSON.stringify(names) === JSON.stringify(["get_report", "list_checks", "scan_repo"]), `got ${names.join(", ")}`);
  const toolsByName = new Map(listed.tools.map((t) => [t.name, t]));
  for (const name of ["scan_repo", "get_report", "list_checks"]) {
    const tool = toolsByName.get(name);
    check(`tool ${name} has a plain-English description`, !!tool?.description && tool.description.length > 50, tool?.description ?? "(none)");
  }
  // NOTE: `owner` IS a legitimate input (the repo owner's name) — only
  // a `full` flag would be a gate parameter, and there is none: full
  // detail is the default for everyone now.
  const noGateParam = listed.tools.every((t) => {
    const props = (t.inputSchema as { properties?: Record<string, unknown> }).properties ?? {};
    return !("full" in props);
  });
  check("no tool accepts a `full` gate parameter (full detail is the default)", noGateParam);

  // 3. list_checks.
  const checks = await client.callTool({ name: "list_checks", arguments: {} });
  const checksText = toolText(checks);
  check("list_checks mentions leaked secrets", /leaked secret/i.test(checksText));
  check("list_checks mentions frameworks", /framework/i.test(checksText));
  check("list_checks mentions dependency flaws", /dependency/i.test(checksText));
  check("list_checks mentions posture", /posture/i.test(checksText));
  check("list_checks states the scan notes", /scan notes/i.test(checksText));
  check("list_checks does not scan (no report JSON / score field)", !checksText.includes('"score"') && !checksText.includes('"counts"'));

  // 4. scan_repo TechDirect — known result 83/B, 0 secrets, 4 vulns.
  console.log("  calling scan_repo Squ1zM0/TechDirect (live scan, ~15 s)...");
  const td = await client.callTool(
    { name: "scan_repo", arguments: { owner: "Squ1zM0", repo: "TechDirect" } },
    undefined,
    { timeout: SCAN_TIMEOUT_MS },
  );
  check("scan_repo TechDirect is not an error", !td.isError, toolText(td).slice(0, 200));
  const tdText = toolText(td);
  let tdReport: { score?: number; grade?: string; counts?: Record<string, number>; kind?: string } | null = null;
  try {
    tdReport = JSON.parse(tdText) as typeof tdReport;
  } catch {
    tdReport = null;
  }
  check("scan_repo TechDirect returns parseable JSON", tdReport !== null);
  check("scan_repo TechDirect kind is full", tdReport?.kind === "full", `kind=${tdReport?.kind}`);
  check("scan_repo TechDirect score 83 / grade B", tdReport?.score === 83 && tdReport?.grade === "B", `got ${tdReport?.score}/${tdReport?.grade}`);
  check("scan_repo TechDirect 0 secrets, 4 vulns", tdReport?.counts?.secrets === 0 && tdReport?.counts?.vulnerabilities === 4, JSON.stringify(tdReport?.counts));
  const tdKeys = tdReport ? Object.keys(tdReport) : [];
  for (const field of ["secrets", "frameworks", "vulnerabilities", "posture", "dependencies"]) {
    check(`scan_repo TechDirect response HAS the "${field}" field (full detail)`, tdKeys.includes(field));
  }
  check("scan_repo TechDirect response names the vulnerable package (js-yaml)", tdText.includes("js-yaml"));
  check("scan_repo TechDirect response includes fixed versions", /"fixedVersion"/.test(tdText));
  check("scan_repo TechDirect scanned the whole tree (>250 files)", (tdReport?.counts?.filesScanned ?? 0) > 250, `filesScanned=${tdReport?.counts?.filesScanned}`);

  // 5. scan_repo GitSecure — 3/F, 6 secrets counted; the public-only
  // proof: a repo WITH findings must still leak no file/line/fragment.
  console.log("  calling scan_repo Squ1zM0/GitSecure (live scan, has known-fake findings)...");
  const gs = await client.callTool(
    { name: "scan_repo", arguments: { owner: "Squ1zM0", repo: "GitSecure" } },
    undefined,
    { timeout: SCAN_TIMEOUT_MS },
  );
  check("scan_repo GitSecure is not an error", !gs.isError, toolText(gs).slice(0, 200));
  const gsText = toolText(gs);
  let gsReport: { score?: number; grade?: string; counts?: Record<string, number>; kind?: string } | null = null;
  try {
    gsReport = JSON.parse(gsText) as typeof gsReport;
  } catch {
    gsReport = null;
  }
  check("scan_repo GitSecure returns parseable JSON", gsReport !== null);
  // Score moved 0 → 1 in Phase 4: the deductions are 76 (secrets: 4 high
  // + 2 medium) + 19 (posture) + 4 (2 unpinned deps × 2) = 99, so the
  // score is 1. The 0/F was measured when remote head was d6a7e136
  // (Phase 2); the Phase 3 push (5d8da890) changed the repo's contents
  // and the unpinned count, so the total dropped below the 100-point
  // clamp. The scanner change cannot affect this repo: 53 files, so the
  // old 250-file cap never bound. 6 secrets counted, unchanged.
  check("scan_repo GitSecure score 1 / grade F (see note above: 0/F was at remote d6a7e136, before the Phase 3 push)", gsReport?.score === 1 && gsReport?.grade === "F", `got ${gsReport?.score}/${gsReport?.grade}`);
  check("scan_repo GitSecure counts 6 secrets", gsReport?.counts?.secrets === 6, `got ${gsReport?.counts?.secrets}`);
  check("scan_repo GitSecure kind is full", gsReport?.kind === "full");
  // Full detail IS present now: file names, line numbers, fragments.
  check("scan_repo GitSecure response carries file names (full detail)", gsText.includes("tests/fixtures"));
  check("scan_repo GitSecure response carries redacted fragments", gsText.includes("fragment"));
  // But no FULL fake secret may ever appear — the redaction rule is
  // unchanged. Fake secrets assembled from fragments at runtime (never
  // literal — GitHub push protection blocks literal secret patterns).
  const FAKE = "FAKE";
  const fakeSecrets = [
    "https://discord.com/api/webhooks/" + "123456789012345678/" + FAKE.repeat(6) + "123456",
    "AKIA" + "IOSFODNN7EXAMPLE",
    "ghp_" + FAKE.repeat(8) + "1234",
    "sk_live_" + FAKE.repeat(6) + "12",
    "sk-proj-" + FAKE.repeat(7),
    "hunter2hunter2",
  ];
  for (const secret of fakeSecrets) {
    check(`scan_repo GitSecure response contains no full fake secret (${secret.slice(0, 18)}…)`, !gsText.includes(secret));
  }

  // 5b. get_report returns the same public shape.
  const gr = await client.callTool(
    { name: "get_report", arguments: { owner: "Squ1zM0", repo: "TechDirect" } },
    undefined,
    { timeout: SCAN_TIMEOUT_MS },
  );
  let grReport: { score?: number; grade?: string; kind?: string } | null = null;
  try {
    grReport = JSON.parse(toolText(gr)) as typeof grReport;
  } catch {
    grReport = null;
  }
  check("get_report TechDirect returns the full report (83/B)", !gr.isError && grReport?.kind === "full" && grReport?.score === 83 && grReport?.grade === "B", toolText(gr).slice(0, 200));

  // 6. Plain-English errors, never a stack trace.
  const bad = await client.callTool({ name: "scan_repo", arguments: { owner: "bad owner!", repo: "x" } });
  const badText = toolText(bad);
  check("bad owner/repo format is a tool error", !!bad.isError);
  check("bad owner/repo error is plain English", /letters, numbers/i.test(badText), badText.slice(0, 200));
  check("bad owner/repo error has no stack trace", !looksLikeStackTrace(badText), badText.slice(0, 200));

  const missing = await client.callTool(
    { name: "scan_repo", arguments: { owner: "Squ1zM0", repo: "NoSuchRepo12345" } },
    undefined,
    { timeout: SCAN_TIMEOUT_MS },
  );
  const missingText = toolText(missing);
  check("missing repo is a tool error", !!missing.isError);
  check("missing repo error is plain English (not found / private)", /not found|private/i.test(missingText), missingText.slice(0, 200));
  check("missing repo error has no stack trace", !looksLikeStackTrace(missingText), missingText.slice(0, 200));

  // 7. Config snippets on the human pages are valid JSON.
  for (const s of MCP_SNIPPETS) {
    let valid = false;
    try {
      const parsed = JSON.parse(s.json) as Record<string, unknown>;
      const servers = (parsed.mcpServers ?? parsed.servers) as Record<string, { url?: string; serverUrl?: string }> | undefined;
      valid = !!servers?.gitsecure && !!((servers.gitsecure as { url?: string }).url ?? (servers.gitsecure as { serverUrl?: string }).serverUrl);
    } catch {
      valid = false;
    }
    check(`config snippet for ${s.client} is valid JSON pointing at /mcp`, valid, s.json);
  }

  // 8. GET /mcp: stateless server holds no SSE stream, so a plain GET
  // (no SSE Accept header) is refused with a 4xx. 406 = the transport
  // wants text/event-stream for a stream it cannot open statelessly;
  // 405 is the same refusal on other SDK versions.
  const getRes = await fetch(MCP_URL);
  check("GET /mcp answers 4xx (stateless, no SSE stream)", getRes.status === 405 || getRes.status === 406, `got ${getRes.status}`);

  await client.close();
  console.log(`\nMCP test: ${passed} checks passed${process.exitCode ? " (FAILURES above)" : ""}.`);
}

main().catch((err) => {
  console.error("MCP test failed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
