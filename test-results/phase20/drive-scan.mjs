// Drive a full live scan against git-secure.com: start, then chunk
// until done. Usage: node /tmp/drive-scan.mjs <owner> <repo>
const [owner, repo] = process.argv.slice(2);
const BASE = "https://git-secure.com";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 300) }; }
  return { status: res.status, json };
}

const start = await post("/api/scan/start", { owner, repo });
console.log("start:", start.status, JSON.stringify(start.json).slice(0, 300));
if (start.status !== 200) process.exit(1);
let cursor = start.json.cursor;
let head = start.json.head ?? null;
let historyFindings = [];
let guard = 0;
while (guard++ < 40) {
  const chunk = await post("/api/scan/chunk", { cursor, head, historyFindings });
  const j = chunk.json;
  console.log(`chunk ${guard}:`, chunk.status, j.status ?? "", j.stage ?? "", `files=${j.filesScanned ?? "?"}`, j.message ? String(j.message).slice(0, 120) : "");
  if (chunk.status !== 200) { console.log(JSON.stringify(j).slice(0, 500)); process.exit(1); }
  if (j.status === "done") {
    const r = j.report;
    console.log("DONE", JSON.stringify({
      score: r.score, grade: r.grade,
      secrets: r.counts?.secrets, vulns: r.counts?.vulnerabilities,
      posture: r.counts?.postureIssues, deps: r.counts?.dependencies,
      files: r.filesScanned, history: r.historyDepth,
      postureByCategory: r.posture?.reduce((m, p) => { m[p.category ?? "none"] = (m[p.category ?? "none"] ?? 0) + 1; return m; }, {}),
    }, null, 1));
    process.exit(0);
  }
  cursor = j.cursor;
  head = j.head ?? head;
  // The caller carries the accumulated history findings: each chunk
  // returns its findings in chunkFindings and the assemble step
  // merges them. Sending [] here loses every history finding.
  if (Array.isArray(j.chunkFindings)) historyFindings = [...historyFindings, ...j.chunkFindings];
  await sleep(1500);
}
console.log("GUARD: scan did not finish in 40 chunks");
process.exit(1);
