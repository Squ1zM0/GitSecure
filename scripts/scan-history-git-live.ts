// Live proof for the Phase 8 git-protocol history path.
// Run: npm run test:history-git
//
// Scans the real Squ1zM0/TechDirect history over the git protocol
// (isomorphic-git, github.com smart HTTP — NOT api.github.com) and
// proves two things the API path could not do unauthenticated:
//   1. all 62 commits are returned (the API path stopped at 56/62
//      when the shared 60 req/hour quota ran out), and
//   2. zero GitHub REST API calls are made for history.
// A counting fetch wrapper is installed first: if any code path in
// the git scan touched api.github.com, the assertion fails loudly.
// The HEAD tarball fetch is NOT part of this script (history only);
// a full scanRepo also makes zero REST calls on the happy path
// (Phase 15, worker D — proved by test:zero-rest), so this script
// stays history-only.

import { scanHistoryViaGit } from "../src/lib/history";

async function main() {
  let apiFetchCalls = 0;
  const hosts = new Map<string, number>();
  const realFetch = globalThis.fetch;
  (globalThis as unknown as { fetch: typeof fetch }).fetch = ((...args: Parameters<typeof fetch>) => {
    const url = String(args[0]);
    try {
      const host = new URL(url).host;
      hosts.set(host, (hosts.get(host) ?? 0) + 1);
      if (host === "api.github.com") apiFetchCalls++;
    } catch {
      // Ignore unparseable URLs in the count.
    }
    return realFetch(...args);
  }) as typeof fetch;

  try {
    const started = Date.now();
    const result = await scanHistoryViaGit("Squ1zM0", "TechDirect", "main");
    const wallMs = Date.now() - started;
    console.log(`ok: ${result.ok}`);
    console.log(`method: ${result.method}`);
    console.log(`commitsScanned: ${result.commitsScanned}`);
    console.log(`commitsFetched: ${result.commitsFetched}`);
    console.log(`cachedCommits: ${result.cachedCommits}`);
    console.log(`findings: ${result.findings.length}`);
    console.log(`restCalls (history's own count): ${result.restCalls}`);
    console.log(`gitRequests (remote-info calls): ${result.gitRequests}`);
    console.log(`api.github.com fetch calls observed: ${apiFetchCalls}`);
    console.log(`fetch calls by host: ${[...hosts.entries()].map(([h, n]) => `${h}=${n}`).join(", ") || "(none)"}`);
    console.log(`wall ms: ${wallMs} (history ms: ${result.ms})`);
    if (result.note) console.log(`note: ${result.note}`);

    // Cache proof, same process: the second scan must reuse all 62.
    const second = await scanHistoryViaGit("Squ1zM0", "TechDirect", "main");
    console.log(`second scan: commitsScanned=${second.commitsScanned} cachedCommits=${second.cachedCommits} commitsFetched=${second.commitsFetched} ms=${second.ms}`);

    const failures: string[] = [];
    if (!result.ok) failures.push("history scan failed");
    if (result.commitsScanned !== 62) failures.push(`expected 62 commits, got ${result.commitsScanned}`);
    if (result.restCalls !== 0) failures.push(`expected 0 REST calls, got ${result.restCalls}`);
    if (apiFetchCalls !== 0) failures.push(`expected 0 api.github.com fetches, saw ${apiFetchCalls}`);
    if (second.cachedCommits !== 62 || second.commitsFetched !== 0) {
      failures.push(`expected second scan to reuse 62 cached commits and fetch 0, got cached=${second.cachedCommits} fetched=${second.commitsFetched}`);
    }
    if (failures.length > 0) {
      console.error(`\nFAILED: ${failures.join("; ")}`);
      process.exit(1);
    }
    console.log("\nLive git-protocol history proof passed: 62/62 commits, 0 REST history calls.");
  } finally {
    (globalThis as unknown as { fetch: typeof fetch }).fetch = realFetch;
  }
}

main().catch((err) => {
  console.error("Live history proof crashed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
