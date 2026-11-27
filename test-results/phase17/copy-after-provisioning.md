# Copy that must change once the scan-state store is provisioned

**Status: NOT YET DONE — the store is not provisioned.** Phase 17 Part 1
(Worker C) ships the store code inert: with no env vars set the scan
behaves exactly as today, plus the honest limits line when earlier
history findings could not be recovered. The public "never stored"
promise below is therefore still TRUE in production today, and none of
it was changed. Do not change it until Freddy provisions the store
(design §4.2) — changing it first would claim transient storage exists
when it does not.

**When the store IS provisioned**, any server-side store — even a 7-day
TTL one holding only redacted fragments — contradicts the current
unqualified promise. Change every location in the table below at that
point. The replacement wording keeps the true promise (fragments only,
never full, never a permanent record, finished reports never stored)
and drops the false one (nothing ever stored, even transiently).

List reused from the design doc
(test-results/phase17/accumulation-design.md §4.7), not re-derived.

| Location | Current copy | Must become (exact replacement) |
|---|---|---|
| `src/lib/mcp.ts` (`LIST_CHECKS_TEXT`) | *"The server holds no scan state, so a restart never loses a scan; GitSecure never stores reports on disk or in a database."* | *"A scan in progress keeps its partial findings in a short-lived server store (redacted fragments only), deleted when the scan finishes or after 7 days; a restart never loses a scan. Finished reports are never stored."* |
| `src/lib/mcp.ts` (`get_report` description) | *"It runs a fresh live scan — GitSecure never stores reports on disk or in a database, so the result is always current."* | *"It runs a fresh live scan — finished reports are never stored, so the result is always current."* |
| `README.md` (secrets line) | *"Secrets are **never shown in full** …, **never stored**, and **never live-validated** …"* | *"Secrets are **never shown in full** …, **never stored after the scan finishes** (in-progress findings are kept only as redacted fragments, deleted at finish or after 7 days), and **never live-validated** …"* |
| `README.md` ("Scan cursors") | *"the server holds **no scan-state** between them — no job, no database, no paid KV store, no new env var"* | *"the server holds **no scan job** between chunks. The cursor carries the resume position; the partial findings of a scan in progress are kept in a short-lived store (redacted fragments only, deleted when the scan finishes or after 7 days) so a resume on another instance loses nothing."* |
| `README.md` (design bullets) | *"**The server holds no scan state.** No durable store, no paid service, no database, no in-memory job map."* | *"**The server holds no scan job.** A short-lived store holds in-progress findings only (redacted fragments, 7-day expiry, deleted at finish). No database of reports, no in-memory job map."* |
| `README.md` (MCP section) | *"It runs a fresh live scan — GitSecure never stores reports on …"* | Same replacement as `mcp.ts` `get_report`. |
| `src/app/page.tsx`, `src/app/layout.tsx` (home-page footer) | *"Secrets are never shown in full, never stored, and never live-validated."* | *"Secrets are never shown in full, never stored after the scan finishes, and never live-validated."* |
| `src/lib/scan.ts` (`buildLimits`) | *"Public repos only. No secret is ever stored, logged, or shown in full."* | *"Public repos only. No secret is ever stored after the scan finishes, logged, or shown in full."* |
| `src/lib/types.ts` (header comment) | *"fragment only, never stored, never live-validated"* | *"fragment only, never stored after the scan finishes, never live-validated"* |
| `src/lib/chunks.ts` header, `src/lib/cursor.ts`, `src/lib/resume.ts`, `src/lib/scan.ts`, `src/lib/types.ts` (code comments) | *"The server holds NO state between chunks" / "holds NO scan state on the server at all" / "the server never stores it"* | Reword to *"the server holds no scan job; in-progress findings live in the short-lived store (see scan-state.ts)"* — comments must not keep asserting a property the code no longer has. |
| `GITSECURE.md` (Phase 9/16 status sections) | *"GitSecure never stores reports"*, *"never stored, never live-validated"*, *"server holds NO scan state"* | Update in the Phase 17 status entry: record the change as a deliberate, dated decision (as Phases 9/16 record theirs), not a silent edit. |

**Honest framing for Freddy:** the findings were *already public* (they
come from public repos, and the finished report already returns them to
anyone). What changes is *where a copy sits for minutes*: from "only in
the caller's memory" to "also in a 7-day TTL store, as fragments". The
promise that matters — no full secret, no permanent record, no report
retention — survives intact; the sentence that must die is the
unqualified "never stored".

**What already changed in Part 1 (no provisioning needed):** the honest
limits line in finished reports — *"History findings from earlier parts
of this scan could not be recovered, so this report may be missing
secrets from the first {N} commits checked — the history count above is
how far the scan walked, not how many findings survived."* — fires
whenever a multi-invocation scan resumes with nothing to recover from.
That line is additive and stays after provisioning (it still fires when
the store is down or state expired).
