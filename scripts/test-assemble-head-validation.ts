// Assemble head validation (2026-11-27 live TechDirect 500 fix).
// A client-supplied HEAD partial missing its arrays made
// assembleReport throw a raw TypeError, which the chunk route
// answered as a 500 at the dependencies step. advanceScan now
// validates the head and re-derives it server-side when it is not
// usable, and the client never sends a malformed saved head.
// Pure checks only - no network. Run: npx tsx scripts/test-assemble-head-validation.ts

import { readFileSync } from "node:fs";
import { isUsableHead } from "../src/lib/chunks";
import type { ScanCursorData } from "../src/lib/cursor";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` - ${extra}` : ""}`);
  if (!ok) failures++;
}

const HEAD_SHA = "a".repeat(40);
const cursor: ScanCursorData = {
  v: 1,
  owner: "Squ1zM0",
  repo: "TechDirect",
  branch: "main",
  headSha: HEAD_SHA,
  stage: "assemble",
  historyMethod: "git",
  histScanned: 62,
  histResumeAfter: null,
  histPage: 1,
  histIdx: 0,
  histPageShas: [],
  histDone: true,
  histStop: null,
  histNote: null,
};

const goodHead = {
  owner: "Squ1zM0",
  repo: "TechDirect",
  branch: "main",
  headSha: HEAD_SHA,
  filesScanned: 2802,
  filesTotal: 2802,
  treeTruncated: false,
  tarballFallback: false,
  secrets: [],
  frameworks: [],
  dependencies: [],
  posture: [],
  unpinnedCount: 0,
  historyMethod: "git",
  retainedIncomplete: false,
};

check("usable head: full shape accepted", isUsableHead(goodHead, cursor));
check("unusable head: null rejected", !isUsableHead(null, cursor));
check("unusable head: empty object rejected", !isUsableHead({}, cursor));
check("unusable head: missing secrets rejected", !isUsableHead({ ...goodHead, secrets: undefined }, cursor));
check("unusable head: dependencies null rejected", !isUsableHead({ ...goodHead, dependencies: null }, cursor));
check("unusable head: frameworks missing rejected", !isUsableHead({ ...goodHead, frameworks: undefined }, cursor));
check("unusable head: posture a string rejected", !isUsableHead({ ...goodHead, posture: "x" }, cursor));
check("unusable head: wrong headSha rejected", !isUsableHead({ ...goodHead, headSha: "b".repeat(40) }, cursor));
check("unusable head: wrong owner rejected", !isUsableHead({ ...goodHead, owner: "someone" }, cursor));
check("unusable head: wrong branch rejected", !isUsableHead({ ...goodHead, branch: "dev" }, cursor));
check("unusable head: NaN filesScanned rejected", !isUsableHead({ ...goodHead, filesScanned: NaN }, cursor));
check("unusable head: missing retainedIncomplete rejected", !isUsableHead({ ...goodHead, retainedIncomplete: undefined }, cursor));
check("unusable head: bad historyMethod rejected", !isUsableHead({ ...goodHead, historyMethod: "svn" }, cursor));
check("usable head: api history method accepted", isUsableHead({ ...goodHead, historyMethod: "api" }, cursor));

// The assemble branch must re-derive instead of trusting the head:
// the validation call sits in the assemble branch of advanceScan.
const chunksSrc = readFileSync("src/lib/chunks.ts", "utf8");
check(
  "assemble branch validates the head before use",
  /if \(!isUsableHead\(head, cursor\)\) \{\s*head = await scanHead/.test(chunksSrc),
);
// The client must never send a malformed saved head.
const progressSrc = readFileSync("src/components/ScanProgress.tsx", "utf8");
check(
  "client resume requires the head arrays",
  /savedHeadUsable/.test(progressSrc) && /Array\.isArray\(\(savedHead as HeadPartial\)\.secrets\)/.test(progressSrc),
);

if (failures > 0) {
  console.log(`\n${failures} check(s) FAILED.`);
  process.exit(1);
}
console.log("\nAll assemble head validation checks passed.");
