// Phase 19 posture tests: Actions hardening, container hardening,
// exposed files, install scripts, plus the score copy and regressions
// for the posture checks that already existed. Run:
//   npx tsx scripts/test-posture-phase19.ts
// (coordinator adds: "test:posture-phase19": "tsx scripts/test-posture-phase19.ts")
//
// Fixture discipline (Phase 14): no literal secret-pattern string is
// committed anywhere in this file. The workflow secret reference uses
// a __SECRET_n__ placeholder, and the SHA pin is assembled at runtime.

import { buildPosture } from "../src/lib/scan";
import { infraFindings, parseWorkflowUses } from "../src/lib/infra";
import { biggestProblem, explainScore } from "../src/lib/score";

let failures = 0;
let passes = 0;
function check(name: string, ok: boolean, extra = "") {
  if (ok) passes++;
  else failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` - ${extra}` : ""}`);
}

// A 40-char hex string assembled at runtime, never written literally:
// GitHub push protection blocks literal 40-hex strings (they look like
// classic personal access tokens), same trick as test-tier3.ts.
const FAKE_SHA = "ab12".repeat(10);

// Hygiene files that silence the legacy no-SECURITY.md /
// no-Dependabot / no-.gitignore findings in buildPosture maps.
const HYGIENE: [string, string][] = [
  ["SECURITY.md", "Report issues to security@example.com.\n"],
  [".github/dependabot.yml", "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n"],
  [".gitignore", ".env\nnode_modules\n*.pem\n"],
];
const withHygiene = (entries: [string, string][]): Map<string, string> => new Map([...HYGIENE, ...entries]);

const byId = (list: { id: string }[], id: string) => list.find((p) => p.id === id);

// ---------------------------------------------------------------------------
// 1. Workflow pinning (infra.ts)
// ---------------------------------------------------------------------------

const pinWorkflow = [
  "name: CI",
  "on: [push]",
  "jobs:",
  "  build:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/checkout@v4",
  "      - uses: actions/setup-node@main",
  "      - uses: actions/cache",
  "      - uses: docker/build-push-action@v5",
  `      - uses: docker/login-action@${FAKE_SHA}`,
  "      - uses: anchore/scan-action",
  "      - uses: github/super-linter@v4",
  `      - uses: actions/setup-python@${FAKE_SHA}`,
].join("\n");
const pinFindings = infraFindings(new Map([[".github/workflows/ci.yml", pinWorkflow]]));
check(
  "third-party @v4 is a high finding (build-push-action)",
  pinFindings.some((f) => f.title === "GitHub Action is not pinned" && f.severity === "high" && f.detail.includes("docker/build-push-action@v5")),
  pinFindings.map((f) => `${f.title} (${f.severity})`).join("; "),
);
check(
  "third-party with no ref is a high finding (anchore)",
  pinFindings.some((f) => f.title === "GitHub Action is not pinned" && f.severity === "high" && f.detail.includes("anchore/scan-action@(no ref)")),
);
check(
  "first-party branch ref keeps the medium finding (setup-node@main)",
  pinFindings.some((f) => f.title === "GitHub Action is not pinned" && f.severity === "medium" && f.detail.includes("actions/setup-node@main")),
);
check(
  "first-party with no ref keeps the medium finding (actions/cache)",
  pinFindings.some((f) => f.title === "GitHub Action is not pinned" && f.severity === "medium" && f.detail.includes("actions/cache@(no ref)")),
);
check(
  "exactly 4 pinning findings (checkout@v4, SHA pins, super-linter@v4 are clean)",
  pinFindings.length === 4,
  pinFindings.map((f) => f.detail.slice(0, 60)).join(" | "),
);
check(
  "parseWorkflowUses marks first-party and SHA pins",
  parseWorkflowUses(pinWorkflow).find((a) => a.name === "actions/checkout")?.firstParty === true &&
    parseWorkflowUses(pinWorkflow).find((a) => a.name === "docker/login-action")?.pinnedSha === true &&
    parseWorkflowUses(pinWorkflow).find((a) => a.name === "docker/build-push-action")?.firstParty === false &&
    parseWorkflowUses(pinWorkflow).find((a) => a.name === "docker/build-push-action")?.pinnedSha === false,
);
const shaOnly = infraFindings(
  new Map([[".github/workflows/sha.yml", `jobs:\n  build:\n    steps:\n      - uses: actions/checkout@${FAKE_SHA}\n      - uses: docker/login-action@${FAKE_SHA}\n`]]),
);
check("SHA-pinned actions (first- and third-party) are clean", shaOnly.length === 0, shaOnly.map((f) => f.title).join("; "));
check(
  "every pinning finding detail ends with an exact fix",
  pinFindings.every((f) => f.detail.includes("Fix: ")),
);

// ---------------------------------------------------------------------------
// 2. Dockerfile (infra.ts)
// ---------------------------------------------------------------------------

const dockerNoUser = new Map([["Dockerfile", "FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nCMD [\"node\", \"index.js\"]\n"]]);
const dockerNoUserFindings = infraFindings(dockerNoUser);
check(
  "no USER instruction is a medium finding",
  dockerNoUserFindings.some((f) => f.title === "Dockerfile has no USER instruction" && f.severity === "medium"),
);
check(
  "no HEALTHCHECK with a CMD is a low finding",
  dockerNoUserFindings.some((f) => f.title === "Dockerfile has no HEALTHCHECK" && f.severity === "low"),
);
check(
  "no-USER Dockerfile yields exactly those 2 findings",
  dockerNoUserFindings.length === 2,
  dockerNoUserFindings.map((f) => f.title).join("; "),
);

const dockerRoot = new Map([["Dockerfile", "FROM node:20-alpine\nUSER root\nHEALTHCHECK CMD curl -f http://localhost/health || exit 1\nCMD [\"node\", \"index.js\"]\n"]]);
const dockerRootFindings = infraFindings(dockerRoot);
check(
  "USER root is still flagged once, no duplicate no-USER finding",
  dockerRootFindings.filter((f) => f.title === "Dockerfile runs as root").length === 1 &&
    !dockerRootFindings.some((f) => f.title === "Dockerfile has no USER instruction"),
);
check(
  "HEALTHCHECK present means no HEALTHCHECK finding",
  !dockerRootFindings.some((f) => f.title === "Dockerfile has no HEALTHCHECK"),
  dockerRootFindings.map((f) => f.title).join("; "),
);

const dockerAdd = new Map([["Dockerfile", "FROM node:20-alpine\nUSER node\nHEALTHCHECK CMD curl -f http://localhost/health || exit 1\nADD https://example.com/releases/fake-app.tar.gz /tmp/fake-app.tar.gz\nCMD [\"node\", \"index.js\"]\n"]]);
const dockerAddFindings = infraFindings(dockerAdd);
check(
  "ADD with a remote URL is a low finding",
  dockerAddFindings.some((f) => f.title === "Dockerfile downloads a file with ADD" && f.severity === "low"),
);
check(
  "ADD fixture yields exactly that 1 finding",
  dockerAddFindings.length === 1,
  dockerAddFindings.map((f) => f.title).join("; "),
);

const dockerClean = new Map([
  ["Dockerfile", "FROM node:20-alpine\nUSER node\nHEALTHCHECK CMD curl -f http://localhost/health || exit 1\nENTRYPOINT [\"node\", \"index.js\"]\n"],
  ["Dockerfile.nohealth", "FROM node:20-alpine\nUSER node\n"],
]);
const dockerCleanFindings = infraFindings(dockerClean);
check(
  "clean Dockerfiles stay quiet (HEALTHCHECK with ENTRYPOINT, no CMD/ENTRYPOINT at all)",
  dockerCleanFindings.length === 0,
  dockerCleanFindings.map((f) => f.title).join("; "),
);
check(
  "every Dockerfile finding detail ends with an exact fix",
  [...dockerNoUserFindings, ...dockerRootFindings, ...dockerAddFindings].every((f) => f.detail.includes("Fix: ")),
);

// ---------------------------------------------------------------------------
// 3. Kubernetes (infra.ts)
// ---------------------------------------------------------------------------

const k8sRoot = new Map([
  ["k8s/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: myapp:1.2.3\n          securityContext:\n            runAsUser: 0\n"],
]);
check(
  "runAsUser 0 is a medium finding",
  infraFindings(k8sRoot).some((f) => f.title === "Kubernetes container runs as root (UID 0)" && f.severity === "medium"),
);
const k8sNonRoot = new Map([
  ["k8s/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: myapp:1.2.3\n          securityContext:\n            runAsNonRoot: false\n"],
]);
check(
  "runAsNonRoot false is a medium finding",
  infraFindings(k8sNonRoot).some((f) => f.title === "Kubernetes container allows running as root" && f.severity === "medium"),
);
const k8sClean = new Map([
  ["k8s/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: myapp:1.2.3\n          securityContext:\n            runAsUser: 1000\n            runAsNonRoot: true\n"],
]);
check(
  "runAsUser 1000 with runAsNonRoot true stays quiet",
  infraFindings(k8sClean).length === 0,
  infraFindings(k8sClean).map((f) => f.title).join("; "),
);

// ---------------------------------------------------------------------------
// 4. Compose (infra.ts)
// ---------------------------------------------------------------------------

const composeCaps = new Map([
  ["docker-compose.yml", "services:\n  app:\n    image: myapp:1.2.3\n    cap_add:\n      - SYS_ADMIN\n      - NET_ADMIN\n"],
]);
check(
  "cap_add SYS_ADMIN is a medium finding",
  infraFindings(composeCaps).some((f) => f.title === "Compose service adds a dangerous Linux capability" && f.severity === "medium" && f.detail.includes("SYS_ADMIN")),
);
const composeAll = new Map([
  ["docker-compose.yml", "services:\n  app:\n    image: myapp:1.2.3\n    cap_add: [ALL]\n"],
]);
check(
  "cap_add ALL (inline list) is a medium finding",
  infraFindings(composeAll).some((f) => f.title === "Compose service adds a dangerous Linux capability" && f.severity === "medium" && f.detail.includes("ALL")),
);
const composeNetAdmin = new Map([
  ["docker-compose.yml", "services:\n  app:\n    image: myapp:1.2.3\n    cap_add:\n      - NET_ADMIN\n"],
]);
check(
  "cap_add NET_ADMIN alone stays quiet",
  infraFindings(composeNetAdmin).length === 0,
  infraFindings(composeNetAdmin).map((f) => f.title).join("; "),
);
const composeImages = new Map([
  ["docker-compose.yml", "services:\n  a:\n    image: myapp:latest\n  b:\n    image: redis\n  c:\n    image: postgres:15\n"],
]);
const composeImageFindings = infraFindings(composeImages);
check(
  "compose image latest is a low finding",
  composeImageFindings.some((f) => f.title === "Compose service image is not pinned to a version" && f.severity === "low" && f.detail.includes("myapp:latest")),
);
check(
  "compose image untagged is a low finding",
  composeImageFindings.some((f) => f.title === "Compose service image is not pinned to a version" && f.severity === "low" && f.detail.includes("redis")),
);
check(
  "compose images yield exactly the 2 unpinned findings (postgres:15 clean)",
  composeImageFindings.length === 2,
  composeImageFindings.map((f) => f.title).join("; "),
);

// ---------------------------------------------------------------------------
// 5. Script injection (scan.ts buildPosture)
// ---------------------------------------------------------------------------

const injectInline = [
  "name: CI",
  "on: [push]",
  "jobs:",
  "  build:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/checkout@v4",
  '      - run: echo "title is ${{ github.event.pull_request.title }}"',
  "      - run: echo hello",
].join("\n");
const injectInlinePosture = buildPosture(withHygiene([[".github/workflows/ci.yml", injectInline]]));
const injectInlineHit = byId(injectInlinePosture, "actions-script-injection");
check(
  "inline run with ${{ }} is a high script-injection finding",
  injectInlineHit?.severity === "high" && injectInlineHit?.category === "actions" && injectInlineHit?.file === ".github/workflows/ci.yml",
  JSON.stringify(injectInlineHit),
);
check(
  "script-injection line points at the run line",
  injectInlineHit?.line != null && injectInline.split("\n")[injectInlineHit.line - 1].includes("${{"),
  `line=${injectInlineHit?.line}`,
);
check(
  "exactly one script-injection finding (plain run stays quiet)",
  injectInlinePosture.filter((p) => p.id === "actions-script-injection").length === 1,
);

const injectBlock = [
  "name: CI",
  "on: [push]",
  "jobs:",
  "  build:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - name: Build",
  "        run: |",
  '          echo "title is ${{ github.event.pull_request.title }}"',
].join("\n");
const injectBlockHit = byId(buildPosture(withHygiene([[".github/workflows/ci.yml", injectBlock]])), "actions-script-injection");
check(
  "multiline run block with ${{ }} in the body is flagged",
  injectBlockHit?.severity === "high",
);
check(
  "multiline script-injection line points at the body line",
  injectBlockHit?.line != null && injectBlock.split("\n")[injectBlockHit.line - 1].includes("${{"),
  `line=${injectBlockHit?.line}`,
);

const noInject = [
  "name: CI",
  "on: [push]",
  "jobs:",
  "  build:",
  "    runs-on: ubuntu-latest",
  "    env:",
  "      TITLE: ${{ github.event.pull_request.title }}",
  "    steps:",
  "      - uses: actions/checkout@v4",
  "      - run: echo hello",
].join("\n");
check(
  "${{ }} outside a run block is not script injection",
  !buildPosture(withHygiene([[".github/workflows/ci.yml", noInject]])).some((p) => p.id === "actions-script-injection"),
);

// ---------------------------------------------------------------------------
// 6. Secrets passed to third-party actions (scan.ts buildPosture)
// ---------------------------------------------------------------------------

const thirdPartySecret = [
  "name: Deploy",
  "on: [push]",
  "jobs:",
  "  deploy:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/checkout@v4",
  "      - uses: docker/login-action@v5",
  "        with:",
  "          username: deployer",
  "          password: ${{ secrets.__SECRET_1__ }}",
].join("\n");
const thirdPartyPosture = buildPosture(withHygiene([[".github/workflows/deploy.yml", thirdPartySecret]]));
const thirdPartyHit = byId(thirdPartyPosture, "actions-secret-third-party");
check(
  "secret in a third-party with block is a medium finding",
  thirdPartyHit?.severity === "medium" && thirdPartyHit?.category === "actions" && thirdPartyHit?.file === ".github/workflows/deploy.yml",
  JSON.stringify(thirdPartyHit),
);
check(
  "third-party secret line points at the with entry",
  thirdPartyHit?.line != null && thirdPartySecret.split("\n")[thirdPartyHit.line - 1].includes("secrets."),
  `line=${thirdPartyHit?.line}`,
);

const firstPartySecret = [
  "name: CI",
  "on: [push]",
  "jobs:",
  "  build:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/checkout@v4",
  "        with:",
  "          token: ${{ secrets.__SECRET_1__ }}",
].join("\n");
check(
  "secret in a first-party with block stays quiet",
  !buildPosture(withHygiene([[".github/workflows/ci.yml", firstPartySecret]])).some((p) => p.id === "actions-secret-third-party"),
);

const thirdPartyClean = [
  "name: Deploy",
  "on: [push]",
  "jobs:",
  "  deploy:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: docker/login-action@v5",
  "        with:",
  "          username: deployer",
].join("\n");
check(
  "third-party with block without a secret stays quiet",
  !buildPosture(withHygiene([[".github/workflows/deploy.yml", thirdPartyClean]])).some((p) => p.id === "actions-secret-third-party"),
);

const namedStepSecret = [
  "name: Deploy",
  "on: [push]",
  "jobs:",
  "  deploy:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - name: Log in",
  "        uses: docker/login-action@v5",
  "        with:",
  "          password: ${{ secrets.__SECRET_1__ }}",
].join("\n");
check(
  "secret in a third-party step written with - name: then uses: is flagged",
  byId(buildPosture(withHygiene([[".github/workflows/deploy.yml", namedStepSecret]])), "actions-secret-third-party")?.severity === "medium",
);

// ---------------------------------------------------------------------------
// 7. pull_request_target tightening (scan.ts buildPosture)
// ---------------------------------------------------------------------------

const prWithCheckout = [
  "name: CI",
  "on:",
  "  pull_request_target:",
  "    types: [opened]",
  "jobs:",
  "  build:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/checkout@v4",
].join("\n");
const prWithHit = byId(buildPosture(withHygiene([[".github/workflows/ci.yml", prWithCheckout]])), "actions-pr-target");
check(
  "pull_request_target with a checkout step is still a high finding",
  prWithHit?.severity === "high" && prWithHit?.category === "actions" && prWithHit?.file === ".github/workflows/ci.yml",
  JSON.stringify(prWithHit),
);

const prNamedCheckout = [
  "name: CI",
  "on:",
  "  pull_request_target:",
  "    types: [opened]",
  "jobs:",
  "  build:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - name: Check out",
  "        uses: actions/checkout@v4",
].join("\n");
check(
  "pull_request_target with a - name: checkout step is flagged",
  byId(buildPosture(withHygiene([[".github/workflows/ci.yml", prNamedCheckout]])), "actions-pr-target")?.severity === "high",
);

const prNoCheckout = [
  "name: CI",
  "on:",
  "  pull_request_target:",
  "    types: [opened]",
  "jobs:",
  "  build:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - run: echo hi",
].join("\n");
check(
  "pull_request_target without a checkout step stays quiet",
  !buildPosture(withHygiene([[".github/workflows/ci.yml", prNoCheckout]])).some((p) => p.id === "actions-pr-target"),
);

// ---------------------------------------------------------------------------
// 8. Exposed files (scan.ts buildPosture)
// ---------------------------------------------------------------------------

const exposedFiles = withHygiene([
  ["certs/server.pem", "key material\n"],
  ["certs/client.key", "key material\n"],
  ["backups/dump.sql", "INSERT INTO users VALUES (1);\n"],
  ["old.bak", "backup\n"],
  ["notes.orig", "backup\n"],
  ["notes.txt.swp", "swap\n"],
  ["infra/state.tfstate", "{}\n"],
  ["infra/state.tfstate.backup", "{}\n"],
  [".terraform/providers/a", "binary\n"],
  [".terraform/providers/b", "binary\n"],
  ["data/app.sqlite", "binary\n"],
  ["data/app.db", "binary\n"],
  ["README.md", "# Hi\n"],
  [".terraformrc", "config\n"],
  [".env", "FOO=bar\n"],
]);
const exposedPosture = buildPosture(exposedFiles);
const exposedExpect: [string, string, string][] = [
  ["exposed-private-key", "certs/server.pem", "high"],
  ["exposed-private-key", "certs/client.key", "high"],
  ["exposed-sql-dump", "backups/dump.sql", "high"],
  ["exposed-backup-file", "old.bak", "medium"],
  ["exposed-backup-file", "notes.orig", "medium"],
  ["exposed-backup-file", "notes.txt.swp", "medium"],
  ["exposed-tfstate", "infra/state.tfstate", "medium"],
  ["exposed-tfstate", "infra/state.tfstate.backup", "medium"],
  ["exposed-terraform-dir", ".terraform", "medium"],
  ["exposed-database-file", "data/app.sqlite", "medium"],
  ["exposed-database-file", "data/app.db", "medium"],
];
for (const [id, file, severity] of exposedExpect) {
  check(
    `exposed file ${file} flagged (${id}, ${severity})`,
    exposedPosture.some((p) => p.id === id && p.file === file && p.severity === severity && p.category === "exposed-file"),
  );
}
check(
  "exactly 11 exposed-file findings (two files in one .terraform dir give one dir finding)",
  exposedPosture.filter((p) => p.category === "exposed-file").length === 11,
  exposedPosture.filter((p) => p.category === "exposed-file").map((p) => `${p.id}:${p.file}`).join("; "),
);
check(
  ".terraformrc is not a Terraform working directory",
  !exposedPosture.some((p) => p.id === "exposed-terraform-dir" && p.file !== ".terraform"),
);
check(
  ".env is not re-flagged as an exposed file",
  !exposedPosture.some((p) => p.category === "exposed-file" && p.file === ".env"),
);
check(
  ".env still fires the existing env-committed finding",
  byId(exposedPosture, "env-committed")?.severity === "high",
);

// ---------------------------------------------------------------------------
// 9. Install scripts (scan.ts buildPosture)
// ---------------------------------------------------------------------------

const installPkg = JSON.stringify(
  {
    name: "demo",
    version: "1.0.0",
    scripts: {
      postinstall: "node scripts/setup.js",
      preinstall: "curl -fsSL https://example.com/install.sh | sh",
      prepare: "",
      build: "tsc",
    },
  },
  null,
  2,
);
const installPosture = buildPosture(withHygiene([["package.json", installPkg]]));
const postHit = byId(installPosture, "install-script-postinstall");
check(
  "postinstall names the script and its command",
  postHit?.severity === "medium" && postHit?.category === "install-script" && postHit?.file === "package.json" &&
    postHit.detail.includes("postinstall") && postHit.detail.includes("node scripts/setup.js"),
  JSON.stringify(postHit),
);
check(
  "postinstall line points at the script line",
  postHit?.line != null && installPkg.split("\n")[postHit.line - 1].includes("postinstall"),
  `line=${postHit?.line}`,
);
check(
  "preinstall is flagged",
  byId(installPosture, "install-script-preinstall")?.severity === "medium",
);
check(
  "empty prepare script stays quiet",
  !installPosture.some((p) => p.id === "install-script-prepare"),
);
check(
  "exactly 2 install-script findings",
  installPosture.filter((p) => p.category === "install-script").length === 2,
);
const noScriptsPosture = buildPosture(withHygiene([["package.json", JSON.stringify({ name: "demo", version: "1.0.0" })]]));
check(
  "package.json with no scripts stays quiet",
  !noScriptsPosture.some((p) => p.category === "install-script"),
);
const badJsonPosture = buildPosture(withHygiene([["package.json", "{not json"]]));
check(
  "invalid package.json does not crash and stays quiet",
  !badJsonPosture.some((p) => p.category === "install-script"),
);
const wsScriptPosture = buildPosture(withHygiene([["package.json", JSON.stringify({ name: "demo", scripts: { prepare: "   " } })]]));
check(
  "whitespace-only prepare script stays quiet",
  !wsScriptPosture.some((p) => p.category === "install-script"),
);

// ---------------------------------------------------------------------------
// 10. Score copy (score.ts)
// ---------------------------------------------------------------------------

check(
  "explainScore drops small when a high posture issue exists",
  !explainScore({ score: 85, grade: "B", secrets: 0, vulnerabilities: 0, postureIssues: 2, postureHigh: 1 }).includes("small"),
  explainScore({ score: 85, grade: "B", secrets: 0, vulnerabilities: 0, postureIssues: 2, postureHigh: 1 }),
);
check(
  "explainScore keeps small with no high posture issue",
  explainScore({ score: 90, grade: "A", secrets: 0, vulnerabilities: 0, postureIssues: 2 }).includes("small security-hygiene"),
);
check(
  "explainScore keeps small when postureHigh is 0",
  explainScore({ score: 90, grade: "A", secrets: 0, vulnerabilities: 0, postureIssues: 2, postureHigh: 0 }).includes("small security-hygiene"),
);
check(
  "biggestProblem drops small when a high posture issue exists",
  !biggestProblem({ secrets: 0, vulnerabilities: 0, postureIssues: 2, postureHigh: 1 }).includes("small"),
  biggestProblem({ secrets: 0, vulnerabilities: 0, postureIssues: 2, postureHigh: 1 }),
);
check(
  "biggestProblem keeps small with no high posture issue",
  biggestProblem({ secrets: 0, vulnerabilities: 0, postureIssues: 2 }).includes("small security-hygiene"),
);
check(
  "biggestProblem still prefers secrets over posture",
  biggestProblem({ secrets: 1, vulnerabilities: 0, postureIssues: 2, postureHigh: 1 }).includes("leaked secret"),
);

// ---------------------------------------------------------------------------
// 11. Regressions: existing posture behavior unchanged
// ---------------------------------------------------------------------------

const legacyMissing = buildPosture(new Map());
check(
  "regression: no SECURITY.md is still low",
  byId(legacyMissing, "no-security-md")?.severity === "low",
);
check(
  "regression: no Dependabot config is still low",
  byId(legacyMissing, "no-dependabot")?.severity === "low",
);
check(
  "regression: no .gitignore is still medium",
  byId(legacyMissing, "no-gitignore")?.severity === "medium",
);

const legacyGaps = buildPosture(withHygiene([]).set(".gitignore", ".env\nnode_modules\n"));
check(
  "regression: .gitignore gaps still medium",
  byId(legacyGaps, "gitignore-gaps")?.severity === "medium",
);
check(
  "regression: hygiene files silence the legacy findings",
  !byId(legacyGaps, "no-security-md") && !byId(legacyGaps, "no-dependabot") && !byId(legacyGaps, "no-gitignore"),
);

const legacyEnv = buildPosture(withHygiene([[".env", "FOO=bar\n"]]));
check(
  "regression: .env committed is still high",
  byId(legacyEnv, "env-committed")?.severity === "high",
);

const legacyCurl = buildPosture(
  withHygiene([[".github/workflows/ci.yml", "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | sh\n"]]),
);
check(
  "regression: curl piped to shell is still high",
  byId(legacyCurl, "actions-curl-pipe-shell")?.severity === "high",
);
check(
  "regression: curl workflow does not trip the new Actions checks",
  !legacyCurl.some((p) => p.id === "actions-script-injection" || p.id === "actions-secret-third-party" || p.id === "actions-pr-target"),
);

// Infra findings still carry file and category through buildPosture.
const infraThrough = buildPosture(
  withHygiene([["Dockerfile", "FROM node:20-alpine\nUSER node\nCMD [\"node\", \"index.js\"]\n"]]),
);
const healthThrough = byId(infraThrough, "infra-dockerfile-has-no-healthcheck");
check(
  "infra finding keeps file and category through buildPosture",
  healthThrough?.file === "Dockerfile" && healthThrough?.category === "container",
  JSON.stringify(healthThrough),
);

console.log(failures === 0 ? `\nAll ${passes} Phase 19 posture tests passed.` : `\n${failures} test(s) FAILED (${passes} passed).`);
process.exit(failures === 0 ? 0 : 1);
