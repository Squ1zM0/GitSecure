// Phase 20 tests: CI pipelines beyond Actions, deeper Actions
// hardening, TLS and network, secrets in logs and errors, XSS sinks.
// Run: npx tsx scripts/test-phase20.ts
//
// Fixture discipline (Phase 14): no literal secret-pattern string is
// committed anywhere in this file, and no literal sink plus tainted
// input sits in it. Fixtures are assembled from fragments at
// runtime so the self-scan check at the end proves the file is clean.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildPosture } from "../src/lib/scan";
import { scanTextForCiRisks } from "../src/lib/ci-risks";
import { scanTextForCodeRisks } from "../src/lib/code-risks";
import type { PostureIssue } from "../src/lib/types";

function j(...parts: string[]): string {
  return parts.join("");
}

let failures = 0;
let passes = 0;
function check(name: string, ok: boolean, extra = "") {
  if (ok) passes++;
  else failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` - ${extra}` : ""}`);
}

const FAKE_SHA = "ab12".repeat(10);

const has = (list: PostureIssue[], id: string): boolean =>
  list.some((f) => f.id.startsWith(`ci-${id}-`) || f.id.startsWith(`code-risk-${id}-`) || f.id === id);

const HYGIENE: [string, string][] = [
  ["SECURITY.md", "Report issues to security@example.com.\n"],
  [".github/dependabot.yml", "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n"],
  [".gitignore", ".env\nnode_modules\n*.pem\n"],
];
const withHygiene = (entries: [string, string][]): Map<string, string> => new Map([...HYGIENE, ...entries]);

// ---------------------------------------------------------------------------
// 1. CI everywhere (ci-risks.ts)
// ---------------------------------------------------------------------------

const gitlabPipe = [
  "stages:",
  "  - test",
  "test:",
  "  script:",
  "    - curl https://example.com/install.sh | bash",
  "",
].join("\n");
const gitlabPipeFindings = scanTextForCiRisks({ path: ".gitlab-ci.yml", content: gitlabPipe });
check("ci gitlab: curl piped to shell flagged", has(gitlabPipeFindings, "curl-pipe-shell") && gitlabPipeFindings[0].severity === "high" && gitlabPipeFindings[0].category === "ci", gitlabPipeFindings.map((f) => f.title).join("; "));

const gitlabClean = [
  "test:",
  "  script:",
  "    - curl -fsSL https://example.com/install.sh -o install.sh",
  "    - shasum -a 256 -c install.sha256",
  "    - sh install.sh",
  "",
].join("\n");
check("ci gitlab: verified download is clean", scanTextForCiRisks({ path: ".gitlab-ci.yml", content: gitlabClean }).length === 0);

const gitlabEcho = [
  "deploy:",
  "  script:",
  j("    - echo $", "DEPLOY_TOKEN"),
  "",
].join("\n");
check("ci gitlab: secret echoed flagged", has(scanTextForCiRisks({ path: ".gitlab-ci.yml", content: gitlabEcho }), "secret-echo"));

const gitlabEchoClean = [
  "deploy:",
  "  script:",
  "    - echo deploying to production",
  "",
].join("\n");
check("ci gitlab: plain echo is clean", scanTextForCiRisks({ path: ".gitlab-ci.yml", content: gitlabEchoClean }).length === 0);

const gitlabImage = ["test:", "  image: node:latest", "  script:", "    - npm test", ""].join("\n");
check("ci gitlab: latest image flagged", has(scanTextForCiRisks({ path: ".gitlab-ci.yml", content: gitlabImage }), "image-latest"));
const gitlabImageClean = ["test:", "  image: node:20.11.0", "  script:", "    - npm test", ""].join("\n");
check("ci gitlab: pinned image is clean", scanTextForCiRisks({ path: ".gitlab-ci.yml", content: gitlabImageClean }).length === 0);

const gitlabRemote = ["include:", "  - remote: https://example.com/ci/shared.yml", ""].join("\n");
check("ci gitlab: unpinned remote include flagged", has(scanTextForCiRisks({ path: ".gitlab-ci.yml", content: gitlabRemote }), "unpinned-ref"));
const gitlabRemoteClean = ["include:", `  - remote: https://example.com/ci/shared.yml@${FAKE_SHA}`, ""].join("\n");
check("ci gitlab: pinned remote include is clean", scanTextForCiRisks({ path: ".gitlab-ci.yml", content: gitlabRemoteClean }).length === 0);

const gitlabInject = [
  "test:",
  "  script:",
  "    - ./run-tests.sh $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
  "",
].join("\n");
check("ci gitlab: merge request value in script flagged", has(scanTextForCiRisks({ path: ".gitlab-ci.yml", content: gitlabInject }), "script-injection"));
const gitlabInjectClean = [
  "test:",
  "  script:",
  "    - ./run-tests.sh $CI_COMMIT_SHA",
  "",
].join("\n");
check("ci gitlab: pipeline-set variable is clean", scanTextForCiRisks({ path: ".gitlab-ci.yml", content: gitlabInjectClean }).length === 0);

const circleOrb = ["orbs:", "  node: circleci/node", "jobs:", "  build:", "    steps:", "      - node/install", ""].join("\n");
check("ci circleci: unpinned orb flagged", has(scanTextForCiRisks({ path: ".circleci/config.yml", content: circleOrb }), "unpinned-ref"));
const circleOrbClean = ["orbs:", "  node: circleci/node@5.1.0", ""].join("\n");
check("ci circleci: pinned orb is clean", scanTextForCiRisks({ path: ".circleci/config.yml", content: circleOrbClean }).length === 0);

const azureTask = ["steps:", "- task: NodeTool", "  inputs:", "    versionSpec: 20.x", ""].join("\n");
check("ci azure: unversioned task flagged", has(scanTextForCiRisks({ path: "azure-pipelines.yml", content: azureTask }), "unpinned-ref"));
const azureTaskClean = ["steps:", "- task: NodeTool@0", "  inputs:", "    versionSpec: 20.x", ""].join("\n");
check("ci azure: versioned task is clean", scanTextForCiRisks({ path: "azure-pipelines.yml", content: azureTaskClean }).length === 0);

const jenkinsLib = ["@Library('shared-lib') _", "pipeline {", "  stages {", "    stage('build') {", "      steps {", "        sh 'make'", "      }", "    }", "  }", "}", ""].join("\n");
check("ci jenkins: unpinned shared library flagged", has(scanTextForCiRisks({ path: "Jenkinsfile", content: jenkinsLib }), "unpinned-ref"));
const jenkinsLibClean = ["@Library('shared-lib@1.4.0') _", "pipeline {}", ""].join("\n");
check("ci jenkins: pinned shared library is clean", scanTextForCiRisks({ path: "Jenkinsfile", content: jenkinsLibClean }).length === 0);

const jenkinsInject = ["pipeline {", "  stages {", "    stage('test') {", "      steps {", j("        sh \"./test.sh ${", "params.BRANCH", "}\"", ""), "      }", "    }", "  }", "}", ""].join("\n");
check("ci jenkins: params interpolated in sh flagged", has(scanTextForCiRisks({ path: "Jenkinsfile", content: jenkinsInject }), "script-injection"));
const jenkinsClean = ["pipeline {", "  stages {", "    stage('test') {", "      steps {", "        sh './test.sh'", "      }", "    }", "  }", "}", ""].join("\n");
check("ci jenkins: constant sh is clean", scanTextForCiRisks({ path: "Jenkinsfile", content: jenkinsClean }).length === 0);

const bitbucketImage = ["pipelines:", "  default:", "    - step:", "        image: python:latest", "        script:", "          - pytest", ""].join("\n");
check("ci bitbucket: latest image flagged", has(scanTextForCiRisks({ path: "bitbucket-pipelines.yml", content: bitbucketImage }), "image-latest"));

check("ci: non-CI file returns nothing", scanTextForCiRisks({ path: "app.js", content: "curl https://example.com/install.sh | bash" }).length === 0);

// ---------------------------------------------------------------------------
// 2. Deeper GitHub Actions (buildPosture)
// ---------------------------------------------------------------------------

const artifactWorkflow = [
  "name: CI",
  "on: [pull_request]",
  "jobs:",
  "  test:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/download-artifact@v4",
  "",
].join("\n");
const artifactPosture = buildPosture(withHygiene([[".github/workflows/ci.yml", artifactWorkflow]]));
check("actions: artifact download on pull request flagged", has(artifactPosture, "actions-artifact-poisoning") && artifactPosture.find((p) => p.id === "actions-artifact-poisoning")?.severity === "medium");

const artifactCleanWorkflow = [
  "name: CI",
  "on: [push]",
  "jobs:",
  "  test:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/download-artifact@v4",
  "",
].join("\n");
check("actions: artifact download on push is clean", !has(buildPosture(withHygiene([[".github/workflows/ci.yml", artifactCleanWorkflow]])), "actions-artifact-poisoning"));

const cacheWorkflow = [
  "name: CI",
  "on: [pull_request]",
  "jobs:",
  "  test:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/cache@v4",
  "        with:",
  "          key: cache-${{ github.event.pull_request.number }}",
  "",
].join("\n");
const cachePosture = buildPosture(withHygiene([[".github/workflows/ci.yml", cacheWorkflow]]));
check("actions: PR controlled cache key flagged", has(cachePosture, "actions-cache-poisoning") && cachePosture.find((p) => p.id === "actions-cache-poisoning")?.severity === "high");

const cacheCleanWorkflow = [
  "name: CI",
  "on: [pull_request]",
  "jobs:",
  "  test:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/cache@v4",
  "        with:",
  "          key: cache-${{ runner.os }}-node",
  "",
].join("\n");
check("actions: safe cache key is clean", !has(buildPosture(withHygiene([[".github/workflows/ci.yml", cacheCleanWorkflow]])), "actions-cache-poisoning"));

const reusableWorkflow = [
  "name: CI",
  "on: [push]",
  "jobs:",
  "  test:",
  `    uses: other-org/shared/.github/workflows/test.yml@main`,
  "",
].join("\n");
check("actions: reusable workflow on a branch flagged", has(buildPosture(withHygiene([[".github/workflows/ci.yml", reusableWorkflow]])), "actions-reusable-unpinned"));

const reusableCleanWorkflow = [
  "name: CI",
  "on: [push]",
  "jobs:",
  "  test:",
  `    uses: other-org/shared/.github/workflows/test.yml@${FAKE_SHA}`,
  "",
].join("\n");
check("actions: reusable workflow pinned to a SHA is clean", !has(buildPosture(withHygiene([[".github/workflows/ci.yml", reusableCleanWorkflow]])), "actions-reusable-unpinned"));

const selfHostedWorkflow = [
  "name: CI",
  "on: [push]",
  "jobs:",
  "  test:",
  "    runs-on: self-hosted",
  "    steps:",
  "      - run: make test",
  "",
].join("\n");
check("actions: self-hosted runner flagged", has(buildPosture(withHygiene([[".github/workflows/ci.yml", selfHostedWorkflow]])), "actions-self-hosted"));

const hostedWorkflow = [
  "name: CI",
  "on: [push]",
  "jobs:",
  "  test:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - run: make test",
  "",
].join("\n");
check("actions: hosted runner is clean", !has(buildPosture(withHygiene([[".github/workflows/ci.yml", hostedWorkflow]])), "actions-self-hosted"));

// ---------------------------------------------------------------------------
// 3. TLS and network (code-risks.ts)
// ---------------------------------------------------------------------------

const tlsOff = scanTextForCodeRisks({ path: "app.js", content: j("const c = { rejectUnauthorized", ": false", " };") });
check("tls: rejectUnauthorized false flagged", has(tlsOff, "tls-verify-off") && tlsOff[0].category === "tls" && tlsOff[0].severity === "high");

const tlsOffPy = scanTextForCodeRisks({ path: "app.py", content: j("requests.get(url, ", "verify", "=", "False", ")") });
check("tls: verify False flagged", has(tlsOffPy, "tls-verify-off"));

const tlsOffGo = scanTextForCodeRisks({ path: "app.go", content: j("cfg := &tls.Config{", "InsecureSkipVerify", ": true", "}") });
check("tls: InsecureSkipVerify flagged", has(tlsOffGo, "tls-verify-off"));

const tlsOn = scanTextForCodeRisks({ path: "app.js", content: "const c = { rejectUnauthorized: true };" });
check("tls: validation on is clean", tlsOn.length === 0);

const plainHttp = scanTextForCodeRisks({ path: "app.js", content: j("fetch", "(", '"http', "://example.com/api'", ")") });
check("tls: plain HTTP fetch flagged", has(plainHttp, "tls-plain-http") && plainHttp[0].severity === "medium");

const plainHttpClean = scanTextForCodeRisks({ path: "app.js", content: "fetch(\"http://localhost:3000/api\")" });
check("tls: localhost HTTP is clean", plainHttpClean.length === 0);
const plainHttpsClean = scanTextForCodeRisks({ path: "app.js", content: "fetch(\"https://example.com/api\")" });
check("tls: HTTPS is clean", plainHttpsClean.length === 0);

const weakTls = scanTextForCodeRisks({ path: "app.py", content: j("ctx = ssl.SSLContext(ssl.PROTOCOL_TLS", "v1)") });
check("tls: old TLS version flagged", has(weakTls, "tls-weak-version"));
const strongTls = scanTextForCodeRisks({ path: "app.py", content: "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)" });
check("tls: TLS 1.2 is clean", strongTls.length === 0);

// ---------------------------------------------------------------------------
// 4. Secrets in logs and errors (code-risks.ts)
// ---------------------------------------------------------------------------

const logSecret = scanTextForCodeRisks({ path: "app.js", content: j("console.", "log", "(", "pass", "word", ")") });
check("logging: secret value in a log call flagged", has(logSecret, "log-secret") && logSecret[0].category === "logging");

const logClean = scanTextForCodeRisks({ path: "app.js", content: "console.log(userName)" });
check("logging: plain value logged is clean", logClean.length === 0);

const logNamedNotLogged = scanTextForCodeRisks({ path: "app.ts", content: "const k = api_key; console.log(k);" });
check("logging: secret named on the line but not in the call is clean", logNamedNotLogged.length === 0);

const logStringOnly = scanTextForCodeRisks({ path: "app.js", content: j("console.log", "(", '"api_key is set"', ")") });
check("logging: message that merely names a secret is clean", logStringOnly.length === 0);

const stackLeak = scanTextForCodeRisks({ path: "app.js", content: j("res.send", "(", "err", ")") });
check("logging: error sent in response flagged", has(stackLeak, "error-stack-leak"));

const stackClean = scanTextForCodeRisks({ path: "app.js", content: "res.send(\"something went wrong\")" });
check("logging: generic error message is clean", stackClean.length === 0);

const debugOn = scanTextForCodeRisks({ path: "settings.py", content: j("DEBUG", " = ", "True") });
check("logging: debug mode on flagged", has(debugOn, "debug-mode"));

const debugOff = scanTextForCodeRisks({ path: "settings.py", content: "DEBUG = False" });
check("logging: debug mode off is clean", debugOff.length === 0);

// ---------------------------------------------------------------------------
// 5. XSS sinks (code-risks.ts)
// ---------------------------------------------------------------------------

const xssDanger = scanTextForCodeRisks({ path: "app.tsx", content: j("dangerouslySetInnerHTML", "=", "{{__html: userHtml}}") });
check("xss: dangerouslySetInnerHTML with a variable flagged", has(xssDanger, "xss-inner-html") && xssDanger[0].category === "xss" && xssDanger[0].severity === "high");

const xssDangerClean = scanTextForCodeRisks({ path: "app.tsx", content: "dangerouslySetInnerHTML={{__html: \"<b>hi</b>\"}}" });
check("xss: dangerouslySetInnerHTML with a constant is clean", xssDangerClean.length === 0);

const xssJsonLd = scanTextForCodeRisks({ path: "app.tsx", content: "dangerouslySetInnerHTML={{__html: JSON.stringify(jsonLd)}}" });
check("xss: dangerouslySetInnerHTML with a serialised constant is clean", xssJsonLd.length === 0);

const xssInner = scanTextForCodeRisks({ path: "app.js", content: j("el.innerHTML", " = ", "userHtml") });
check("xss: innerHTML with a variable flagged", has(xssInner, "xss-inner-html"));

const xssInnerClean = scanTextForCodeRisks({ path: "app.js", content: "el.innerHTML = \"<b>hi</b>\"" });
check("xss: innerHTML with a constant is clean", xssInnerClean.length === 0);

const xssEval = scanTextForCodeRisks({ path: "app.js", content: j("ev", "al", "(", "input", ")") });
check("xss: eval with a variable flagged", has(xssEval, "xss-eval"));

const xssEvalClean = scanTextForCodeRisks({ path: "app.js", content: "eval(\"1 + 1\")" });
check("xss: eval with a constant is clean", xssEvalClean.length === 0);

// ---------------------------------------------------------------------------
// Self-scan: this file must not trip any of the detectors it tests.
// ---------------------------------------------------------------------------

const selfPath = fileURLToPath(import.meta.url);
const selfContent = readFileSync(selfPath, "utf8");
const selfCodeRisks = scanTextForCodeRisks({ path: selfPath, content: selfContent });
const selfCiRisks = scanTextForCiRisks({ path: selfPath, content: selfContent });
check("self-scan: this test file is clean", selfCodeRisks.length === 0 && selfCiRisks.length === 0, [...selfCodeRisks, ...selfCiRisks].map((f) => `${f.id} line ${f.line}`).join("; "));

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
