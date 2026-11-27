// Phase 17 (Worker B) — detection-coverage tests.
//
// New detectors (Anthropic, Google, npm, PyPI, SendGrid, Telegram,
// Hugging Face, AWS secret key), the Slack xoxe extension, the
// pyproject.toml / poetry.lock / pubspec parsers, Cargo dev/build
// deps, the Fastify/Koa/Hono/SvelteKit fingerprints, and the new
// posture checks (curl-piped-to-shell, Dockerfile ENV secret, k8s
// hostIPC / allowPrivilegeEscalation, compose privileged / host
// network). Run: npm run test:phase17-worker-b
//
// Fixture discipline (Phase 14): every secret value below is
// assembled at runtime from a short prefix plus a repeated
// single-character filler — no literal secret-pattern string is
// committed anywhere in this file. The values are invented and
// never worked.

import { loadFakeRepo, loadFakeRepoTier3 } from "./fixture-gen";
import { scanTextForSecrets } from "../src/lib/secrets";
import { triageFinding } from "../src/lib/triage";
import { computeUsageForFindings } from "../src/lib/usage";
import { buildPosture } from "../src/lib/scan";
import { infraFindings } from "../src/lib/infra";
import {
  fingerprintFrameworks,
  parseCargoToml,
  parsePackageJson,
  parsePoetryLock,
  parsePubspecLock,
  parsePubspecYaml,
  parsePyprojectToml,
} from "../src/lib/frameworks";
import { leaksSecret, redactSecret } from "../src/lib/redact";

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

// Invented secrets, assembled in memory only.
const ANTHROPIC = "sk-ant-api03-" + "K".repeat(25);
const GOOGLE = "AIza" + "K".repeat(35);
const NPM = "npm_" + "N".repeat(36);
const PYPI = "pypi-" + "P".repeat(24);
const SENDGRID = "SG." + "S".repeat(22) + "." + "S".repeat(43);
const TELEGRAM = "123456789:" + "T".repeat(35);
const HF = "hf_" + "H".repeat(34);
const GITLAB = "glpat-" + "G".repeat(20);
const AWS_SECRET = "A".repeat(40);
const ALL_NEW = [ANTHROPIC, GOOGLE, NPM, PYPI, SENDGRID, TELEGRAM, HF, GITLAB];
const NEW_IDS = new Set([
  "anthropic-api-key", "google-api-key", "npm-token", "pypi-token",
  "sendgrid-api-key", "telegram-bot-token", "huggingface-token", "aws-secret-key",
  "gitlab-token",
]);

// --- 1. New secret detectors: detection ---
const newSecretsContent = [
  `const ANTHROPIC_API_KEY = "${ANTHROPIC}";`,
  `const GOOGLE_API_KEY = "${GOOGLE}";`,
  `const NPM_TOKEN = "${NPM}";`,
  `const PYPI_TOKEN = "${PYPI}";`,
  `const SENDGRID_API_KEY = "${SENDGRID}";`,
  `const TELEGRAM_BOT_TOKEN = "${TELEGRAM}";`,
  `const HF_TOKEN = "${HF}";`,
  `const GITLAB_TOKEN = "${GITLAB}";`,
  `aws_secret_access_key = "${AWS_SECRET}"`,
  `AWS_SECRET_ACCESS_KEY=${"B".repeat(40)}`,
].join("\n");
const newFindings = scanTextForSecrets({ path: "config.js", content: newSecretsContent, commit: "HEAD" });
const newTypes = new Set(newFindings.map((f) => f.type));
for (const id of NEW_IDS) check(`detects ${id}`, newTypes.has(id));
check("aws secret key fires on both cases (lower + upper)", newFindings.filter((f) => f.type === "aws-secret-key").length === 2, `${newFindings.filter((f) => f.type === "aws-secret-key").length} found`);
check("no duplicate detector fires on the new-secret block", newFindings.every((f) => NEW_IDS.has(f.type)), newFindings.map((f) => f.type).join(","));

// --- 2. New secret detectors: negatives (must NOT fire) ---
const negativeContent = [
  `const SHORT_GOOGLE = "AIza${"K".repeat(10)}";`,
  `const SHORT_NPM = "npm_${"N".repeat(10)}";`,
  `const SHORT_ANTHROPIC = "sk-ant-api03-${"K".repeat(5)}";`,
  `const SHORT_SG = "SG.${"S".repeat(5)}";`,
  `const SHORT_TELEGRAM = "123456789:${"T".repeat(10)}";`,
  `const SHORT_HF = "hf_${"H".repeat(10)}";`,
  `const SHORT_PYPI = "pypi-${"P".repeat(5)}";`,
  `const SHORT_GITLAB = "glpat-${"G".repeat(5)}";`,
  `aws_secret_access_key = "short"`,
  // No word boundary before AIza: a longer identifier ending in it.
  `const NOT_A_KEY = "xAIza${"K".repeat(35)}";`,
  // A bare 40-hex string with no aws name attached is not a key.
  `const SHA = "${"ab12".repeat(10)}";`,
].join("\n");
const negativeFindings = scanTextForSecrets({ path: "clean.js", content: negativeContent, commit: "HEAD" });
check("short / boundary-less values fire nothing", negativeFindings.length === 0, negativeFindings.map((f) => `${f.type}:${f.line}`).join(","));

// --- 3. Slack xoxe extension ---
const xoxe = scanTextForSecrets({ path: "s.js", content: `const t = "xoxe-${"E".repeat(12)}";`, commit: "HEAD" });
check("detects slack xoxe- token", xoxe.some((f) => f.type === "slack-token"));
const xoxb = scanTextForSecrets({ path: "s.js", content: `const t = "xoxb-${"E".repeat(12)}";`, commit: "HEAD" });
check("slack xoxb- token still detected", xoxb.some((f) => f.type === "slack-token"));

// --- 4. Redaction: no full invented secret anywhere in the findings ---
const findingsJson = JSON.stringify(newFindings);
for (const secret of [...ALL_NEW, AWS_SECRET]) {
  check(`redaction: full invented secret never appears (${secret.slice(0, 10)}…)`, !leaksSecret(findingsJson, secret));
}
check("every new fragment is redacted (< 12 chars)", newFindings.every((f) => f.fragment.length < 12));

// --- 5. Clean-fixture regression: new detectors stay quiet ---
const cleanFiles = new Map([...loadFakeRepo(), ...loadFakeRepoTier3()]);
let cleanNewHits = 0;
for (const [path, content] of cleanFiles) {
  for (const f of scanTextForSecrets({ path, content, commit: "HEAD" })) {
    if (NEW_IDS.has(f.type)) cleanNewHits++;
  }
}
check("new detectors fire nothing on the committed clean fixtures", cleanNewHits === 0, `${cleanNewHits} hits`);

// --- 6. Triage flow: new types triage like other credentials ---
const anthropicFinding = {
  id: "anthropic-api-key-config-js-1",
  type: "anthropic-api-key",
  title: "Anthropic API key",
  severity: "critical" as const,
  confidence: "high" as const,
  file: "src/config.ts",
  line: 1,
  commit: "HEAD",
  fragment: redactSecret(ANTHROPIC),
  fix: "Revoke it.",
  plainEnglish: "An Anthropic key.",
};
const prodContent = `const ANTHROPIC_API_KEY = "${ANTHROPIC}";`;
check(
  "triage: anthropic key in a prod path is likely-genuine-leak",
  triageFinding({ ...anthropicFinding }, { content: prodContent }).triage.verdict === "likely-genuine-leak",
);
check(
  "triage: same key under tests/ is likely-test-key",
  triageFinding({ ...anthropicFinding, file: "tests/fake.ts" }, { content: prodContent }).triage.verdict === "likely-test-key",
);
check(
  "triage: test-key finding referenced from prod code upgrades to likely-genuine-leak",
  triageFinding(
    { ...anthropicFinding, file: "tests/fake.ts" },
    {
      content: prodContent,
      usage: { referencedBy: [{ file: "src/app.ts", line: 3 }], referencedByTotal: 1, referencedByTests: [], referencedByTestsTotal: 0, deadEnd: false },
    },
  ).triage.verdict === "likely-genuine-leak",
);

// --- 7. Usage flow: identifier extraction works for a new detector ---
const usageFiles = new Map<string, string>([
  ["config.ts", prodContent],
  ["src/app.ts", `import { key } from "./config";\nconsole.log(ANTHROPIC_API_KEY);\n`],
]);
const usageFindings = scanTextForSecrets({ path: "config.ts", content: prodContent, commit: "HEAD" });
computeUsageForFindings(usageFindings, usageFiles, (f) => ({
  content: prodContent,
  lineText: prodContent.split("\n")[f.line - 1] ?? null,
}));
const usageHit = usageFindings.find((f) => f.type === "anthropic-api-key");
check("usage: anthropic key referenced from src/app.ts is found", usageHit?.usage?.referencedByTotal === 1 && usageHit.usage.referencedBy[0]?.file === "src/app.ts", JSON.stringify(usageHit?.usage));
const googleContent = `const GOOGLE_API_KEY = "${GOOGLE}";`;
const deadFindings = scanTextForSecrets({ path: "other.ts", content: googleContent, commit: "HEAD" });
computeUsageForFindings(deadFindings, new Map([["other.ts", googleContent]]), (f) => ({
  content: googleContent,
  lineText: googleContent.split("\n")[f.line - 1] ?? null,
}));
check("usage: unreferenced google key is a dead end", deadFindings.find((f) => f.type === "google-api-key")?.usage?.deadEnd === true);

// --- 8. pyproject.toml + poetry.lock ---
const pyproject = [
  "[project]",
  'name = "fake-app"',
  'version = "0.1.0"',
  "dependencies = [",
  '  "django==5.2.17",',
  '  "flask>=3.0",',
  '  "requests",',
  "]",
  "",
  "[project.optional-dependencies]",
  'dev = ["pytest==8.0.0"]',
  "",
  "[tool.poetry.dependencies]",
  'python = "^3.11"',
  'django = "^5.0"',
  'celery = { version = "5.3.0" }',
  "",
].join("\n");
const pyDeps = parsePyprojectToml(pyproject, "pyproject.toml");
const pyByName = new Map(pyDeps.map((d) => [d.name + "@" + (d.version ?? "null"), d]));
check("pyproject: django ==5.2.17 pinned (PEP 621)", pyDeps.some((d) => d.name === "django" && d.version === "5.2.17"));
check("pyproject: flask range yields null, never a guessed version", pyDeps.some((d) => d.name === "flask" && d.version === null));
check("pyproject: bare requests yields null", pyDeps.some((d) => d.name === "requests" && d.version === null));
check("pyproject: optional pytest ==8.0.0 parsed", pyDeps.some((d) => d.name === "pytest" && d.version === "8.0.0"));
check("pyproject: poetry celery {version} parsed", pyDeps.some((d) => d.name === "celery" && d.version === "5.3.0"));
check("pyproject: poetry django ^5.0 kept as a range string", pyDeps.some((d) => d.name === "django" && d.version === "^5.0"));
check("pyproject: python interpreter entry is skipped", !pyDeps.some((d) => d.name === "python"));
check("pyproject: project name/version strings are not deps", !pyDeps.some((d) => d.name === "fake-app" || d.name === "0.1.0"), pyDeps.map((d) => d.name).join(","));
check("pyproject: all deps are pypi", pyDeps.every((d) => d.ecosystem === "pypi"));
const pyFrameworks = fingerprintFrameworks(pyDeps, new Map());
check("pyproject: Django fingerprinted at 5.2.17 (pinned wins over range)", pyFrameworks.find((f) => f.name === "Django")?.version === "5.2.17", pyFrameworks.find((f) => f.name === "Django")?.version ?? "missing");
const poetryLock = [
  "[[package]]",
  'name = "django"',
  'version = "5.2.17"',
  "",
  "[[package]]",
  'name = "flask"',
  'version = "3.0.0"',
  "",
].join("\n");
const lockDeps = parsePoetryLock(poetryLock, "poetry.lock");
check("poetry.lock: django 5.2.17 pinned, not direct", lockDeps.some((d) => d.name === "django" && d.version === "5.2.17" && d.direct === false));
check("poetry.lock: flask 3.0.0 pinned", lockDeps.some((d) => d.name === "flask" && d.version === "3.0.0"));
check("pyproject with no deps parses to []", parsePyprojectToml('[project]\nname = "x"\nversion = "0.1.0"\n', "pyproject.toml").length === 0);

// --- 9. Cargo dev/build/workspace dependencies ---
const cargo = [
  "[package]",
  'name = "x"',
  'version = "0.1.0"',
  "",
  "[dependencies]",
  'serde = "1.0.0"',
  "",
  "[dev-dependencies]",
  'tokio = "1.0.0"',
  "",
  "[build-dependencies]",
  'cc = "1.0.0"',
  "",
  "[workspace.dependencies]",
  'foo = "2.0.0"',
  "",
].join("\n");
const cargoDeps = parseCargoToml(cargo, "Cargo.toml");
check("cargo: dev-dependency tokio parsed", cargoDeps.some((d) => d.name === "tokio" && d.version === "1.0.0"));
check("cargo: build-dependency cc parsed", cargoDeps.some((d) => d.name === "cc" && d.version === "1.0.0"));
check("cargo: workspace dependency foo parsed", cargoDeps.some((d) => d.name === "foo" && d.version === "2.0.0"));
check("cargo: plain [dependencies] still parsed", cargoDeps.some((d) => d.name === "serde" && d.version === "1.0.0"));

// --- 10. pubspec.yaml / pubspec.lock + Flutter fingerprint ---
const pubspec = [
  "name: fake_app",
  "environment:",
  "  sdk: ^3.0.0",
  "",
  "dependencies:",
  "  flutter:",
  "    sdk: flutter",
  "  http: ^1.2.0",
  "  provider: 6.1.0",
  "",
  "dev_dependencies:",
  "  flutter_test:",
  "    sdk: flutter",
  "  lints: ^3.0.0",
  "",
].join("\n");
const pubDeps = parsePubspecYaml(pubspec, "pubspec.yaml");
check("pubspec: http ^1.2.0 direct, ecosystem pub", pubDeps.some((d) => d.name === "http" && d.version === "^1.2.0" && d.direct === true && d.ecosystem === "pub"));
check("pubspec: provider 6.1.0 parsed", pubDeps.some((d) => d.name === "provider" && d.version === "6.1.0"));
check("pubspec: dev lints parsed as not direct", pubDeps.some((d) => d.name === "lints" && d.version === "^3.0.0" && d.direct === false));
check("pubspec: flutter sdk entry is skipped (not a package)", !pubDeps.some((d) => d.name === "flutter" || d.name === "flutter_test"));
const pubspecLock = [
  "packages:",
  "  http:",
  '    dependency: "direct main"',
  '    version: "1.2.0"',
  "  provider:",
  '    dependency: "direct main"',
  '    version: "6.1.0"',
  "sdks:",
  '  dart: ">=3.0.0 <4.0.0"',
  "",
].join("\n");
const pubLockDeps = parsePubspecLock(pubspecLock, "pubspec.lock");
check("pubspec.lock: http 1.2.0 pinned, not direct", pubLockDeps.some((d) => d.name === "http" && d.version === "1.2.0" && d.direct === false));
check("pubspec.lock: provider 6.1.0 pinned", pubLockDeps.some((d) => d.name === "provider" && d.version === "6.1.0"));
const flutterFrameworks = fingerprintFrameworks(pubDeps, new Map([["pubspec.yaml", pubspec]]));
const flutter = flutterFrameworks.find((f) => f.name === "Flutter");
check("pubspec: Flutter fingerprinted, version null, not unpinned", flutter?.version === null && flutter?.unpinned === false && flutter?.sourceFile === "pubspec.yaml", JSON.stringify(flutter));

// --- 11. Framework map additions ---
const jsDeps = parsePackageJson(
  JSON.stringify({ dependencies: { fastify: "4.25.0", koa: "2.15.0", hono: "4.0.0", "@sveltejs/kit": "2.0.0" } }),
  "package.json",
);
const jsFrameworks = fingerprintFrameworks(jsDeps, new Map());
for (const name of ["Fastify", "Koa", "Hono", "SvelteKit"]) {
  check(`framework map: ${name} fingerprinted`, jsFrameworks.some((f) => f.name === name));
}

// --- 12. Posture: new checks ---
const baseline = new Map<string, string>([
  ["SECURITY.md", "# Security\n"],
  [".github/dependabot.yml", "version: 2\n"],
  [".gitignore", ".env\nnode_modules\n*.pem\n"],
]);
const curlWorkflow = new Map([
  ...baseline,
  [".github/workflows/install.yml", "jobs:\n  build:\n    steps:\n      - run: curl -fsSL https://example.com/install.sh | sudo bash\n"],
]);
check(
  "posture: curl piped to shell flagged (high)",
  buildPosture(curlWorkflow).some((p) => p.id === "actions-curl-pipe-shell" && p.severity === "high"),
);
const wgetWorkflow = new Map([
  ...baseline,
  [".github/workflows/install.yml", "jobs:\n  build:\n    steps:\n      - run: wget -qO- https://example.com/setup.sh | sh\n"],
]);
check("posture: wget piped to sh flagged", buildPosture(wgetWorkflow).some((p) => p.id === "actions-curl-pipe-shell"));
const cleanWorkflow = new Map([
  ...baseline,
  [".github/workflows/ci.yml", "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci && npm test\n"],
]);
check("posture: clean workflow raises nothing at all", buildPosture(cleanWorkflow).length === 0, buildPosture(cleanWorkflow).map((p) => p.id).join(","));

const envDocker = new Map([["Dockerfile", "FROM node:20-alpine\nUSER node\nENV API_TOKEN=placeholder\nCMD [\"node\", \"index.js\"]\n"]]);
check("posture: Dockerfile ENV secret flagged (high)", infraFindings(envDocker).some((f) => /ENV/.test(f.title) && f.severity === "high"));
const envDockerMulti = new Map([["Dockerfile", "FROM node:20-alpine\nUSER node\nENV NODE_ENV=production API_KEY=placeholder\nCMD [\"node\", \"index.js\"]\n"]]);
check("posture: ENV secret flagged even when not the first var", infraFindings(envDockerMulti).some((f) => /ENV/.test(f.title)));
const cleanDocker = new Map([["Dockerfile", "FROM node:20-alpine\nUSER node\nENV NODE_ENV=production\nCMD [\"node\", \"index.js\"]\n"]]);
check("posture: plain ENV NODE_ENV stays quiet", !infraFindings(cleanDocker).some((f) => /ENV/.test(f.title)));

const riskyK8s = new Map([[
  "k8s/deployment.yaml",
  "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n      hostIPC: true\n      containers:\n        - name: app\n          image: myapp:1.2.3\n          securityContext:\n            allowPrivilegeEscalation: true\n            privileged: false\n            runAsUser: 1000\n",
]]);
const k8sFindings = infraFindings(riskyK8s);
check("posture: k8s hostIPC flagged", k8sFindings.some((f) => /host IPC/.test(f.title)));
check("posture: k8s allowPrivilegeEscalation flagged", k8sFindings.some((f) => /privilege escalation/.test(f.title)));
const cleanK8s = new Map([[
  "k8s/deployment.yaml",
  "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: myapp:1.2.3\n          securityContext:\n            allowPrivilegeEscalation: false\n            privileged: false\n            runAsUser: 1000\n",
]]);
check("posture: clean k8s manifest stays quiet", infraFindings(cleanK8s).length === 0, infraFindings(cleanK8s).map((f) => f.title).join(";"));

const riskyCompose = new Map([[
  "docker-compose.yml",
  "services:\n  app:\n    image: myapp:1.2.3\n    privileged: true\n    network_mode: host\n",
]]);
const composeFindings = infraFindings(riskyCompose);
check("posture: compose privileged flagged", composeFindings.some((f) => /privileged/.test(f.title)));
check("posture: compose host network flagged", composeFindings.some((f) => /host network/.test(f.title)));
const cleanCompose = new Map([[
  "docker-compose.yml",
  "services:\n  db:\n    image: postgres:15\n  app:\n    image: myapp:1.2.3\n    ports:\n      - \"3000:3000\"\n",
]]);
check("posture: clean compose stays quiet", infraFindings(cleanCompose).length === 0, infraFindings(cleanCompose).map((f) => f.title).join(";"));

console.log(failures === 0 ? "\nAll Phase 17 Worker B tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
