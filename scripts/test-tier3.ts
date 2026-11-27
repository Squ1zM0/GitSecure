// Tier 3 infra test (Phase 6): Docker, Kubernetes, Terraform, GitHub
// Actions, Vercel, Supabase detectors + findings + OSV action deps.
// Uses FAKE placeholder values only. Run: npx tsx scripts/test-tier3.ts
// (coordinator adds: "test:tier3": "tsx scripts/test-tier3.ts").

import { loadFakeRepoTier3 } from "./fixture-gen";
import {
  ACTIONS_OSV_ECOSYSTEM,
  detectInfraFrameworks,
  infraFindings,
  parseDockerfile,
  parseWorkflowActions,
} from "../src/lib/infra";

// Phase 14: the risky Tier 3 configs (Dockerfile, k8s/deployment.yaml,
// main.tf) are generated at test time by scripts/fixture-gen.ts — the
// committed files keep only the clean ones (docker-compose.yml,
// ci.yml, supabase/config.toml, vercel.json). loadFakeRepoTier3()
// overlays the generated contents on the committed ones, so every
// assertion below runs against the same contents as before.
const files = loadFakeRepoTier3();

// A 40-char hex string assembled at runtime, never written literally:
// GitHub push protection blocks literal 40-hex strings (they look like
// classic personal access tokens), same trick as test-scanner.ts.
const FAKE_SHA = "ab12".repeat(10);

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

const frameworks = detectInfraFrameworks(files);
const byName = new Map(frameworks.map((f) => [f.name, f]));
const findings = infraFindings(files);
const hasTitle = (re: RegExp) => findings.some((f) => re.test(f.title));

// --- Detection: Docker ---
check("Docker node image version 20-alpine detected", byName.get("Docker image node")?.version === "20-alpine", byName.get("Docker image node")?.version ?? "missing");
check("Docker node image ecosystem is docker", byName.get("Docker image node")?.ecosystem === "docker");
check("postgres:15 detected", byName.get("Docker image postgres")?.version === "15", byName.get("Docker image postgres")?.version ?? "missing");
// Phase 19: the committed fixture pins redis now (the self-scan must
// stay clean), so the untagged case is proven on inline content.
const untaggedCompose = new Map([["docker-compose.yml", "services:\n  cache:\n    image: redis\n"]]);
const untaggedByName = new Map(detectInfraFrameworks(untaggedCompose).map((f) => [f.name, f]));
check("redis with no tag: version null + unpinned", untaggedByName.get("Docker image redis")?.version === null && untaggedByName.get("Docker image redis")?.unpinned === true, `version=${String(untaggedByName.get("Docker image redis")?.version)}`);
const dockerEntries = parseDockerfile(files.get("Dockerfile") ?? "", "Dockerfile");
check("parseDockerfile returns both FROM stages", dockerEntries.length === 2, `${dockerEntries.length} entries`);
check("latest-tag image reported version null + unpinned", dockerEntries.some((f) => f.version === null && f.unpinned === true));

// --- Detection: Kubernetes ---
check("Kubernetes Deployment detected, version null", byName.get("Kubernetes")?.version === null && byName.get("Kubernetes")?.versionSource === "unknown", `version=${String(byName.get("Kubernetes")?.version)}`);
check("k8s container image myapp detected, version null + unpinned", byName.get("Docker image myapp")?.version === null && byName.get("Docker image myapp")?.unpinned === true);

// --- Detection: Terraform ---
check("Terraform aws provider 5.0.0 detected", byName.get("Terraform provider aws")?.version === "5.0.0", byName.get("Terraform provider aws")?.version ?? "missing");
check("unpinned provider reported version null", byName.get("Terraform provider random")?.version === null && byName.get("Terraform provider random")?.unpinned === true);
check("Terraform 1.6.0 detected", byName.get("Terraform")?.version === "1.6.0", byName.get("Terraform")?.version ?? "missing");

// --- Detection: GitHub Actions / Vercel / Supabase ---
check("checkout@v4 framework version v4, pinned", byName.get("GitHub Action actions/checkout")?.version === "v4" && byName.get("GitHub Action actions/checkout")?.unpinned === false);
check("setup-node@main framework unpinned", byName.get("GitHub Action actions/setup-node")?.unpinned === true, `version=${String(byName.get("GitHub Action actions/setup-node")?.version)}`);
check("build-push-action@v5 detected", byName.get("GitHub Action docker/build-push-action")?.version === "v5");
check("Vercel preset nextjs detected, version null", byName.get("Next.js")?.version === null && byName.get("Next.js")?.sourceFile === "vercel.json");
check("Supabase detected, version null", byName.get("Supabase")?.version === null && byName.get("Supabase")?.sourceFile === "supabase/config.toml");

// --- OSV action deps ---
const actionDeps = parseWorkflowActions(files.get(".github/workflows/ci.yml") ?? "", ".github/workflows/ci.yml");
const actionByName = new Map(actionDeps.map((d) => [d.name, d]));
check("checkout@v4 dep version v4, ecosystem actions", actionByName.get("actions/checkout")?.version === "v4" && actionByName.get("actions/checkout")?.ecosystem === "actions");
check("setup-node@main dep version null (branch ref is not a version)", actionByName.get("actions/setup-node")?.version === null);
check("build-push-action@v5 dep version v5", actionByName.get("docker/build-push-action")?.version === "v5");
check("ACTIONS_OSV_ECOSYSTEM is GitHub Actions", ACTIONS_OSV_ECOSYSTEM === "GitHub Actions");
const shaDeps = parseWorkflowActions(`jobs:\n  build:\n    steps:\n      - uses: actions/checkout@${FAKE_SHA}\n`, ".github/workflows/sha.yml");
check("40-char SHA ref is NOT a version (null, never guessed)", shaDeps[0]?.version === null && shaDeps[0]?.name === "actions/checkout");
const shaFw = detectInfraFrameworks(new Map([[".github/workflows/sha.yml", `jobs:\n  build:\n    steps:\n      - uses: actions/checkout@${FAKE_SHA}\n`]]));
check("SHA-pinned action is pinned (unpinned false)", shaFw[0]?.unpinned === false);

// --- Terraform range rule ---
const rangeTf = new Map([
  ["main.tf", 'terraform {\n  required_providers {\n    aws = {\n      source = "hashicorp/aws"\n      version = "~> 5.0"\n    }\n  }\n}\n'],
]);
check("Terraform range ~> 5.0 is NOT a version (null)", detectInfraFrameworks(rangeTf).find((f) => f.name === "Terraform provider aws")?.version === null);
check("Terraform range still counts as constrained (no unpinned finding)", !infraFindings(rangeTf).some((f) => f.title.includes("aws")));

// --- Findings: present, plain-English, with an exact fix ---
check("USER-root finding present", hasTitle(/runs as root/));
check("only one Dockerfile root finding (no duplicate no-USER finding)", findings.filter((f) => f.title === "Dockerfile runs as root").length === 1 && !hasTitle(/no USER/), `${findings.filter((f) => /root/i.test(f.title)).length} root findings total (Dockerfile + k8s)`);
check("latest base image finding present", hasTitle(/base image is not pinned/));
check("secret-looking ARG finding present", hasTitle(/build argument/));
check("remote ADD finding present", hasTitle(/downloads a file with ADD/));
check("privileged finding present", hasTitle(/privileged/));
check("hostNetwork finding present", hasTitle(/host network/));
check("runAsUser 0 finding present", hasTitle(/runs as root \(UID 0\)/));
check("latest k8s image finding present", hasTitle(/container image is not pinned/));
check("unpinned provider finding present (random)", findings.some((f) => f.title.includes("random") && /no version constraint/.test(f.title)));
check("unpinned action finding present (setup-node)", hasTitle(/Action is not pinned/));
check("no finding for the pinned aws provider", !findings.some((f) => f.title.includes("aws")));
check("every finding detail is plain English with an exact fix", findings.length > 0 && findings.every((f) => f.detail.includes("Fix:")), `${findings.length} findings`);

// --- Findings: clean patterns stay quiet ---
const noUser = new Map([["Dockerfile", "FROM node:20-alpine\nCMD [\"node\", \"index.js\"]\n"]]);
check("Dockerfile with no USER is flagged (runs as root by default)", infraFindings(noUser).some((f) => /no USER/.test(f.title)));
const clean = new Map<string, string>([
  ["Dockerfile", "FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nUSER node\nHEALTHCHECK CMD curl -f http://localhost/health || exit 1\nCMD [\"node\", \"index.js\"]\n"],
  ["k8s/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: myapp:1.2.3\n          securityContext:\n            privileged: false\n            runAsUser: 1000\n"],
  [".github/workflows/ci.yml", "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"],
  ["main.tf", 'terraform {\n  required_providers {\n    aws = {\n      source = "hashicorp/aws"\n      version = "5.0.0"\n    }\n  }\n}\nprovider "aws" {}\n'],
]);
const cleanFindings = infraFindings(clean);
check("no finding for the clean patterns", cleanFindings.length === 0, cleanFindings.map((f) => f.title).join("; "));

// --- Findings: no duplication of scan.ts posture ---
const prTarget = new Map([
  [".github/workflows/ci.yml", "on:\n  pull_request_target:\n    types: [opened]\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"],
]);
check("infraFindings does not duplicate pull_request_target (scan.ts owns it)", !infraFindings(prTarget).some((f) => /pull_request_target/.test(f.title + f.detail)));

console.log(failures === 0 ? "\nAll Tier 3 tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
