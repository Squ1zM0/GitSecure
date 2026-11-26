# Phase 12 — self-scan score breakdown (measured, not assumed)

Measured 2026-11-26 by running the real scanner locally against the live
remote `Squ1zM0/GitSecure` (`scanRepo`, no auth): 34 secrets, 197
vulnerabilities, 15 posture issues, 3 unpinned frameworks, 79 files,
27 history commits. Old-rule score: **0/F**.

Old weights: secrets critical 25 / high 15 / medium 8 / low 3; vulns
critical 15 / high 10 / medium 5 / low 2; posture critical 15 / high 10 /
medium 5 / low 2; unpinned min(n*2, 10); floor 0.

## Component breakdown (old rule)

- Secrets: **384 points** — 16 high x 15 = 240, 18 medium x 8 = 144.
  - likely-test-key: 32 findings, 368 points (16 high = 240, 16 medium = 128).
  - uncertain: 2 findings, 16 points (2 medium x 8).
  - likely-genuine-leak: 0 findings, 0 points.
  - No-triage findings: 0.
- Vulnerabilities: **547 points** — 51 medium x 5 = 255, 146 low x 2 = 292,
  0 critical, 0 high.
- Posture: **84 points** — 5 high x 10 = 50, 6 medium x 5 = 30,
  2 low x 2 = 4, 2 info x 0 = 0.
- Unpinned: **4 points** — 2 unpinned direct dependencies x 2
  (Microsoft.NET.Sdk.Web and org.example:unresolvable, both version-null
  in the Tier 2 fixtures). Note: the scorer counts unpinned *direct
  dependencies*, not unpinned frameworks — the 3 unpinned frameworks
  (Docker image myapp, Docker image redis, Terraform provider random)
  are a different count and do not feed the score.
- Total deductions: 384 + 547 + 84 + 4 = **1019**, so the score floors at 0/F.

## What actually drives the F

- Secrets alone (384) would floor the score — but so would vulnerabilities
  alone (547). The F is NOT caused by test keys alone.
- Under the Phase 12 rule the secrets deduction falls 384 -> 8
  (32 test keys at weight 0, 2 uncertain at half weight: 2 x 8 x 0.5 = 8),
  but the new total is still 8 + 547 + 84 + 4 = **643**, so the new
  self-scan score is still **0/F** (wouldBeScore 0/F). Phase 12 fixes the
  false-alarm secrets component; it does not and cannot lift the
  self-scan grade while the other components stand.
- Vulnerabilities: the 197 are real OSV advisories on deliberately old
  dependency versions in the Tier 2 test fixtures (Django 4.2.0, Laravel,
  Echo, Fiber, ...). They are fixture files, but the flaws in them are
  real flaws in real pinned versions — relabelling them harmless would
  be wrong, so they are left at full weight per the Phase 12 scope
  (secrets only). Any future change to how fixture-driven vulns/posture
  score is a separate decision, not part of this phase.
- Posture: the 84 includes Tier 3 fixture configs (Dockerfile runs as
  root / unpinned base image / secret build arg / ADD download,
  Kubernetes privileged + hostNetwork + run-as-root, unpinned Terraform
  provider) plus the committed `.env` fixture, missing SECURITY.md /
  Dependabot, and Vite dev-server items. Same note as vulnerabilities:
  fixture-driven, scored as real, unchanged by Phase 12.
