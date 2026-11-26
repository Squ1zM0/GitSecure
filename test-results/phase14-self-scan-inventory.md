# Phase 14 — self-scan inventory (measured, not assumed)

Measured 2026-11-26 by running the real scanner locally against the live
remote `Squ1zM0/GitSecure` (`scanRepo`, no auth, ~15 s). Raw full report
used to build this file: `/tmp/phase14-full-report.json` (ephemeral, kept
outside the repo so this worker creates only this one inventory file).

- Remote head scanned: `858bd7aa2a1186341735f8a9baff57e7ca33d89c` (== remote
  `HEAD`, verified via `git ls-remote`), branch `main`.
- Score: **0/F** — scoreDetail: `{"score": 0, "grade": "F",
  "secretsDeduction": 8, "secretsFullWeight": 0, "secretsHalfWeight": 2,
  "secretsExcluded": 32, "wouldBeScore": 0, "vulnDeduction": 206,
  "postureDeduction": 84, "unpinnedDeduction": 4}`
- Counts: secrets 34 (32 likely-test-key, 2 uncertain, 0 genuine),
  **vulnerabilities 73** (20 medium, 53 low; 0 critical, 0 high),
  posture 15, frameworks 29, dependencies 233, files scanned 86,
  history commits 30 (29 at the Phase 13 live check — one more commit
  since, the Phase 13 push itself).
- No literal secret values in this file: fragments only, as the scanner
  produces them.

## 0. Local working copy vs remote head — MISMATCH (read before acting)

The local working copy at `~/workspace/gitsecure/` is **not** an exact
match for remote head 858bd7aa. It has no `.git` directory, so this was
checked by diffing the local file list against the remote tree API
(`GET /repos/Squ1zM0/GitSecure/git/trees/858bd7aa…?recursive=1`):

- Files in local but **not** on remote (exactly 2):
  - `SECURITY.md` (76 lines, real content — security policy)
  - `.github/dependabot.yml` (12 lines, real content — npm updates)
- Files on remote but not local: **none**.
- Every other local file matches the remote tree by path (contents spot-
  checked: `package.json` diff 8.0.4 / zod 4.6.7, `go.mod` fiber
  v2.52.14, `requirements.txt` Django 5.2.17, fake-repo `package.json`
  next 15.5.29 — all the Phase 13 upgraded versions).

Consequence: the two repo-level posture items in §2 (`no-security-md`,
`no-dependabot`, 4 points) are already fixed in the local working copy
and will clear on the next push of this tree — they are still live on
the remote, which is what this scan measured. The rest of this inventory
describes the **remote** state.

## 1. Vulnerabilities — all 73

Weights: critical 15 / high 10 / medium 5 / low 2. Deduction:
20 medium x 5 + 53 low x 2 = 100 + 106 = **206**.

### 1a. Summary by source file

| File | Vulns | Med | Low | Packages | Classification |
|---|---:|---:|---:|---|---|
| `tests/fixtures/fake-repo-tier2/go.mod` | 28 | 14 | 14 | github.com/labstack/echo/v4 v4.11.1 | Kept-vulnerable fixture (Phase 13, Go) |
| `tests/fixtures/fake-repo/package.json` | 23 | 0 | 23 | vite 5.0.0 | Kept-vulnerable fixture (Phase 13, npm) |
| `tests/fixtures/fake-repo/Cargo.toml` | 9 | 6 | 3 | tokio 1.0.0 | Kept-vulnerable fixture (Phase 13, crates) |
| `tests/fixtures/fake-repo-tier2/composer.lock` | 7 | 0 | 7 | laravel/framework v10.34.2 | Kept-vulnerable fixture (Phase 13, PHP) |
| `tests/fixtures/fake-repo-tier2/pom.xml` | 3 | 0 | 3 | org.springframework:spring-core 6.1.2 | Kept-vulnerable fixture (Phase 13, Java) |
| `tests/fixtures/fake-repo/requirements.txt` | 2 | 0 | 2 | Flask 3.0.0 | Kept-vulnerable fixture (Phase 13, PyPI) |
| `tests/fixtures/fake-repo-tier2/Gemfile.lock` | 1 | 0 | 1 | rails 7.1.3 | Kept-vulnerable fixture (Phase 13, Ruby) |
| **Total** | **73** | **20** | **53** | | |

**Nothing else remains.** Every one of the 73 is a deliberately kept-
vulnerable fixture from Phase 13 (Echo, rails, laravel, spring-core,
Flask, vite, tokio — one per ecosystem). No real-repo dependency has any
advisory: `diff` 8.0.4 and `zod` 4.6.7 (real deps, fixed in Phase 13)
are clean, as are Django 5.2.17, next 15.5.29, fiber v2.52.14, sinatra
4.2.0, puma 7.2.1, phpunit 10.5.62 (all Phase 13 upgrades, verified
0 advisories in this scan). Tier 3 fixtures contribute 0 vulns.

### 1b. Full grouped list (all 73)

Grouped by source file (from the dependency→source-file join; every
vuln matched exactly one dependency), then package, then advisory ID.
`Fixed (scanner)` is the OSV fixed version as the scanner reports it
(first `fixed` event across all advisory ranges — for multi-branch
advisories this can name a fix from a different release line than the
installed version). `Fixed (branch-correct)` is the Phase 13
re-check against the OSV API for the range actually containing the
installed version, copied from `test-results/phase13-vuln-inventory.md`
(the installed versions are unchanged since Phase 13, so those
re-checks still apply); `—` means Phase 13 did not re-check that
package (tokio, vite, Flask) — scanner value only. `NO FIX` means the
range ends in `last_affected` with no fix in the installed release line.

#### `tests/fixtures/fake-repo-tier2/go.mod` — Echo v4.11.1 (28)

| Package | Installed | Severity | Advisory | Fixed (scanner) | Fixed (branch-correct) |
|---|---|---|---|---|---|
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-23wf-92cp-8pcj | 5.1.1 | 4.15.2 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-246p-cpwv-v3jq | 5.1.0 | NO FIX in v4 line |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-2ffq-g2xg-c22p | 5.4.0 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-375p-5qhx-8wq4 | 5.4.0 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-3pmx-cf9f-34xr | 5.4.0 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-99jh-6h7p-pp36 | 5.4.0 | NO FIX in v4 line |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-cxf3-9h37-7rr8 | 4.16.1 | 4.16.1 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-f48p-c9v4-h7xv | 4.16.1 | 4.16.1 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-h7wr-284f-5qvc | 4.16.1 | 4.16.1 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-h9g5-28mm-hx3g | 5.4.0 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-r7w9-592q-9vg4 | 5.4.0 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-v753-g4cw-jm48 | 5.4.0 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-vfp3-v2gw-7wfq | 5.2.0 | 4.15.3 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-xwq5-6cqp-vx96 | 5.2.0 | 4.15.3 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6293 | 4.15.3 | 4.15.3 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6839 | 4.16.1 | 4.16.1 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6840 | 4.16.1 | 4.16.1 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6842 | 4.16.1 | 4.16.1 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6872 | 4.16.3 | 4.16.3 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6873 | 4.16.0 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6875 | 4.16.3 | 4.16.3 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6876 | 4.16.0 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6877 | 4.16.0 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6878 | 4.15.2 | 4.15.2 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6879 | 4.16.0 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6881 | 4.16.0 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6883 | 4.16.0 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6885 | 4.15.3 | 4.15.3 |

Echo note (Phase 13, still true): highest v4 fix is 4.16.3; the 2
NO-FIX advisories need v5.4.0 (major jump). Kept to preserve the
`Echo v4.11.1` fingerprint assertion in `test-scanner.ts`.

#### `tests/fixtures/fake-repo/package.json` — vite 5.0.0 (23)

| Package | Installed | Severity | Advisory | Fixed (scanner) | Fixed (branch-correct) |
|---|---|---|---|---|---|
| vite | 5.0.0 | low | GHSA-356w-63v5-8wf4 | 6.2.6 | — |
| vite | 5.0.0 | low | GHSA-4r4m-qw57-chr8 | 6.2.4 | — |
| vite | 5.0.0 | low | GHSA-4w7w-66w2-5vf9 | 8.0.5 | — |
| vite | 5.0.0 | low | GHSA-587h-7wmj-h5pm | 2.14.2 | — |
| vite | 5.0.0 | low | GHSA-64vr-g452-qvp3 | 5.4.6 | — |
| vite | 5.0.0 | low | GHSA-698v-4r3x-3vcv | 2.14.2 | — |
| vite | 5.0.0 | low | GHSA-859w-5945-r5v3 | 6.3.4 | — |
| vite | 5.0.0 | low | GHSA-8jhw-289h-jh2g | 2.9.18 | — |
| vite | 5.0.0 | low | GHSA-92r3-m2mg-pj97 | 4.4.12 | — |
| vite | 5.0.0 | low | GHSA-93m4-6634-74q7 | 7.1.11 | — |
| vite | 5.0.0 | low | GHSA-9cwx-2883-4wfx | 5.4.6 | — |
| vite | 5.0.0 | low | GHSA-9jrq-w75r-8gcw | 8.3.3 | — |
| vite | 5.0.0 | low | GHSA-c24v-8rfc-w8vw | 2.9.17 | — |
| vite | 5.0.0 | low | GHSA-c27g-q93r-2cwf | 2.9.0 | — |
| vite | 5.0.0 | low | GHSA-fx2h-pf6j-xcff | 8.0.16 | — |
| vite | 5.0.0 | low | GHSA-g4jq-h2w9-997c | 7.1.5 | — |
| vite | 5.0.0 | low | GHSA-jqfw-vq24-v9c3 | 7.1.5 | — |
| vite | 5.0.0 | low | GHSA-r825-w8mm-5pxw | 2.14.2 | — |
| vite | 5.0.0 | low | GHSA-rq7h-c2jc-7f22 | 8.3.3 | — |
| vite | 5.0.0 | low | GHSA-v6wh-96g9-6wx3 | 2.14.1 | — |
| vite | 5.0.0 | low | GHSA-vg6x-rcgg-rjx6 | 6.0.9 | — |
| vite | 5.0.0 | low | GHSA-x574-m823-4x7w | 6.2.3 | — |
| vite | 5.0.0 | low | GHSA-xcj6-pq6g-qj4x | 6.2.5 | — |

#### `tests/fixtures/fake-repo/Cargo.toml` — tokio 1.0.0 (9)

| Package | Installed | Severity | Advisory | Fixed (scanner) | Fixed (branch-correct) |
|---|---|---|---|---|---|
| tokio | 1.0.0 | low | GHSA-2grh-hm3w-w7hv | 1.8.1 | — |
| tokio | 1.0.0 | medium | GHSA-4q83-7cq4-p6wg | 1.24.2 | — |
| tokio | 1.0.0 | low | GHSA-fg7r-2g4j-5cgr | 1.8.4 | — |
| tokio | 1.0.0 | low | GHSA-rr8g-9fpq-6wmg | 1.44.2 | — |
| tokio | 1.0.0 | medium | RUSTSEC-2021-0072 | 1.5.1 | — |
| tokio | 1.0.0 | medium | RUSTSEC-2021-0124 | 1.8.4 | — |
| tokio | 1.0.0 | medium | RUSTSEC-2023-0005 | 1.18.5 | — |
| tokio | 1.0.0 | medium | RUSTSEC-2025-0023 | 1.38.2 | — |
| tokio | 1.0.0 | medium | RUSTSEC-2026-0386 | 1.51.6 | — |

#### `tests/fixtures/fake-repo-tier2/composer.lock` — laravel/framework v10.34.2 (7)

| Package | Installed | Severity | Advisory | Fixed (scanner) | Fixed (branch-correct) |
|---|---|---|---|---|---|
| laravel/framework | v10.34.2 | low | GHSA-5vg9-5847-vvmq | 13.10.0 | 12.60.0 |
| laravel/framework | v10.34.2 | low | GHSA-63hm-g96r-2m2q | 12.71.0 | 12.71.0 |
| laravel/framework | v10.34.2 | low | GHSA-78fx-h6xr-vch4 | 12.1.1 | 10.48.29 |
| laravel/framework | v10.34.2 | low | GHSA-crmm-hgp2-wgrp | 13.12.0 | 12.61.1 |
| laravel/framework | v10.34.2 | low | GHSA-f9x3-7vq9-cph6 | 13.27.0 | 10.50.4 |
| laravel/framework | v10.34.2 | low | GHSA-gv7v-rgg6-548h | 6.20.45 | 10.48.23 |
| laravel/framework | v10.34.2 | low | GHSA-jh5r-qr3c-85q8 | 12.69.0 | 12.69.0 |

Laravel note (Phase 13, still true): highest 10.x fix is 10.50.4; 4 of
7 advisories are only fixed in 12.x (max 12.71.0, major jump). Kept to
preserve the `Laravel lockfile v10.34.2 wins over ^10.0` behaviour test.

#### `tests/fixtures/fake-repo-tier2/pom.xml` — spring-core 6.1.2 (3)

| Package | Installed | Severity | Advisory | Fixed (scanner) | Fixed (branch-correct) |
|---|---|---|---|---|---|
| org.springframework:spring-core | 6.1.2 | low | GHSA-659m-px2c-25wj | 7.0.8 | NO FIX in 6.1.x line |
| org.springframework:spring-core | 6.1.2 | low | GHSA-jmp9-x22r-554x | 6.2.11 | NO FIX in 6.1.x line |
| org.springframework:spring-core | 6.1.2 | low | GHSA-r4q3-7g4q-x89m | 6.1.3 | 6.1.3 |

spring-core note (Phase 13, still true): 2 of 3 have no fix in the
6.1.x line (ranges end `last_affected: 6.1.21` / `6.1.22`); a future fix
needs 6.2.11/6.2.19 or 7.0.8. Highest 6.1.x fix is 6.1.3. Kept: the
only vulnerable Java package; preserves the `${spring.version}` test.

#### `tests/fixtures/fake-repo/requirements.txt` — Flask 3.0.0 (2)

| Package | Installed | Severity | Advisory | Fixed (scanner) | Fixed (branch-correct) |
|---|---|---|---|---|---|
| Flask | 3.0.0 | low | GHSA-68rp-wp8r-4726 | 3.1.3 | — |
| Flask | 3.0.0 | low | PYSEC-2026-2151 | 3.1.3 | — |

#### `tests/fixtures/fake-repo-tier2/Gemfile.lock` — rails 7.1.3 (1)

| Package | Installed | Severity | Advisory | Fixed (scanner) | Fixed (branch-correct) |
|---|---|---|---|---|---|
| rails | 7.1.3 | low | GHSA-9822-6m93-xqf4 | 7.0.8.1 | 7.1.3.1 |

Rails note (Phase 13, still true): scanner's 7.0.8.1 is the 7.0-branch
fix; the 7.1-branch fix is 7.1.3.1. Kept to preserve the `Rails lockfile
7.1.3 wins over Gemfile range` behaviour test.

### 1c. What is NOT in the list (verified clean in this scan)

- Real deps: `diff` 8.0.4, `zod` 4.6.7 — 0 advisories.
- Phase 13 upgrades: Django 5.2.17, next 15.5.29, fiber v2.52.14,
  sinatra 4.2.0, puma 7.2.1, phpunit 10.5.62 — 0 advisories each.
- `org.example:unresolvable` (`pom.xml`, version `${no.such.property}`)
  stays version-null by design and is never OSV-queried — no advisory,
  not a vuln, counted under §4 instead.
- No critical or high vulnerabilities remain anywhere in the repo.

## 2. Posture — all 15

Weights: critical 15 / high 10 / medium 5 / low 2 / info 0. Deduction:
5 high x 10 + 6 medium x 5 + 2 low x 2 + 2 info x 0 = 50 + 30 + 4 + 0
= **84**. The scanner's posture items carry no line numbers, so the
exact line was located by reading the flagged file (remote state == local
state for all fixture files; verified in §0).

| # | Check (id) | Severity | Points | File : line / config | Real gap or fixture-driven? |
|---|---|---|---|---|---|
| 1 | `.env file committed` (`env-committed`) | high | 10 | `tests/fixtures/fake-repo/.env:1` — committed fixture env file (`# FAKE fixture only — invented values`) | Fixture-driven. The file is deliberate detector bait; its values are invented. A real repo would not commit it. |
| 2 | `Possible secret passed as a Docker build argument` (`infra-possible-secret-passed-as-a-docker-build-argument`) | high | 10 | `tests/fixtures/fake-repo-tier3/Dockerfile:13` — `ARG API_TOKEN` | Fixture-driven (Tier 3 Dockerfile fixture). |
| 3 | `Kubernetes pod uses the host network` (`infra-kubernetes-pod-uses-the-host-network`) | high | 10 | `tests/fixtures/fake-repo-tier3/k8s/deployment.yaml:10` — `hostNetwork: true` | Fixture-driven (Tier 3 K8s fixture). |
| 4 | `Kubernetes container runs privileged` (`infra-kubernetes-container-runs-privileged`) | high | 10 | `tests/fixtures/fake-repo-tier3/k8s/deployment.yaml:15` — `privileged: true` | Fixture-driven (Tier 3 K8s fixture). |
| 5 | `Kubernetes container runs as root (UID 0)` (`infra-kubernetes-container-runs-as-root-uid-0-`) | high | 10 | `tests/fixtures/fake-repo-tier3/k8s/deployment.yaml:16` — `runAsUser: 0` | Fixture-driven (Tier 3 K8s fixture). |
| 6 | `Vite dev server bound to 0.0.0.0` (`vite-vite-dev-server-bound-to-0-0-0-0`) | medium | 5 | `tests/fixtures/fake-repo/vite.config.ts:6` — `server: { host: "0.0.0.0", port: 5173 }` | Fixture-driven (Tier 1 vite fixture config). |
| 7 | `Docker base image is not pinned to a version` (`infra-docker-base-image-is-not-pinned-to-a-version`) | medium | 5 | `tests/fixtures/fake-repo-tier3/Dockerfile:10` — `FROM node:latest` (line 3, `FROM node:20-alpine AS build`, is pinned and not flagged) | Fixture-driven (Tier 3 Dockerfile fixture). |
| 8 | `Dockerfile runs as root` (`infra-dockerfile-runs-as-root`) | medium | 5 | `tests/fixtures/fake-repo-tier3/Dockerfile:14` — `USER root` | Fixture-driven (Tier 3 Dockerfile fixture). |
| 9 | `Dockerfile downloads a file with ADD` (`infra-dockerfile-downloads-a-file-with-add`) | medium | 5 | `tests/fixtures/fake-repo-tier3/Dockerfile:15` — `ADD https://example.com/releases/fake-app.tar.gz …` | Fixture-driven (Tier 3 Dockerfile fixture). |
| 10 | `Kubernetes container image is not pinned to a version` (`infra-kubernetes-container-image-is-not-pinned-to-a-version`) | medium | 5 | `tests/fixtures/fake-repo-tier3/k8s/deployment.yaml:13` — `image: myapp:latest` | Fixture-driven (Tier 3 K8s fixture). |
| 11 | `Terraform provider random has no version constraint` (`infra-terraform-provider-random-has-no-version-constraint`) | medium | 5 | `tests/fixtures/fake-repo-tier3/main.tf:12-13` — `random = { source = "hashicorp/random" }` with no version (the `aws` provider at line 10 has `version = "5.0.0"` and is not flagged) | Fixture-driven (Tier 3 Terraform fixture). |
| 12 | `No SECURITY.md` (`no-security-md`) | low | 2 | Repo root — no `SECURITY.md` on the remote | **Real gap in the repo itself** — but see §0: the local working copy already contains a real 76-line `SECURITY.md` not yet on the remote. Clears on next push of the local tree. |
| 13 | `No Dependabot config` (`no-dependabot`) | low | 2 | `.github/` — no `dependabot.yml` on the remote | **Real gap in the repo itself** — but see §0: the local working copy already contains a real 12-line `.github/dependabot.yml` not yet on the remote. Clears on next push of the local tree. |
| 14 | `Vite plugins in use` (`vite-vite-plugins-in-use`) | info | 0 | `tests/fixtures/fake-repo/vite.config.ts:2,5` — imports `vite`, `@vitejs/plugin-react` | Fixture-driven (Tier 1 vite fixture config). Informational only. |
| 15 | `VITE_ variables are public by design` (`vite-vite-variables-are-public-by-design`) | info | 0 | `tests/fixtures/fake-repo/vite.config.ts:8` — references `VITE_API_URL` | Fixture-driven (Tier 1 vite fixture config). Informational only. |

Posture split: **13 of 15 are fixture-driven** (11 Tier 3 infra
fixture findings + the committed `.env` fixture + the 3 Vite fixture
items — 9 + 1 + 3 = 13; the 2 info items deduct 0). **2 of 15 are real
repo gaps** (#12, #13, 4 points total) and both already exist as real
files in the local working copy (see §0).

Not flagged, for completeness: the unpinned `redis` image in
`tests/fixtures/fake-repo-tier3/docker-compose.yml:8` (`image: redis`,
no tag) produces an unpinned *framework* entry but no posture item
(see §4); the pinned `postgres:15` at line 4 is not flagged.

## 3. Secrets — the 2 uncertain findings

34 secrets total: 32 likely-test-key (16 high, 16 medium — full-weight
value 368 points, weight ×0), 2 uncertain (both medium — full-weight
value 16 points, weight ×0.5 → **8**), 0 likely-genuine-leak.
17 at HEAD, 17 in history. The 32 test-key findings are listed compactly
in §3c; the 2 uncertain ones are detailed here. No secret value is
shown — fragments only, as the scanner produces them.

### 3a. Uncertain #1 — `scripts/test-scanner.ts:104` (HEAD)

- Detector type: `hardcoded-password`, severity medium, confidence
  medium. Fragment (redacted): `api_…}"`.
- The line is a test fixture: `api_key = "<fake value>"; api_key =
  "<fake value>";` (value assembled from test placeholders, not a real
  credential — the line lives in the scanner's own test file).
- Triage signals: `test-path:test-scanner.ts`, `filename-test:test`,
  `content-test:test`, `usage-referenced`.
- Why uncertain, not test-key: the Phase 10 points alone (+4 test path,
  +2 filename token, +2 content phrase = +8) would make it
  likely-test-key — but Phase 11 usage analysis found the identifier
  `api_key` referenced from **non-test** files, and the feed-back rule
  (likely-test-key + non-test reference → at minimum uncertain) applies:
  - `GITSECURE.md:1294` — prose in the Phase 11.1 write-up naming the
    identifier (`api_key = "FAKEPW"` in the incident description).
  - `GITSECURE.md:1301` — same write-up, second mention.
  - `README.md:1228` — same Phase 11.1 write-up, condensed.
  - Plus 13 test-only references in `scripts/test-usage-phase11.ts`
    (lines 333, 335, 336, 344, 346, 367, 374–377), which do not count
    as "in use" but are recorded.
- Why not genuine-leak: the upgrade rule needs a referencing file in a
  production-ish path (`src/`, `lib/`, `app/`, `config/`, `deploy/`,
  `scripts/`, repo-root config) AND a credential detector type. The
  three non-test references are all in **docs** (`.md` prose), not
  production code — so it stops at uncertain. Note the irony: the three
  references exist only because the docs *describe this exact false
  flip* (Phase 11.1: `api_key` named in `usage.ts`'s own doc comments
  was counted as a production reference; the fix strips comments
  before matching). The docs mention the identifier; they do not use
  the value.
- What would settle it: (a) a human confirms the value is a test
  placeholder (it is — assembled from `__SECRET_n__`-style test
  placeholders in the same file) and the triage rule learns that a
  reference from **docs/prose** is not usage the way a reference from
  code is — i.e. treat `.md` (and other prose) references as
  test-only/docs-only, not as non-test code references; or (b) the
  Phase 11.1 write-up stops quoting the identifier verbatim (rename it
  in the docs), which removes all three non-test references and the
  finding falls back to likely-test-key on its test signals alone.
  Either change moves it to test-key (weight ×0, −4 points).

### 3b. Uncertain #2 — `scripts/test-usage-phase11.ts:333` (HEAD)

- Detector type: `hardcoded-password`, severity medium, confidence
  medium. Fragment (redacted): `api_…_"`.
- The line is the Phase 11.1 live-regression test fixture itself: the
  `commentLine` used to prove a comment mention is not usage
  (`api_key = "__SECRET_9__"; …`).
- Triage signals: identical to #1 — `test-path:test-usage-phase11.ts`,
  `filename-test:test`, `content-test:test`, `usage-referenced`.
- Why uncertain: the **same three non-test doc references**
  (`GITSECURE.md:1294`, `GITSECURE.md:1301`, `README.md:1228`) plus 1
  test-only reference (`scripts/test-scanner.ts:104` — the other
  uncertain line). Same feed-back rule, same docs-only reason it stops
  short of genuine-leak.
- What would settle it: the same two options as #1 — docs/prose
  references excluded from the non-test bucket, or the identifier no
  longer quoted verbatim in the Phase 11.1 docs. Either moves it to
  test-key (−4 points).

Settling **both** uncertain findings would move secretsDeduction 8 → 0
and the total 302 → 294. The score stays 0/F either way (vulns +
posture alone floor it).

### 3c. The 32 likely-test-key findings (compact list)

All are known-fake fixture values (test-assembled placeholders, the
official AWS example key in an old README commit, the committed `.env`
fixture). HEAD 15, history 17.

| File : line | Type | Severity | Commit |
|---|---|---|---|
| `scripts/test-public-full.ts:128` | database-url | high | HEAD |
| `scripts/test-scanner.ts:33` | database-url | high | HEAD |
| `scripts/test-scanner.ts:107` | database-url | high | HEAD |
| `scripts/test-scanner.ts:84` (x2 findings) | hardcoded-password | medium | HEAD |
| `scripts/test-scanner.ts:93` (x2 findings) | hardcoded-password | medium | HEAD |
| `scripts/test-triage-phase10.ts:119` | hardcoded-password | medium | HEAD |
| `scripts/test-usage-phase11.ts:279` | database-url | high | HEAD |
| `scripts/test-usage-phase11.ts:280` | database-url | high | HEAD |
| `scripts/test-usage-phase11.ts:285` | database-url | high | HEAD |
| `scripts/test-usage-phase11.ts:288` | database-url | high | HEAD |
| `scripts/test-usage-phase11.ts:305` | hardcoded-password | medium | HEAD |
| `tests/fixtures/fake-repo/.env:1` | env-file | high | HEAD |
| `tests/fixtures/fake-repo/config.js:13` | hardcoded-password | medium | HEAD |
| `scripts/test-usage-phase11.ts:333` | hardcoded-password | medium | d030692 |
| `scripts/test-usage-phase11.ts:275` | database-url | high | 517bbd8 |
| `scripts/test-usage-phase11.ts:276` | database-url | high | 517bbd8 |
| `scripts/test-usage-phase11.ts:281` | database-url | high | 517bbd8 |
| `scripts/test-usage-phase11.ts:284` | database-url | high | 517bbd8 |
| `scripts/test-usage-phase11.ts:301` | hardcoded-password | medium | 517bbd8 |
| `scripts/test-triage-phase10.ts:118` | hardcoded-password | medium | b4ca165 |
| `scripts/test-scanner.ts:107` | database-url | high | 8f4ffa4 |
| `scripts/test-scanner.ts:84` (x2 findings) | hardcoded-password | medium | 8f4ffa4 |
| `scripts/test-scanner.ts:93` (x2 findings) | hardcoded-password | medium | 8f4ffa4 |
| `scripts/test-scanner.ts:104` | hardcoded-password | medium | 8f4ffa4 |
| `scripts/test-public-full.ts:88` | database-url | high | 836180c |
| `scripts/test-scanner.ts:29` | database-url | high | 0909728 |
| `tests/fixtures/fake-repo/config.js:13` | hardcoded-password | medium | 0909728 |
| `README.md:96` | aws-access-key | high | 92c3a49 |

Dead ends (usage `deadEnd: true`, i.e. an identifier was found and
nothing references it): `tests/fixtures/fake-repo/.env:1` (HEAD) and
the two history `api_key` lines (§6 — those two are dead ends only
because the history usage search sees an empty corpus; see §6).

## 4. Unpinned — 4 points

Rule (`src/lib/score.ts`): `unpinnedDeduction = min(unpinnedCount × 2,
10)`, where `unpinnedCount` is the number of **direct dependencies with
a null version**. 2 × 2 = **4**.

| # | Direct dependency (null version) | Ecosystem | Where |
|---|---|---|---|
| 1 | `Microsoft.NET.Sdk.Web` | dotnet | `tests/fixtures/fake-repo-tier2/app.csproj` — the SDK itself, recorded version-null (a TargetFramework/SDK is not a package version; the scanner never guesses one) |
| 2 | `org.example:unresolvable` | java | `tests/fixtures/fake-repo-tier2/pom.xml` — version is `${no.such.property}`, unresolvable by design (fixture proving unresolvable versions stay null); never OSV-queried |

Both are fixtures, not real-repo deps. There is no unpinned real
dependency: the root `package.json` pins every direct dep exactly, and
`package-lock.json` carries the pinned versions.

Not scored (do not confuse with the 4 points above):

- **3 unpinned frameworks** (version-null, `unpinned: true` in the
  frameworks list — the scorer does not count frameworks, only direct
  dependencies; Phase 12 established this split):
  - `Docker image myapp` — `tests/fixtures/fake-repo-tier3/k8s/deployment.yaml` (`image: myapp:latest`)
  - `Docker image redis` — `tests/fixtures/fake-repo-tier3/docker-compose.yml:8` (`image: redis`, no tag)
  - `Terraform provider random` — `tests/fixtures/fake-repo-tier3/main.tf` (no version constraint)
  - Two of these three also appear as posture items in §2 (#10, #11);
    `redis` has no posture item, only the framework flag.
- `express: "*"` in `tests/fixtures/fake-repo/package.json` does **not**
  surface as an unpinned dep: the name+ecosystem dedupe keeps the
  pinned `express 5.3.0` from the root `package-lock.json` (first pinned
  wins), so no `express` entry with a null/`*` version exists in the
  report.

## 5. Per-component deduction table — sums to 302

Weights: secrets critical 25 / high 15 / medium 8 / low 3; vulns
critical 15 / high 10 / medium 5 / low 2; posture critical 15 / high 10
/ medium 5 / low 2 / info 0; unpinned min(n×2, 10); score =
max(0, 100 − total).

| Component | Detail | Deduction |
|---|---|---|
| Secrets — likely-test-key | 32 findings (16 high × 15 + 16 medium × 8 = 368 full-weight) × 0 | 0 |
| Secrets — uncertain | 2 findings (2 medium × 8 = 16 full-weight) × 0.5, rounded at the total | 8 |
| Secrets — likely-genuine-leak | 0 findings | 0 |
| Secrets — no triage | 0 findings | 0 |
| **Secrets subtotal** | | **8** |
| Vulnerabilities | 20 medium × 5 + 53 low × 2 + 0 critical + 0 high | **206** |
| Posture | 5 high × 10 + 6 medium × 5 + 2 low × 2 + 2 info × 0 | **84** |
| Unpinned | 2 direct deps × 2 | **4** |
| **Total deductions** | 8 + 206 + 84 + 4 | **302** |
| **Score** | 100 − 302, floored at 0 | **0, grade F** |
| Would-be score (Phase 10 full-weight rule) | 100 − (384 + 206 + 84 + 4) = 100 − 678, floored at 0 | **0, grade F** |

Cross-checks: secrets full-weight value 384 = 368 (test-key) + 16
(uncertain); wouldBeScore 0 matches the report's `scoreDetail`. The
score is 0/F under both the current rule and the old rule — the
vulnerabilities (206) + posture (84) + unpinned (4) alone total 294,
so even with secrets at 0 the score floors at 0.

## 6. Discrepancies found while measuring (for the fix worker)

### 6a. History usage search sees an empty corpus — triage of history findings is wrong

**Observation.** All 17 history findings have
`referencedByTotal: 0` / `referencedByTestsTotal: 0`, while the 17 HEAD
findings find references normally. In particular the history copies of
the two uncertain `api_key` lines triage **likely-test-key with
`usage-dead-end`** (`scripts/test-scanner.ts:104 @ 8f4ffa4`,
`scripts/test-usage-phase11.ts:333 @ d030692`), while their HEAD twins
triage **uncertain** on the strength of the three doc references (§3).

**Reproduction (done this run, read-only).** Calling
`scanHistoryViaGit("Squ1zM0", "GitSecure", "main", "858bd7aa…")`
standalone returns the same 17 findings with 0 references and the same
2 dead ends. Calling `computeUsageForFindings` directly on the history
finding with a corpus built from the working copy (which matches remote
HEAD) finds the 3 doc references + 13 test references — the usage code
itself is correct.

**Root cause (verified).** `readHeadUsageCorpus` in `src/lib/history.ts`
builds its corpus with `git.walk({ trees: [git.TREE({ ref: branch })]
})` over the `noCheckout: true` isomorphic-git clone. Replicating those
exact calls in isolation: the walk visits **1 entry (the root) and 0
blobs** — the tree walk does not descend in a no-checkout clone
(`resolveRef("main")` and `git.log` work fine in the same clone, so the
clone itself is good). The corpus is therefore an **empty Map (non-
null)**, so `computeUsageForFindings` searches nothing, every history
finding gets zero references, and any history finding with an identifier
is labelled a dead end. The `corpus === null` fallback (triage without
usage) never triggers because the map exists — it is just empty.

**Impact on this inventory's numbers.** If the corpus worked, the two
history `api_key` copies would almost certainly triage uncertain like
their HEAD twins (same identifier, same doc references): secretsHalfWeight
2 → 4, secretsDeduction 8 → 16, total 302 → 310. Score stays 0/F.
More importantly, the bug is not confined to these two lines: **no**
history finding can ever be reported as in-use today, so a genuinely
referenced history secret would be mis-triaged as a dead-end test key.
This is a scanner bug to fix, not a scoring decision — it changes the
triage evidence, not the weights.

**Note for the fix worker:** the fix belongs in `readHeadUsageCorpus` /
the git-path history walk (make the HEAD corpus read actually return
files — e.g. walk the commit tree object instead of the branch ref, or
read blobs via `git.readTree` / the log's tree OID). Do not "fix" it by
re-labelling the two findings by hand.

### 6b. The two uncertain findings are an artifact of the docs quoting the identifier

See §3a/§3b: the only non-test references keeping the two `api_key`
fixtures uncertain are prose mentions in `GITSECURE.md` and `README.md`
describing the Phase 11.1 false flip. Whether the fix is "docs are not
usage" (exclude `.md`/prose references from the non-test bucket) or
"stop quoting the identifier verbatim in the docs" is a decision for
the fix worker — either way the finding becomes test-key. This is
separate from §6a: even with a working history corpus, the HEAD copies
stay uncertain until one of those two changes lands.

### 6c. Local tree already contains the SECURITY.md / Dependabot fix

See §0/§2: pushing the current local working copy as-is clears posture
items #12 and #13 (4 points, total 302 → 298, score still 0/F). If the
fix worker's baseline is the local tree rather than the remote, those
two items will already be gone — verify by re-scanning after the push,
do not assume.
