# Phase 13 — vulnerability inventory (measured, not assumed)

Measured 2026-11-26 by running the real scanner locally against the live
remote `Squ1zM0/GitSecure` (`scanRepo`, no auth). Full report saved as
`test-results/gitsecure-full-phase13-before.json`.

- Score: **0/F** — scoreDetail: {"score": 0, "grade": "F", "secretsDeduction": 8, "secretsFullWeight": 0, "secretsHalfWeight": 2, "secretsExcluded": 32, "wouldBeScore": 0, "vulnDeduction": 547, "postureDeduction": 84, "unpinnedDeduction": 4}
- Counts: secrets 34 (32 likely-test-key, 2 uncertain, 0 genuine), **vulnerabilities 197**, posture 15, frameworks 29, dependencies 233, files scanned 81, history commits 28.
- Vuln deduction (old rule): 547 points — 51 medium x 5 + 146 low x 2 = 547. 0 critical, 0 high. Severity split overall: low 146, medium 51.

## Vulns per source file

| File | Vulns | Packages |
|---|---:|---|
| `tests/fixtures/fake-repo/requirements.txt` | 98 | Django 4.2.0, Flask 3.0.0 |
| `tests/fixtures/fake-repo-tier2/go.mod` | 47 | github.com/gofiber/fiber/v2 v2.49.0, github.com/labstack/echo/v4 v4.11.1 |
| `tests/fixtures/fake-repo/package.json` | 23 | vite 5.0.0 |
| `tests/fixtures/fake-repo/Cargo.toml` | 9 | tokio 1.0.0 |
| `tests/fixtures/fake-repo-tier2/composer.lock` | 8 | laravel/framework v10.34.2, phpunit/phpunit 10.5.0 |
| `tests/fixtures/fake-repo-tier2/Gemfile.lock` | 5 | puma 6.4.0, rails 7.1.3 |
| `tests/fixtures/fake-repo-tier2/pom.xml` | 3 | org.springframework:spring-core 6.1.2 |
| `package-lock.json` | 2 | diff 8.0.2, zod 4.3.5 |
| `tests/fixtures/fake-repo-tier2/Gemfile` | 2 | sinatra 3.0.5 |

Tier 2 fixture files contribute **65** of the 197. The other 132 are out of
Phase 13 scope (Tier 1 fixtures in `tests/fixtures/fake-repo/` + 2 in the
repo's own `package-lock.json`) and were left untouched:

| File | Vulns | Note |
|---|---:|---|
| `tests/fixtures/fake-repo/requirements.txt` | 98 | Tier 1 Python fixture (Django 4.2.0 x96, Flask 3.0.0 x2) — out of scope |
| `tests/fixtures/fake-repo/package.json` | 23 | Tier 1 fixture (vite 5.0.0) — out of scope |
| `tests/fixtures/fake-repo/Cargo.toml` | 9 | Tier 1 fixture (tokio 1.0.0) — out of scope |
| `package-lock.json` | 2 | Real repo deps (diff 8.0.2, zod 4.3.5) — NOT fixtures, out of scope |

## Full grouped list (all 197)

Grouped by source file, then package. `fixed` is the OSV fixed version as
reported by the scanner (first `fixed` event across all advisory ranges —
see the note at the end: for multi-branch advisories that can be a fix from
a different release line than the installed version. Branch-correct fixed
versions for all Tier 2 advisories are in the table below this list).

### `package-lock.json`

| Package | Installed | Severity | Advisory | Fixed (scanner) |
|---|---|---|---|---|
| diff | 8.0.2 | low | GHSA-73rr-hh4g-fpgx | 8.0.3 |
| zod | 4.3.5 | low | GHSA-mrhx-c7xc-m3w5 | 4.6.6 |

### `tests/fixtures/fake-repo-tier2/Gemfile`

| Package | Installed | Severity | Advisory | Fixed (scanner) |
|---|---|---|---|---|
| sinatra | 3.0.5 | low | GHSA-hxx2-7vcw-mqr3 | 4.1.0 |
| sinatra | 3.0.5 | low | GHSA-mr3q-g2mv-mr4q | 4.2.0 |

### `tests/fixtures/fake-repo-tier2/Gemfile.lock`

| Package | Installed | Severity | Advisory | Fixed (scanner) |
|---|---|---|---|---|
| puma | 6.4.0 | low | GHSA-2vqw-3mp8-cgmx | 8.0.2 |
| puma | 6.4.0 | low | GHSA-9hf4-67fc-4vf4 | 5.6.9 |
| puma | 6.4.0 | low | GHSA-c2f4-cvqm-65w2 | 6.4.2 |
| puma | 6.4.0 | low | GHSA-qpgp-93vx-g8v8 | 8.0.2 |
| rails | 7.1.3 | low | GHSA-9822-6m93-xqf4 | 7.0.8.1 |

### `tests/fixtures/fake-repo-tier2/composer.lock`

| Package | Installed | Severity | Advisory | Fixed (scanner) |
|---|---|---|---|---|
| laravel/framework | v10.34.2 | low | GHSA-5vg9-5847-vvmq | 13.10.0 |
| laravel/framework | v10.34.2 | low | GHSA-63hm-g96r-2m2q | 12.71.0 |
| laravel/framework | v10.34.2 | low | GHSA-78fx-h6xr-vch4 | 12.1.1 |
| laravel/framework | v10.34.2 | low | GHSA-crmm-hgp2-wgrp | 13.12.0 |
| laravel/framework | v10.34.2 | low | GHSA-f9x3-7vq9-cph6 | 13.27.0 |
| laravel/framework | v10.34.2 | low | GHSA-gv7v-rgg6-548h | 6.20.45 |
| laravel/framework | v10.34.2 | low | GHSA-jh5r-qr3c-85q8 | 12.69.0 |
| phpunit/phpunit | 10.5.0 | low | GHSA-vvj3-c3rp-c85p | 8.5.52 |

### `tests/fixtures/fake-repo-tier2/go.mod`

| Package | Installed | Severity | Advisory | Fixed (scanner) |
|---|---|---|---|---|
| github.com/gofiber/fiber/v2 | v2.49.0 | low | GHSA-3q5p-3558-364f | 2.49.2 |
| github.com/gofiber/fiber/v2 | v2.49.0 | low | GHSA-68rr-p4fp-j59v | 2.52.11 |
| github.com/gofiber/fiber/v2 | v2.49.0 | low | GHSA-94w9-97p3-p368 | 2.50.0 |
| github.com/gofiber/fiber/v2 | v2.49.0 | low | GHSA-98j2-3j3p-fw2v | 2.52.5 |
| github.com/gofiber/fiber/v2 | v2.49.0 | low | GHSA-fmg4-x8pw-hjhg | 2.52.1 |
| github.com/gofiber/fiber/v2 | v2.49.0 | low | GHSA-gcfq-8gqf-4876 | 3.3.0 |
| github.com/gofiber/fiber/v2 | v2.49.0 | low | GHSA-mrq8-rjmw-wpq3 | 2.52.12 |
| github.com/gofiber/fiber/v2 | v2.49.0 | low | GHSA-mv73-f69x-444p | 2.50.0 |
| github.com/gofiber/fiber/v2 | v2.49.0 | low | GHSA-qjv7-627w-8qjv | 3.2.0 |
| github.com/gofiber/fiber/v2 | v2.49.0 | low | GHSA-qx2q-88mx-vhg7 | 2.52.9 |
| github.com/gofiber/fiber/v2 | v2.49.0 | medium | GO-2023-2052 | 2.49.2-0.20230906112033-b8c9ede6efa2 |
| github.com/gofiber/fiber/v2 | v2.49.0 | medium | GO-2023-2115 | 2.50.0 |
| github.com/gofiber/fiber/v2 | v2.49.0 | medium | GO-2023-2116 | 2.50.0 |
| github.com/gofiber/fiber/v2 | v2.49.0 | medium | GO-2024-2574 | 2.52.1 |
| github.com/gofiber/fiber/v2 | v2.49.0 | medium | GO-2024-2959 | 2.52.5 |
| github.com/gofiber/fiber/v2 | v2.49.0 | medium | GO-2025-3845 | 2.52.9 |
| github.com/gofiber/fiber/v2 | v2.49.0 | medium | GO-2026-4471 | 2.52.11 |
| github.com/gofiber/fiber/v2 | v2.49.0 | medium | GO-2026-4543 | 2.52.12 |
| github.com/gofiber/fiber/v2 | v2.49.0 | medium | GO-2026-5585 | 2.52.13 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-23wf-92cp-8pcj | 5.1.1 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-246p-cpwv-v3jq | 5.1.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-2ffq-g2xg-c22p | 5.4.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-375p-5qhx-8wq4 | 5.4.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-3pmx-cf9f-34xr | 5.4.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-99jh-6h7p-pp36 | 5.4.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-cxf3-9h37-7rr8 | 4.16.1 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-f48p-c9v4-h7xv | 4.16.1 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-h7wr-284f-5qvc | 4.16.1 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-h9g5-28mm-hx3g | 5.4.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-r7w9-592q-9vg4 | 5.4.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-v753-g4cw-jm48 | 5.4.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-vfp3-v2gw-7wfq | 5.2.0 |
| github.com/labstack/echo/v4 | v4.11.1 | low | GHSA-xwq5-6cqp-vx96 | 5.2.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6293 | 4.15.3 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6839 | 4.16.1 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6840 | 4.16.1 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6842 | 4.16.1 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6872 | 4.16.3 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6873 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6875 | 4.16.3 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6876 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6877 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6878 | 4.15.2 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6879 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6881 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6883 | 4.16.0 |
| github.com/labstack/echo/v4 | v4.11.1 | medium | GO-2026-6885 | 4.15.3 |

### `tests/fixtures/fake-repo-tier2/pom.xml`

| Package | Installed | Severity | Advisory | Fixed (scanner) |
|---|---|---|---|---|
| org.springframework:spring-core | 6.1.2 | low | GHSA-659m-px2c-25wj | 7.0.8 |
| org.springframework:spring-core | 6.1.2 | low | GHSA-jmp9-x22r-554x | 6.2.11 |
| org.springframework:spring-core | 6.1.2 | low | GHSA-r4q3-7g4q-x89m | 6.1.3 |

### `tests/fixtures/fake-repo/Cargo.toml`

| Package | Installed | Severity | Advisory | Fixed (scanner) |
|---|---|---|---|---|
| tokio | 1.0.0 | low | GHSA-2grh-hm3w-w7hv | 1.8.1 |
| tokio | 1.0.0 | medium | GHSA-4q83-7cq4-p6wg | 1.24.2 |
| tokio | 1.0.0 | low | GHSA-fg7r-2g4j-5cgr | 1.8.4 |
| tokio | 1.0.0 | low | GHSA-rr8g-9fpq-6wmg | 1.44.2 |
| tokio | 1.0.0 | medium | RUSTSEC-2021-0072 | 1.5.1 |
| tokio | 1.0.0 | medium | RUSTSEC-2021-0124 | 1.8.4 |
| tokio | 1.0.0 | medium | RUSTSEC-2023-0005 | 1.18.5 |
| tokio | 1.0.0 | medium | RUSTSEC-2025-0023 | 1.38.2 |
| tokio | 1.0.0 | medium | RUSTSEC-2026-0386 | 1.51.6 |

### `tests/fixtures/fake-repo/package.json`

| Package | Installed | Severity | Advisory | Fixed (scanner) |
|---|---|---|---|---|
| vite | 5.0.0 | low | GHSA-356w-63v5-8wf4 | 6.2.6 |
| vite | 5.0.0 | low | GHSA-4r4m-qw57-chr8 | 6.2.4 |
| vite | 5.0.0 | low | GHSA-4w7w-66w2-5vf9 | 8.0.5 |
| vite | 5.0.0 | low | GHSA-587h-7wmj-h5pm | 2.14.2 |
| vite | 5.0.0 | low | GHSA-64vr-g452-qvp3 | 5.4.6 |
| vite | 5.0.0 | low | GHSA-698v-4r3x-3vcv | 2.14.2 |
| vite | 5.0.0 | low | GHSA-859w-5945-r5v3 | 6.3.4 |
| vite | 5.0.0 | low | GHSA-8jhw-289h-jh2g | 2.9.18 |
| vite | 5.0.0 | low | GHSA-92r3-m2mg-pj97 | 4.4.12 |
| vite | 5.0.0 | low | GHSA-93m4-6634-74q7 | 7.1.11 |
| vite | 5.0.0 | low | GHSA-9cwx-2883-4wfx | 5.4.6 |
| vite | 5.0.0 | low | GHSA-9jrq-w75r-8gcw | 8.3.3 |
| vite | 5.0.0 | low | GHSA-c24v-8rfc-w8vw | 2.9.17 |
| vite | 5.0.0 | low | GHSA-c27g-q93r-2cwf | 2.9.0 |
| vite | 5.0.0 | low | GHSA-fx2h-pf6j-xcff | 8.0.16 |
| vite | 5.0.0 | low | GHSA-g4jq-h2w9-997c | 7.1.5 |
| vite | 5.0.0 | low | GHSA-jqfw-vq24-v9c3 | 7.1.5 |
| vite | 5.0.0 | low | GHSA-r825-w8mm-5pxw | 2.14.2 |
| vite | 5.0.0 | low | GHSA-rq7h-c2jc-7f22 | 8.3.3 |
| vite | 5.0.0 | low | GHSA-v6wh-96g9-6wx3 | 2.14.1 |
| vite | 5.0.0 | low | GHSA-vg6x-rcgg-rjx6 | 6.0.9 |
| vite | 5.0.0 | low | GHSA-x574-m823-4x7w | 6.2.3 |
| vite | 5.0.0 | low | GHSA-xcj6-pq6g-qj4x | 6.2.5 |

### `tests/fixtures/fake-repo/requirements.txt`

| Package | Installed | Severity | Advisory | Fixed (scanner) |
|---|---|---|---|---|
| Django | 4.2.0 | low | GHSA-2mcm-79hx-8fxw | 6.0.2 |
| Django | 4.2.0 | low | GHSA-33mw-q7rj-mjwj | 6.0.2 |
| Django | 4.2.0 | low | GHSA-3h9f-r86x-qvjx | 5.2.16 |
| Django | 4.2.0 | low | GHSA-4rrr-2h4v-f3j9 | 6.0.2 |
| Django | 4.2.0 | low | GHSA-5hgc-2vfp-mqvc | 5.1.1 |
| Django | 4.2.0 | low | GHSA-5mf9-h53q-7mhq | 6.0.4 |
| Django | 4.2.0 | low | GHSA-6426-9fv3-65x8 | 6.0.2 |
| Django | 4.2.0 | low | GHSA-6w2r-r2m5-xq5w | 4.2.24 |
| Django | 4.2.0 | low | GHSA-795c-9xpc-xw6g | 5.0.8 |
| Django | 4.2.0 | low | GHSA-7h4p-27mh-hmrw | 3.2.21 |
| Django | 4.2.0 | low | GHSA-7xr5-9hcq-chf9 | 5.2.2 |
| Django | 4.2.0 | low | GHSA-8498-2h75-472j | 5.1.4 |
| Django | 4.2.0 | low | GHSA-8cjm-8mp7-r2xf | 5.2.15 |
| Django | 4.2.0 | low | GHSA-8j24-cjrq-gr2m | 4.2.21 |
| Django | 4.2.0 | low | GHSA-8p8v-wh79-9r56 | 6.0.3 |
| Django | 4.2.0 | low | GHSA-8qcx-xf44-272x | 5.2.16 |
| Django | 4.2.0 | low | GHSA-923m-gv2p-w5qp | 5.2.15 |
| Django | 4.2.0 | low | GHSA-933h-hp56-hf7m | 6.0.4 |
| Django | 4.2.0 | low | GHSA-9jmf-237g-qf46 | 5.0.7 |
| Django | 4.2.0 | low | GHSA-crhf-3pfg-w68w | 5.2.16 |
| Django | 4.2.0 | low | GHSA-f6f8-9mx6-9mx2 | 5.0.7 |
| Django | 4.2.0 | low | GHSA-frmv-pr5f-9mcr | 5.2.8 |
| Django | 4.2.0 | low | GHSA-gvg8-93h5-g6qq | 6.0.2 |
| Django | 4.2.0 | low | GHSA-h7pc-vwp9-298g | 5.2.15 |
| Django | 4.2.0 | low | GHSA-h8gc-pgj2-vjm3 | 3.2.22 |
| Django | 4.2.0 | low | GHSA-hpr9-3m2g-3j9p | 4.2.25 |
| Django | 4.2.0 | low | GHSA-jh3w-4vvf-mjgr | 3.2.20 |
| Django | 4.2.0 | low | GHSA-jh75-99hh-qvx9 | 5.0.8 |
| Django | 4.2.0 | low | GHSA-m9g8-fxxm-xg86 | 5.0.10 |
| Django | 4.2.0 | low | GHSA-mjgh-79qc-68w3 | 6.0.3 |
| Django | 4.2.0 | low | GHSA-mmwr-2jhp-mc7j | 6.0.4 |
| Django | 4.2.0 | low | GHSA-mvfq-ggxm-9mc5 | 6.0.4 |
| Django | 4.2.0 | low | GHSA-mwm9-4648-f68q | 6.0.2 |
| Django | 4.2.0 | low | GHSA-p3fp-8748-vqfq | 4.2.20 |
| Django | 4.2.0 | low | GHSA-pv4p-cwwg-4rph | 5.0.8 |
| Django | 4.2.0 | low | GHSA-pwjp-ccjc-ghwg | 6.0.4 |
| Django | 4.2.0 | low | GHSA-q238-5cxm-5c9h | 5.2.17 |
| Django | 4.2.0 | low | GHSA-q95w-c7qg-hrff | 4.2.25 |
| Django | 4.2.0 | low | GHSA-qcgg-j2x8-h9g8 | 5.1.5 |
| Django | 4.2.0 | low | GHSA-qg2p-9jwr-mmqf | 4.2.14 |
| Django | 4.2.0 | low | GHSA-qmf9-6jqf-j8fq | 3.2.23 |
| Django | 4.2.0 | low | GHSA-qw25-v68c-qjf3 | 5.2.8 |
| Django | 4.2.0 | low | GHSA-r3xc-prgr-mg9p | 3.2.19 |
| Django | 4.2.0 | low | GHSA-r836-hh6v-rg5g | 5.0.8 |
| Django | 4.2.0 | low | GHSA-rqw2-ghq9-44m7 | 5.2.9 |
| Django | 4.2.0 | low | GHSA-rrqc-c2jx-6jgv | 5.1.1 |
| Django | 4.2.0 | low | GHSA-vm8q-m57g-pff3 | 3.2.25 |
| Django | 4.2.0 | low | GHSA-vrcr-9hj9-jcg6 | 5.2.9 |
| Django | 4.2.0 | low | GHSA-wvqv-fj8w-qmhm | 5.2.17 |
| Django | 4.2.0 | low | GHSA-x7q2-wr7g-xqmf | 5.0.7 |
| Django | 4.2.0 | low | GHSA-xxj9-f6rv-m3x4 | 3.2.24 |
| Django | 4.2.0 | medium | PYSEC-2023-100 | 4.2.3 |
| Django | 4.2.0 | medium | PYSEC-2023-222 | 3.2.23 |
| Django | 4.2.0 | medium | PYSEC-2023-225 | 3.2.21 |
| Django | 4.2.0 | medium | PYSEC-2023-226 | 3.2.22 |
| Django | 4.2.0 | medium | PYSEC-2023-61 | 3.2.19 |
| Django | 4.2.0 | medium | PYSEC-2024-102 | 5.1.1 |
| Django | 4.2.0 | medium | PYSEC-2024-156 | 5.1.4 |
| Django | 4.2.0 | medium | PYSEC-2024-157 | 5.1.4 |
| Django | 4.2.0 | medium | PYSEC-2024-28 | 3.2.24 |
| Django | 4.2.0 | medium | PYSEC-2024-47 | 3.2.25 |
| Django | 4.2.0 | medium | PYSEC-2024-56 | 4.2.14 |
| Django | 4.2.0 | medium | PYSEC-2024-57 | 5.0.7 |
| Django | 4.2.0 | medium | PYSEC-2024-58 | 5.0.7 |
| Django | 4.2.0 | medium | PYSEC-2024-59 | 5.0.7 |
| Django | 4.2.0 | medium | PYSEC-2024-67 | 5.0.8 |
| Django | 4.2.0 | medium | PYSEC-2024-68 | 5.0.8 |
| Django | 4.2.0 | medium | PYSEC-2024-69 | 5.0.8 |
| Django | 4.2.0 | medium | PYSEC-2024-70 | 5.0.8 |
| Django | 4.2.0 | medium | PYSEC-2025-1 | 5.1.5 |
| Django | 4.2.0 | low | PYSEC-2025-104 | 4.2.27 |
| Django | 4.2.0 | low | PYSEC-2025-105 | 4.2.24 |
| Django | 4.2.0 | low | PYSEC-2025-106 | 4.2.25 |
| Django | 4.2.0 | low | PYSEC-2025-107 | 4.2.26 |
| Django | 4.2.0 | low | PYSEC-2025-108 | 4.2.26 |
| Django | 4.2.0 | low | PYSEC-2025-109 | 4.2.27 |
| Django | 4.2.0 | medium | PYSEC-2025-13 | 5.1.7 |
| Django | 4.2.0 | medium | PYSEC-2025-37 | 4.2.21 |
| Django | 4.2.0 | medium | PYSEC-2025-47 | 5.2.2 |
| Django | 4.2.0 | low | PYSEC-2026-1296 | 4.2.25 |
| Django | 4.2.0 | low | PYSEC-2026-1297 | 4.2.16 |
| Django | 4.2.0 | low | PYSEC-2026-2448 | 4.2.29 |
| Django | 4.2.0 | low | PYSEC-2026-2449 | 4.2.29 |
| Django | 4.2.0 | low | PYSEC-2026-3717 | 5.2.17 |
| Django | 4.2.0 | low | PYSEC-2026-4035 | 5.2.17 |
| Django | 4.2.0 | low | PYSEC-2026-42 | 4.2.28 |
| Django | 4.2.0 | low | PYSEC-2026-43 | 4.2.28 |
| Django | 4.2.0 | low | PYSEC-2026-44 | 4.2.28 |
| Django | 4.2.0 | low | PYSEC-2026-45 | 4.2.28 |
| Django | 4.2.0 | low | PYSEC-2026-46 | 4.2.28 |
| Django | 4.2.0 | low | PYSEC-2026-47 | 4.2.28 |
| Django | 4.2.0 | low | PYSEC-2026-48 | 4.2.30 |
| Django | 4.2.0 | low | PYSEC-2026-49 | 4.2.30 |
| Django | 4.2.0 | low | PYSEC-2026-51 | 4.2.30 |
| Django | 4.2.0 | low | PYSEC-2026-52 | 4.2.30 |
| Django | 4.2.0 | low | PYSEC-2026-53 | 4.2.30 |
| Flask | 3.0.0 | low | GHSA-68rp-wp8r-4726 | 3.1.3 |
| Flask | 3.0.0 | low | PYSEC-2026-2151 | 3.1.3 |

## Tier 2 — branch-correct fixed versions (OSV range analysis)

The scanner's `fixedVersion` is the FIRST `fixed` event across all advisory
ranges, which for multi-branch advisories can name a fix from a different
release line than the installed version (e.g. rails 7.1.3 reported as fixed
in 7.0.8.1 — the 7.0-branch fix; the 7.1-branch fix is 7.1.3.1). Each advisory
below was re-checked against the OSV API (`GET /v1/vulns/{id}`) and the fixed
version shown is the one in the range that actually contains the installed
version. `NO FIX in installed branch` means that range ends in `last_affected`
with no fix — the release line is end-of-life for that flaw and only a newer
major/minor line carries the patch.

| Package | Installed | Advisory | Scanner fixed | Branch-correct fixed | Note |
|---|---|---|---|---|---|
| github.com/gofiber/fiber/v2 | v2.49.0 | GHSA-3q5p-3558-364f | 2.49.2 | 2.49.2 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GHSA-68rr-p4fp-j59v | 2.52.11 | 2.52.11 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GHSA-94w9-97p3-p368 | 2.50.0 | 2.50.0 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GHSA-98j2-3j3p-fw2v | 2.52.5 | 2.52.5 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GHSA-fmg4-x8pw-hjhg | 2.52.1 | 2.52.1 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GHSA-gcfq-8gqf-4876 | 3.3.0 | 2.52.14 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GHSA-mrq8-rjmw-wpq3 | 2.52.12 | 2.52.12 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GHSA-mv73-f69x-444p | 2.50.0 | 2.50.0 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GHSA-qjv7-627w-8qjv | 3.2.0 | 2.52.13 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GHSA-qx2q-88mx-vhg7 | 2.52.9 | 2.52.9 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GO-2023-2052 | 2.49.2-0.20230906112033-b8c9ede6efa2 | 2.49.2-0.20230906112033-b8c9ede6efa2 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GO-2023-2115 | 2.50.0 | 2.50.0 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GO-2023-2116 | 2.50.0 | 2.50.0 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GO-2024-2574 | 2.52.1 | 2.52.1 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GO-2024-2959 | 2.52.5 | 2.52.5 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GO-2025-3845 | 2.52.9 | 2.52.9 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GO-2026-4471 | 2.52.11 | 2.52.11 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GO-2026-4543 | 2.52.12 | 2.52.12 |  |
| github.com/gofiber/fiber/v2 | v2.49.0 | GO-2026-5585 | 2.52.13 | 2.52.13 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-23wf-92cp-8pcj | 5.1.1 | 4.15.2 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-246p-cpwv-v3jq | 5.1.0 | — | NO FIX in installed branch |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-2ffq-g2xg-c22p | 5.4.0 | 4.16.0 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-375p-5qhx-8wq4 | 5.4.0 | 4.16.0 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-3pmx-cf9f-34xr | 5.4.0 | 4.16.0 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-99jh-6h7p-pp36 | 5.4.0 | — | NO FIX in installed branch |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-cxf3-9h37-7rr8 | 4.16.1 | 4.16.1 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-f48p-c9v4-h7xv | 4.16.1 | 4.16.1 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-h7wr-284f-5qvc | 4.16.1 | 4.16.1 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-h9g5-28mm-hx3g | 5.4.0 | 4.16.0 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-r7w9-592q-9vg4 | 5.4.0 | 4.16.0 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-v753-g4cw-jm48 | 5.4.0 | 4.16.0 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-vfp3-v2gw-7wfq | 5.2.0 | 4.15.3 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GHSA-xwq5-6cqp-vx96 | 5.2.0 | 4.15.3 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6293 | 4.15.3 | 4.15.3 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6839 | 4.16.1 | 4.16.1 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6840 | 4.16.1 | 4.16.1 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6842 | 4.16.1 | 4.16.1 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6872 | 4.16.3 | 4.16.3 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6873 | 4.16.0 | 4.16.0 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6875 | 4.16.3 | 4.16.3 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6876 | 4.16.0 | 4.16.0 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6877 | 4.16.0 | 4.16.0 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6878 | 4.15.2 | 4.15.2 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6879 | 4.16.0 | 4.16.0 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6881 | 4.16.0 | 4.16.0 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6883 | 4.16.0 | 4.16.0 |  |
| github.com/labstack/echo/v4 | v4.11.1 | GO-2026-6885 | 4.15.3 | 4.15.3 |  |
| laravel/framework | v10.34.2 | GHSA-5vg9-5847-vvmq | 13.10.0 | 12.60.0 |  |
| laravel/framework | v10.34.2 | GHSA-63hm-g96r-2m2q | 12.71.0 | 12.71.0 |  |
| laravel/framework | v10.34.2 | GHSA-78fx-h6xr-vch4 | 12.1.1 | 10.48.29 |  |
| laravel/framework | v10.34.2 | GHSA-crmm-hgp2-wgrp | 13.12.0 | 12.61.1 |  |
| laravel/framework | v10.34.2 | GHSA-f9x3-7vq9-cph6 | 13.27.0 | 10.50.4 |  |
| laravel/framework | v10.34.2 | GHSA-gv7v-rgg6-548h | 6.20.45 | 10.48.23 |  |
| laravel/framework | v10.34.2 | GHSA-jh5r-qr3c-85q8 | 12.69.0 | 12.69.0 |  |
| org.springframework:spring-core | 6.1.2 | GHSA-659m-px2c-25wj | 7.0.8 | — | NO FIX in installed branch |
| org.springframework:spring-core | 6.1.2 | GHSA-jmp9-x22r-554x | 6.2.11 | — | NO FIX in installed branch |
| org.springframework:spring-core | 6.1.2 | GHSA-r4q3-7g4q-x89m | 6.1.3 | 6.1.3 |  |
| phpunit/phpunit | 10.5.0 | GHSA-vvj3-c3rp-c85p | 8.5.52 | 10.5.62 |  |
| puma | 6.4.0 | GHSA-2vqw-3mp8-cgmx | 8.0.2 | 7.2.1 |  |
| puma | 6.4.0 | GHSA-9hf4-67fc-4vf4 | 5.6.9 | 6.4.3 |  |
| puma | 6.4.0 | GHSA-c2f4-cvqm-65w2 | 6.4.2 | 6.4.2 |  |
| puma | 6.4.0 | GHSA-qpgp-93vx-g8v8 | 8.0.2 | 7.2.1 |  |
| rails | 7.1.3 | GHSA-9822-6m93-xqf4 | 7.0.8.1 | 7.1.3.1 |  |
| sinatra | 3.0.5 | GHSA-hxx2-7vcw-mqr3 | 4.1.0 | 4.1.0 |  |
| sinatra | 3.0.5 | GHSA-mr3q-g2mv-mr4q | 4.2.0 | 4.2.0 |  |

## Tier 2 — upgrade targets (Phase 13)

Target = the highest branch-correct fixed version across all advisories for
the package, so the bump clears every advisory affecting the installed
version. Every target version was verified to exist as a real release
(Go module proxy / RubyGems API / Packagist).

| Package | Installed | Target | Source | Files changed |
|---|---|---|---|---|
| github.com/gofiber/fiber/v2 | v2.49.0 | **v2.52.14** | max of 19 branch fixes (GHSA-gcfq-8gqf-4876 fixed 2.52.14 in the v2 range; scanner's 3.3.0 is the v3-branch fix) | `go.mod` |
| sinatra | 3.0.5 | **4.2.0** | max of 2 branch fixes; no 3.x fix exists, major bump required | `Gemfile`, `Gemfile.lock` |
| puma | 6.4.0 | **7.2.1** | max of 4 branch fixes; GHSA-2vqw-3mp8-cgmx and GHSA-qpgp-93vx-g8v8 are only fixed in 7.x (range 5.5.0 -> 7.2.1), no 6.x fix | `Gemfile.lock` (unpinned in `Gemfile`) |
| phpunit/phpunit | 10.5.0 | **10.5.62** | 10.x-branch fix for GHSA-vvj3-c3rp-c85p (scanner's 8.5.52 is the 8.x-branch fix); stays in 10.x, so `composer.json` `^10.0` still satisfied | `composer.lock` |

## Kept vulnerable (one per ecosystem, by design)

| Ecosystem | Package kept | File | Vulns kept | Why |
|---|---|---:|---|---|
| Go | github.com/labstack/echo/v4 v4.11.1 | `go.mod` | 28 (14 medium, 14 low) | Richest single-package detection proof in the fixtures; also preserves the `Echo v4.11.1` fingerprint assertion in `test-scanner.ts`. Note: 2 of its 28 advisories (GHSA-246p-cpwv-v3jq, GHSA-99jh-6h7p-pp36) have NO fix in the v4 line (range ends `last_affected: 4.16.2`) — a future fix needs v5.4.0, a major jump. Highest v4 fix is 4.16.3. |
| Ruby | rails 7.1.3 | `Gemfile.lock` | 1 (low) | Preserves the `Rails lockfile 7.1.3 wins over Gemfile range` behaviour test in `test-scanner.ts`; 1 advisory still proves Ruby OSV detection. Branch-correct fix would be 7.1.3.1 (GHSA-9822-6m93-xqf4). |
| PHP | laravel/framework v10.34.2 | `composer.lock` | 7 (low) | Preserves the `Laravel lockfile v10.34.2 wins over ^10.0` behaviour test; 7 advisories still prove PHP OSV detection. Note: 4 of its 7 advisories are only fixed in 12.x (max 12.71.0) — a future fix needs a major jump to 12.71.0; highest 10.x fix is 10.50.4. |
| Java | org.springframework:spring-core 6.1.2 | `pom.xml` | 3 (low) | The only vulnerable Java package in the fixtures; preserves the `Spring Framework 6.1.2 via ${spring.version}` test. Note: 2 of its 3 advisories have NO fix in the 6.1.x line (GHSA-659m-px2c-25wj ends `last_affected: 6.1.21`, GHSA-jmp9-x22r-554x ends `last_affected: 6.1.22`) — a future fix needs 6.2.11/6.2.19 or 7.0.8. Highest 6.1.x fix is 6.1.3 (GHSA-r4q3-7g4q-x89m only). |
| .NET | — | `app.csproj` | 0 | No vulnerable .NET package exists in the fixture (Microsoft.AspNetCore.Mvc 8.0.0 has no advisories), so there is nothing to keep; .NET coverage stays fingerprint-only and is unaffected. |

Kept-vulnerable total: **39** of the 65 Tier 2 vulns (echo 28 + rails 1 +
laravel 7 + spring-core 3). Fixed by the upgrades: **26** (fiber 19 + sinatra 2
+ puma 4 + phpunit 1). Expected post-upgrade totals: 197 - 26 = **171** vulns;
vuln deduction 547 - 79 = **468** (fiber 65 + sinatra 4 + puma 8 + phpunit 2);
total deductions 8 + 468 + 84 + 4 = 564, so the self-scan stays **0/F**.

## Unfixable (left in place, not deleted)

| Package | File | Reason |
|---|---|---|
| org.example:unresolvable | `pom.xml` | Version is `${no.such.property}` — unresolvable, so the scanner records it version-null and it is never OSV-queried. It exists as a fixture to prove unresolvable versions stay null and are never guessed (`test-scanner.ts`: `Tier 2: unresolvable ${...} pom version stays null, never guessed`). There is no version to bump and no advisory to fix. |

No Tier 2 advisory lacks a fix in the installed version's range: every one
of the 26 upgraded advisories has a branch-correct fixed version (see table
above). The only no-fix cases in Tier 2 are inside KEPT packages (echo x2,
spring-core x2 — see kept table), where they are expected and recorded.

## Unchanged Tier 2 files / packages

- `build.gradle`: spring-boot-starter-web 3.2.0, kotlin-stdlib 1.9.20 — 0 advisories, nothing to bump.
- `app.csproj`: Microsoft.AspNetCore.Mvc 8.0.0 — 0 advisories, nothing to bump.
- `wp-config.php`: WordPress detected with unknown version, no deps, nothing to bump.
- `go.mod`: gin v1.9.1, cobra v1.8.0 — 0 advisories, untouched.
- `Gemfile.lock`: rails 7.1.3 — kept vulnerable (see above).
- `composer.json`: unchanged — laravel `^10.0` still satisfied by kept v10.34.2; phpunit `^10.0` still satisfied by 10.5.62.
- `composer.lock`: symfony/http-kernel v6.3.8 — 0 advisories, untouched; laravel v10.34.2 — kept.
- `pom.xml`: spring-boot-starter-parent 3.2.0, spring-core 6.1.2 (kept), org.example:unresolvable (unfixable, see above).

## Verification (local, after the edits)

Re-ran the scanner's own code against the LOCAL fixture directory after the
edits (same parsers + `checkDependencies` against live OSV that `scanRepo`
uses for HEAD files; `depsChecked=16, depsQueryable=16, advisoriesFound=39,
detailCapped=0`). A full live re-scan of the remote was not possible — the
remote still carries the old fixtures, and this phase does not push.

| File | Vulns before | Vulns after | Change |
|---|---:|---:|---|
| `go.mod` | 47 | 28 | fiber 19 fixed (v2.49.0 -> v2.52.14); echo 28 kept |
| `Gemfile` | 2 | 0 | sinatra fixed (3.0.5 -> 4.2.0) |
| `Gemfile.lock` | 5 | 1 | puma 4 fixed (6.4.0 -> 7.2.1); rails 1 kept |
| `composer.lock` | 8 | 1 | phpunit 1 fixed (10.5.0 -> 10.5.62); laravel 7 kept |
| `pom.xml` | 3 | 3 | spring-core 3 kept |
| `build.gradle` | 0 | 0 | already clean |
| `app.csproj` | 0 | 0 | already clean |
| `wp-config.php` | 0 | 0 | no version, no deps |
| **Tier 2 total** | **65** | **39** | **-26** |

Remaining 39 are exactly the kept-vulnerable set (echo 28, laravel 7,
spring-core 3, rails 1) — no upgraded package shows any advisory, and no
new advisory appeared. Projected repo-wide total after push: 197 - 26 =
**171** vulns; projected vuln deduction 468 (was 547); projected total
deductions 8 + 468 + 84 + 4 = 564, self-scan stays **0/F**. To be confirmed
by a fresh live scan once the coordinator pushes.
