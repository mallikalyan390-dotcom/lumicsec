# LumicSec development progress

Last reviewed: 2026-11-18 (Asia/Kolkata). Target branch: `main` only.

## Repository safeguards

- Target: https://github.com/mallikalyan390-dotcom/lumicsec.
- Existing initial implementation: `8cf1038825848bddc92d82307356afb4e577a082`.
- No extra branches or force pushes are permitted.
- The original Web and API security repositories are read-only inputs.
- No production deployment, paid cloud resources, billing activation or DNS changes are authorized.

## Immediate CI repair

The initial CI and bootstrap workflows (run IDs 44308401247 and 44308399043) failed **before any jobs started** because backslashes escaped GitHub expressions; both YAML files also used unsupported `hashFiles()` at the job-level condition.

Corrections in the repair commit:
- Remove the stray backslash before GitHub expression syntax and eliminate job-level `hashFiles` conditions.
- Commit a generated `pnpm-lock.yaml` directly to `main`.
- Change the bootstrap workflow into an unconditional **lockfile verification** job, using `pnpm install --frozen-lockfile` and checking no lockfile diff.
- CI executes frozen installation, lint, typecheck, unit tests, production builds, production dependency audit, and secret scan.
- Pin Node.js 26.13.0 and pnpm 12.19.0; explicitly authorize only esbuild postinstall in pnpm 12 `allowBuilds`.

## Local validation evidence

Executed on 2026-11-18 in a clean clone of `main`, using Node.js v26.13.0, pnpm v12.19.0 and an approximately 8 GB RAM Linux development device. Local dependency installation used bounded concurrency.

| Check | Command | Local result |
|---|---|---|
| Lockfile generation | `pnpm install --lockfile-only --no-frozen-lockfile` | PASS |
| Frozen installation | `pnpm install --frozen-lockfile` | PASS (after esbuild build authorization) |
| Lint | `pnpm lint` | PASS, 0 errors |
| TypeScript | `pnpm typecheck` | PASS, all 6 workspace projects |
| Unit tests | `pnpm test` | PASS, 21/21 tests across 9 files |
| Production builds | `pnpm build` | PASS, Fastify API + Vite React frontend + engine packages |
| Production dependency audit | `pnpm security:audit` | PASS, no known vulnerabilities in production dependencies |

The original source parser accepts a valid OpenAPI document containing zero operations, so its target test was corrected to **assert an empty inventory**, not incorrectly demand a parse rejection. Browser API transport tests were added; the shared type-only package has no test runner.

These are **local results**, not GitHub CI green checks. Record hosted workflow run IDs and final commit SHA only after the checks pass on GitHub.

## First GitHub-hosted CI evidence

Commit `816c8bdf84b3599faad2a837b429fcc7f125890d`:
- Lockfile verification: run [44313693401](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44313693401) **SUCCESS**, frozen installation and unchanged lockfile verified.
- CI: run [44313693444](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44313693444) **FAILURE**, install and lint passed, typecheck failed with `TS2307` because workspace library `dist` files did not exist before the typecheck step.
- Correction: add an explicit workspace-library build phase before CI TypeScript checks. This is a CI ordering correction, not a claim that the first CI run passed.

## Known security advisory

The full (including dev tooling) audit reports **GHSA-fc5q-39xc-vjpf (CVE-2026-112366)** in `picomatch <= 4.0.7`. The registry advisory reports no patched version as of 2026-11-18. Production-only audit is clean. This advisory remains unresolved and must be tracked; do not claim all dependencies are vulnerability-free. See `docs/security/dependency-advisories.md`.

## Roadmap status

| Milestone | State | Evidence / acceptance dependency |
|---|---|---|
| Source branch inventory and engine qualification matrix | PARTIAL | 47 source heads inspected, source evidence reviewed; complete historical lineage still pending |
| Monorepo and developer infrastructure | LOCAL VERIFIED; CI PENDING | Frozen install, lint, types, tests, build passing locally; GitHub checks pending |
| Supabase PostgreSQL schema / tenant RLS | NOT IMPLEMENTED | New migration, dedicated local database tests, cross-tenant attack tests |
| Google OAuth + mandatory TOTP | SCAFFOLD ONLY | Hosted provider settings, PKCE callback, AAL2 E2E, recovery-code implementation |
| Customer dashboard and organizations | INITIAL UI ONLY | Persistent org memberships, asset ownership, RLS and authorized operations |
| Platform admin dashboard | NOT IMPLEMENTED | Server-controlled platform roles, immutable audit evidence |
| Web Security engine | OFFLINE PASSIVE MODULES PORTED | Ownership verification and SSRF-safe transport required before live scanning |
| API Security engine | SPEC_ONLY MODULES PORTED | Live API authorization worker requires separate qualification |
| Findings, reports, remediation, retesting | NOT IMPLEMENTED | Canonical evidence, reviewer authority, PDF tests |
| Monitoring, notifications, billing | NOT IMPLEMENTED | Job schedules, rate budgets, payment approval |
| Cloud Run / Cloudflare deployment | DOCUMENTATION ONLY | Budget/credential approval, hardened release tests, independent security review |

## Next acceptance gates

1. Commit the repairs and lockfile on `main`, then inspect both GitHub Actions runs and resolve all failures.
2. Update this file with the exact passing checks and commit SHA; verify the documentation commit's own CI checks.
3. Introduce Supabase SQL migrations and RLS tests without modifying the remote hosted project until migration review.
4. Complete Google-only OAuth, TOTP, recovery codes, session revocation and tenant isolation before customer onboarding.
5. Only then qualify authorized passive scans, canonical findings, reporting and commercial capabilities.

Never use `READY`, `PRODUCTION` or `VERIFIED_FIXED` for an untested implementation.
