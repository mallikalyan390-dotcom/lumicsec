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
| Unit tests | `pnpm test` | PASS, 37/37 tests across 10 files (new customer endpoints and origin tests) |
| Production builds | `pnpm build` | PASS, Fastify API + Vite React frontend + engine packages |
| Production dependency audit | `pnpm security:audit` | PASS, no known vulnerabilities in production dependencies |

The original source parser accepts a valid OpenAPI document containing zero operations, so its target test was corrected to **assert an empty inventory**, not incorrectly demand a parse rejection. Browser API transport tests were added; the shared type-only package has no test runner.

These are **local results**. See the exact GitHub-hosted CI proof below. A subsequent feature commit must independently pass both GitHub Actions workflows before its own milestone is accepted.

## First GitHub-hosted CI evidence

Commit `816c8bdf84b3599faad2a837b429fcc7f125890d`:
- Lockfile verification: run [44313693401](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44313693401) **SUCCESS**, frozen installation and unchanged lockfile verified.
- CI: run [44313693444](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44313693444) **FAILURE**, install and lint passed, typecheck failed with `TS2307` because workspace library `dist` files did not exist before the typecheck step.
- Correction: add an explicit workspace-library build phase before CI TypeScript checks. This is a CI ordering correction, not a claim that the first CI run passed.

## Verified GitHub Actions foundation

Exact `main` commit `f5c566bb77c645a8831d4debe04d33aef9658d05`:
- [CI run 44314223186](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44314223186) **SUCCESS**; checkout, pnpm frozen install, workspace builds, lint, TypeScript, unit tests, production build, production dependency audit and secret scan each succeeded.
- [Lockfile verification run 44314223183](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44314223183) **SUCCESS**; committed pnpm-lock.yaml installed with --frozen-lockfile and remained unchanged.

This resolved the workflow-validation issue and earlier TypeScript build-order failure. Other source implementation commits are NOT covered by these two older runs; run fresh checks on every new main commit.

## Development Supabase tenant foundation

On 2026-11-18, `tenant_rls_foundation` version `20261118133942` was applied to the **lumicsec-local development project only**. Verification: six public tables have RLS enabled; 10 RLS policies present; anon has zero SELECT privileges on these tables; authenticated has no table DELETE privileges; Supabase security advisors returned no lints.

The checked-in `supabase/tests/tenant-isolation.sql` was executed on that development database and PASSed in a single rolled-back transaction, simulating two authorized Google AAL2 users, checking owner visibility, tenant B isolation, foreign-tenant asset insert/update denial, and AAL1 / non-Google membership and creation denial. No synthetic users or tenant rows were retained.

Customer feature code now includes a React Organizations & Assets page and tenant-scoped Fastify GET/POST endpoints. Assets can only be registered as PENDING, and browser roles cannot mark them verified. The origin validator performs no DNS or network requests. Live OAuth/TOTP, invitations, domain ownership verification, scanner workers and commercial customer E2E remain pending. The development database policy test is not a replacement for hosted end-to-end authorization testing.

Local validation after these changes: frozen installation, lint, typecheck, all 37 unit tests, production builds and production dependency audit PASSED on Node 26.13.0 / pnpm 12.19.0 (8GB-class Linux machine). New feature commit GitHub checks still require verification.

## Known security advisory

The full (including dev tooling) audit reports **GHSA-fc5q-39xc-vjpf (CVE-2026-112366)** in `picomatch <= 4.0.7`. The registry advisory reports no patched version as of 2026-11-18. Production-only audit is clean. This advisory remains unresolved and must be tracked; do not claim all dependencies are vulnerability-free. See `docs/security/dependency-advisories.md`.

## Roadmap status

| Milestone | State | Evidence / acceptance dependency |
|---|---|---|
| Source branch inventory and engine qualification matrix | PARTIAL | 47 source heads inspected, source evidence reviewed; complete historical lineage still pending |
| Monorepo and developer infrastructure | VERIFIED ON f5c566b | CI 44314223186 and lockfile verification 44314223183 SUCCESS; new changes need fresh checks |
| Supabase PostgreSQL schema / tenant RLS | INITIAL DEVELOPMENT FOUNDATION VERIFIED | 6 tables, 10 RLS policies, no advisor lints, cross-tenant transactional SQL tests passed; session-level E2E and memberships administration pending |
| Google OAuth + mandatory TOTP | SCAFFOLD ONLY | Hosted provider settings, PKCE callback, AAL2 E2E, recovery-code implementation |
| Customer dashboard and organizations | INITIAL PERSISTENT WORKFLOW CODED | Create/list organizations and pending assets via user-scoped Supabase RLS, React UI, unit tests; hosted Google Auth E2E, ownership verification, invitations not complete |
| Platform admin dashboard | NOT IMPLEMENTED | Server-controlled platform roles, immutable audit evidence |
| Web Security engine | OFFLINE PASSIVE MODULES PORTED | Ownership verification and SSRF-safe transport required before live scanning |
| API Security engine | SPEC_ONLY MODULES PORTED | Live API authorization worker requires separate qualification |
| Findings, reports, remediation, retesting | NOT IMPLEMENTED | Canonical evidence, reviewer authority, PDF tests |
| Monitoring, notifications, billing | NOT IMPLEMENTED | Job schedules, rate budgets, payment approval |
| Cloud Run / Cloudflare deployment | DOCUMENTATION ONLY | Budget/credential approval, hardened release tests, independent security review |

## Next acceptance gates

1. Verify both GitHub-hosted workflows for the next exact `main` commit containing the tenant migration and customer code; resolve any failure.
2. Configure Google-only OAuth and complete hosted PKCE + mandatory TOTP E2E, recovery codes, session revocation and cross-tenant browser tests before live user onboarding.
3. Implement a safe ownership challenge, verification lifecycle, secure role-controlled membership administration and audit trail.
4. Only then qualify bounded, authorized passive scanners, canonical findings, reporting, monitoring, billing and admin features; no customer scanner or worker may bypass these release gates.
5. Prepare Cloud Run/Cloudflare deployments only after founder approval and budgets/security review.

Never use `READY`, `PRODUCTION` or `VERIFIED_FIXED` for an untested implementation.
