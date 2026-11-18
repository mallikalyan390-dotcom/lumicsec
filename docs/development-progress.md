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

Local validation after these changes: frozen installation, lint, typecheck, all 37 unit tests, production builds and production dependency audit PASSED on Node 26.13.0 / pnpm 12.19.0 (8GB-class Linux machine). GitHub-hosted checks for the tenant/customer code milestone are now successful; see exact run evidence below.

## Tenant workflow GitHub-hosted verification

Exact `main` code commit `db2d7d61ff767e861367171a9f7fd38806666d6e` includes the version-controlled migration `20261118133942_tenant_rls_foundation.sql`, rollback-only SQL test, Fastify customer organization/asset endpoints, HTTPS origin validator, React asset UI, tests and documentation. All 23 updated GitHub blob SHAs matched the locally staged Git blobs.

- [CI run 44325014580](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44325014580) **SUCCESS** for this exact commit: frozen install, workspace compilation, lint, TypeScript, 37 unit tests, production builds, production dependency audit and secret scanning.
- [Lockfile verification run 44325014585](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44325014585) **SUCCESS** for the same commit: frozen install and unchanged lockfile.
- Local 8 GB-class Linux development check: Node 26.13.0 and pnpm 12.19.0; frozen install, build, lint, typecheck, 37/37 unit tests and production dependency audit passed.
- Supabase `lumicsec-local`: migration `20261118133942` previously applied once; six RLS-enabled tables, ten policies and no security advisor lints. Two-user tenant-isolation SQL test passed in a rollback-only transaction. **This database SQL test was not run by GitHub CI.**

Status: organization and **pending** asset persistence is implemented and verified by CI and database-policy tests. Hosted Google OAuth + mandatory TOTP E2E, membership management, domain ownership verification, scanners, reports, monitoring and billing are NOT complete. No production deployment or paid resources were used.

## MFA QR and safe unverified-factor recovery checkpoint

On 2026-11-18, reviewed Supabase's current TOTP JavaScript reference and GoTrue JS source. An enrollment QR from Supabase JS is **already an SVG image Data URL**; the previous React code incorrectly added a second Data URL prefix and percent-encoded the original string. The frontend now passes the original bounded/validated image source to the browser and offers an explicit safe regeneration action.

A second enrollment-blocking issue was corrected: Supabase `listFactors().totp` lists verified factors, whereas new unverified TOTP factors are in `listFactors().all`. The verifier selects the exact user's unverified LumicSec factor via the HTTP-only pending cookie, fails closed on stale cookies, and checks that MFA verification actually reaches AAL2. Replacement cleans only app-owned unverified factors. Verified factors and unrelated factors are never automatically deleted; enrolling an additional factor requires AAL2.

New tests cover QR format validation, factor selection, Fastify enrollment/verification behavior and protected Google+AAL2 customer API gates, using **mocked Supabase responses**. Controlled, secret-free synthetic SVG images were tested in actual local Chromium (direct Data URL loaded, double-prefixed image failed) and Firefox/Xvfb (direct image rendered with 32,400 dark pixels in the fixture region; double-prefixed image 60 dark pixels). Local hosted Google OAuth with a real authenticator was **not** performed. A previous exposed QR must be rotated at the next authorized live enrollment; no founder login factor was remotely modified.

See `docs/security/mfa-enrollment-qualification.md` for test methodology, handling of previously exposed enrollment secrets, and the remaining **production-blocking** hosted authentication checks (real QR scan, session refresh/expiry, logout/login challenge, recovery, device/session management). No Supabase schema changes or deployments were required for this checkpoint.

### MFA QR code checkpoint — verified GitHub-hosted evidence

Exact `main` code commit: `335766c31d20736538f91ded91b130039d78f02e`, created from the nine-file locally tested tree `91fdc36e5e27b33100e38f3d8ef9cd11960f3879`. Every new GitHub blob SHA matched its locally committed blob before advancing `main`; the change was a non-force fast-forward.

- [CI run 44333300508](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44333300508): **SUCCESS**, one quality job / 16 successful steps.
- [Lockfile verification run 44333300598](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44333300598): **SUCCESS**, one frozen-lockfile job / 11 successful steps.
- Local (8GB-class Linux, Node 26.13.0 / pnpm 12.19.0): frozen install, builds, lint, TypeScript checks, **62/62 tests**, production dependency audit and whitespace validation all PASS.
- Browser fixture: Chromium headless and Firefox via Xvfb both rendered the direct SVG Data URL and rejected the previous double-prefixed format. These synthetic browser tests did not touch real MFA factors.
- No schema, production infrastructure, billing, DNS, or live authentication factor was altered. Recovery codes, real Google OAuth with authenticator scan, actual AAL2 hosted E2E, session-revocation testing, and full customer onboarding security qualification are still blocked/pending.

Documentation-only updates after the code commit require their own exact-SHA GitHub Actions verification; do not reuse prior run IDs as proof for newer commits.

## Founder laptop active-checkout synchronization and manual MFA fallback

Independent CTO inspection on 2026-11-18 identified the founder's **active** development checkout at `/home/kalyan/lumicsec` was still at `db2d7d61ff767e861367171a9f7fd38806666d6e`, despite the separate validation workspace and GitHub `main` being at `d5706429f6de5afdf70ffb7b922a3fd6bfb362a5`. The active checkout was clean, on `main`, and its origin pointed to the expected repository. It was synchronized with `git fetch origin main` and `git merge --ff-only FETCH_HEAD`, after checking that the old commit was an ancestor. No reset, re-clone, force-push, environment change or deletion was performed. It was clean at the synchronized HEAD.

The original app's dev-process tree was confirmed under `/home/kalyan/lumicsec` (Vite under `apps/web`, Fastify under `apps/api`). Only the old LumicSec dev-process chain was terminated, and `pnpm dev` restarted in **the active checkout**. Both services listened on loopback: frontend `127.0.0.1:5173` and API `127.0.0.1:8787`. HTTP checks returned 200 for the frontend and `/healthz`. `/auth/session` returned `anonymous` with Supabase configured; `/v1/organizations` rejected an unauthenticated request with HTTP 401; the negative OAuth callback returned 302. The served Vite module included the committed direct QR Data URL fix.

A follow-up React bug was confirmed: when the QR image failed, the manual setup key appeared but the six-digit verification form was hidden. The setup page now keeps the verification form available for **every active enrollment**, independent of QR rendering, and explains how to manually enter the time-based secret. Generating a replacement disables code submission during that request. The manual secret remains limited to the authenticated enrollment page; no real secret was printed, logged, or used in the browser tests.

The controlled optional browser fixture `apps/web/tests/mfa-manual-fallback-smoke.mjs` serves the **actual built React frontend** with a self-contained synthetic API on `127.0.0.1:5187`. It never calls Supabase or the real API. Chromium and Firefox each passed two scenarios (valid synthetic SVG and deliberately broken synthetic SVG), checking the QR's load/error status, visible manual entry instructions, visible six-digit field and an attempted verification that produced a simulated failure message. **Four of four local browser scenarios passed**. This is browser/UI evidence, NOT an actual hosted Google OAuth or real authenticator success.

The API OAuth/session regression suite now additionally covers Google-only OAuth initiation, callback success/error handling, AAL1/AAL2 session gating, unavailable session claims and sign-out through mocked Supabase methods. Real session revocation propagation, live factors, recovery codes, backup authenticator management, hosted PKCE and actual device re-login/expiry tests are **still unverified or unimplemented**. See `docs/security/mfa-enrollment-qualification.md`. Do not onboard production customers on this basis.

## Known security advisory

The full (including dev tooling) audit reports **GHSA-fc5q-39xc-vjpf (CVE-2026-112366)** in `picomatch <= 4.0.7`. The registry advisory reports no patched version as of 2026-11-18. Production-only audit is clean. This advisory remains unresolved and must be tracked; do not claim all dependencies are vulnerability-free. See `docs/security/dependency-advisories.md`.

## Roadmap status

| Milestone | State | Evidence / acceptance dependency |
|---|---|---|
| Source branch inventory and engine qualification matrix | PARTIAL | 47 source heads inspected, source evidence reviewed; complete historical lineage still pending |
| Monorepo and developer infrastructure | VERIFIED ON f5c566b | CI 44314223186 and lockfile verification 44314223183 SUCCESS; new changes need fresh checks |
| Supabase PostgreSQL schema / tenant RLS | INITIAL DEVELOPMENT FOUNDATION VERIFIED | 6 tables, 10 RLS policies, no advisor lints, cross-tenant transactional SQL tests passed; session-level E2E and memberships administration pending |
| Google OAuth + mandatory TOTP | QR RENDERING + ENROLLMENT REGRESSION CODE TESTED; HOSTED E2E PENDING | Direct QR data source, pending factor rotation and AAL2 gate tests; real Google/Auth-app E2E and recovery codes remain blockers |
| Customer dashboard and organizations | PERSISTENCE CODE AND CI VERIFIED; HOSTED E2E PENDING | Organization and pending asset API + React UI, user-scoped Supabase RLS, CI 44325014580 SUCCESS and SQL isolation PASS; live Google Auth E2E, domain verification and invitations not complete |
| Platform admin dashboard | NOT IMPLEMENTED | Server-controlled platform roles, immutable audit evidence |
| Web Security engine | OFFLINE PASSIVE MODULES PORTED | Ownership verification and SSRF-safe transport required before live scanning |
| API Security engine | SPEC_ONLY MODULES PORTED | Live API authorization worker requires separate qualification |
| Findings, reports, remediation, retesting | NOT IMPLEMENTED | Canonical evidence, reviewer authority, PDF tests |
| Monitoring, notifications, billing | NOT IMPLEMENTED | Job schedules, rate budgets, payment approval |
| Cloud Run / Cloudflare deployment | DOCUMENTATION ONLY | Budget/credential approval, hardened release tests, independent security review |

## Next acceptance gates

1. Keep both workflows green on each new `main` commit, confirming the exact SHA. Hosted security E2E is required before any customer onboarding.
2. Configure Google-only OAuth and complete hosted PKCE + mandatory TOTP E2E, recovery codes, session revocation and cross-tenant browser tests before live user onboarding.
3. Implement a safe ownership challenge, verification lifecycle, secure role-controlled membership administration and audit trail.
4. Only then qualify bounded, authorized passive scanners, canonical findings, reporting, monitoring, billing and admin features; no customer scanner or worker may bypass these release gates.
5. Prepare Cloud Run/Cloudflare deployments only after founder approval and budgets/security review.

Never use `READY`, `PRODUCTION` or `VERIFIED_FIXED` for an untested implementation.
