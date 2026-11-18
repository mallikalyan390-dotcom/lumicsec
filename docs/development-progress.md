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

### Active checkout and MFA manual fallback — GitHub-hosted checkpoint

Exact `main` code commit `ce4c5dc5d7b3261f1a0f11fbfd0a59865e24529a`. The GitHub tree `acb9c7dd52388b714edb8d63ee40723857fa906a` was identical to the locally committed, tested tree before the non-force remote ref update. The active local checkout was aligned to that exact GitHub commit by an atomic local Git ref update **only after proving both commits had an identical tree and parent**. No working-tree reset or file overwrite occurred, and `main` remained clean.

- [GitHub CI run 44338785713](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44338785713): **SUCCESS**; 16 workflow steps passed.
- [GitHub lockfile verification run 44338785783](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44338785783): **SUCCESS**; 11 workflow steps passed.
- Local actual folder `/home/kalyan/lumicsec`: frozen install, full build, lint, TypeScript, **71/71 tests**, production dependency audit, and Git diff whitespace check: **PASS**. Vite displayed a nonfatal bundle chunk-size optimization warning (>500 KB).
- Synthetic browser UI test: Firefox and Chromium each passed valid-QR and broken-QR scenarios (4/4), including visible manual key/instructions, accessible six-digit verification form, and simulated rejected-code feedback. No real factor or secret was used.
- Local API negative checks: `/healthz` HTTP 200, `/v1/organizations` without user HTTP 401, failed callback HTTP 302, unauthenticated `/auth/session` returns `anonymous`. Frontend HTTP 200. Both real services remain in the correct active folder.
- Non-login hosted authorization redirect inspection: `/auth/google` HTTP 302 to the configured Supabase `/auth/v1/authorize` with `provider=google` and PKCE `code_challenge_method=S256`; a single non-followed Supabase authorize request returned HTTP 302 to `accounts.google.com`. **No Google user sign-in, callback code exchange, current-user AAL2, token revocation, or real TOTP enrollment was qualified by this test.**

The custom single-use recovery-code scheme, AAL2-protected backup authenticator management, verified-factor rotation and session revocation propagation remain **required but incomplete**. The previously exposed QR secret must never be reused. No database migrations, live factor changes, production deployments or paid services occurred in this checkpoint. This exact code SHA has hosted CI evidence; any later docs-only commit needs fresh checks.

## P0 Supabase TOTP QR false-rejection hardening

On 2026-11-18, a founder-reproduced error `TOTP_QR_FORMAT_UNSUPPORTED` was investigated at `/auth/mfa/enroll`. The installed `@supabase/auth-js@2.119.0` source (`GoTrueClient.ts`, `mfa.enroll`) confirms the SDK attaches `data:image/svg+xml;utf-8,` to the provider's raw SVG; it does **not** strip or URI-encode XML whitespace/newlines. The previous validator rejected all raw newlines and only recognized an SVG tag at the very beginning. This was a confirmed false-negative defect. **The exact payload of the founder's hosted enrollment was not collected and remains unverified.**

The validator now handles raw multiline/CRLF SVG, supported XML declarations with whitespace, URI-encoded SVG, and base64 SVG, under strict bounds. An intentionally conservative SVG drawing-element/attribute allowlist rejects scripts, events, external links, CSS, foreignObject, DTD, entities, CDATA, invalid nesting, and oversized/malformed data. Accepted images become canonical percent-encoded SVG Data URLs; unsafe SVG is never sent to the browser.

**Manual availability fallback:** After Google identity checks, a Supabase enrollment with a valid factor ID and manual TOTP key can proceed when its QR is absent/unsafe. The API returns `qrCodeSvg: null`, the same enrollment's key, and the pending-factor HTTP-only cookie with `Cache-Control: no-store`. Only categorical format metadata is logged—no SVG, factor ID, secret, OTP URI, token, cookie, or user ID. The frontend retains manual key and six-digit form; Supabase challenge/verification and AAL2 are still mandatory. Missing/invalid secrets fail closed. **QR rejection no longer deletes the new or any verified factor.** Explicit replacement of app-owned abandoned *unverified* factors remains separate.

Synthetic validator and API route tests cover safe/unsafe SVG, malformed QR manual flow, pending factor selection, failed codes and protected Google+AAL2 gates. The actual compiled Fastify backend is additionally exercised on a separate loopback port beside the compiled React synthetic-browser fixture; no real MFA secrets or hosted factors are used.

**Remaining release blockers:** founder-driven hosted Google callback, actual provider QR shape, real authenticator scan/manual code, AAL2 session, customer API access, expiration/revocation, recovery codes and backup factor management. Production/deployment/MFA settings and databases were not modified.

## Local PNG TOTP QR milestone — independent code acceptance, hosted QR pending

The founder reported successful interactive Google sign-in, manual TOTP enrollment and access to the LumicSec dashboard, API Security and Assets. This is evidence of that **specific founder-controlled local journey**, not independent verification of every hosted PKCE, session revocation or recovery scenario. The real application QR image still failed and therefore remained a P0 blocker after prior SVG-validation fixes.

The API now uses the MIT-licensed **qrcode 1.5.4** package to generate a bounded **256×256 PNG QR entirely locally**, from the **same Supabase-provided pending TOTP factor secret**. The encoded provisioning URI is local memory only, with standard TOTP SHA1/6 digits/30-second parameters and a validated label; neither secret nor URI is logged or sent to any QR service. The original hardened Supabase SVG may be used as a compatibility fallback if PNG generation is unavailable; the manual entry key and mandatory six-digit challenge always remain available. Google remains the only first factor, AAL2 remains mandatory on protected customer APIs, and no verified factors are automatically removed.

Browser-side PNG validation accepts only a bounded PNG base64 Data URL with a checked PNG signature, IHDR and image dimensions, and never inserts QR markup into HTML. The server returns `qrCodePng` alongside legacy `qrCodeSvg` and `secret` only during authenticated enrollment; `Cache-Control: no-store` is retained. A failed image can never act as an MFA bypass. Existing pending-factor rotation and safe error paths are preserved.

**Independent local verification, using public synthetic secrets only:** The **jsQR 1.4.0 (Apache-2.0)** test decoder re-read the PNG from the independent **pngjs 5.0.0 (MIT)** image parser and proved that the embedded provisioning URI exactly matched the expected synthetic TOTP secret and parameters. Automated API regression tests verified that a malformed upstream SVG does not stop local PNG generation. Built React frontend in Chromium and Firefox: valid PNG shown; absent QR shows manual key/form; both paths submit a synthetic failed code. Four out of four browser fixture reports passed (Firefox runs were force-stopped by a headless test timeout **after** the test reports were received). All browser authenticator data were synthetic, not actual Supabase factors. The full local dependency audit, build, TypeScript and unit suite were rerun with frozen install. Node 26.13.0 / pnpm 12.19.0, no paid services or production deployment.

**Explicitly outstanding:** A real founder-driven **fresh QR scan** in the hosted/local OAuth application is required; the PNG code milestone does NOT prove it has worked in the founder's authenticator. Existing verified exposed factors cannot be silently deleted. Recovery codes, audited backup authenticator management, session refresh/expiry/revocation, independently observed AAL2 sessions, and production release qualification are still open. No database migration was applied. Development Supabase remains on version `20261118133942`, with six application tables, six with RLS, and ten policies. The Supabase advisor reports an Auth leaked-password protection warning (not changed during this milestone).

Dependency provenance: qrcode 1.5.4 (MIT, runtime), @types/qrcode 1.5.6 (MIT, dev), jsQR 1.4.0 (Apache-2.0, dev), pngjs 5.0.0 and @types/pngjs 6.0.5 (MIT, dev). No source-engine repository was modified or code imported for this QR checkpoint. `pnpm audit --prod --audit-level high` passed. Existing development-only dependency advisories remain separately tracked.

**Recovery qualification, 2026-11-19:** The founder's active checkout contained exactly **10 modified tracked files and one new untracked AccountSecurityPage.tsx** at the verified GitHub HEAD `fb5784d39b06e0810ff63f28aa0b752698bb2e70`. No other source session was modifying the checkout; the interrupted draft was preserved and resumed in place. Frozen lockfile install, production build, ESLint, TypeScript, full **126/126 automated tests**, production dependency audit and `git diff --check` passed. Compiled frontend UI synthetic backup-factor tests on **Chromium and Firefox** passed **4/4** (valid PNG and manual fallback for each browser, with a simulated rejected OTP). Firefox's headless processes exited by timeout after the successful UI reports; they are not treated as hosted authentication qualification. An initially premature synthetic-browser click was corrected to wait for the verified-factor list to enable the backup button; the AAL2 safety gating was **not** bypassed. Local live Fastify `/auth/mfa/factors` without authentication returned HTTP **401**, and `/healthz` and the frontend returned **200**. These tests did not enroll/remove any hosted factor or disclose a real TOTP secret. Backup-factor actual enrollment, full session lifecycle tests, recovery codes and safe owner-approved rotation remain pending.

## AAL2-gated backup authenticator enrollment — code milestone (hosted verification pending)

A new Account security workspace page at `/app/account-security` shows only the signed-in user's **verified** TOTP factor labels and offers an explicit “Add backup authenticator” workflow. The new read-only `GET /auth/mfa/factors` route validates the user's primary Google identity, JWT OAuth+TOTP AMR, and active AAL2 session assurance before retrieving any factor list; it omits pending factors, provisioning secrets and enrollment URIs, sets `Cache-Control: no-store`, and has a request rate limit. AAL1, non-Google, expired JWT, or absent TOTP claims are denied. No endpoint for removing verified factors was added.

The backup form reuses the tested initial `/auth/mfa/enroll` and `/auth/mfa/verify` routes, including local PNG QR, manual setup and TOTP challenge. When a verified factor already exists, enrollment now requires the **full Google+TOTP JWT/AAL2 policy**, not just a numeric AAL2 assurance level. The existing factor is retained. Verification refreshes the factors display. The flow is user-initiated and has not changed any real Supabase factor.

Automated API regression tests cover positive read-only listing and AAL1/non-Google/invalid JWT denial, plus denial of backup enrollment when TOTP proof is missing. Compiled React browser fixture includes an authenticated **synthetic** factor list and tests backup enrollment with locally generated PNG versus manual-key fallback; these are not real founder factors. The remaining blocking work is real AAL2 browser qualification, safe verified-factor revocation following explicit owner approval, tested session lifecycle, and single-use recovery codes/private storage. Until these pass, Account security is **partial backup enrollment**, not full recovery management.

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
