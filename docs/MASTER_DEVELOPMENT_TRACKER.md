# LUMICSEC — MASTER DEVELOPMENT TRACKER

_Last updated: 2026-11-19. Canonical repository: `mallikalyan390-dotcom/lumicsec`, branch `main` only._

This is an evidence-based development ledger, not a claim that the full commercial platform is production-ready. Evidence and the actual GitHub SHA/CI results must be attached to each future milestone. No production deployment, customer scanning, paid infrastructure or billing activation is authorized by this tracker.

## 1. Completed and independently checked code milestones

| Area | Delivered source and behavior | Verification status |
|---|---|---|
| Workspace scaffolding | React/Vite UI, Fastify BFF, TypeScript packages, validation shared types, automated CI and frozen lockfile | Build, lint, typechecks, tests and GitHub Actions proven |
| Google-only + TOTP | Google PKCE OAuth handoff, Supabase TOTP enrollment/challenge, mandatory Google+TOTP AAL2 for customer routes, logout and session states | Unit/integration tests and some founder manual-login evidence; **complete hosted session expiry/revocation unverified** |
| Safe MFA enrollment QR | Server-generated local PNG QR from Supabase pending factor; independent synthetic QR decode; manual TOTP and hardened SVG fallback | Unit/API tests + Chromium/Firefox synthetic UI checks; founder live PNG scan **not independently qualified** |
| MFA backup factor UI | AAL2-protected factor list; backup authenticator enrollment; never automatically removes verified factors | API negative tests + synthetic browser tests; real backup enrollment and lost-device recovery **unverified** |
| Tenant database foundation | Existing organizations, owner bootstrap, memberships, assets, assessments, audit events, strict RLS and private helpers | `20261118133942` unchanged; six extra restrictive Google+TOTP AAL2 RLS policies applied forward-only in `20261119005151`; direct Data API downgrade tests PASS |
| Customer asset registration | Exact public HTTPS origins, pending-only creation, no network scan on registration | Unit/route tests + DB constraints; **no scanner authorization** |
| Organization RBAC and invitations | Owner/Admin/Member plus historic analyst/viewer preservation; manually shared, SHA-256-hashed single-use invited-email-bound 7-day tokens; issue/accept/revoke, role changes, last-owner safety, member removal, audit trail | Migrations `20261118235406`, `20261118235735`, AAL2 restrictive RLS `20261119005151`; rollback-only PostgreSQL isolation and mocked Fastify tests PASS; hosted multi-user E2E **pending** |
| Domain/API asset proof | Per-asset 30-minute DNS TXT or HTTPS-file challenge, 30-day proof validity, renewal, revocation, RLS-protected challenge/audit history, no scanner grant | DB transaction tests, DNS/HTTPS resolver and SSRF negatives, mocked Fastify and browser UI. **Actual trusted verification completion locally blocked by missing server-only `SUPABASE_SECRET_KEY`.** |
| Authorized security-engine inventory | Existing offline Web passive and API specification engines preserved; current repo reuses exact qualified source SHA baselines, never imports entire source apps | See `docs/source-engine-inventory.md`; source and target integration evidence are separate; no customer scan |
| Authorized saved offline API specification assessments | **NEW development-integrated** asset/org-scoped explicit consent, verified ownership checks at queue/begin/complete, backend-only DB state transitions, customer history/evidence/cancel UI, durable SPEC_ONLY and INVENTORY_ONLY observations; no raw document saved or live API requests | Dev migration `20261119013152`, rollback-only SQL PASS, 14 new API tests and Chromium three-scenario fixture PASS; hosted key provisioning and real user acceptance **blocked**, production worker and live Web/API scanning **not implemented** |

## 2. Organization RBAC — acceptance breakdown

- **Owner:** create org, manage members and role changes, send Admin/Member invitations, see audit events, issue/revoke asset proof. Last owner cannot be demoted/removed.
- **Admin:** issue Member invitations, view member/invite inventory and audit events, issue/revoke asset proof. Cannot add another Admin, remove members or change owner roles.
- **Member:** access its own organization and asset read view, accept own email-bound invitation. Cannot manage team members, issue/revoke challenges or create scans.
- **Legacy analyst/viewer:** preserve existing records and existing access while explicit migration to standardized roles remains a separate audited operation.
- **Direct Data API RLS security:** Six prior permissive tenant table policies checked organization membership but lacked a complete AAL2 Google+TOTP guard on every read/write. A separate **restrictive** policy was added to each of the original six tenant tables; it ANDs with the existing tenant policy rather than replacing it. The rollback-only PostgreSQL suites prove that AAL1, missing TOTP AMR and non-Google tokens cannot read the original tenant's organizations/assets directly. No source rows were migrated.
- **Security gate:** signed Supabase Google identity with OAuth+TOTP AMR and AAL2 in Fastify and in privileged DB functions. All member-related state mutations are database checked, audited and tenant bound. No direct membership write grant.
- **Invitation delivery limitation:** a one-time token is displayed privately to the inviting owner for manual delivery. Automated transactional delivery/invitation emails are not yet implemented.
- **Account email requirement:** acceptor must have a matching **confirmed** Supabase Auth email. Unknown, duplicate, revoked or expired invite tokens are rejected.

## 3. Asset ownership — acceptance breakdown

- **Not scanning:** Registration is not ownership authorization, ownership verification is not scanner authorization, and no user-facing action starts a scan.
- **Origin binding:** Exact organization, asset UUID, canonical HTTPS origin, verification method, and a 30-minute random challenge. Token stored hashed in Postgres; only initial issue response carries the one-time token.
- **DNS TXT:** Proof at `_lumicsec-challenge.<asset-domain>` containing `lumicsec-verification=<token>`. All A/AAAA addresses must be public and DNS queries are bounded.
- **HTTPS file:** `https://<exact-asset-domain>/.well-known/lumicsec-verification.txt`; pinned previously validated public socket IP, real TLS/SNI validation, no redirects, 4s timeout and 512B maximum body.
- **Safety:** Reject localhost/private/reserved addresses, IPv6 mapped/6to4/Teredo, mixed public+private DNS responses, wrong hostname, wrong token, expired challenges, cross-org access. No arbitrary URL, port, credential or path accepted.
- **Completion:** Only trusted `service_role` database RPC can atomically confirm observed proof, origin/asset/org binding, validity and current owner/admin membership. Regular user JWT cannot self-certify.
- **Validity:** Successful proof is time-limited to 30 days; old `verified` rows with NULL expiry are not considered currently authorized. Revocation immediately makes ownership noncurrent; audit is retained.
- **Current local blocker:** `SUPABASE_SECRET_KEY` intentionally absent from founder's `.env`. Check endpoint refuses with 503. Do not insert a secret in public Git, client env or logs. Founder-controlled secure key provisioning is needed before **actual** ownership verification; until then no verified status is issued through the local application.

## 4. Test evidence — RBAC and ownership checkpoint

- **Development database:** two forward-only migrations applied after existing 20261118133942 foundation. The second forward-only migration repaired a PostgreSQL varchar/text return mismatch without rewriting the first migration.
- **Rollback-only SQL:** `supabase/tests/rbac-ownership.sql`; synthetic users/orgs, last-owner guard, member/admin role boundaries, invitation creation/one-time accept, expired invite, wrong-email and cross-tenant denial, AAL1/non-Google rejection, wrong/expired challenge, owner revocation, service-role-only completion and audit. Transaction ends in `ROLLBACK`. No permanent synthetic rows.
- **2026-11-19 recovery and quality gates:** Recovered **12 tracked modified + 14 untracked** files from the founder's original checkout; no re-clone/reset, unrelated process termination or file destruction. Full frozen dependency installation, production build, lint, TypeScript, unit/API suites, and production dependency audit passed: **178/178 automated tests** after an additional DNS stall regression. The CLI's old idle migration-new process was terminated after verifying both migration files were already present and the development database migrations applied. The synthetic browser fixture server was retained to validate its stored 8/8 result reports, then stopped when testing ended. GitHub Actions must be checked at the exact final commit before CI is called green.
- **Direct Data API RLS tests:** The old foundation `supabase/tests/tenant-isolation.sql` and extended `supabase/tests/rbac-ownership.sql` both pass in development PostgreSQL with transaction rollback. New checks cover an existing member's AAL1 reads, AAL2 JWT missing TOTP AMR, non-Google AAL2, and fully authorized AAL2 reaccess. Six restrictive RLS policies preserve original membership AND authorization.
- **Network tests:** `apps/api/tests/ownership-proof.test.ts` uses injected synthetic DNS answers and an instrumented HTTPS mock; added a **4s total DNS deadline** and **5s absolute HTTPS deadline** (in addition to 4s idle timeout and 512B content cap); **no real customer website or DNS target** is queried.
- **API route tests:** `apps/api/tests/organization-ownership-routes.test.ts` verifies AAL2, error mapping, cross-tenant DB rejects, spoofed client tokens, 503 fail-closed without trusted key, pending challenge and revocation semantics.
- **UI browser fixture:** `apps/web/tests/organization-ownership-smoke.mjs` serves compiled React with synthetic API responses only. Tests owner and member roles in Team and Assets screens, private one-time invite UI, challenge instructions, no-scanning messages and missing-key failure.
- **Known nonblocking build issue:** Vite large bundled client chunk warning; code splitting and performance checks before production.
- **Known Supabase INFO:** `organization_invitations` has deliberately no direct RLS SELECT policy and no authenticated table grant; authorized RPCs only. Advisor `rls_enabled_no_policy` is expected deny-all, not a missing invitation authorization rule.
- **Existing Auth WARN:** leaked password protection disabled. Primary login is Google-only, but review project settings before launch. See <https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection>.

### Do not promote without

- Founder-assisted Google OAuth plus real backup MFA enrollment, all recovery codes and re-enrollment lifecycle.
- Hosted cross-tenant owner/admin/member invitations and email delivery with multiple real test accounts.
- Safely provisioned server-only trusted DB key, actual DNS/HTTPS ownership tests using **founder-controlled** domains and independent evidence; no unknown/customer website checks.
- Review of RLS function/grant threat model and separate worker authorization; see launch blockers.

## 5. Known bugs, limitations and deliberate nonfeatures

| Status | Item |
|---|---|
| Blocker | Local ownership proof completion requires a properly secured server-only trusted Supabase key; absent by design on founder laptop. |
| Blocker | Signed Google OAuth/backup TOTP E2E, recovery codes, session revocation/expiry and owner-approved factor rotation remain incomplete. |
| Partial | Manual invitation token handoff is implemented; email invitations/notification templates/provider delivery are not. |
| Partial | Member management is bounded to 100 members and invites per page; pagination, ownership transfers UI and membership export are pending. |
| Partial | DNS TXT proof currently checks bounded records and the first syntactically valid candidate; customers should remove obsolete TXT records when renewing. |
| Partial | Ownership revocation/expiry is enforced in the DB predicate, but no qualified scanner scheduler has been launched; future workers MUST check ownership at queue AND execution time. |
| Partial | Server-only service key cannot be configured without explicit local founder secret provisioning. No shortcuts or direct browser UPDATEs. |
| Partial | Real customer website/API proof browser qualification and browser support matrix not finished; synthetic fixture tests are not substitutes. |
| Partial | Production observability, audit retention, abuse detection, replay and rate-limit load tests are still pending. |
| Partial | Vite bundle >500 KB warning; split routes, measure load/performance. |

## 6. Full commercial roadmap (retain original scope)

1. **Authentication recovery and session security** — audited hashed single-use recovery codes, rotation, device/session inventory, Google+TOTP E2E, backup management and suspicious login monitoring.
2. **Organization RBAC + Asset Ownership Verification** — this checkpoint: code + DB tests, browser/UI checks, key provisioning and hosted proof final acceptance still pending.
3. **IN PROGRESS: Advanced Authorized Web/API Security Engine Integration** — exact SHA source evidence rechecked and **authorized persisted offline API-spec assessments** now development-integrated. Existing offline Web passive modules retained. A separate bounded execution worker, pinning/SSRF-safe network transport, durable cancellation and actual live customer assessments remain **pending/not authorized**. Never enable scanning without explicit founder approval.
4. **Ownership and scanning execution controls** — proof gate at scheduling AND execution, allowlisted scopes, per-target rate/concurrency/bytes, DNS rebinding defenses, private IP blocking, safe redirects, kill switches and asset revocation handling.
5. **Findings, evidence, severity and remediation** — reproducible evidence, manual review, false-positive controls, no synthetic rule presented as a verified vulnerability, retesting and status history.
6. **Professional reporting** — executive + engineer PDF exports, evidentiary trail, customer-specific branding, scheduled authorized delivery.
7. **Monitoring** — bounded recurring authorized checks, drift history, alert routing, pause/resume, cost caps, no unsanctioned traffic.
8. **Customer, agency and founder dashboards** — onboarding, organizations, RBAC, asset portfolio, security posture, cross-tenant agency boundaries, support administration and analytics.
9. **Billing and entitlement management** — design subscription tiers, metering, limits, invoices, retries, tax and webhook idempotency. **No live payment or paid subscription activation without founder approval.**
10. **Integrations, public commercial website and operations** — marketing/onboarding, support workflow, help center, API/SSO where authorized, audit export, policies and data retention.
11. **Full quality assurance and release qualification** — independent pentest, RLS cross-tenant coverage, auth recovery, data privacy, backups/disaster recovery, abuse/cost management, performance, accessibility, browser E2E and launch readiness.

**Next checkpoint:** isolate and qualify the bounded, zero-privilege authorized-read worker + SSRF/DNS-pinned transport with synthetic targets, then connect existing Web passive modules to the authorized job/evidence pipeline. Maintain all current release blockers. This milestone must not activate customer network scanning.
