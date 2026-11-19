# LumicSec — Authorization-gated offline API assessments: development qualification

**Date:** 2026-11-19 (Asia/Kolkata)
**Target:** `mallikalyan390-dotcom/lumicsec`, `main`.
**Starting GitHub/local HEAD:** `c84570c686fa470b50cb8c7fe36610f27fe1e31b`.
**Status:** TARGET-SYNTHETIC/DEVELOPMENT-INTEGRATED, NOT HOSTED-CUSTOMER-QUALIFIED.
**Production / live network traffic:** DISABLED. No target HTTP requests or DNS scans issued.

## Provenance and reviewed source

- Web audited source `kalyankumarmalli480-sys/lumicsec-security-platform`, branch `audit/preintegration-forensic-completion-20261117`, SHA `10704777f758737927d70aed9c95c0f4f9d98e1c`. The pinned `src/lib/web-assessment/analysis.ts` was fetched independently. Previously integrated `@lumicsec/web-security-engine` passive response capture, bounded injected-read discovery and deterministic analysis were **preserved unchanged**. No unqualified Web transport was imported.
- Relevant later Web branches independently verified: `integration/unified-web-api-s0-s1-20261111` at `9959e4a1929949c87d5f97a4302057ed5d3f615a` and `work/web-family-phase20-complete-product-ux-operations` at `edfe0bb663c6be6c157176231e88bc35bd8b5331`. Later workflows do not automatically qualify the target stack.
- API source `mkalyankumar903-hash/API-security-family`, branch `work/phase15-plugin-packaging-release-qualification-handover`, SHA `ff8bf63b71eee8f349a7003ae419b8a0ad39c398`. Pinned `packages/assessment-engine/src/inventory.ts` fetched independently; existing `@lumicsec/api-security-engine` OpenAPI 3.x / Swagger 2 importer, Postman inventory and deterministic spec rules are reused, not duplicated. Existing importer already prohibits network fetches, external references and unbounded spec traversals.
- Existing `THIRD_PARTY_NOTICES.md` records the founder-owned source provenance and missing source-branch LICENSE/NOTICE/COPYING files. No new source package, licence claim, copied auth app or dependency was added in this checkpoint. Dependencies and lockfile were preserved.

## Delivered implementation

- `POST /v1/assessments/api-spec`: bounded document up to 1 MiB, **400-operation ceiling**, explicit `I_AM_AUTHORIZED_FOR_OFFLINE_SPEC_REVIEW` declaration, verified API asset, Google+TOTP AAL2, authenticated tenant-scoped asset lookup. Only trusted backend invokes database RPC; no URL fetches or raw specification storage.
- `GET /v1/assessments/api-spec`: last 30 tenant-scoped offline jobs, status, format, source fingerprint, authorization timestamp and coverage metadata. `GET /v1/assessments/api-spec/observations`: up to 100 review-only persisted observations. Both use the authenticated customer's RLS client.
- `POST /v1/assessments/api-spec/cancel`: cancels an active job only after authenticated job visibility and server-authorized membership check.
- `apps/web/src/components/SavedAssessmentsPanel.tsx`: owner/admin/legacy-analyst gated verified API asset selection; document upload, explicit scoped consent, saved history, review observations and bounded cancellation. Legacy transient upload stays intact. Viewer/member sees read-only history; cannot submit.
- Forward-only development migration `20261119013152_authorized_offline_api_assessments.sql`: database-owned queue/begin/complete/stop state machine. Queue and execution revalidate active owner/admin/analyst role plus exact org + asset + currently verified proof; expires authorization after two minutes, caps concurrent jobs to two per asset and cancels stale entries. Result commit **again checks** ownership/role and requires bounded observations and coverage. Results are review-only, never confirmed runtime vulnerabilities. Audits queue/complete/stop/revalidation cancellation. Only `service_role` may execute the write RPCs, no direct authenticated write grant.
- New backend secret provisioning is **not** performed. Without server-only `SUPABASE_SECRET_KEY`, the saved-assessment endpoint returns 503 and does not queue. This prevents self-certification on the founder laptop.

## Customer security value and limits

**Problem:** API specifications can drift from documented authentication and input schemas; one-off transient scans do not preserve what was reviewed.
**Evidence:** durable organization-and-asset-scoped job provenance, normalized fingerprint, rule names, severity estimate, bounded remediation guidance, coverage metadata, explicit limitation statements.
**Action:** authorized teams can review and correct their API design, compare future retained runs manually and start follow-up review workflows when later implemented.
**Recurring value path:** saved history and repeated voluntary offline reviews support future remediation/retest/monitoring subscriptions. Automatic schedules, pricing, entitlements and notifications are **NOT** implemented or sold.
**Claim limit:** only static specification observations, with `SPEC_ONLY` or `INVENTORY_ONLY` designation; zero runtime API requests, no exploit validation, no assertion that the target is secure. Postman remains inventory-only.

## Tests executed (development / synthetic only)

1. `pnpm install --frozen-lockfile` PASS — no lockfile changes or dependency additions.
2. `pnpm lint`, `pnpm typecheck`, `pnpm build` PASS (Vite warns about a bundle above 500 KB; performance refinement pending).
3. `pnpm test` PASS **192/192 tests** across packages (API 133, validation 45, API engine 5, Web engine 4, frontend 5). New API route test suite: **14/14** tests.
4. `pnpm security:audit` / production high-severity dependency audit PASS (no known vulnerabilities reported).
5. Supabase development migration `20261119013152` applied after confirming the four previous versions already existed. Direct PG privilege check: authenticated cannot queue, service_role can, `assessment_jobs` RLS enabled and existing restrictive Google+TOTP AAL2 policy retained.
6. **Rollback-only actual development PostgreSQL:** `supabase/tests/offline-api-assessments.sql` PASS including valid result writes, duplicate-completion rejection, cross-tenant and AAL1 isolation, pending/revoked ownership denial, mid-execution revocation, evidence caps and no partial invalid evidence writes. Existing `tenant-isolation.sql` and `rbac-ownership.sql` also PASS unchanged. No synthetic user, tenant, asset or job persisted.
7. Compiled Chromium React UI via `apps/web/tests/offline-api-assessment-smoke.mjs`: **3 synthetic scenarios passed**: owner consent/upload/result/history/evidence, member read-only access, and unverified asset denial. Browser sent one synthetic authorized submission, no external target request. Browser fixture tested the built JS, not real Supabase login.
8. Existing ownership resolver/SSRF tests remain included in API 133/133; this checkpoint did **not** implement a new network transport, so runtime DNS rebinding/SSRF qualification is NOT satisfied.
9. Commit SHA and exact-HEAD GitHub CI results must be added following push.

## Security and release limitations

- Saved offline processing is **in-request**, not a separate durable worker; no background queue consumer, execution isolation sandbox, cross-process kill switch, schedule/resume/retry lease or validated hosting load limits. The DB provides state transitions and bounded idempotency constraints, not a qualified distributed worker system.
- Scanning of live Web or API targets, DNS rebinding protection for future scanner transport, private-network blocking for a new scanner and externally reached asset endpoints remain entirely **DISABLED / NOT IMPLEMENTED**. Existing DNS/HTTPS ownership verification SSRF safety is separate.
- Real hosted ownership acceptance, secure backend secret provisioning, multi-user invitations, email delivery, MFA recovery codes, session expiry/revocation, real backup factor E2E, customer-owned test fixture E2E, independent security review, regulatory/privacy work and production hardening remain pending.
- No new production infrastructure, paid service, production deployment, commercial traffic or payment action was activated.
- Next: independently qualify an isolated authorized-read transport and Web passive runtime with synthetic pinned-IP, DNS rebinding and cancellation test fixtures; reauthorize on scheduling, execution and resume. Do not enable live customer scanning without explicit founder approval.
