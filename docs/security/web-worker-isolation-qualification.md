# Isolated authorized Web assessment worker — development qualification

Date: 2026-11-19. Repository: `mallikalyan390-dotcom/lumicsec`; branch: `main`.
Baseline before work: `ccb8331dec7e21c842f4251fee04cde3f924c792` (remote = local; clean).
**Classification: DEVELOPMENT + CONTROLLED SYNTHETIC TLS ONLY. NOT A PRODUCTION SCANNER.**

## Independent source qualification and selective reuse

The founder-controlled original Web Security source repository
`kalyankumarmalli480-sys/lumicsec-security-platform` was independently checked at:

- Audit `10704777f758737927d70aed9c95c0f4f9d98e1c`.
- Phase 20 `edfe0bb663c6be6c157176231e88bc35bd8b5331`.

Pinned source files reviewed on BOTH SHAs:
`src/lib/pentest/network-safety.ts` (blob `933d1548a11ce1341b373b7e754b41909772b0f3`),
`node-read-only-transport.ts` (`f52326beedd31ae1a074e2500797f857523c5813`),
`safe-execution.ts` (`b1d7be25f8139d2a74aaaba76b74b7ab65a2bac5`),
`safety-governor.ts` (`7740bfb4501815b3c174135a4226af5fe89df1e4`) and
`runtime-contracts.ts` (`154b61485d4936712cebc63ff062458e9a1d1feb`).
Existing, independently reused `@lumicsec/web-security-engine` response capture,
discovery and deterministic analysis source blobs preserved unchanged:
response capture `3773e036753ef376a18198a16a0ba0fe40a8c10b`,
discovery `77478a621b17fb6034a1355c9311f5d16590c109`,
analysis `62c6e38552947b1b431eb593e51b3244dcf6f8d3`.

The original pentest executor directly imports legacy Phase 6 execution grants, old contracts and
custom SSRF resolution tied to the old Next.js application. Rather than importing its auth,
database, or broad dependency graph, a constrained adapter reuses its IP blocklist,
one-shot IP pin, TLS/SNI, streaming size bounds, absolute timeouts and cancellation concepts.
Source attribution in code comments is preserved. No external Web scanner packages added.
Only a workspace dependency `@lumicsec/web-security-engine` was linked to Fastify's backend.

## Implemented end-to-end development contracts

- `apps/api/src/lib/web-pinned-transport.ts`: exact HTTPS same-origin, GET/HEAD-only,
  forbids URL parameters and sensitive paths, denies private/reserved/metadata IPv4,
  mapped/tunnel/ULA IPv6, mixed DNS answers and unsafe redirects. Every socket is
  DNS-preflight pinned; TLS hostname, SNI and CA verification stay on. Compression denied.
  Streaming body/header size budgets, absolute socket timeout, AbortSignal cancellation.
- `apps/api/src/workers/web-assessment-worker.ts`: separately runnable claim-driven worker.
  Existing Phase 8 discovery and Phase 9 deterministic analysis reused unchanged.
  Hard limit **6 requests, 240,000 aggregate bytes, 60,000 bytes per response, 2 seconds
  per HTTP request, 1.5 seconds DNS, 15 seconds overall, 1 concurrent read,
  0 followed redirects**, depth 1. Heartbeat before and after each read and periodically.
  Retains bounded rule ID, evidence fingerprints/node IDs, priority, explanation, remediation,
  limitations; omits raw cookies, response bodies, credentials.
- `apps/api/src/workers/web-supabase-store.ts`: backend-only Supabase service role adapter.
  Requires separately provisioned secret; cannot be created from customer browser.
- `supabase/migrations/20261119021508_isolated_authorized_web_assessments.sql`:
  forward-only, applied to **development Supabase project only**. Adds idempotent,
  organization/asset-bound Web jobs, 5-minute queue authorization, 20-second worker
  leases, SHA256 token hash, fencing generation, recheck ownership and org role
  on queue/claim/heartbeat/completion, capped results, atomic tenant-isolated
  persistence, and auditable cancellation. New public RPC wrappers are
  **service_role-only** and no browser write grants are added. Previous five
  migrations and existing records retained.
- `apps/api/src/routes/web-assessments.ts`: Google+TOTP AAL2 protected RLS
  tenant-isolated Web history, evidence, cancellation. **POST creation HARD DISABLED
  (HTTP 423)** even for properly authorized clients; public network scanning
  remains disabled pending founder approval, worker isolation and hosted qualification.
- `apps/web/src/pages/WebSecurityPage.tsx`: React customer route, verified website
  selector, explicit permission language, disabled scan button, job states,
  observations including actual source fingerprints, classification,
  remediation, limitations, review history, role-limited cancellation.
  Full API offline import and organization/ownership functionality preserved.

## Actual controlled TLS execution — detection accuracy

The integration test generates ephemeral self-signed TLS credentials **inside a temporary
test directory** (never committed), starts a real local HTTPS server on loopback,
and uses an explicitly test-only request factory to connect to that isolated fixture.
The production transport does **not** allow loopback. The worker performs real
HTTPS GETs with certificate validation against the ephemeral fixture certificate,
through the actual pinned transport, existing discovery and existing analyzer.
A second test spawns a **separate Node OS process** that runs the same worker
against that local TLS fixture without a Supabase key.

| Targeted passive rule | Expected insecure fixture | Actual insecure fixture | Expected secure fixture | Actual secure fixture |
|---|---|---|---|---|
| `P09.HSTS.ABSENT` | Signal | Detected | No signal | Not flagged |
| `P09.CSP.ABSENT` | Signal | Detected | No signal | Not flagged |
| `P09.FRAME.NO_POLICY` | Signal | Detected | No signal | Not flagged |
| `P09.COOKIE.SECURE_AGG` | Signal | Detected | No signal | Not flagged |

Targeted detections: **4 expected positives, 4 detected; 4 expected negatives,
0 incorrectly flagged; targeted false positives = 0; targeted misses = 0**.
This is **one controlled fixture pair**, not statistical real-world accuracy or
proof of exploitability. Other passive observations can be present.
No authenticated runtime, XSS, SQL injection, CSRF proof, business logic exploit,
credential disclosure, false-positive calibration against production or full
attack-path detection was performed. These categories remain NOT TESTED.

## Acceptance and security negative results

Real local TLS:
- Redirect attempts to cloud metadata denied without second socket.
- Oversized responses rejected, no partial evidence persisted.
- A slow fixture triggers a 2-second absolute HTTP deadline.
- Six-request discovery cap tested against 18 internal links.
- Cancellation aborts in-flight HTTPS request; lost ownership/claim blocks result commit.
- Duplicate/stale worker claim denied; result-time authorization denial blocks commit.

Unit/runtime checks: private and metadata IPv4/IPv6, DNS rebinding, mixed DNS answers,
DNS resolution timeout, exact origin, URL query/path, unsupported methods.

Actual development PostgreSQL rollback-only suite:
`supabase/tests/web-worker-lifecycle.sql` =>
`ROLLBACK_ONLY_WEB_WORKER_LIFECYCLE_PASS`.
Covers pending/revoked ownership, wrong tenant actor, direct authenticated
RPC denial, idempotency key, duplicate claim, stale claim fencing/reclaim,
revocation at heartbeat/commit, bounded result insertion, double-completion,
AAL1 and cross-tenant reads. Zero synthetic rows persisted.
Existing `tenant-isolation.sql`, `rbac-ownership.sql`, and
`offline-api-assessments.sql` were rerun successfully after migration.

Local Web UI synthetic compiled-bundle browser fixture:
`apps/web/tests/web-assessment-customer-smoke.mjs` on localhost only;
checks owner, member, expired/unverified, evidence, remediation, safe
no-observations reporting, and no public scan queue traffic.
Chromium owner/member/unverified scenarios **3/3 PASS**, no customer scan enqueue calls. Firefox fresh-profile headless launch/screenshot succeeded (exit 0) but interactive DOM assertion/report did not complete; **Firefox customer-workflow acceptance not qualified**.

## Boundaries / release blockers

The real worker is a separately spawned Node OS process in the controlled fixture,
**not** a production sandbox, container, hardware-enforced egress policy, or
independently secured hosted execution infrastructure. Customer POST is locked.
There is no production worker daemon/poller running, no hosted customer network
requests, no live customer onboarding, no globally deployed kill switch,
no third-party asset scanning approval, no paid infrastructure, no commercial
deployment and no production billable subscriptions.

Hosted current-owner proof and real multi-user AAL2 acceptance, secure backend-only
service credential provisioning, invitation emails, MFA recovery codes,
session revocation/expiry, real backup MFA E2E, distributed worker durability,
replay/abuse/load controls, compliance review, independent pentest, professional
reporting/remediation/retest/monitoring/billing remain pending.

**Next milestone:** founder-authorized hosted-independent sandbox/eBPF/network-egress
isolation and production worker hard kill controls; demonstrate actual DB-backed
worker and real owned hosted fixture acceptance before any customer network scans.
All user-facing live scanning stays disabled.
