# Controlled Network Broker + Authorized Synthetic Web/API Runtime Qualification
**Milestone date:** 2026-11-19.
**Starting exact main:** `9817834dbb8e3540e9105fed1877c7a469d0e75a`; CI `44462631056` SUCCESS; lockfile `44462631011` SUCCESS.
**Outcome:** Local DEVELOPMENT / CONTROLLED SYNTHETIC FIXTURE ONLY. **No production or customer scanning qualification.**

## What is actually implemented

The original no-egress worker remains the default and customer `POST /v1/assessments/web` remains HTTP 423. No customer route can trigger the new runner. The new explicit opt-in developer-only commands are `pnpm build:controlled-runtime`, `pnpm test:controlled-runtime`, `pnpm capture:controlled-runtime`. They do not create cloud resources, change firewall/DNS, use real customer targets or authenticate as real customers.

Architecture:

1. Trusted local controller claims a bounded Web job using the existing `executeWebSandboxController` store/heartbeat/generation fencing (when in Web mode). The controller alone owns any DB lease; its claim token and Supabase secret never enter the worker, bundle, environment, socket or report. API mode has a separate explicit synthetic fixture executor (no production scheduler, worker polling or customer queue).
2. A unique, temporary **AF_UNIX socket** links the Docker worker to an independent trusted host broker. Docker retains `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534`, CPU 0.5, 128 MiB memory, pids 24, private 16 MiB tmpfs, <=17s controller deadline. Mounts only a compiled unprivileged bundle and the **read-only socket-only directory**; TLS private keys are in a parent directory NOT mounted to the worker. No Docker socket, host home, `.env`, arbitrary host networking or general DNS route.
3. The broker accepts one strict JSONL GET request per socket: schema version, execution ID, exact authorized origin/URL, one of three synthetic identity **labels**. It checks the hard-coded fixture hostname/profile, path, method, no query/fragment, protected paths, remaining request/response/deadline budget, single concurrency and caller cancellation. It never accepts an arbitrary hostname, body, method, header or bearer credential. The credentials `SYNTHETIC_*_FIXTURE_ONLY` exist in host-only broker code, never the worker bundle or output.
4. A *real* HTTPS server with a short-lived SAN certificate (generated for the controlled hostname) is bound to host `127.0.0.1` ephemeral port. The broker's **test-only HTTPS request factory** substitutes the local socket and temporary CA while retaining hostname/SNI verification, GET-only, exact origin and no redirects. Verified HTTPS response data traverses broker IPC back into the no-network Docker worker; only bounded allowed response headers/body travel inward. The worker computes summarized SHA-256 evidence without persisting raw API bodies or synthetic bearer strings.
5. **Important isolation limit:** The broker is a trusted host process; its OS-level network namespace is not independently restricted to the target. Test-only resolver substitution simulates a public candidate `8.8.8.8` but actually connects to the local fixture. Thus no production-grade public-IP pinning/real DNS egress isolation through the broker has been demonstrated. The existing `PublicPinnedWebTransport` validates all DNS answers, public IP classification and rebinding, and the default worker remains no-egress, but full real-public broker isolation needs a separate architecture/security qualification before activation.

## Exact source components reviewed/reused

- LumicSec original pinned/GET-only `apps/api/src/lib/web-pinned-transport.ts`, the `PublicPinnedWebTransport`, bounded response streaming, TLS hostname checking, DNS-all-answers and private/metadata address blocking. This milestone additionally prevents encoded dot-segment traversal **before** URL parser normalization.
- Existing Web security engine `@lumicsec/web-security-engine` `crawlWebAssessment`, `analyzeWebAssessmentSnapshot`, existing `executeUnprivilegedWebRead` and `mapWebEvidence`, existing `WEB_READONLY_V1` strict IPC and trusted controller/stale-lease state machine. No Web engine or protected customer route was replaced.
- Source `mkalyankumar903-hash/API-security-family` inspected on GitHub: **current `main` contains README only**. Existing packaged `@lumicsec/api-security-engine` `parseAndValidateSpec`/`assess` was imported from founder-controlled historical Phase15 `ff8bf63b...` and remains **SPEC_ONLY**. New runtime checks are separate: no synthetic-only PT rule is falsely upgraded to runtime exploit proof.
- New files: `controlled-runtime-broker.ts`, `controlled-broker-client.ts`, `controlled-runtime-contract.ts`, `controlled-runtime-entry.ts`, `controlled-runtime-runner.ts`, `controlled-api-runtime.ts`; standalone bundle via `build-controlled-runtime-worker.mjs`. Bundler checks **zero privileged imports and zero embedded synthetic credentials**.

## Actual detection evidence: controlled, synthetic, bounded

`apps/api/tests/fixtures/controlled-runtime-actual-results.json` was generated by **four independently executed real Docker + Unix broker + HTTPS fixture sessions**, not by hand-written expected response objects. Captured status, coverage, rule IDs, immutable SHA-256 evidence references, execution IDs, job/source scope, byte counts. File contains no bearer credentials or raw customer content. Runtime API makes **three serialized GET requests** to `/v1/accounts/owner`: anonymous, synthetic owner and synthetic other. Web makes one bounded GET to `/`. No public network requests.

| Rule | Intended detection | Insecure fixture actual | Secure fixture actual | Result/interpretation |
|---|---|---|---|---|
| `P09.COOKIE.SECURE_AGG` | Missing cookie attribute | Observed | Not observed | Cookie configuration estimate; not proven theft |
| `P09.HSTS.ABSENT` | Missing HSTS | Observed | Not observed | Header-only |
| `P09.CSP.ABSENT` | Missing CSP | Observed | Not observed | Not XSS verification |
| `P09.FRAME.NO_POLICY` | Missing clickjacking policy | Observed | Not observed | No clickjacking exploit |
| `P09.XCTO.CONFIG` | Missing nosniff | Observed additionally | Not observed | Bounded configuration signal |
| `API.RUNTIME.AUTH.ANON_SUCCESS` | Anonymous request to fixture-protected path returns success | HTTP 200 | HTTP 401 (not observed) | **INCONCLUSIVE review signal**; HTTP success alone does not prove data disclosure |
| `API.RUNTIME.AUTHZ.OTHER_SUCCESS` | Other synthetic identity receives success on owner's path | HTTP 200 | HTTP 403 (not observed) | **INCONCLUSIVE review signal**; not confirmed object-level exploit |
| `API.RUNTIME.HEADER.HSTS_ABSENT` | Missing HSTS on API response | Observed | Not observed | Configuration-only |
| `API.RUNTIME.HEADER.NOSNIFF_ABSENT` | Missing nosniff on API response | Observed | Not observed | Configuration-only |

**Controlled-fixture targeted score:** Web 4/4 intended insecure positives, 0/4 false alarms in secure comparator, 0/4 misses in these four selected rules. API 4/4 intended insecure review signals, 0/4 false alarms in its secure comparator, 0/4 misses in these four selected rules. These tiny controlled-fixture numbers are **NOT real-customer precision/recall, vulnerability detection accuracy, or broad security coverage**.

Unsupported: production DNS/HTTPS destinations, logged-in human Web journeys, non-GET requests, parameter fuzzing, CSRF/XSS/SQLi, API logic and complex object policies, API rate limiting, encrypted secret vault, full endpoint inventory coverage, side-channel checks, OAuth audience/scopes, tenant-wide business impact, signed forensic proof, independent resolution certification. A 200 response may be a login/placeholder page, so authorization outcomes remain review signals.

## Security/negative test evidence

- Local **real Docker + TLS broker integration** test `controlled-runtime-container.test.ts`: 15 opt-in cases including secure/insecure Web/API, Web/API redirects to metadata denied, oversize Web/API denied, slow/timeout Web/API denied, cancellation killing in-flight Docker container, duplicate execution rejected, lease-loss Web controller denial, scope mismatch and private-address protection. Worker never obtains a general TCP route.
- Always-on **contract and captured-evidence tests** `controlled-runtime-contract.test.ts`: 8 cases verifying actual captured source result, secure comparison, strict protocol/scope fingerprint tampering, malformed URL fail-closed Unix-socket recovery, POST/arbitrary header rejection, DNS mixed rebinding/private/metadata denial before any socket, and encoded traversal/cross-origin/query denial.
- Existing 9 opt-in isolated-worker Docker tests remain required for independent real kernel network namespace no-egress proof, SIGKILL/crash fencing, resource caps and secret separation. Existing Web controller tests cover cancellation, revocation, duplicates and stale leases.
- **Actual development PostgreSQL** rollback-only `ROLLBACK_ONLY_ACTUAL_RUNTIME_API_FINDINGS_PASS`: the exact captured 4 runtime API observations are recorded via a service-role-only fixture RPC for a synthetic verified-owned `https://controlled-api.fixture-api.net` asset, imported via existing AAL2 role-controlled `findings_import`, source fingerprints/evidence links and review decisions verified. Secure actual 0-observation comparator saved later and retest returns `not_observed_in_review`, **never** `verified_resolved`. Cross-tenant, AAL1, revoked ownership, replay conflict, browser direct SQL privilege denied. Transaction rolled back; no synthetic users, customer assets or findings retained.
- Existing real Web SSL fixture and all prior rollback-only tenant isolation/ownership/assessment/Findings SQL suites must remain green. Browser acceptance uses the compiled React UI in isolated Chromium and Firefox with synthetic API responses, not a hosted Google OAuth session. Added both browsers' customer saved API-runtime-finding review sourced from the actual Docker JSON capture (existing full Findings workflow unchanged).

## Database and release separation

Forward-only **development-only** migrations, preserving earlier nine:
- `20261119052948_controlled_api_runtime_review`: add `api_runtime_review` assessment/finding kind, `runtime_fixture_only` flag, exact fixed-origin **service_role-only synthetic recorder**, existing authorized findings import/retest extension. No customer queue/scan endpoint, no new public table or RLS weakening.
- `20261119053303_runtime_fixture_completion_clock`: accurate post-request comparator completion timestamp in one rollback-only transaction.
- `20261119053433_runtime_api_retest_coverage`: use API's actual result-coverage rather than Web report when comparing. All outputs stay review-only and never auto-resolved.

**12 total applied migrations, 12 existing RLS-enabled application tables.** No production billing, deployment, customer scanning or paid services. No MFA changes.

## Production security blockers and next milestone

**NO-GO for customer or public network scanning.** Missing hardened independently restricted broker network namespace (or transparent egress proxy), independently proven real public DNS/IP pin and rebinding after connection retries, full host-to-Docker principal attestation, signed minimal images, end-to-end AAL2 and authorization before live queue, secure actor-scoped short-lived credential vault, zero-trust request logging/secret masking, hosted scan governor/cancel/reclaim/scheduler, audit retention, real multi-tenant report download/retest proof, independent external penetration review, incident kill switch and founder explicit approval. The current fixture probe assumes a known protected path and synthetic identities, not a general customer runtime API scanner.

**Next customer-value milestone:** tenant-scoped *authorized runtime assessment plans* (safe explicit endpoint allowlists, customer consent/grant expiration, managed short-lived synthetic test identities, dedicated confined broker with destination-only egress proven by OS/network tests, hosted controller admission and independently reviewed launch gates), then real verified retesting under audit. Advanced Web/API, monitoring, billing/entitlements, agency workflows and enterprise/commercial launch remain on the roadmap.
