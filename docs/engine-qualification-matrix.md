# Engine qualification matrix

Status labels: SOURCE-EVIDENCE-PASS, TARGET-INTEGRATION-PENDING, SPEC-ONLY, SYNTHETIC-ONLY, DEFERRED, NOT-IMPLEMENTED.

| Component | Source status | LumicSec status | Safe commercial claim |
|---|---|---|---|
| Web passive response capture | Source Phase 20 regression evidence passed | Copied; target unit/API regression tests passed; code CI 44345864482 passed; hosted runtime still unqualified | Passive header / cookie-attribute observation only |
| Web passive discovery | Source Phase 20 regression evidence passed | Copied; target unit/API regression tests passed; code CI 44345864482 passed; hosted runtime still unqualified | Bounded discovery through an injected authorized-read adapter |
| Web deterministic analysis | Audited+Phase20 blobs inspected; existing source module unchanged | Same engine executed against actual isolated local HTTPS fixture via bounded worker: 4/4 chosen insecure rules detected; secure comparator 0/4 false signals; evidence fingerprint/classification/remediation stored through qualified dev DB RPC. Hosted customer runtime unqualified | Passive review-only signals; not proven vulnerabilities |
| Web SSRF network safety | Source Phase07 network-safety `933d1548...` and node transport `f52326be...` independently inspected at audited and Phase20 SHAs | Adapted to new restrictive target transport. Local IP literal/private/meta/IPv6 tunnel exclusion, all DNS answers, rebinding regression, zero redirects, exact-origin GET-only tests PASS. Production sandbox and independent network review pending | No live customer transport certification |
| Web pinned HTTPS GET transport | Audited `10704777` + Phase20 `edfe0bb` code inspected for pin, policy and bounded streaming dependencies | **Development synthetic TLS execution PASS:** target adapter validates all DNS answers, pins public IP socket and validates TLS, no redirects or credential, byte/deadline/cancellation limits; 37 real fixture/negative tests including independent OS subprocess. Hosted network qualification and independent egress sandbox pending | Passive, controlled synthetic read-only signal extraction only; customer scanning DISABLED |
| API OpenAPI / Swagger parsing | Source Phase 15 test evidence passed | Copied; target unit/API regression tests passed; code CI 44345864482 passed; hosted runtime still unqualified | Offline specification import and structural validation |
| API deterministic rule engine | Source Phase 15 test evidence passed | Copied; target unit/API regression tests passed; code CI 44345864482 passed; hosted runtime still unqualified | SPEC_ONLY observations; no runtime exploitability claim |
| API Postman import | Source inventory supports it | Imported as inventory only; supported by new bounded persisted offline job path without deterministic API vulnerability claim | No OpenAPI-equivalent security assessment claim |
| Verified-asset offline API job execution | Uses existing pinned-source API import and deterministic SPEC_ONLY engine; no new external engine import | Development database `20261119013152` applied; service_role-only queue/begin/complete/stop, role/proof rechecks, bounded evidence, audit, tenant-isolated history and explicit consent React UI; 14 API tests + rollback SQL + 3 Chromium scenarios passed; hosted real-user completion **blocked** | Saved offline review observations only, not runtime security tests; production worker not qualified |
| Isolated Web worker lease / authorization | Source Phase06/07/20 grant/governor contracts reviewed, not copied due legacy dependencies | **Development-level:** forward-only Supabase `20261119021508` lease token hash, generation fencing, revocation checks at queue/claim/heartbeat/commit, fail-closed stop, tenant history, AAL2 customer UI, real SQL rollback PASS; subprocess local TLS fixture PASS. No production daemon/sandbox/hosted customer scan | Bounded controlled synthetic-only Web assessment, customer scan activation permanently disabled pending founder approval |
| API authenticated runtime / authorization testing | Host adapters disabled or incomplete in source qualification | Not integrated | No live API vulnerability claim |
| Synthetic PT detection | Synthetic fixture coverage only | Not integrated | Never market fixtures as real detection |
| Google OAuth + TOTP | Source policy tests and source integration evidence exist | BFF Google/TOTP AAL2 gates; founder manual-TOTP dashboard evidence; independent local PNG decode; read-only AAL2 factor list and backup enrollment UI with mocked tests; full hosted/recovery acceptance pending | Founder manual sign-in evidence is limited to their local journey; no independently captured hosted AAL2/session revocation or QR scan qualification |
| Single-use recovery codes | Not natively provided by Supabase Auth project-user MFA API | Not implemented; custom private-schema flow required | Not available |
| Supabase schema and RLS | Source migration chains are not safe to merge directly | Dev migration 20261118133942 applied; six application tables with RLS enabled and ten policies, manually tested isolation; authenticated browser E2E pending | Development RLS metadata and rollback-only SQL test passed; real cross-tenant browser tests still required |
| PDF reporting, billing, monitoring, agency, admin | Source candidates exist in places; production integration not qualified | Not implemented | No commercial feature claim |

## Source-repository evidence

The Web audited branch comment records 72/72 full workflow steps passing at 10704777. The same pre-integration audit records 83/83 API workflow steps, 24/24 AUTH04 database steps, 44/44 integration steps and 15/15 focused regression steps passing.

That evidence is limited to the source branch and its disposable/pre-integration test environment. The audit explicitly keeps hosted/production qualification at NO-GO. It does not certify the LumicSec port, hosted Supabase configuration, independent security review or production deployment.

## Acceptance rule

A component is not TARGET-QUALIFIED until its copied code builds, its target tests pass, integration boundaries are reviewed, and any external credentials or hosted services required by its workflow have been verified. A green source-repository workflow does not satisfy target acceptance.
