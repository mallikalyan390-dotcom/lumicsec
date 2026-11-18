# Engine qualification matrix

Status labels: SOURCE-EVIDENCE-PASS, TARGET-INTEGRATION-PENDING, SPEC-ONLY, SYNTHETIC-ONLY, DEFERRED, NOT-IMPLEMENTED.

| Component | Source status | LumicSec status | Safe commercial claim |
|---|---|---|---|
| Web passive response capture | Source Phase 20 regression evidence passed | Copied; target unit/API regression tests passed; code CI 44345864482 passed; hosted runtime still unqualified | Passive header / cookie-attribute observation only |
| Web passive discovery | Source Phase 20 regression evidence passed | Copied; target unit/API regression tests passed; code CI 44345864482 passed; hosted runtime still unqualified | Bounded discovery through an injected authorized-read adapter |
| Web deterministic analysis | Source Phase 20 regression evidence passed | Copied; target unit/API regression tests passed; code CI 44345864482 passed; hosted runtime still unqualified | Review observations from a validated passive snapshot |
| Web SSRF network safety | Source code and regression tests exist | Deferred pending dependency-complete port | No live scanning claim |
| Web pinned HTTP transport | Source code exists | Deferred pending adapter and target tests | No live scanning claim |
| API OpenAPI / Swagger parsing | Source Phase 15 test evidence passed | Copied; target unit/API regression tests passed; code CI 44345864482 passed; hosted runtime still unqualified | Offline specification import and structural validation |
| API deterministic rule engine | Source Phase 15 test evidence passed | Copied; target unit/API regression tests passed; code CI 44345864482 passed; hosted runtime still unqualified | SPEC_ONLY observations; no runtime exploitability claim |
| API Postman import | Source inventory supports it | Imported as inventory only | No OpenAPI-equivalent security assessment claim |
| API authenticated runtime / authorization testing | Host adapters disabled or incomplete in source qualification | Not integrated | No live API vulnerability claim |
| Synthetic PT detection | Synthetic fixture coverage only | Not integrated | Never market fixtures as real detection |
| Google OAuth + TOTP | Source policy tests and source integration evidence exist | BFF and Google-only/AAL2 regression gates; founder reports working manual TOTP and dashboard; local PNG QR generation/decoding tests passed; full hosted acceptance pending | Founder manual sign-in evidence is limited to their local journey; no independently captured hosted AAL2/session revocation or QR scan qualification |
| Single-use recovery codes | Not natively provided by Supabase Auth project-user MFA API | Not implemented; custom private-schema flow required | Not available |
| Supabase schema and RLS | Source migration chains are not safe to merge directly | Dev migration 20261118133942 applied; six application tables with RLS enabled and ten policies, manually tested isolation; authenticated browser E2E pending | Development RLS metadata and rollback-only SQL test passed; real cross-tenant browser tests still required |
| PDF reporting, billing, monitoring, agency, admin | Source candidates exist in places; production integration not qualified | Not implemented | No commercial feature claim |

## Source-repository evidence

The Web audited branch comment records 72/72 full workflow steps passing at 10704777. The same pre-integration audit records 83/83 API workflow steps, 24/24 AUTH04 database steps, 44/44 integration steps and 15/15 focused regression steps passing.

That evidence is limited to the source branch and its disposable/pre-integration test environment. The audit explicitly keeps hosted/production qualification at NO-GO. It does not certify the LumicSec port, hosted Supabase configuration, independent security review or production deployment.

## Acceptance rule

A component is not TARGET-QUALIFIED until its copied code builds, its target tests pass, integration boundaries are reviewed, and any external credentials or hosted services required by its workflow have been verified. A green source-repository workflow does not satisfy target acceptance.
