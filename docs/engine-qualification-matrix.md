# Engine qualification matrix

Status labels: SOURCE-EVIDENCE-PASS, TARGET-INTEGRATION-PENDING, SPEC-ONLY, SYNTHETIC-ONLY, DEFERRED, NOT-IMPLEMENTED.

| Component | Source status | LumicSec status | Safe commercial claim |
|---|---|---|---|
| Web passive response capture | Source Phase 20 regression evidence passed | Copied; target tests added, CI pending | Passive header / cookie-attribute observation only |
| Web passive discovery | Source Phase 20 regression evidence passed | Copied; target tests added, CI pending | Bounded discovery through an injected authorized-read adapter |
| Web deterministic analysis | Source Phase 20 regression evidence passed | Copied; target tests added, CI pending | Review observations from a validated passive snapshot |
| Web SSRF network safety | Source code and regression tests exist | Deferred pending dependency-complete port | No live scanning claim |
| Web pinned HTTP transport | Source code exists | Deferred pending adapter and target tests | No live scanning claim |
| API OpenAPI / Swagger parsing | Source Phase 15 test evidence passed | Copied; target tests added, CI pending | Offline specification import and structural validation |
| API deterministic rule engine | Source Phase 15 test evidence passed | Copied; target tests added, CI pending | SPEC_ONLY observations; no runtime exploitability claim |
| API Postman import | Source inventory supports it | Imported as inventory only | No OpenAPI-equivalent security assessment claim |
| API authenticated runtime / authorization testing | Host adapters disabled or incomplete in source qualification | Not integrated | No live API vulnerability claim |
| Synthetic PT detection | Synthetic fixture coverage only | Not integrated | Never market fixtures as real detection |
| Google OAuth + TOTP | Source policy tests and source integration evidence exist | Fastify BFF scaffold added; hosted provider configuration and target E2E pending | Not accepted until live Supabase OAuth/MFA and AAL2 tests pass |
| Single-use recovery codes | Not natively provided by Supabase Auth project-user MFA API | Not implemented; custom private-schema flow required | Not available |
| Supabase schema and RLS | Source migration chains are not safe to merge directly | New schema not yet applied | No tenant-isolation claim until target RLS tests pass |
| PDF reporting, billing, monitoring, agency, admin | Source candidates exist in places; production integration not qualified | Not implemented | No commercial feature claim |

## Source-repository evidence

The Web audited branch comment records 72/72 full workflow steps passing at 10704777. The same pre-integration audit records 83/83 API workflow steps, 24/24 AUTH04 database steps, 44/44 integration steps and 15/15 focused regression steps passing.

That evidence is limited to the source branch and its disposable/pre-integration test environment. The audit explicitly keeps hosted/production qualification at NO-GO. It does not certify the LumicSec port, hosted Supabase configuration, independent security review or production deployment.

## Acceptance rule

A component is not TARGET-QUALIFIED until its copied code builds, its target tests pass, integration boundaries are reviewed, and any external credentials or hosted services required by its workflow have been verified. A green source-repository workflow does not satisfy target acceptance.
