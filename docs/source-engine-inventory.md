# Source-engine inventory

Audit date: 2026-11-18.

## Repository A — Web Security

Repository: https://github.com/kalyankumarmalli480-sys/lumicsec-security-platform

The repository's default branch is intentionally minimal: two blobs (.gitignore and README.md). The implementation is in non-main branches. All 30 available branch heads were enumerated and their recursive trees inspected. The latest 100 commit records were queried for each branch; additional history pages were queried for the current audit and integration candidates. Full historical pagination remains open for branches exceeding the retrieved windows.

### All available branches

- audit/preintegration-forensic-completion-20261117 — 10704777f758737927d70aed9c95c0f4f9d98e1c
- candidate/web-family-phase01-convergence-20261008 — 118284dd21cbd86029d63fa5a5570b257e8b9641
- candidate/web-family-phase03-convergence-20261008 — 398797167e5cd4b1488f6cf45b105a35762010c0
- integration/unified-web-api-s0-s1-20261111 — 9959e4a1929949c87d5f97a4302057ed5d3f615a
- main — eebe755a9032b65c3e178cda18755e75d1ebc7fb
- task01-isolated-preview — 70bb04e2f068d5187e88aeb1b679852b0997b4a5
- work/web-family-03-integration — bd908e2452c0b9b8c1c1cced6d29d5a51ec33666
- work/web-family-04-platform-structure — f5bdfa31f69ac74fc788357b87f5200d737933bd
- work/web-family-phase02-platform-architecture — 0a6bf11d55630db78aa886b2c10a2aa293d8f636
- work/web-family-phase03-database-replay — bfa74b52197f5e39fd430f560ebcee3ae274ac63
- work/web-family-phase03-db-replay — 35dfd67ab52bf8a27ae531297271dcc39d13eb23
- work/web-family-phase04-identity-tenant-security — 10a7040e98adff93dd6bf1753ce3a7a904d295b7
- work/web-family-phase05-target-ownership-authorization — 4362e110e4b86f020b8ceb9a01fe52ba6842412e
- work/web-family-phase06-shared-job-control-plane — 765c7840a4251c46fc2ab2e750123aa1cde5a4b7
- work/web-family-phase07-network-safety-governor — 921345073ea64ca31bece3e81f2b19ea690cdaaa
- work/web-family-phase08-web-assessment-discovery — 8cbfb1fd5d7a3f54f098c182fd22afdb64abdfbf
- work/web-family-phase09-web-assessment-analysis — 9c147e0ed317672aea61186ba18632e159da69db
- work/web-family-phase10-web-assessment-customer-e2e — e02f03574867a1bf451a0ffcf4666d3a867a6141
- work/web-family-phase11-autonomous-pentest-planning — 458b4204fbfd7fddb17f25fdd87ed697d6459ccf
- work/web-family-phase12-authorized-vulnerability-validation — 75d2ee4b1d84dec618b4046bf4fc77659085bc28
- work/web-family-phase13-autonomous-vapt-runtime-e2e — adc0ca5ee6fe61db6c10917cbc42c7d275d8d96c
- work/web-family-phase14-authenticated-browser-broker — 692d1cff4970beecf6a728d82121b726287df41f
- work/web-family-phase15-authenticated-differential-analysis — c8500f9750ff3d8d017618c51925e43882d959d4
- work/web-family-phase16-authenticated-autonomous-vapt — f7559228d031cbb17f694b2907f88b74e7c62133
- work/web-family-phase17-unified-canonical-evidence-findings — ee646937106f6cf27f8454d569eec43736122ddf
- work/web-family-phase18-professional-review-reporting — 93429dfe332947774d31f6970137f9dcd68aad69
- work/web-family-phase19-remediation-authoritative-retest — bb7afdde67d87bca4db3f035011002925726a2c4
- work/web-family-phase20-complete-product-ux-operations — edfe0bb663c6be6c157176231e88bc35bd8b5331
- work/web-vapt-01-reuse — 75c4ac5b2d464c09d20061a7be777a0a91ba2c07
- work/web-vapt-02-runtime — d23a48d29651175c99e397a5bd655ac74a0cf72b

### Candidate branch and files

- Audited source baseline: audit/preintegration-forensic-completion-20261117 at 10704777f758737927d70aed9c95c0f4f9d98e1c; recursive tree: 939 blobs.
- Newer integration branch: integration/unified-web-api-s0-s1-20261111 at 9959e4a1929949c87d5f97a4302057ed5d3f615a; recursive tree: 944 blobs. It contains later integration work and is not treated as the audited baseline for the first target port.
- Phase 20 work branch: work/web-family-phase20-complete-product-ux-operations at edfe0bb663c6be6c157176231e88bc35bd8b5331.

Reviewed reusable Web files:
- src/lib/web-assessment/discovery.ts — bounded passive crawler. It has no native fetch, DNS or socket implementation; every read is injected through an AuthorizedRead callback.
- src/lib/web-assessment/response-capture.ts — privacy-preserving allowlisted response metadata. It records cookie attributes and counts, not raw cookie values.
- src/lib/web-assessment/analysis.ts — deterministic offline analysis over a validated snapshot. It emits observations and review candidates, not canonical confirmed vulnerabilities.
- src/lib/pentest/network-safety.ts, node-read-only-transport.ts, errors.ts and related contracts — candidate for a later isolated network-safety package. Not yet ported because the transport depends on the legacy SSRF resolver and execution-contract graph.
- src/lib/security/ssrf.ts — audited legacy resolver subset; its own header explicitly says it is not the public-assessment scan implementation.

Reviewed tests:
- tests/web-family-phase08-discovery.test.ts
- tests/web-family-phase09-analysis.test.ts
- tests/web-family-phase07-network-safety.test.ts
- tests/web-family-phase07-dns-rebinding.test.ts
- tests/web-vapt-core.test.ts
- tests/web-vapt-runtime.test.ts
- tests/web-family-mfa-policy.test.ts
- tests/web-family-mfa-access-gate.test.ts

Root stack is Next.js 15 / React 19 with npm lockfile and Supabase JS 2.57.0. The target directive requires Vite and Fastify, so the Next.js application and its login pages are not copied. Existing login paths include methods that are prohibited by the LumicSec product directive; only the policy concepts and safe engine modules may be reused.

## Repository B — API Security

Repository: https://github.com/mkalyankumar903-hash/API-security-family

The default branch contains only README.md. The implementation is in work branches. All 17 branch heads were enumerated and their recursive trees inspected. The latest 100 commit records were queried for each branch; pages 2 and 3 were also queried for the Phase 15 candidate.

### All available branches

- main — 69b8137ac4b1d6880ec02ef3d497e7560eaba234
- work/phase0-spec-only-assessment — 79b74895ed2c3c1369d9468e2ec2ca76b383faa9
- work/phase01-secure-target-onboarding — d57f6c572cc903e9cd44ff7a9c28953bfce1a08b
- work/phase02-api-specification-discovery — 57cc3fde31a5c18c2d0456202364cef41d1098b5
- work/phase03-deterministic-api-detection — 182fec93884abde91ba0c0b448ee465216dbb4f2
- work/phase04-authenticated-api-assessment — cbfca77fd26aad9ef484a7029fd074ce1cb730c4
- work/phase05-complete-api-assessment — 5fcd33cdb83a80616d4f172e382e0bbc7b8156a2
- work/phase06-api-pt-authorization-safe-execution — ac1c13dfa495be065e6dfd62691a9c01b6c254a3
- work/phase07-api-pt-detection-engine — fab1351fc1ab1655eecf376d41959b257f99f145
- work/phase08-complete-api-pt-product — 8cfd9697af8bb93d4656484c20cb86b5f429bf92
- work/phase09-deterministic-autonomous-orchestrator — 34b8b93afe17d336d931ffb7bb7e27025388f28f
- work/phase10-advanced-workers-execution-safety — 0808346ce2c7b053b1301657c370bc651bf2e35b
- work/phase11-complete-autonomous-api-vapt — 141283396cba29bed1ac9441cff03f755bf5c0f6
- work/phase12-unified-ux-reports-readonly-ai — 31b8c402524dcc5e6d0c7fecf3a7c5b1262d4e6b
- work/phase13-commercial-entitlements-host-adapters-sdk — b66243daf2f227489743f14794eed3f6e8afac27
- work/phase14-production-hardening-reliability-performance-qa — 418f07bd8efed24d6094b84ac71aacfac0097e54
- work/phase15-plugin-packaging-release-qualification-handover — ff8bf63b71eee8f349a7003ae419b8a0ad39c398

### Candidate branch and files

- Candidate: work/phase15-plugin-packaging-release-qualification-handover at ff8bf63b71eee8f349a7003ae419b8a0ad39c398; recursive tree: 312 blobs.
- Phase 15 PR #16 remains a draft handover candidate; it is not an independent production certification.
- Root package targets Node >=22 and uses Fastify 5.12.5, pg 8.16.3, Vite 7.3.7, React 19.1.1, YAML 2.9.1 and @platformatic/openapi-schema-validator 3.0.0. The repository uses an npm lockfile, not a pnpm workspace.

Reviewed reusable files:
- packages/assessment-engine/src/index.ts — bounded JSON/YAML parsing and structural validation.
- packages/discovery/src/index.ts — offline OpenAPI 3.0/3.1, Swagger 2.0 and Postman 2.1 inventory.
- packages/assessment-engine/src/inventory.ts — deterministic API specification observation rules.
- packages/pt/src/detection.ts and related PT modules — synthetic fixture / safe-execution candidate only; not eligible as real customer vulnerability detection without a separately qualified Host runtime.
- packages/service and packages/database — use pg and an independent migration / tenant context. They are not copied into LumicSec because the target requires Supabase as the only database and RLS as the tenant boundary.

## Licensing and dependencies

No LICENSE, NOTICE or COPYING file was found in the inspected branch trees of either source repository. Source attribution is retained in copied modules and THIRD_PARTY_NOTICES.md. Dependency versions are being re-resolved and pinned in the LumicSec pnpm lockfile rather than importing the original npm lockfiles.
