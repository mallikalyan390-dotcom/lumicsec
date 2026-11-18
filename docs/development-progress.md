# Development progress

Last updated: 2026-11-18.

## Repository and branch policy

- Target: mallikalyan390-dotcom/lumicsec.
- Work directly on main. No feature/development/temporary branches.
- Never force-push. Commits use an expected main SHA.
- Original Web and API source repositories remain read-only.

## Phase status

| Phase | Status | Evidence / remaining work |
|---|---|---|
| 1. Repository inspection and source audit | PARTIAL | Target history/tree/settings inspected; all 47 source branches enumerated; candidate trees, manifests, tests, CI and audit reports reviewed. Full historical pagination and additional file-by-file source review remain open. |
| 2. Product architecture | INITIAL BASELINE RECORDED | Stack, trust boundaries, source mapping and qualification matrix documented. |
| 3. Monorepo and development infrastructure | INITIAL IMPLEMENTATION | pnpm workspace, apps/packages, strict TypeScript, Vite, Fastify and CI bootstrap added. Lockfile generation and target CI remain pending. |
| 4. Supabase schema and RLS | NOT STARTED | Existing lumicsec-local development project was found empty (Postgres 17, ap-south-1). No migrations or SQL changes were applied. |
| 5. Google OAuth and mandatory TOTP | SCAFFOLD | BFF routes and AAL2 policy added. Google provider activation, live OAuth, TOTP E2E, recovery codes and session-revocation tests remain pending. |
| 6. Public website and design system | INITIAL UI | Auth gate and initial workspace UI added; public pages and complete design system remain pending. |
| 7. Customer dashboard and organizations | NOT STARTED | No organization persistence or tenant RLS yet. |
| 8. Admin dashboard | NOT STARTED | Requires server-controlled platform-admin model and audit tables. |
| 9. Web engine integration | INITIAL CORE PORT | Passive capture, discovery and offline analysis copied; target CI pending. Network transport is deferred. |
| 10. API engine integration | INITIAL CORE PORT | Offline spec import, inventory and SPEC_ONLY rules copied; target CI pending. |
| 11–24. Remaining product, workers, billing, reports, QA and deployment | NOT STARTED | Tracked in the master directive; no phase will be silently marked complete. |

## Current commit contents

- Source inventory, integration mapping, engine qualification matrix and security architecture.
- Vite React app and Fastify API.
- Supabase cookie-session / Google OAuth / TOTP scaffold.
- Offline API specification assessment route.
- Passive Web assessment core modules.
- Unit tests and GitHub Actions workflows.

## Test and acceptance record

No target-repository build, typecheck, test suite or live OAuth/MFA test is claimed as passing until GitHub Actions and configured hosted tests report their exact results. The bootstrap workflow must first generate pnpm-lock.yaml; then the normal CI workflow can run with frozen dependencies.

## External blockers

- Google OAuth client ID/secret and Supabase Auth provider configuration.
- Supabase redirect allowlist and project Auth settings.
- Custom single-use recovery-code implementation in Supabase private schema.
- Supabase migrations and cross-tenant RLS tests.
- Cloudflare and Google Cloud credentials / budget approval.
- Payment gateway credentials and founder approval.
- Independent security review before any production readiness statement.
