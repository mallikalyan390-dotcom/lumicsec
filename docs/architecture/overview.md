# LumicSec architecture baseline

## Applications

- apps/web: React, TypeScript, Vite, Tailwind CSS and shadcn-style local components. Cloudflare Pages is the intended frontend host.
- apps/api: Node.js and Fastify BFF / REST API. Google Cloud Run is the intended API host.
- packages/web-security-engine: pure passive discovery, response metadata capture and deterministic offline analysis.
- packages/api-security-engine: offline OpenAPI/Swagger import, inventory and SPEC_ONLY observations.
- packages/shared and packages/validation: shared contracts and Zod validation.
- supabase: the only database and auth platform; schema changes are versioned SQL migrations. The initial six-table organization and asset foundation has been applied only to the lumicsec-local development project.

## Request and identity flow

Browser -> Fastify BFF -> Supabase Auth / Supabase PostgreSQL.

The browser receives HttpOnly session cookies, not access or refresh tokens in localStorage. Google OAuth uses PKCE and a fixed callback. Every protected product action requires a Google identity and AAL2 verified through Supabase Auth. The database remains the final tenant authorization boundary through RLS.

## Customer organizations and asset onboarding

A verified Google+AAL2 BFF session can create organizations and register public HTTPS origins as pending assets. The PostgreSQL migration establishes organizations, memberships, assets, assessment-job metadata, review observations and audit events. RLS is the final tenant authorization boundary, and column-level privileges stop customer modification of asset verification state or trusted-worker records.

The React workspace now has an Organizations & Assets page. Live ownership verification, customer scanning, billing, reporting and platform administration are not implemented. Hosted OAuth/TOTP flows require independent end-to-end testing before user onboarding.

## Assessment flow

1. A user uploads an OpenAPI / Swagger document.
2. Fastify validates size and authenticated AAL2 session.
3. The offline parser validates document structure and rejects external references.
4. Deterministic rules produce SPEC_ONLY observations with evidence pointers and review-required flags.
5. No network request is sent to the declared API servers.

For Web assessment, the current discovery engine accepts a separately authorized read callback. The callback is not connected to a live transport. Domain ownership, exact scope, DNS validation, IP pinning, redirect checks and request budgets must be complete before a worker can supply it.

## Data and workers

Supabase PostgreSQL is the single system of record. Cloud Tasks and Cloud Scheduler are planned orchestration services; they are not enabled yet. No Redis, MongoDB, Firebase, Cloudflare D1 or second PostgreSQL provider is introduced.

## Deployment boundary

No Cloud Run service, Cloudflare Pages site, bucket, task queue, scheduler, domain or DNS record is created or changed by the initial implementation. Deployment configuration is documentation-only until separately approved.
