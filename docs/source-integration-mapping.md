# Source integration mapping

## Integration principles

- Do not copy either original product wholesale.
- Do not modify either source repository.
- Reuse pure deterministic modules where imports and runtime assumptions are understood.
- Keep source observations distinct from runtime-confirmed vulnerabilities.
- Preserve original repository, branch and commit provenance in each copied module.
- Do not carry forward a second PostgreSQL client, database, queue store or tenant GUC.
- Supabase PostgreSQL is the single system of record. User-scoped database calls must carry the user's Supabase JWT so RLS applies.

## Web Security mapping

| Source | LumicSec target | Decision |
|---|---|---|
| src/lib/web-assessment/response-capture.ts | packages/web-security-engine/src/response-capture.ts | Reused; passive header and cookie-attribute projection only |
| src/lib/web-assessment/discovery.ts | packages/web-security-engine/src/discovery.ts | Reused; all reads injected; no native network calls |
| src/lib/web-assessment/analysis.ts | packages/web-security-engine/src/analysis.ts | Reused; deterministic offline observations and review candidates |
| src/lib/pentest/network-safety.ts | packages/network-safety (planned) | Defer until the complete dependency and test graph is ported |
| src/lib/pentest/node-read-only-transport.ts | packages/network-safety (planned) | Defer; depends on SSRF resolver and execution permits |
| src/lib/security/ssrf.ts | packages/network-safety (planned) | Do not copy the legacy resolver as a drop-in scanner |
| Next.js app, pages and auth UI | apps/web (Vite) | Do not copy; target has a different required stack and Google-only login policy |

The passive crawler accepts an AuthorizedRead function. The target worker must provide that function only after domain ownership verification, exact-origin scope compilation, DNS public-address validation, IP pinning, redirect revalidation, byte/time limits and job authorization. Until then the crawler is used only with deterministic test callbacks.

## API Security mapping

| Source | LumicSec target | Decision |
|---|---|---|
| packages/assessment-engine/src/index.ts | packages/api-security-engine/src/assessment/index.ts | Reused; bounded offline parser and validator |
| packages/discovery/src/index.ts | packages/api-security-engine/src/discovery/index.ts | Reused; import and inventory only |
| packages/assessment-engine/src/inventory.ts | packages/api-security-engine/src/assessment/inventory.ts | Reused; deterministic SPEC_ONLY observations |
| packages/pt/* | not yet integrated | Synthetic fixture / safe-execution only; no customer runtime claims |
| packages/service/* | apps/api (new Fastify service) | Do not copy; it uses pg and source-specific tenancy |
| packages/database/* and original migrations | supabase/migrations (new schema, planned) | Do not copy; incompatible with the single Supabase/RLS design |
| original Host adapters | apps/api and workers (planned) | Disabled until authorization and integration qualification |

Supported source import profiles are bounded. The parser rejects external references, YAML aliases, oversized documents, excessive node depth and operation counts. It does not fetch remote references. The detection result is labelled SPEC_ONLY and every observation requires review.

## Supabase integration boundary

- The browser never receives a Supabase secret/service key.
- Auth sessions are cookie-backed through a Fastify BFF; auth cookies are HttpOnly, Secure in production and SameSite=Lax.
- Google OAuth uses PKCE and a fixed callback URL. Only Google is exposed as a login option.
- TOTP is mandatory before protected product routes.
- Server-side authorization checks trusted app_metadata and verified AAL2 claims; user_metadata is never an authorization source.
- Customer data tables will use organization-aware RLS and auth.uid(). No source migration is applied to the target project.
- Custom single-use recovery codes are still required: Supabase Auth's JavaScript MFA API does not provide project-user recovery codes. This needs a dedicated private-schema implementation and tests before the auth phase is accepted.
