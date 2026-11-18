# Security architecture baseline

## Identity

- Google OAuth is the only first-factor provider exposed by LumicSec.
- OAuth uses PKCE and a fixed callback URL.
- TOTP enrollment is mandatory for new users; verified users must reach AAL2 before protected routes.
- The Fastify BFF stores Supabase session state in HttpOnly cookies. Cookies are Secure in production and SameSite=Lax.
- No password, email OTP, magic link, phone/SMS OTP, GitHub or Facebook login UI is implemented.
- Server authorization reads trusted app_metadata and verified Supabase claims. user_metadata is never an authorization source.
- Supabase Auth does not natively provide project-user recovery codes through its JavaScript MFA API. LumicSec still needs a custom single-use recovery-code store and protected recovery operation.

## Authorization and tenancy

- Supabase PostgreSQL is the only system of record.
- All exposed application tables must enable RLS.
- Organization membership and role checks belong in database policies / server-controlled tables.
- Protected database operations must use the user's JWT so RLS is evaluated.
- Service/secret keys are server-only and reserved for narrow worker operations.
- Cross-tenant IDOR/BOLA tests are mandatory before customer data features are accepted.

## Scanner safety

No live scan is enabled by the initial commit.

Before a worker can read a customer asset, it must verify ownership, compile exact origin and path scope, resolve DNS, reject every private / loopback / link-local / multicast / metadata address, pin the resolved public IP, revalidate every redirect, enforce HTTPS and safe methods, cap ports, requests, response bytes, concurrency and deadlines, and record the authorization and evidence chain.

The Web discovery package itself has no native fetch, DNS or socket implementation. Its only network boundary is an injected AuthorizedRead function. Do not connect that function to arbitrary URL fetch.

## Finding truth

- API specification observations are SPEC_ONLY and require review.
- Passive Web observations are not confirmed vulnerabilities.
- UNKNOWN is not SAFE.
- Absence of a signal is not proof of absence.
- A retest that no longer observes a condition is not VERIFIED_FIXED without runtime evidence.
- Synthetic fixtures are never represented as real customer detections.

## Application hardening

Fastify validates input, applies CORS allowlists, rate limits, security headers and CSRF checks. Logs redact cookies, auth headers, uploaded specification content and TOTP codes. Uploads are size-bounded and processed in memory; raw specification contents are not persisted by the current route.
