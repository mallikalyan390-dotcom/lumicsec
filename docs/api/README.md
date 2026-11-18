# API contract notes

The initial public health route is GET /healthz.

The protected API specification route is POST /v1/api-specs/assess. It requires a Google-authenticated AAL2 session and a valid CSRF token. The request contains a bounded JSON body with a content string and optional filename.

The route imports OpenAPI / Swagger documents offline. It does not send requests to the declared servers and does not persist the raw specification. Results are SPEC_ONLY observations or inventory-only output, not confirmed runtime vulnerabilities.

Auth routes:
- GET /auth/google
- GET /auth/callback
- GET /auth/session
- POST /auth/mfa/enroll
- POST /auth/mfa/verify
- POST /auth/logout

## Customer organizations and pending assets

These endpoints require a Google-authenticated, verified TOTP AAL2 session. Every POST requires the origin-bound CSRF token provided by GET /auth/session. Data access uses the caller's Supabase session and tenant RLS; no service-key bypass is used.

- GET /v1/organizations: returns only accessible organizations and current-user memberships.
- POST /v1/organizations with JSON {"displayName":"Acme Engineering"}: creates an organization; a private trigger creates its requester as owner atomically. Returns HTTP 201.
- GET /v1/assets?organizationId=<uuid>: returns only RLS-authorized assets.
- POST /v1/assets with JSON {"organizationId":"<uuid>","kind":"website","displayName":"Portal","origin":"https://example.com"}: inserts an asset using the database's fixed pending default; returns HTTP 201 and scanningEnabled:false.

The origin validator requires a public-DNS-style HTTPS hostname; it rejects credentials, IP literals, paths, queries, non-default ports and local/reserved suffixes. It makes NO DNS lookup, does not prove asset ownership, does not set verification to verified, and cannot launch a scan. Browser users cannot alter verification status or insert worker jobs/findings.

Hosted Google OAuth/TOTP end-to-end completion is still pending configuration and real live session tests. The endpoints are implemented and unit tested, and database RLS checks have passed transactionally, but commercial onboarding is NOT certified.
