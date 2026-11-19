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

These endpoints require a Google-authenticated, verified TOTP AAL2 session. The original six tenant tables now additionally carry **restrictive PostgreSQL RLS** policies checking the complete JWT Google OAuth+TOTP AMR/AAL2 gate, not just per-org membership, so a direct Supabase Data API request with a downgraded session cannot read tenant data. Every POST requires the origin-bound CSRF token provided by GET /auth/session. Data access uses the caller's Supabase session and tenant RLS; no service-key bypass is used.

- GET /v1/organizations: returns only accessible organizations and current-user memberships.
- POST /v1/organizations with JSON {"displayName":"Acme Engineering"}: creates an organization; a private trigger creates its requester as owner atomically. Returns HTTP 201.
- GET /v1/assets?organizationId=<uuid>: returns only RLS-authorized assets.
- POST /v1/assets with JSON {"organizationId":"<uuid>","kind":"website","displayName":"Portal","origin":"https://example.com"}: inserts an asset using the database's fixed pending default; returns HTTP 201 and scanningEnabled:false.

The origin validator requires a public-DNS-style HTTPS hostname; it rejects credentials, IP literals, paths, queries, non-default ports and local/reserved suffixes. It makes NO DNS lookup, does not prove asset ownership, does not set verification to verified, and cannot launch a scan. Browser users cannot alter verification status or insert worker jobs/findings.

Hosted Google OAuth/TOTP end-to-end completion is still pending configuration and real live session tests. The endpoints are implemented and unit tested, and database RLS checks have passed transactionally, but commercial onboarding is NOT certified.

## Organization RBAC and private invitations (development)

All routes require signed-in Google OAuth + verified TOTP AAL2, tenant-scoped PostgreSQL RPC checks, and a CSRF token for writes. No direct membership table write grants exist.

- `GET /v1/organizations/:organizationId/members`: manager inventory (Owner/Admin), no tokens.
- `GET /v1/organizations/:organizationId/invitations`: manager invitation statuses, no token/hash.
- `POST /v1/organizations/:organizationId/invitations` body `{ "email": "person@example.com", "role": "member" }`: owner/admin permitted; owner may also invite admin. Returns single-use `invitation.invite_token` in the explicit one-time response, not logs.
- `POST /v1/organizations/invitations/accept` body `{ "token": "<64 lowercase hex>" }`: consumes only valid, unexpired, matching-confirmed-email invite.
- `POST /v1/organizations/:organizationId/invitations/:invitationId/revoke`: revoke pending invite.
- `POST /v1/organizations/:organizationId/members/:userId/role` body `{ "role": "admin" }`: owner-only role assignment with final-owner preservation.
- `POST /v1/organizations/:organizationId/members/:userId/remove`: owner-only removal with final-owner preservation.
- `GET /v1/organizations/:organizationId/audit`: manager-only, RLS-scoped event history.

These are manually delivered one-time invitation codes, **not** an automated email invitation service. Legacy analyst/viewer membership values are preserved.

## Time-limited ownership challenges (development)

- `POST /v1/assets/verification/challenges`: body `{ "organizationId":"<uuid>", "assetId":"<uuid>", "method":"dns_txt" }` or `https_file`. Returns a 30-minute per-org/asset challenge, private one-time token and exact DNS TXT host or HTTPS path, with `scanningEnabled:false`.
- `GET /v1/assets/verification/challenges?organizationId=<uuid>&assetId=<uuid>`: manager-only RLS-scoped history, never the token or its hash.
- `POST /v1/assets/verification/check`: body `{ "organizationId":"<uuid>", "assetId":"<uuid>", "challengeId":"<uuid>" }`. **Never accepts proof text from the client.** Backend independently retrieves DNS TXT or bounded TLS-verified HTTPS proof, validates it and calls a service-role-only DB function. Returns 503 `TRUSTED_VERIFICATION_BACKEND_NOT_CONFIGURED` while the founder's server-only secret key is absent.
- `POST /v1/assets/verification/revoke`: body `{ "organizationId":"<uuid>", "assetId":"<uuid>" }`; owner/admin revokes proof, sets ownership invalid and emits audit history.

No customer scanner execution, automatic asset probing, or production worker entitlement is enabled. In future worker code, both origin scope and active proof expiry **must** be validated before scheduling and again before any outbound operation. See the security qualification report and master tracker.
