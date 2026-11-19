# Organization RBAC & Asset Ownership — Security Qualification

**Environment:** development Supabase project `qiazvmygrordewkesqpr` and the founder's authorized local `/home/kalyan/lumicsec` checkout. No paid infrastructure, customer network scan, or production deployment.

## Tenant ownership and manager authorization

The existing foundation migration `20261118133942` remains intact. Forward-only migrations `20261118235406`, `20261118235735` and `20261119005151` add RLS-covered invitation and challenge tables plus private narrowly scoped, audited ownership functions, then layer six restrictive Google+TOTP AAL2 RLS guards onto the original six customer tables. Existing memberships use `owner/admin/analyst/viewer`; the `member` role is added without rewriting historical memberships.

- Existing owner bootstrap still runs when an authenticated Google user creates a tenant. SQL privileges still forbid direct membership invitation, role update and deletion by the browser.
- **Direct Supabase Data API protection:** Original SELECT/UPDATE RLS policies enforced tenant membership but did not independently require the full Google+TOTP AMR/AAL2 JWT for all original tables. The forward-only restrictive policy on each original table adds this requirement while retaining the prior permissive tenant predicate. Transaction-only tests verify AAL1, non-Google AAL2 and missing-TOTP-AAL2 cannot access an otherwise accessible tenant. No verified factors or existing tenant data were changed.
- The Fastify routes require authenticated Google OAuth, verified TOTP and current AAL2. Database mutation functions independently check the signed JWT provider, OAuth/TOTP methods, AAL2, active membership and required role. Admin can invite Member but not Admin; only Owner changes roles or removes members; final active Owner is protected.
- Invitation tokens are 256-bit cryptographically generated random values encoded as 64 lowercase hex characters. Only SHA-256 digests are stored in the DB. A token is one-time, bound to a specific organization, intended **confirmed email**, role and seven-day expiry. A new invite for the same email revokes a prior pending invite. Revocation and acceptance are audited.
- The owner privately hands the invited user the one-time code. Email delivery service and production email templates remain an explicit missing feature.
- The public `organization_invitations` table has RLS enabled, **no direct policy and no direct authenticated table grants**, intentionally deny-all. Only validated internal RPCs can read/change invitation state; the Supabase advisor INFO `rls_enabled_no_policy` is an expected deny-all control, not a missing browser SELECT policy.

## Asset ownership and time bounds

- Assets begin `pending` and asset registration **never** confers scan rights.
- Owners/Admins can issue a 30-minute, 256-bit, per-org/asset DNS TXT or HTTPS-file ownership challenge. Only its SHA-256 digest is stored; the plaintext is shown only in the issuing response. Existing pending proofs are revoked when replaced.
- DNS TXT location: `_lumicsec-challenge.<canonical-domain>`, exact value `lumicsec-verification=<64-hex-token>`. HTTPS location: `https://<canonical-domain>/.well-known/lumicsec-verification.txt`.
- Public A/AAAA DNS answers are all checked for public global unicast using `ipaddr.js`; any private, loopback, link-local, reserved, malformed, mapped, Teredo or 6to4 answer blocks the request. IP literals, non-HTTPS, nonstandard ports, private suffixes and path/credential manipulation are rejected by existing canonical-origin validation.
- HTTPS transport uses a bounded, pinned public IP socket; real hostname SNI and valid TLS certificates; no followed redirects; 4,000ms idle timeout plus **5,000ms absolute HTTPS deadline**, 4,000ms DNS preflight/TXT deadline, 8KB max headers, 512B max body, one URL path, no cookies or proxy. This is a **single file proof** request, not a crawler. The OS and browser are never asked to scan a customer target.
- The browser cannot self-attest by submitting a token to `/v1/assets/verification/check`; schema disallows token override. Only the backend-observed exact proof may be submitted to the **service_role-only** finalization RPC. DB re-checks current manager authorization, challenge hash, org/asset binding, unused status and expiry. Successful verification expires in 30 days.
- Renewal issues a fresh challenge. Owner/Admin can revoke proof. `asset_ownership_is_current` requires `verified` **and** a future expiration timestamp. Historical verified rows without expiration do not pass. Future workers must check again both before and during any authorized execution.
- All challenge reads omit token_hash; event history includes only the state and bounded summaries, never raw secrets.
- **Local blocker:** Current `.env` has **no `SUPABASE_SECRET_KEY`**. Authenticated user can issue/inspect a proof challenge but check returns HTTP **503** instead of granting verification. Configure a valid backend-only key through founder-approved secret management to run an actual target proof. Never use this key in `VITE_*`, public Git or browser JS. **No owner proof has been verified on a real external domain**.

## Test evidence

The original foundation `supabase/tests/tenant-isolation.sql` and the extended `supabase/tests/rbac-ownership.sql` both run in DEVELOPMENT within `BEGIN`...`ROLLBACK`. Both produced a PASS marker; neither retains synthetic rows. The latter additionally checks direct Data API RLS downgrade rejection (AAL1, no TOTP, non-Google), after a fully authorized AAL2 owner had registered an asset.

The rollback-only development SQL regression `supabase/tests/rbac-ownership.sql` ran under `BEGIN`...`ROLLBACK`, reporting `ROLLBACK_ONLY_RBAC_OWNERSHIP_TESTS_PASS`. It covered owner/Admin/Member permissions, last-owner safety, invitation issuance, email binding, replay, expiry and wrong-role denial, cross-tenant RLS isolation, no scan authorization, wrong/expired proof, revocation and privileged backend finalization. All synthetic rows rolled back.

The synthetic network test `apps/api/tests/ownership-proof.test.ts` exercises IPv4/IPv6 public/private/reserved addresses, mixed DNS rebinding, exact DNS TXT name, incorrect domain proof, pinned TLS, redirects blocked and client input validation; no customer DNS queries. The API test `apps/api/tests/organization-ownership-routes.test.ts` covers auth gates, failed database permissions, browser attempts to spoof tokens, proof missing trusted key and revocation. Both use mocks for external systems.

Built React UI smoke fixture `apps/web/tests/organization-ownership-smoke.mjs` runs on a separate local port with entirely synthetic orgs, domain, ownership token and Fastify-style JSON responses. Owner/Member Team and Assets pages passed **8/8** scenarios across Chromium/Firefox; Firefox was stopped by a headless process timeout after all UI result reports had been captured. The fixture doesn't call real Supabase, DNS or customer HTTPS.

**Not qualified yet:** actual founder-controlled domain proof via external DNS/HTTPS; production trusted key management; real multi-user Google/AAL2 invitation redemption, cross-tenant UI E2E; live email invite delivery; scanner authorization and worker gating; full MFA recovery/session security. Synthetic findings are not verified vulnerabilities, and synthetic proof doesn't authorize live scans.

## Remaining Supabase security notices

- `auth_leaked_password_protection` WARNING pre-existing. See <https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection>. Google-only sign-in remains enforced; no settings changed.
- `rls_enabled_no_policy` INFO for `public.organization_invitations` is intentional deny-all (see above). No direct user access should be added to silence the informational check.

See `docs/MASTER_DEVELOPMENT_TRACKER.md` for the full commercial roadmap and release gates.
