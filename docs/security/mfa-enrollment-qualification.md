# MFA enrollment regression and qualification

Reviewed 2026-11-18. This documents code-level security repairs; **hosted OAuth/TOTP sign-in is not yet qualified**.

## Verified upstream behavior

- Supabase JS `auth.mfa.enroll({ factorType: "totp" })` creates an **unverified** factor and returns `totp.qr_code` as an SVG image **Data URL**. The JS client prefixes the SVG with `data:image/svg+xml;utf-8,`; do not prepend/encode this value again.
- `auth.mfa.listFactors().all` includes unverified factors. The `totp` subset contains verified factors; an initial enrollment cannot be verified by looking only in `totp`.
- Verify with `mfa.challenge({ factorId })` followed by `mfa.verify({ factorId, challengeId, code })`. A successful session must reach AAL2 before protected routes are accessible.

Sources: [Supabase TOTP guide](https://supabase.com/docs/guides/auth/auth-mfa/totp), [MFA enroll](https://supabase.com/docs/reference/javascript/auth-mfa-enroll), and [Supabase JS GoTrueClient](https://github.com/supabase/supabase-js/blob/master/packages/core/auth-js/src/GoTrueClient.ts).

## Mitigations implemented

- The React page passes the **original validated Data URL** to `<img>`; it does not double-encode the result. Only bounded SVG image Data URLs are accepted, and image-load failures display a recovery action.
- A user can explicitly discard the enrollment and request a fresh QR. This rotates the app's own **unverified** TOTP factors; the server does not delete verified factors or unverified factors from other applications.
- The verifier looks up the exact unverified factor in `listFactors().all` using the HTTP-only pending-factor cookie. It rejects a stale, missing or unexpected factor; it never falls back to another factor while a pending cookie is present.
- A fresh unverified factor is cleaned up on unsupported QR response formats. Failure to clean an abandoned factor blocks creation of another factor.
- Existing verified TOTP factors require **AAL2** before adding a new backup factor. The server continues to enforce Google-first-factor and AAL2 for customer APIs.
- MFA secrets are returned only to the authenticated browser during enrollment, with `Cache-Control: no-store`; this flow must not print them to logs, screenshots, telemetry or development notes.

## Evidence

- Automated API regression tests use mocked Supabase client responses, not real users: enrollment rotation, cleanup failures, wrong image format, pending factor selection, valid/invalid/stale code paths, AAL2 confirmation and protected customer API authorization checks.
- Unit tests exercise Supabase-style SVG Data URLs and reject nonimage URL schemes and double-prefixed image data.
- Chromium headless: a synthetic `data:image/svg+xml;utf-8,` fixture loaded, while the old double-encoded URL did not load.
- Firefox through Xvfb: the same synthetic fixture rendered (32,400 dark pixels in the test area); the old encoding did not (60 dark pixels). **No live enrollment secret was used** in browser fixtures.
- No authentication factors or authentication settings were changed in the hosted Supabase project by these tests. No migration was applied.

## Unverified acceptance gates — BLOCKING production onboarding

The following require a controlled hosted environment and real user interaction, so unit tests and synthetic QR images **cannot** establish success:

1. Confirm hosted Google-only OAuth, PKCE, callback cookies, real authenticator QR scanning, and correct TOTP verification.
2. Confirm the resulting Supabase session claims and assurance are both AAL2; confirm protected API requests with actual AAL1 and AAL2 user sessions.
3. Test incorrect/expired TOTP codes, challenge replay, rate limits, repeated login, logout, refresh, expiry and session revocation.
4. Test Chromium and Firefox on the **actual hosted enrollment page**, including responsive display and authenticator scanning.
5. Test abandoned factor regeneration across refresh and logout without unintended factor deletion.
6. Deliver audited recovery codes, backup authenticator management and secure loss-of-device/re-enrollment flows before production customer usage.

### Previously exposed enrollment QR

An enrollment QR/key already appeared in an earlier screenshot. **Do not reuse that enrollment secret.** When the founder next enters the MFA setup flow, explicitly generate a fresh factor; the normal enrollment route removes obsolete unverified LumicSec factors. If the exposed factor has already been **verified**, do **not** blindly delete it: first authenticate at AAL2 and establish a tested backup or recovery path, then perform a carefully confirmed rotation. No live factor deletion is authorized in this milestone.

Do not mark the commercial authentication milestone or full SaaS as complete until the above acceptance gates pass.
