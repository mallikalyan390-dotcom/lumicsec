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

## Active-checkout synchronization and QR-error manual path

The founder's active app folder `/home/kalyan/lumicsec` was safely fast-forwarded from `db2d7d61ff767e861367171a9f7fd38806666d6e` to the verified `main` version. The local dev frontend/API were restarted from that folder, not the earlier validation workspace. `http://127.0.0.1:5173/` and `http://127.0.0.1:8787/healthz` both returned HTTP 200; `/auth/session` was `anonymous`, not a hosted Google sign-in success.

**Manual enrollment fallback fix:** In `MfaSetupPage`, the enrollment verification form is now rendered whenever an enrollment exists, even if its QR cannot load. The key can be entered manually into a time-based authenticator app; selecting a replacement factor temporarily blocks verification during rotation. This fixes the previously inaccessible manual setup path. It does not enable access without verification.

**Reproducible synthetic browser fixture:** Build the frontend, then start `node apps/web/tests/mfa-manual-fallback-smoke.mjs`; it serves the actual compiled React app on loopback port 5187, replacing `/auth/session`, `/auth/mfa/enroll`, and `/auth/mfa/verify` with synthetic responses only. Visit `/?valid` for a well-formed test SVG and `/` for an intentionally broken test SVG. The page automatically exercises enrollment, the visible verification form and a simulated rejected code. Inspect the safe-result-only `/__status` endpoint. This fixture **must not be used to qualify hosted OAuth or TOTP**.

Actual local browser evidence, 2026-11-18:

| Browser | Test image | QR status observed | Manual instructions and code input | Rejected fixture code feedback |
|---|---|---|---|---|
| Chromium | Valid SVG Data URL | Image loaded | Visible | Displayed |
| Firefox | Valid SVG Data URL | Image loaded | Visible | Displayed |
| Chromium | Broken SVG Data URL | QR error shown | Visible | Displayed |
| Firefox | Broken SVG Data URL | QR error shown | Visible | Displayed |

A separate API regression test suite verifies Google-only OAuth callback route initiation, code exchange and failure redirects, JWT/assurance AAL1 denial, AAL2 positive branch, session failures, and sign-out **with mocks only**. Protected workspace access for unauthenticated requests was additionally denied by the actual local Fastify API (401).

**Release blockers remain:** founder-assisted hosted Google login, live authenticator enrollment with a **fresh** never-exposed key, real TOTP scanning/code acceptance, current and next AAL checks, protected tenant API access with a real authenticated session, real logout/re-login, token refresh/expiry and revocation propagation, rate-limit/failed-code checks under hosted behavior, audited single-use recovery codes, and safe backup authenticator/re-enrollment management. Supabase's built-in MFA APIs do not themselves implement this application's required recovery codes; recovery cannot be described as complete without a designed private schema and tested protections. No founder factor was modified by these validations.

## Non-login OAuth redirect verification (not a full login)

A read-only inspection of the active local API's `/auth/google` route showed an HTTP 302 to the expected Supabase project authorize endpoint, with `provider=google`, PKCE `S256`, a code challenge and a callback URL. One further **non-followed** authorization request to Supabase redirected with HTTP 302 to `accounts.google.com`. OAuth URLs, challenge parameters and all cookies were deliberately excluded from agent-visible output. No real user login or factors were touched.

This establishes that the Google authorization **handoff** is configured, not that consent, callback code exchange, browser cookie policy, token refresh, authenticator challenge or AAL2 work against the hosted provider. The latter require founder-assisted interactive tests and must remain release blockers.

Code checkpoint `ce4c5dc5d7b3261f1a0f11fbfd0a59865e24529a` passed GitHub [CI 44338785713](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44338785713) and [lockfile verification 44338785783](https://github.com/mallikalyan390-dotcom/lumicsec/actions/runs/44338785783).

## P0 QR false-negative and manual enrollment continuity

The founder reproduced `TOTP_QR_FORMAT_UNSUPPORTED`. The initial validator's rejection of raw newline and XML-prefixed SVG was an independently reproducible code defect, but the exact hosted QR payload remains **unknown** without founder authentication. Installed `@supabase/auth-js@2.119.0` prepends `data:image/svg+xml;utf-8,` to the raw provider SVG.

A size-bounded parser now accepts supported raw, multiline, XML-prefixed, URI-encoded and Base64 SVG Data URLs while strictly allowlisting drawing elements/attributes. Unsafe scripts, events, style, external refs, DTD/entities, CDATA, invalid nesting and excess input are rejected. Accepted SVG is canonicalized before display. Unknown SVG is not rendered, but it **does not invalidate an otherwise authorized TOTP enrollment**.

When a QR is unsafe or missing but the verified Google user's new pending factor ID and TOTP manual secret are available, the API returns `qrCodeSvg: null` plus that secret and the same pending-factor HTTP-only cookie. The existing manual-key UI and six-digit challenge remain functional. The API does not delete verified factors on QR failure. Only safe categorical QR metadata may be logged.

Unit, mocked Fastify, and synthetic Chromium/Firefox tests do not constitute live hosted MFA qualification. A fresh real authenticator, OAuth callback, verified AAL2/session behavior, expiry/revocation, recovery codes and safe backup management remain release blockers. No actual factor was changed by automated tests.
