# Supabase development setup

Supabase is the only database and authentication provider.

## Existing development project

A connected Supabase project named lumicsec-local was found in ap-south-1 with PostgreSQL 17. Its public application schema and migration history were empty at inspection time (2026-11-18). No schema or Auth settings were changed by this initial repository commit.

## Required configuration

- Copy the project URL and publishable key into the server-side .env values.
- Keep any Supabase secret key out of Vite variables and browser bundles.
- Configure Google OAuth in Supabase Auth.
- Register the Google OAuth callback URL shown by the Supabase dashboard with Google Cloud: https://YOUR_PROJECT_REF.supabase.co/auth/v1/callback.
- Add http://localhost:8787/auth/callback to Supabase Auth's allowed redirect URLs.
- For production, add only the approved API callback URL.
- Disable ordinary email/password, phone/SMS, anonymous and other social providers for the application.

## MFA

The application uses the Supabase TOTP enroll, challenge, verify and assurance-level APIs. New users must enroll before accessing the workspace. Existing users must verify TOTP to reach AAL2.

Supabase's JavaScript MFA API does not provide recovery codes for project users. LumicSec must implement its own single-use recovery codes in a non-exposed private schema, store only strong hashes, rate-limit attempts, atomically consume a code and require Google identity plus a tightly audited recovery action. That implementation is not yet complete.

## Database workflow

Use Supabase CLI migrations for every schema change. Do not apply the original Web or API source migration chains: they contain source-specific schemas and tenant context assumptions. Build a new organization-aware schema with RLS, then test cross-tenant reads and writes before connecting customer data features.

No migrations have been applied to the remote project yet.
