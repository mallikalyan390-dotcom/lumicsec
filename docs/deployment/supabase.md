# Supabase development setup

Supabase is the only database and authentication provider.

## Existing development project

The connected Supabase project lumicsec-local runs in ap-south-1 on PostgreSQL 17. It initially had no public application tables or migrations. On 2026-11-18 the tenant_rls_foundation migration was applied to this DEVELOPMENT project only, with recorded migration version 20261118133942.

After applying, catalog queries confirmed all six public tables have RLS enabled, anon has no SELECT privileges, authenticated has no DELETE privileges, and ten RLS policies exist. Supabase Security Advisor returned zero lints. A two-user, rollback-only regression test (supabase/tests/tenant-isolation.sql) also executed successfully. Zero lints are not a production security certification.

Production Supabase projects and Auth provider settings were not changed.

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

Use Supabase CLI migrations for every schema change; never replay incompatible migrations from the two original engine repositories. The migration supabase/migrations/20261118133942_tenant_rls_foundation.sql matches the recorded development migration version. The SQL isolation regression is supabase/tests/tenant-isolation.sql.

Do not run the SQL test on a production database. It creates two synthetic auth.users and tenant records INSIDE one transaction, swaps authenticated JWT context, checks positive and negative RLS behavior, and ROLLBACK removes all test data. Run only with explicit permission in a disposable/development project.

The schema is an initial foundation. Membership invitations, ownership verification, trusted-worker APIs, audit writing, session revocation, admin policies and customer end-to-end tests are still unimplemented.
