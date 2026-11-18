-- LumicSec RLS isolation regression. Run on a disposable/dev database only.
-- All synthetic Auth users and organization/asset rows are rolled back.
-- This test expects migration 20261118133942_tenant_rls_foundation.sql.

BEGIN;

INSERT INTO auth.users (id, instance_id, aud, role, email, created_at, updated_at)
VALUES
 ('00000000-0000-4000-8000-000000000101', '00000000-0000-0000-0000-000000000000',
  'authenticated', 'authenticated', 'lumicsec-rls-test-a@example.test', now(), now()),
 ('00000000-0000-4000-8000-000000000102', '00000000-0000-0000-0000-000000000000',
  'authenticated', 'authenticated', 'lumicsec-rls-test-b@example.test', now(), now());

SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub', '00000000-0000-4000-8000-000000000101', true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-000000000101","aal":"aal2","app_metadata":{"provider":"google"}}',
 true);

INSERT INTO public.organizations (display_name, created_by)
VALUES ('RLS Tenant A', '00000000-0000-4000-8000-000000000101');

SELECT set_config('app.test_org_a',
 (SELECT id::text FROM public.organizations WHERE display_name = 'RLS Tenant A'), true);

INSERT INTO public.assets
 (organization_id, asset_kind, display_name, canonical_origin, created_by)
VALUES
 (current_setting('app.test_org_a')::uuid, 'website', 'A site',
  'https://tenant-a.example.test', '00000000-0000-4000-8000-000000000101');

DO $$
BEGIN
 IF (SELECT count(*) FROM public.organizations) <> 1 THEN
  RAISE EXCEPTION 'RLS_REGRESSION: owner cannot read own organization';
 END IF;
 IF (SELECT count(*) FROM public.organization_memberships) <> 1 THEN
  RAISE EXCEPTION 'RLS_REGRESSION: owner bootstrap failed';
 END IF;
 IF (SELECT count(*) FROM public.assets) <> 1 THEN
  RAISE EXCEPTION 'RLS_REGRESSION: owner cannot read own asset';
 END IF;
END $$;

-- Switch to a second, unrelated Google AAL2 user.
SELECT set_config('request.jwt.claim.sub', '00000000-0000-4000-8000-000000000102', true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-000000000102","aal":"aal2","app_metadata":{"provider":"google"}}',
 true);

DO $$
BEGIN
 IF (SELECT count(*) FROM public.organizations) <> 0 THEN
  RAISE EXCEPTION 'RLS_REGRESSION: cross-tenant organization read';
 END IF;
 IF (SELECT count(*) FROM public.organization_memberships) <> 0 THEN
  RAISE EXCEPTION 'RLS_REGRESSION: cross-tenant membership read';
 END IF;
 IF (SELECT count(*) FROM public.assets) <> 0 THEN
  RAISE EXCEPTION 'RLS_REGRESSION: cross-tenant asset read';
 END IF;
 UPDATE public.assets SET display_name = 'tampered'
 WHERE organization_id = current_setting('app.test_org_a')::uuid;
 IF FOUND THEN
  RAISE EXCEPTION 'RLS_REGRESSION: cross-tenant asset update';
 END IF;
 BEGIN
  INSERT INTO public.assets
   (organization_id, asset_kind, display_name, canonical_origin, created_by)
  VALUES (current_setting('app.test_org_a')::uuid, 'website',
   'B forged', 'https://forged.example.test',
   '00000000-0000-4000-8000-000000000102');
  RAISE EXCEPTION 'RLS_REGRESSION: cross-tenant asset insert';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;

INSERT INTO public.organizations (display_name, created_by)
VALUES ('RLS Tenant B', '00000000-0000-4000-8000-000000000102');

DO $$
BEGIN
 IF (SELECT count(*) FROM public.organizations) <> 1 THEN
  RAISE EXCEPTION 'RLS_REGRESSION: B can see A or cannot see B';
 END IF;
 IF (SELECT count(*) FROM public.organization_memberships) <> 1 THEN
  RAISE EXCEPTION 'RLS_REGRESSION: B membership isolation failed';
 END IF;
END $$;

-- Downgrading to AAL1 must remove membership access and block creation.
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-000000000102","aal":"aal1","app_metadata":{"provider":"google"}}',
 true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.organization_memberships) <> 0 THEN
  RAISE EXCEPTION 'RLS_REGRESSION: AAL1 membership read';
 END IF;
 BEGIN
  INSERT INTO public.organizations (display_name, created_by)
  VALUES ('AAL1 forged', '00000000-0000-4000-8000-000000000102');
  RAISE EXCEPTION 'RLS_REGRESSION: AAL1 organization insert';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;

-- AAL2 with a non-Google first-factor provider is still insufficient.
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-000000000102","aal":"aal2","app_metadata":{"provider":"email"}}',
 true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.organization_memberships) <> 0 THEN
  RAISE EXCEPTION 'RLS_REGRESSION: non-Google membership read';
 END IF;
 BEGIN
  INSERT INTO public.organizations (display_name, created_by)
  VALUES ('Email forged', '00000000-0000-4000-8000-000000000102');
  RAISE EXCEPTION 'RLS_REGRESSION: non-Google organization insert';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;

-- Tests are intentionally non-persistent; nothing may survive.
ROLLBACK;
