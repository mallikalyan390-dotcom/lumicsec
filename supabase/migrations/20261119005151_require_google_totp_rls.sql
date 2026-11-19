-- Forward-only RLS defense in depth for ALL existing tenant data.
-- Prior permissive RLS policies restricted membership but did not require
-- the Google+TOTP AAL2 JWT on every directly readable/updateable table.
-- A client could bypass the Fastify AAL2 guard by querying the Supabase Data
-- API with an AAL1 token after a previously verified session had created a
-- membership. These restrictive policies close that alternate path.
--
-- Existing owner bootstrap, tenant IDs, role assignments, data and permissive
-- policies are preserved. New restrictive RLS checks are combined with the
-- existing per-row tenant membership policies (logical AND).

CREATE FUNCTION lumicsec_private.has_google_totp_aal2()
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=''
AS $$
  SELECT
    (select auth.uid()) IS NOT NULL
    AND (select auth.jwt()) ->> 'aal' = 'aal2'
    AND (select auth.jwt()) -> 'app_metadata' ->> 'provider' = 'google'
    AND coalesce((select auth.jwt()) -> 'amr' @> '[{"method":"oauth"}]'::jsonb, false)
    AND coalesce((select auth.jwt()) -> 'amr' @> '[{"method":"totp"}]'::jsonb, false);
$$;

REVOKE ALL ON FUNCTION lumicsec_private.has_google_totp_aal2()
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.has_google_totp_aal2()
  TO authenticated;

-- RESTRICTIVE policies never grant a row on their own; the original
-- organization/asset/audit membership policies still must pass.
CREATE POLICY tenant_google_totp_aal2_guard ON public.organizations
  AS RESTRICTIVE FOR ALL TO authenticated
  USING ((select lumicsec_private.has_google_totp_aal2()))
  WITH CHECK ((select lumicsec_private.has_google_totp_aal2()));

CREATE POLICY tenant_google_totp_aal2_guard ON public.organization_memberships
  AS RESTRICTIVE FOR ALL TO authenticated
  USING ((select lumicsec_private.has_google_totp_aal2()))
  WITH CHECK ((select lumicsec_private.has_google_totp_aal2()));

CREATE POLICY tenant_google_totp_aal2_guard ON public.assets
  AS RESTRICTIVE FOR ALL TO authenticated
  USING ((select lumicsec_private.has_google_totp_aal2()))
  WITH CHECK ((select lumicsec_private.has_google_totp_aal2()));

CREATE POLICY tenant_google_totp_aal2_guard ON public.assessment_jobs
  AS RESTRICTIVE FOR ALL TO authenticated
  USING ((select lumicsec_private.has_google_totp_aal2()))
  WITH CHECK ((select lumicsec_private.has_google_totp_aal2()));

CREATE POLICY tenant_google_totp_aal2_guard ON public.assessment_observations
  AS RESTRICTIVE FOR ALL TO authenticated
  USING ((select lumicsec_private.has_google_totp_aal2()))
  WITH CHECK ((select lumicsec_private.has_google_totp_aal2()));

CREATE POLICY tenant_google_totp_aal2_guard ON public.audit_events
  AS RESTRICTIVE FOR ALL TO authenticated
  USING ((select lumicsec_private.has_google_totp_aal2()))
  WITH CHECK ((select lumicsec_private.has_google_totp_aal2()));

-- Deliberately no security-definer bypass for Data API access; trusted
-- internal SECURITY DEFINER functions continue their own explicit checks.
-- This migration does NOT enable customer scanning.
