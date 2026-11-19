-- LumicSec authorized runtime ASSESSMENT PLANS ONLY.
-- No network executor, job queue, service-role grants or scanning activation.
-- Every direct Data API plan read requires tenant membership AND Google+TOTP AAL2.
CREATE TABLE public.assessment_plans (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
 asset_id uuid NOT NULL,
 created_by uuid NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
 revoked_by uuid REFERENCES auth.users(id) ON DELETE RESTRICT,
 idempotency_key uuid NOT NULL,
 asset_kind text NOT NULL CHECK(asset_kind IN ('website','api')),
 exact_origin text NOT NULL CHECK(exact_origin ~ '^https://[a-z0-9.-]{4,240}$'),
 approved_paths text[] NOT NULL CHECK(cardinality(approved_paths) BETWEEN 1 AND 6),
 http_method text NOT NULL DEFAULT 'GET' CHECK(http_method='GET'),
 safe_profile text NOT NULL CHECK(safe_profile IN ('web_readonly','api_readonly')),
 max_requests smallint NOT NULL CHECK(max_requests BETWEEN 1 AND 6),
 max_response_bytes integer NOT NULL CHECK(max_response_bytes BETWEEN 1024 AND 60000),
 max_total_bytes integer NOT NULL CHECK(max_total_bytes BETWEEN 1024 AND 240000),
 max_execution_ms integer NOT NULL CHECK(max_execution_ms BETWEEN 1000 AND 15000),
 consent_version text NOT NULL DEFAULT 'EXPLICIT_OWNED_ASSET_READONLY_V1'
   CHECK(consent_version='EXPLICIT_OWNED_ASSET_READONLY_V1'),
 authorization_reference text NOT NULL CHECK(length(authorization_reference) BETWEEN 12 AND 140),
 proof_verified_at timestamptz NOT NULL,
 proof_expires_at timestamptz NOT NULL,
 scope_sha256 text NOT NULL CHECK(scope_sha256 ~ '^[a-f0-9]{64}$'),
 expires_at timestamptz NOT NULL,
 plan_state text NOT NULL DEFAULT 'active' CHECK(plan_state IN ('active','revoked')),
 created_at timestamptz NOT NULL DEFAULT now(),
 revoked_at timestamptz,
 UNIQUE(organization_id,created_by,idempotency_key),
 UNIQUE(id,organization_id),
 FOREIGN KEY(asset_id,organization_id) REFERENCES public.assets(id,organization_id),
 CONSTRAINT plan_revocation_consistency CHECK(
   (plan_state='active' AND revoked_at IS NULL AND revoked_by IS NULL) OR
   (plan_state='revoked' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL))
);
CREATE INDEX assessment_plans_tenant_history
 ON public.assessment_plans(organization_id,created_at DESC);
CREATE INDEX assessment_plans_asset
 ON public.assessment_plans(organization_id,asset_id,created_at DESC);

CREATE TABLE public.assessment_plan_events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
 plan_id uuid NOT NULL,
 actor_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
 event_type text NOT NULL CHECK(event_type IN ('scope_authorized','authorization_revoked')),
 details jsonb NOT NULL DEFAULT '{}'::jsonb
   CHECK(pg_catalog.octet_length(details::text)<=1200),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(plan_id,organization_id) REFERENCES public.assessment_plans(id,organization_id)
);
CREATE INDEX assessment_plan_events_history ON public.assessment_plan_events
 (organization_id,plan_id,created_at DESC);

ALTER TABLE public.assessment_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.assessment_plan_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.assessment_plans,public.assessment_plan_events
 FROM PUBLIC,anon,authenticated;
GRANT SELECT ON public.assessment_plans,public.assessment_plan_events TO authenticated;
CREATE POLICY plan_active_member_read ON public.assessment_plans FOR SELECT TO authenticated
 USING (EXISTS(SELECT 1 FROM public.organization_memberships m
 WHERE m.organization_id=assessment_plans.organization_id
 AND m.user_id=(SELECT auth.uid()) AND m.member_status='active'));
CREATE POLICY plan_signed_aal2_guard ON public.assessment_plans
 AS RESTRICTIVE FOR ALL TO authenticated
 USING ((SELECT lumicsec_private.has_google_totp_aal2()))
 WITH CHECK ((SELECT lumicsec_private.has_google_totp_aal2()));
CREATE POLICY plan_events_active_member_read ON public.assessment_plan_events FOR SELECT TO authenticated
 USING (EXISTS(SELECT 1 FROM public.organization_memberships m
 WHERE m.organization_id=assessment_plan_events.organization_id
 AND m.user_id=(SELECT auth.uid()) AND m.member_status='active'));
CREATE POLICY plan_events_signed_aal2_guard ON public.assessment_plan_events
 AS RESTRICTIVE FOR ALL TO authenticated
 USING ((SELECT lumicsec_private.has_google_totp_aal2()))
 WITH CHECK ((SELECT lumicsec_private.has_google_totp_aal2()));

CREATE FUNCTION lumicsec_private.immutable_plan_event()
RETURNS trigger LANGUAGE plpgsql SET search_path=''
AS $$ BEGIN RAISE EXCEPTION 'authorization audit immutable' USING ERRCODE='42501'; END $$;
CREATE TRIGGER immutable_assessment_plan_event
 BEFORE UPDATE OR DELETE ON public.assessment_plan_events
 FOR EACH ROW EXECUTE FUNCTION lumicsec_private.immutable_plan_event();

CREATE FUNCTION lumicsec_private.create_assessment_plan(
 p_org uuid,p_asset uuid,p_profile text,p_paths text[],
 p_expires timestamptz,p_requests integer,p_response_bytes integer,
 p_total_bytes integer,p_execution_ms integer,p_reference text,p_request uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_actor uuid;v_asset public.assets%ROWTYPE;
 v_paths text[];v_path text;v_hash text;v_prior public.assessment_plans%ROWTYPE;
 v_plan uuid;
BEGIN
 v_actor:=lumicsec_private.require_google_aal2();
 PERFORM lumicsec_private.require_org_role(p_org,ARRAY['owner','admin','analyst']);
 IF p_org IS NULL OR p_asset IS NULL OR p_request IS NULL
 OR p_profile NOT IN ('web_readonly','api_readonly')
 OR p_paths IS NULL OR cardinality(p_paths) NOT BETWEEN 1 AND 6
 OR p_expires IS NULL OR p_expires<=now()+interval '5 minutes'
 OR p_expires>now()+interval '24 hours'
 OR p_requests NOT BETWEEN 1 AND 6
 OR p_response_bytes NOT BETWEEN 1024 AND 60000
 OR p_total_bytes NOT BETWEEN p_response_bytes AND 240000
 OR p_execution_ms NOT BETWEEN 1000 AND 15000
 OR p_reference IS NULL OR length(btrim(p_reference)) NOT BETWEEN 12 AND 140
 OR p_reference ~ '[[:cntrl:]]'
 THEN RAISE EXCEPTION 'invalid authorization scope or budget' USING ERRCODE='22023'; END IF;
 v_paths:=ARRAY(SELECT DISTINCT z FROM unnest(p_paths) AS z ORDER BY z);
 IF cardinality(v_paths)<>cardinality(p_paths)
 THEN RAISE EXCEPTION 'duplicate allowed endpoint' USING ERRCODE='22023';END IF;
 FOREACH v_path IN ARRAY v_paths LOOP
  IF v_path IS NULL OR v_path !~ '^/[a-zA-Z0-9._~/-]{0,119}$'
   OR v_path ~ '//|(^|/)[.]{1,2}(/|$)'
   OR v_path ~* '(^|/)(logout|delete|destroy|transfer|purchase|checkout|reset|token|secret|admin|signout)(/|$)'
  THEN RAISE EXCEPTION 'unsafe approved path' USING ERRCODE='22023'; END IF;
 END LOOP;
 SELECT * INTO v_asset FROM public.assets a
 WHERE a.id=p_asset AND a.organization_id=p_org FOR SHARE;
 IF NOT FOUND OR v_asset.asset_kind IS DISTINCT FROM
    (CASE p_profile WHEN 'web_readonly' THEN 'website' ELSE 'api' END)
 OR v_asset.verification_status<>'verified'
 OR v_asset.verified_at IS NULL OR v_asset.verification_expires_at IS NULL
 OR v_asset.verification_expires_at<=now()
 OR p_expires>v_asset.verification_expires_at
 THEN RAISE EXCEPTION 'current matching asset ownership required' USING ERRCODE='42501';END IF;
 v_hash:=encode(extensions.digest(pg_catalog.convert_to(
  pg_catalog.concat_ws('|','ASSESSMENT_PLAN_V1',p_org,p_asset,v_asset.canonical_origin,
   p_profile,array_to_string(v_paths,','),p_requests,p_response_bytes,
   p_total_bytes,p_execution_ms,v_asset.verified_at::text,p_expires::text),'UTF8'),
  'sha256'),'hex');
 SELECT * INTO v_prior FROM public.assessment_plans
 WHERE organization_id=p_org AND created_by=v_actor AND idempotency_key=p_request
 FOR UPDATE;
 IF FOUND THEN
  IF v_prior.scope_sha256=v_hash AND v_prior.authorization_reference=btrim(p_reference)
   AND v_prior.asset_id=p_asset AND v_prior.plan_state='active'
   AND v_prior.expires_at>now()
  THEN RETURN v_prior.id;END IF;
  RAISE EXCEPTION 'replayed authorization scope rejected' USING ERRCODE='42501';
 END IF;
 INSERT INTO public.assessment_plans(organization_id,asset_id,created_by,idempotency_key,
   asset_kind,exact_origin,approved_paths,safe_profile,max_requests,
   max_response_bytes,max_total_bytes,max_execution_ms,authorization_reference,
   proof_verified_at,proof_expires_at,scope_sha256,expires_at)
 VALUES(p_org,p_asset,v_actor,p_request,v_asset.asset_kind,v_asset.canonical_origin,
   v_paths,p_profile,p_requests,p_response_bytes,p_total_bytes,p_execution_ms,
   btrim(p_reference),v_asset.verified_at,v_asset.verification_expires_at,v_hash,p_expires)
 RETURNING id INTO v_plan;
 INSERT INTO public.assessment_plan_events(organization_id,plan_id,actor_id,event_type,details)
 VALUES(p_org,v_plan,v_actor,'scope_authorized',
  jsonb_build_object('profile',p_profile,'scopeSha256',v_hash,'paths',v_paths,
   'expiresAt',p_expires,'scanningEnabled',false));
 INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
 VALUES(p_org,v_actor,'assessment.plan.authorized',
  'Explicit bounded assessment plan saved; public network execution remains disabled');
 RETURN v_plan;
END $$;

CREATE FUNCTION lumicsec_private.revoke_assessment_plan(p_org uuid,p_plan uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_actor uuid;v_role text;v_plan public.assessment_plans%ROWTYPE;
BEGIN
 v_actor:=lumicsec_private.require_google_aal2();
 v_role:=lumicsec_private.require_org_role(p_org,ARRAY['owner','admin','analyst']);
 SELECT * INTO v_plan FROM public.assessment_plans
 WHERE id=p_plan AND organization_id=p_org FOR UPDATE;
 IF NOT FOUND OR (v_role='analyst' AND v_plan.created_by<>v_actor)
 THEN RAISE EXCEPTION 'scope revocation forbidden' USING ERRCODE='42501';END IF;
 IF v_plan.plan_state='revoked' THEN RETURN true;END IF;
 UPDATE public.assessment_plans SET plan_state='revoked',revoked_at=clock_timestamp(),
  revoked_by=v_actor WHERE id=p_plan AND organization_id=p_org;
 INSERT INTO public.assessment_plan_events(organization_id,plan_id,actor_id,event_type,details)
 VALUES(p_org,p_plan,v_actor,'authorization_revoked',
 jsonb_build_object('scopeSha256',v_plan.scope_sha256,'scanningEnabled',false));
 INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
 VALUES(p_org,v_actor,'assessment.plan.revoked',
  'Assessment scope authorization revoked; no public execution was active');
 RETURN true;
END $$;

CREATE FUNCTION lumicsec_private.assessment_plan_eligibility(p_org uuid,p_plan uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_actor uuid;v_plan public.assessment_plans%ROWTYPE;v_asset public.assets%ROWTYPE;
 v_reason text;
BEGIN
 v_actor:=lumicsec_private.require_google_aal2();
 PERFORM lumicsec_private.require_org_role(p_org,ARRAY['owner','admin','analyst','viewer','member']);
 SELECT * INTO v_plan FROM public.assessment_plans
 WHERE id=p_plan AND organization_id=p_org;
 IF NOT FOUND THEN RAISE EXCEPTION 'plan not visible' USING ERRCODE='42501';END IF;
 SELECT * INTO v_asset FROM public.assets
 WHERE id=v_plan.asset_id AND organization_id=p_org;
 v_reason:=CASE
  WHEN v_plan.plan_state='revoked' THEN 'REVOKED'
  WHEN v_plan.expires_at<=clock_timestamp() THEN 'EXPIRED'
  WHEN v_asset.id IS NULL OR v_asset.verification_status<>'verified'
    OR v_asset.verified_at IS DISTINCT FROM v_plan.proof_verified_at
    OR v_asset.verification_expires_at IS NULL
    OR v_asset.verification_expires_at<=clock_timestamp()
    OR v_asset.canonical_origin<>v_plan.exact_origin
    THEN 'OWNERSHIP_CHANGED'
  ELSE 'ELIGIBLE_FOR_FUTURE_REVIEW' END;
 RETURN jsonb_build_object('planId',v_plan.id,'eligibility',v_reason,
 'authorizedForPlanning',v_reason='ELIGIBLE_FOR_FUTURE_REVIEW',
 'publicScanningEnabled',false,'executionAllowed',false,
 'scopeSha256',v_plan.scope_sha256);
END $$;

-- Only signed authenticated users can enter these functions. No browser
-- direct INSERT/UPDATE/DELETE, no service role required by the Fastify BFF.
CREATE FUNCTION public.assessment_plan_create(
 p_org uuid,p_asset uuid,p_profile text,p_paths text[],p_expires timestamptz,
 p_requests integer,p_response_bytes integer,p_total_bytes integer,
 p_execution_ms integer,p_reference text,p_request uuid)
RETURNS uuid LANGUAGE sql SECURITY DEFINER SET search_path=''
AS $$ SELECT lumicsec_private.create_assessment_plan(p_org,p_asset,p_profile,p_paths,
 p_expires,p_requests,p_response_bytes,p_total_bytes,p_execution_ms,p_reference,p_request) $$;
CREATE FUNCTION public.assessment_plan_revoke(p_org uuid,p_plan uuid)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=''
AS $$ SELECT lumicsec_private.revoke_assessment_plan(p_org,p_plan) $$;
CREATE FUNCTION public.assessment_plan_check(p_org uuid,p_plan uuid)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=''
AS $$ SELECT lumicsec_private.assessment_plan_eligibility(p_org,p_plan) $$;

REVOKE ALL ON FUNCTION
 lumicsec_private.create_assessment_plan(uuid,uuid,text,text[],timestamptz,integer,integer,integer,integer,text,uuid),
 lumicsec_private.revoke_assessment_plan(uuid,uuid),
 lumicsec_private.assessment_plan_eligibility(uuid,uuid),
 public.assessment_plan_create(uuid,uuid,text,text[],timestamptz,integer,integer,integer,integer,text,uuid),
 public.assessment_plan_revoke(uuid,uuid),
 public.assessment_plan_check(uuid,uuid)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION
 public.assessment_plan_create(uuid,uuid,text,text[],timestamptz,integer,integer,integer,integer,text,uuid),
 public.assessment_plan_revoke(uuid,uuid),
 public.assessment_plan_check(uuid,uuid)
 TO authenticated;
