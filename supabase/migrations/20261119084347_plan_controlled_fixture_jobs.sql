-- Forward-only: durable, private development-fixture execution queue for saved plans.
-- NO public customer execution, public egress, or production scheduler is enabled.
-- The trusted service role alone may invoke write RPCs; worker holds no DB credentials.
CREATE TABLE public.assessment_plan_executions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
 plan_id uuid NOT NULL,
 asset_id uuid NOT NULL,
 requested_by uuid NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
 request_id uuid NOT NULL,
 scope_hash text NOT NULL CHECK(scope_hash ~ '^[a-f0-9]{64}$'),
 exact_origin text NOT NULL
   CHECK(exact_origin IN ('https://controlled-web.fixture-web.net','https://controlled-api.fixture-api.net')),
 approved_paths text[] NOT NULL CHECK(cardinality(approved_paths) BETWEEN 1 AND 6),
 safe_profile text NOT NULL CHECK(safe_profile IN ('web_readonly','api_readonly')),
 max_requests smallint NOT NULL CHECK(max_requests BETWEEN 1 AND 6),
 max_response_bytes integer NOT NULL CHECK(max_response_bytes BETWEEN 1024 AND 60000),
 max_total_bytes integer NOT NULL CHECK(max_total_bytes BETWEEN 1024 AND 240000),
 max_execution_ms integer NOT NULL CHECK(max_execution_ms BETWEEN 1000 AND 15000),
 proof_verified_at timestamptz NOT NULL,
 proof_expires_at timestamptz NOT NULL,
 plan_expires_at timestamptz NOT NULL,
 status text NOT NULL DEFAULT 'queued'
   CHECK(status IN ('queued','running','succeeded','failed','cancelled')),
 worker_id uuid,
 lease_generation smallint NOT NULL DEFAULT 0 CHECK(lease_generation BETWEEN 0 AND 2),
 lease_hash text CHECK(lease_hash IS NULL OR lease_hash ~ '^[a-f0-9]{64}$'),
 lease_until timestamptz,
 result_count integer NOT NULL DEFAULT 0 CHECK(result_count BETWEEN 0 AND 60),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 started_at timestamptz,
 completed_at timestamptz,
 error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{3,80}$'),
 UNIQUE(organization_id,plan_id,request_id),
 UNIQUE(id,organization_id),
 FOREIGN KEY(plan_id,organization_id) REFERENCES public.assessment_plans(id,organization_id),
 FOREIGN KEY(asset_id,organization_id) REFERENCES public.assets(id,organization_id),
 CONSTRAINT plan_execution_lease_shape CHECK(
   (status='running' AND worker_id IS NOT NULL
    AND lease_hash IS NOT NULL AND lease_until IS NOT NULL)
   OR status<>'running')
);
CREATE INDEX assessment_plan_execution_history ON public.assessment_plan_executions
  (organization_id,created_at DESC);
CREATE INDEX assessment_plan_execution_queue ON public.assessment_plan_executions
  (status,created_at) WHERE status IN ('queued','running');

ALTER TABLE public.assessment_plan_executions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.assessment_plan_executions FROM PUBLIC,anon,authenticated;
GRANT SELECT(id,organization_id,plan_id,asset_id,requested_by,request_id,scope_hash,
 exact_origin,safe_profile,status,lease_generation,result_count,created_at,
 started_at,completed_at,error_code)
 ON public.assessment_plan_executions TO authenticated;
CREATE POLICY plan_execution_tenant_read ON public.assessment_plan_executions
 FOR SELECT TO authenticated USING (EXISTS(
   SELECT 1 FROM public.organization_memberships m
    WHERE m.organization_id=assessment_plan_executions.organization_id
      AND m.user_id=(SELECT auth.uid()) AND m.member_status='active'
 ));
CREATE POLICY plan_execution_google_totp_guard ON public.assessment_plan_executions
 AS RESTRICTIVE FOR ALL TO authenticated
 USING ((SELECT lumicsec_private.has_google_totp_aal2()))
 WITH CHECK ((SELECT lumicsec_private.has_google_totp_aal2()));

-- Calls are trusted, not open public API. Each stage rechecks the immutable
-- snapshot, original scope, live ownership and member status.
CREATE FUNCTION lumicsec_private.plan_fixture_current(v public.assessment_plan_executions)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=''
AS $$
 SELECT EXISTS(
 SELECT 1 FROM public.assessment_plans p
 JOIN public.assets a ON a.id=p.asset_id AND a.organization_id=p.organization_id
 JOIN public.organization_memberships m ON m.organization_id=p.organization_id
 WHERE p.organization_id=v.organization_id AND p.id=v.plan_id
 AND p.asset_id=v.asset_id AND p.created_by=v.requested_by
 AND p.plan_state='active' AND p.expires_at>clock_timestamp()
 AND p.scope_sha256=v.scope_hash AND p.exact_origin=v.exact_origin
 AND p.approved_paths=v.approved_paths AND p.safe_profile=v.safe_profile
 AND p.max_requests=v.max_requests AND p.max_response_bytes=v.max_response_bytes
 AND p.max_total_bytes=v.max_total_bytes AND p.max_execution_ms=v.max_execution_ms
 AND p.proof_verified_at=v.proof_verified_at
 AND p.proof_expires_at=v.proof_expires_at AND p.expires_at=v.plan_expires_at
 AND v.proof_expires_at>clock_timestamp()
 AND a.canonical_origin=v.exact_origin AND a.verification_status='verified'
 AND a.verified_at=v.proof_verified_at
 AND a.verification_expires_at=v.proof_expires_at
 AND a.verification_expires_at>clock_timestamp()
 AND a.asset_kind=CASE p.safe_profile WHEN 'web_readonly' THEN 'website' ELSE 'api' END
 AND m.user_id=v.requested_by AND m.member_status='active'
 AND m.member_role IN ('owner','admin','analyst'))
$$;

-- Least-privilege current plan materialization for the backend controller.
-- Avoid granting service_role broad direct reads on Auth/RLS tables.
CREATE FUNCTION lumicsec_private.plan_fixture_current_snapshot(
 p_org uuid,p_plan uuid,p_actor uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_plan public.assessment_plans%ROWTYPE;
 v_asset public.assets%ROWTYPE;
 v_member public.organization_memberships%ROWTYPE;
BEGIN
 SELECT * INTO v_plan FROM public.assessment_plans
 WHERE id=p_plan AND organization_id=p_org AND created_by=p_actor;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO v_asset FROM public.assets
 WHERE id=v_plan.asset_id AND organization_id=p_org;
 SELECT * INTO v_member FROM public.organization_memberships
 WHERE organization_id=p_org AND user_id=p_actor;
 IF v_asset.id IS NULL OR v_member.user_id IS NULL THEN RETURN NULL; END IF;
 RETURN jsonb_build_object(
 'planId',v_plan.id,'organizationId',v_plan.organization_id,
 'assetId',v_plan.asset_id,'createdBy',v_plan.created_by,
 'assetKind',v_plan.asset_kind,'origin',v_plan.exact_origin,
 'scopeHash',v_plan.scope_sha256,'approvedPaths',v_plan.approved_paths,
 'profile',v_plan.safe_profile,'state',v_plan.plan_state,
 'maxRequests',v_plan.max_requests,'maxResponseBytes',v_plan.max_response_bytes,
 'maxTotalBytes',v_plan.max_total_bytes,'maxExecutionMs',v_plan.max_execution_ms,
 'proofVerifiedAt',v_plan.proof_verified_at,'proofExpiresAt',v_plan.proof_expires_at,
 'expiresAt',v_plan.expires_at,'assetVerification',v_asset.verification_status,
 'assetOrigin',v_asset.canonical_origin,
 'assetProofVerifiedAt',v_asset.verified_at,
 'assetProofExpiresAt',v_asset.verification_expires_at,
 'actorMembership',v_member.member_status,'actorRole',v_member.member_role);
END $$;

CREATE FUNCTION lumicsec_private.plan_fixture_enqueue(
 p_org uuid,p_plan uuid,p_actor uuid,p_request uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_plan public.assessment_plans%ROWTYPE;
 v_asset public.assets%ROWTYPE; v_prior public.assessment_plan_executions%ROWTYPE;
 v_job uuid;
BEGIN
 IF p_org IS NULL OR p_plan IS NULL OR p_actor IS NULL OR p_request IS NULL
 THEN RAISE EXCEPTION 'invalid fixture request' USING ERRCODE='22023'; END IF;
 SELECT * INTO v_plan FROM public.assessment_plans
 WHERE id=p_plan AND organization_id=p_org FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'plan missing' USING ERRCODE='42501'; END IF;
 SELECT * INTO v_asset FROM public.assets
 WHERE id=v_plan.asset_id AND organization_id=p_org FOR SHARE;
 IF NOT FOUND OR v_plan.created_by<>p_actor OR v_plan.plan_state<>'active'
 OR v_plan.expires_at<=clock_timestamp() OR v_plan.proof_expires_at<=clock_timestamp()
 OR v_plan.exact_origin NOT IN ('https://controlled-web.fixture-web.net',
    'https://controlled-api.fixture-api.net')
 OR v_asset.canonical_origin<>v_plan.exact_origin
 OR v_asset.verification_status<>'verified'
 OR v_asset.verified_at IS DISTINCT FROM v_plan.proof_verified_at
 OR v_asset.verification_expires_at IS DISTINCT FROM v_plan.proof_expires_at
 OR v_asset.verification_expires_at<=clock_timestamp()
 OR NOT EXISTS(SELECT 1 FROM public.organization_memberships m
  WHERE m.organization_id=p_org AND m.user_id=p_actor
    AND m.member_status='active' AND m.member_role IN ('owner','admin','analyst'))
 THEN RAISE EXCEPTION 'fixture scope unauthorized' USING ERRCODE='42501'; END IF;
 SELECT * INTO v_prior FROM public.assessment_plan_executions
 WHERE organization_id=p_org AND plan_id=p_plan AND request_id=p_request FOR UPDATE;
 IF FOUND THEN
   IF v_prior.requested_by<>p_actor OR v_prior.scope_hash<>v_plan.scope_sha256
   THEN RAISE EXCEPTION 'idempotency scope mismatch' USING ERRCODE='42501'; END IF;
   RETURN v_prior.id;
 END IF;
 IF (SELECT count(*) FROM public.assessment_plan_executions
    WHERE organization_id=p_org AND asset_id=v_plan.asset_id
    AND status IN ('queued','running'))>=2
 THEN RAISE EXCEPTION 'fixture capacity exceeded' USING ERRCODE='23514'; END IF;
 INSERT INTO public.assessment_plan_executions(
   organization_id,plan_id,asset_id,requested_by,request_id,
   scope_hash,exact_origin,approved_paths,safe_profile,max_requests,
   max_response_bytes,max_total_bytes,max_execution_ms,proof_verified_at,
   proof_expires_at,plan_expires_at)
 VALUES(p_org,p_plan,v_plan.asset_id,p_actor,p_request,v_plan.scope_sha256,
   v_plan.exact_origin,v_plan.approved_paths,v_plan.safe_profile,
   v_plan.max_requests,v_plan.max_response_bytes,v_plan.max_total_bytes,
   v_plan.max_execution_ms,v_plan.proof_verified_at,
   v_plan.proof_expires_at,v_plan.expires_at)
 RETURNING id INTO v_job;
 INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
 VALUES(p_org,p_actor,'assessment.plan.fixture.queued',
   'Internal controlled fixture queued; no customer network execution');
 RETURN v_job;
END $$;

CREATE FUNCTION lumicsec_private.plan_fixture_claim(
 p_job uuid,p_worker uuid,p_scope text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v public.assessment_plan_executions%ROWTYPE; t text;
BEGIN
 IF p_worker IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'invalid fixture claim' USING ERRCODE='22023'; END IF;
 SELECT * INTO v FROM public.assessment_plan_executions WHERE id=p_job FOR UPDATE;
 IF NOT FOUND OR v.scope_hash<>p_scope OR v.status NOT IN ('queued','running')
 OR (v.status='running' AND v.lease_until>clock_timestamp())
 THEN RETURN NULL; END IF;
 -- Generation exhaustion must not leave a permanently RUNNING row.
 -- An expired last lease is fenced and marked failed; the old token
 -- cannot heartbeat/complete or claim again.
 IF v.lease_generation>=2 THEN
   IF v.status='running' AND v.lease_until<=clock_timestamp() THEN
     UPDATE public.assessment_plan_executions
       SET status='failed',completed_at=clock_timestamp(),
        lease_hash=NULL,lease_until=NULL,error_code='STALE_LEASE'
       WHERE id=p_job;
   END IF;
   RETURN NULL;
 END IF;
 PERFORM 1 FROM public.assessment_plans WHERE id=v.plan_id FOR SHARE;
 PERFORM 1 FROM public.assets WHERE id=v.asset_id FOR SHARE;
 IF NOT lumicsec_private.plan_fixture_current(v) THEN
  UPDATE public.assessment_plan_executions SET status='cancelled',
    completed_at=clock_timestamp(),lease_hash=NULL,lease_until=NULL
    WHERE id=p_job;
  RETURN NULL;
 END IF;
 t:=encode(extensions.gen_random_bytes(32),'hex');
 UPDATE public.assessment_plan_executions SET status='running',
   started_at=coalesce(started_at,clock_timestamp()),worker_id=p_worker,
   lease_generation=lease_generation+1,
   lease_hash=encode(extensions.digest(t,'sha256'),'hex'),
   lease_until=clock_timestamp()+interval '20 seconds'
 WHERE id=p_job;
 RETURN jsonb_build_object('jobId',v.id,'organizationId',v.organization_id,
   'assetId',v.asset_id,'planId',v.plan_id,'actorId',v.requested_by,
   'scopeHash',v.scope_hash,'workerId',p_worker,
   'generation',v.lease_generation+1,'leaseToken',t);
END $$;

CREATE FUNCTION lumicsec_private.plan_fixture_heartbeat(
 p_job uuid,p_token text,p_generation integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v public.assessment_plan_executions%ROWTYPE;
BEGIN
 SELECT * INTO v FROM public.assessment_plan_executions WHERE id=p_job FOR UPDATE;
 IF NOT FOUND OR v.status<>'running' OR p_token !~ '^[a-f0-9]{64}$'
 OR v.lease_generation<>p_generation
 OR v.lease_until<=clock_timestamp()
 OR v.lease_hash IS DISTINCT FROM encode(extensions.digest(p_token,'sha256'),'hex')
 THEN RETURN false; END IF;
 PERFORM 1 FROM public.assessment_plans WHERE id=v.plan_id FOR SHARE;
 PERFORM 1 FROM public.assets WHERE id=v.asset_id FOR SHARE;
 IF NOT lumicsec_private.plan_fixture_current(v) THEN
  UPDATE public.assessment_plan_executions
    SET status='cancelled',completed_at=clock_timestamp(),
    lease_hash=NULL,lease_until=NULL WHERE id=p_job;
  RETURN false;
 END IF;
 UPDATE public.assessment_plan_executions SET lease_until=clock_timestamp()+interval '20 seconds'
 WHERE id=p_job;
 RETURN true;
END $$;

CREATE FUNCTION lumicsec_private.plan_fixture_complete(
 p_job uuid,p_token text,p_generation integer,p_items jsonb,p_report jsonb)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v public.assessment_plan_executions%ROWTYPE;
 item jsonb; v_count integer; v_class text;
BEGIN
 SELECT * INTO v FROM public.assessment_plan_executions WHERE id=p_job FOR UPDATE;
 IF NOT FOUND OR v.status<>'running' OR p_token !~ '^[a-f0-9]{64}$'
 OR v.lease_generation<>p_generation OR v.lease_until<=clock_timestamp()
 OR v.lease_hash IS DISTINCT FROM encode(extensions.digest(p_token,'sha256'),'hex')
 THEN RETURN false; END IF;
 PERFORM 1 FROM public.assessment_plans WHERE id=v.plan_id FOR SHARE;
 PERFORM 1 FROM public.assets WHERE id=v.asset_id FOR SHARE;
 IF NOT lumicsec_private.plan_fixture_current(v) THEN
   UPDATE public.assessment_plan_executions SET status='cancelled',
    completed_at=clock_timestamp(),lease_hash=NULL,lease_until=NULL WHERE id=p_job;
   RETURN false;
 END IF;
 IF p_items IS NULL OR jsonb_typeof(p_items)<>'array'
 OR jsonb_array_length(p_items)>60 OR pg_catalog.octet_length(p_items::text)>105000
 OR p_report IS NULL OR jsonb_typeof(p_report)<>'object'
 OR pg_catalog.octet_length(p_report::text)>10000
 OR p_report->>'scopeHash'<>v.scope_hash
 OR (p_report->>'requests') !~ '^[0-9]{1,2}$'
 OR (p_report->>'requests')::int NOT BETWEEN 1 AND v.max_requests
 OR (p_report->>'bytes') !~ '^[0-9]{1,6}$'
 OR (p_report->>'bytes')::int>v.max_total_bytes
 OR (p_report->>'classification')<>(CASE WHEN v.safe_profile='web_readonly'
   THEN 'PASSIVE_WEB_REVIEW' ELSE 'RUNTIME_API_REVIEW' END)
 THEN RAISE EXCEPTION 'invalid evidence bounds' USING ERRCODE='22023'; END IF;
 v_count:=jsonb_array_length(p_items);
 FOR item IN SELECT value FROM jsonb_array_elements(p_items) LOOP
  IF jsonb_typeof(item)<>'object'
    OR length(coalesce(item->>'ruleId','')) NOT BETWEEN 1 AND 100
    OR length(coalesce(item->>'title','')) NOT BETWEEN 1 AND 240
    OR length(coalesce(item->>'summary','')) NOT BETWEEN 1 AND 3000
    OR length(coalesce(item->>'remediation','')) NOT BETWEEN 1 AND 2000
    OR length(coalesce(item->>'limitation','')) NOT BETWEEN 1 AND 1000
    OR item->>'severityEstimate' NOT IN ('info','low','medium')
    OR item->>'classification' NOT IN
      ('PASSIVE_OBSERVATION','DETERMINISTIC_CONFIGURATION_SIGNAL','INCONCLUSIVE')
    OR jsonb_typeof(item->'evidenceSource')<>'object'
    OR pg_catalog.octet_length((item->'evidenceSource')::text)>1200
    OR jsonb_typeof(item->'evidenceSource'->'paths')<>'array'
    OR jsonb_array_length(item->'evidenceSource'->'paths') NOT BETWEEN 1 AND 3
    OR jsonb_typeof(item->'evidenceSource'->'fingerprints')<>'array'
    OR jsonb_array_length(item->'evidenceSource'->'fingerprints') NOT BETWEEN 1 AND 4
    OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(
      item->'evidenceSource'->'fingerprints') AS fp(value)
      WHERE fp.value !~ '^[a-f0-9]{64}$')
    OR jsonb_typeof(item->'evidenceSource'->'nodeIds')<>'array'
    OR jsonb_array_length(item->'evidenceSource'->'nodeIds') NOT BETWEEN 1 AND 4
    OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(
      item->'evidenceSource'->'nodeIds') AS nd(value)
      WHERE nd.value !~ '^wdn_[a-f0-9]{24}$')
    OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(item->'evidenceSource'->'paths')
      AS src(path) WHERE NOT (src.path=ANY(v.approved_paths)))
  THEN RAISE EXCEPTION 'invalid fixture evidence item' USING ERRCODE='22023'; END IF;
 END LOOP;
 -- Atomic source job + observations: no fabricated partial persisted results.
 v_class:=CASE v.safe_profile WHEN 'web_readonly' THEN 'web_passive'
   ELSE 'api_runtime_review' END;
 INSERT INTO public.assessment_jobs(
   id,organization_id,asset_id,requested_by,assessment_kind,job_state,
   scope_hash,authorization_at,started_at,completed_at,observation_count,
   web_origin,web_report,result_coverage,runtime_fixture_only)
 VALUES(v.id,v.organization_id,v.asset_id,v.requested_by,v_class,'succeeded',
   v.scope_hash,v.created_at,coalesce(v.started_at,clock_timestamp()),
   clock_timestamp(),v_count,v.exact_origin,
   CASE WHEN v_class='web_passive' THEN p_report ELSE NULL END,
   CASE WHEN v_class='api_runtime_review' THEN p_report ELSE NULL END,true);
 FOR item IN SELECT value FROM jsonb_array_elements(p_items) LOOP
   INSERT INTO public.assessment_observations(
    organization_id,job_id,rule_id,title,summary,severity_estimate,review_state,
    evidence_source,observation_classification,remediation,limitation)
   VALUES(v.organization_id,v.id,item->>'ruleId',item->>'title',item->>'summary',
    item->>'severityEstimate','review_required',item->'evidenceSource',
    item->>'classification',item->>'remediation',item->>'limitation');
 END LOOP;
 UPDATE public.assessment_plan_executions SET status='succeeded',
   completed_at=clock_timestamp(),lease_hash=NULL,lease_until=NULL,
   result_count=v_count WHERE id=p_job;
 INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
 VALUES(v.organization_id,v.requested_by,'assessment.plan.fixture.completed',
   'Controlled Docker fixture evidence accepted; public scanning disabled');
 RETURN true;
END $$;

CREATE FUNCTION lumicsec_private.plan_fixture_stop(
 p_job uuid,p_token text,p_generation integer,p_code text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v public.assessment_plan_executions%ROWTYPE;
BEGIN
 SELECT * INTO v FROM public.assessment_plan_executions WHERE id=p_job FOR UPDATE;
 IF NOT FOUND OR v.status NOT IN ('queued','running')
 OR p_code NOT IN ('CANCELLED','FAILED') THEN RETURN false; END IF;
 IF v.status='running' AND (p_token !~ '^[a-f0-9]{64}$'
 OR v.lease_generation<>p_generation
 OR v.lease_hash IS DISTINCT FROM encode(extensions.digest(p_token,'sha256'),'hex'))
 THEN RETURN false; END IF;
 UPDATE public.assessment_plan_executions
 SET status=CASE WHEN p_code='FAILED' THEN 'failed' ELSE 'cancelled' END,
 completed_at=clock_timestamp(),lease_hash=NULL,lease_until=NULL,
 error_code=p_code WHERE id=p_job;
 RETURN true;
END $$;

CREATE FUNCTION public.plan_fixture_current_snapshot(
 p_org uuid,p_plan uuid,p_actor uuid)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=''
AS $$ SELECT lumicsec_private.plan_fixture_current_snapshot(p_org,p_plan,p_actor) $$;
CREATE FUNCTION public.plan_fixture_enqueue(p_org uuid,p_plan uuid,p_actor uuid,p_request uuid)
RETURNS uuid LANGUAGE sql SECURITY DEFINER SET search_path=''
AS $$ SELECT lumicsec_private.plan_fixture_enqueue(p_org,p_plan,p_actor,p_request) $$;
CREATE FUNCTION public.plan_fixture_claim(p_job uuid,p_worker uuid,p_scope text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=''
AS $$ SELECT lumicsec_private.plan_fixture_claim(p_job,p_worker,p_scope) $$;
CREATE FUNCTION public.plan_fixture_heartbeat(p_job uuid,p_token text,p_generation integer)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=''
AS $$ SELECT lumicsec_private.plan_fixture_heartbeat(p_job,p_token,p_generation) $$;
CREATE FUNCTION public.plan_fixture_complete(
 p_job uuid,p_token text,p_generation integer,p_items jsonb,p_report jsonb)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=''
AS $$ SELECT lumicsec_private.plan_fixture_complete(p_job,p_token,p_generation,p_items,p_report) $$;
CREATE FUNCTION public.plan_fixture_stop(
 p_job uuid,p_token text,p_generation integer,p_code text)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=''
AS $$ SELECT lumicsec_private.plan_fixture_stop(p_job,p_token,p_generation,p_code) $$;

REVOKE ALL ON FUNCTION
 lumicsec_private.plan_fixture_current(public.assessment_plan_executions),
 lumicsec_private.plan_fixture_current_snapshot(uuid,uuid,uuid),
 public.plan_fixture_current_snapshot(uuid,uuid,uuid),
 lumicsec_private.plan_fixture_enqueue(uuid,uuid,uuid,uuid),
 lumicsec_private.plan_fixture_claim(uuid,uuid,text),
 lumicsec_private.plan_fixture_heartbeat(uuid,text,integer),
 lumicsec_private.plan_fixture_complete(uuid,text,integer,jsonb,jsonb),
 lumicsec_private.plan_fixture_stop(uuid,text,integer,text),
 public.plan_fixture_enqueue(uuid,uuid,uuid,uuid),
 public.plan_fixture_claim(uuid,uuid,text),
 public.plan_fixture_heartbeat(uuid,text,integer),
 public.plan_fixture_complete(uuid,text,integer,jsonb,jsonb),
 public.plan_fixture_stop(uuid,text,integer,text)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION
 public.plan_fixture_current_snapshot(uuid,uuid,uuid),
 public.plan_fixture_enqueue(uuid,uuid,uuid,uuid),
 public.plan_fixture_claim(uuid,uuid,text),
 public.plan_fixture_heartbeat(uuid,text,integer),
 public.plan_fixture_complete(uuid,text,integer,jsonb,jsonb),
 public.plan_fixture_stop(uuid,text,integer,text)
 TO service_role;
