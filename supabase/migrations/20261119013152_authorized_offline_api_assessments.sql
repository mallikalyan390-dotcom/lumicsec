-- Forward-only authorization-gated OFFLINE API specification assessment jobs.
-- No network scanner, periodic worker, commercial traffic or live target is enabled.
-- All writes use service_role-only RPCs. Customer JWT accesses READ through existing AAL2 restrictive RLS.
ALTER TABLE public.assessment_jobs
  ADD COLUMN source_fingerprint text CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
  ADD COLUMN source_format text CHECK (source_format IN ('OPENAPI_3_0','OPENAPI_3_1','SWAGGER_2','POSTMAN_2_1')),
  ADD COLUMN authorization_at timestamptz,
  ADD COLUMN result_coverage jsonb,
  ADD COLUMN observation_count integer NOT NULL DEFAULT 0 CHECK (observation_count BETWEEN 0 AND 100);

-- Internal job checks are repeated at queue, begin, and completion.
CREATE FUNCTION lumicsec_private.offline_api_eligible(p_org uuid,p_asset uuid,p_actor uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=''
AS $$
 SELECT EXISTS (
   SELECT 1 FROM public.assets a JOIN public.organization_memberships m
     ON m.organization_id=a.organization_id
    WHERE a.id=p_asset AND a.organization_id=p_org AND a.asset_kind='api'
      AND a.verification_status='verified' AND a.verification_expires_at>now()
      AND m.user_id=p_actor AND m.member_status='active'
      AND m.member_role IN ('owner','admin','analyst')
 )
$$;

CREATE FUNCTION lumicsec_private.offline_api_queue(
  p_org uuid,p_asset uuid,p_actor uuid,p_scope text,p_fingerprint text,p_format text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_job uuid;
BEGIN
  IF p_scope IS NULL OR p_scope !~ '^[0-9a-f]{64}$'
     OR p_fingerprint IS NULL OR p_fingerprint !~ '^[0-9a-f]{64}$'
     OR p_format IS NULL OR p_format NOT IN ('OPENAPI_3_0','OPENAPI_3_1','SWAGGER_2','POSTMAN_2_1')
     OR p_actor IS NULL THEN
    RAISE EXCEPTION 'invalid offline assessment request' USING ERRCODE='22023';
  END IF;
  -- Lock the asset to serialize concurrent per-asset queue checks.
  PERFORM 1 FROM public.assets WHERE id=p_asset AND organization_id=p_org FOR UPDATE;
  IF NOT FOUND OR NOT lumicsec_private.offline_api_eligible(p_org,p_asset,p_actor) THEN
    RAISE EXCEPTION 'current verified ownership and authorized member required' USING ERRCODE='42501';
  END IF;
  -- Fail closed and release capacity for stale jobs; no automatic retries.
  UPDATE public.assessment_jobs SET job_state='cancelled',completed_at=now()
    WHERE asset_id=p_asset AND organization_id=p_org
      AND assessment_kind='api_spec_offline'
      AND job_state='queued' AND requested_at<now()-interval '2 minutes';
  UPDATE public.assessment_jobs SET job_state='cancelled',completed_at=now()
    WHERE asset_id=p_asset AND organization_id=p_org
      AND assessment_kind='api_spec_offline'
      AND job_state='running' AND started_at<now()-interval '2 minutes';
  IF (SELECT count(*) FROM public.assessment_jobs
      WHERE asset_id=p_asset AND organization_id=p_org
        AND job_state IN ('queued','running')) >= 2 THEN
    RAISE EXCEPTION 'asset offline job capacity reached' USING ERRCODE='23514';
  END IF;
  INSERT INTO public.assessment_jobs(
    organization_id,asset_id,requested_by,assessment_kind,job_state,
    scope_hash,source_fingerprint,source_format,authorization_at)
    VALUES(p_org,p_asset,p_actor,'api_spec_offline','queued',
      p_scope,p_fingerprint,p_format,now()) RETURNING id INTO v_job;
  INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
    VALUES(p_org,p_actor,'assessment.offline.queued','Explicitly authorized offline API specification assessment queued');
  RETURN v_job;
END $$;

CREATE FUNCTION lumicsec_private.offline_api_begin(p_job uuid,p_actor uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v public.assessment_jobs%ROWTYPE;
BEGIN
  SELECT * INTO v FROM public.assessment_jobs WHERE id=p_job FOR UPDATE;
  IF NOT FOUND OR v.assessment_kind <> 'api_spec_offline' OR v.requested_by <> p_actor
    OR v.job_state <> 'queued' THEN RETURN false; END IF;
  IF v.requested_at < now()-interval '2 minutes'
     OR NOT lumicsec_private.offline_api_eligible(v.organization_id,v.asset_id,p_actor) THEN
    UPDATE public.assessment_jobs SET job_state='cancelled',completed_at=now() WHERE id=p_job;
    INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
      VALUES(v.organization_id,p_actor,'assessment.offline.cancelled','Authorization or ownership invalid at execution');
    RETURN false;
  END IF;
  UPDATE public.assessment_jobs SET job_state='running',started_at=now() WHERE id=p_job;
  RETURN true;
END $$;

CREATE FUNCTION lumicsec_private.offline_api_complete(
  p_job uuid,p_actor uuid,p_items jsonb,p_coverage jsonb)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v public.assessment_jobs%ROWTYPE; i jsonb; v_count integer;
BEGIN
  SELECT * INTO v FROM public.assessment_jobs WHERE id=p_job FOR UPDATE;
  IF NOT FOUND OR v.assessment_kind <> 'api_spec_offline' OR v.requested_by <> p_actor
    OR v.job_state <> 'running' THEN RETURN false; END IF;
  IF v.started_at < now()-interval '2 minutes'
     OR NOT lumicsec_private.offline_api_eligible(v.organization_id,v.asset_id,p_actor) THEN
    UPDATE public.assessment_jobs SET job_state='cancelled',completed_at=now() WHERE id=p_job;
    INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
      VALUES(v.organization_id,p_actor,'assessment.offline.cancelled','Authorization or ownership invalid at result commit');
    RETURN false;
  END IF;
  IF p_items IS NULL OR jsonb_typeof(p_items)<>'array' OR jsonb_array_length(p_items)>100
    OR pg_catalog.octet_length(p_items::text)>150000
    OR p_coverage IS NULL OR jsonb_typeof(p_coverage)<>'object'
    OR pg_catalog.octet_length(p_coverage::text)>12000 THEN
    RAISE EXCEPTION 'bounded evidence required' USING ERRCODE='22023';
  END IF;
  v_count := jsonb_array_length(p_items);
  FOR i IN SELECT value FROM jsonb_array_elements(p_items) LOOP
    IF jsonb_typeof(i)<>'object'
      OR length(coalesce(i->>'ruleId','')) NOT BETWEEN 1 AND 100
      OR length(coalesce(i->>'title','')) NOT BETWEEN 1 AND 240
      OR length(coalesce(i->>'summary','')) NOT BETWEEN 1 AND 3000
      OR coalesce(i->>'severityEstimate','') NOT IN ('info','low','medium','high') THEN
      RAISE EXCEPTION 'invalid observation evidence' USING ERRCODE='22023';
    END IF;
    INSERT INTO public.assessment_observations(
      organization_id,job_id,rule_id,title,summary,severity_estimate,review_state)
    VALUES(v.organization_id,p_job,i->>'ruleId',i->>'title',i->>'summary',
      i->>'severityEstimate','review_required');
  END LOOP;
  UPDATE public.assessment_jobs SET job_state='succeeded',
    completed_at=now(),result_coverage=p_coverage,observation_count=v_count WHERE id=p_job;
  INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
    VALUES(v.organization_id,p_actor,'assessment.offline.completed',
      'Offline specification observation results persisted; no network scan performed');
  RETURN true;
END $$;

CREATE FUNCTION lumicsec_private.offline_api_stop(p_job uuid,p_actor uuid,p_failed boolean)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v public.assessment_jobs%ROWTYPE;
BEGIN
  SELECT * INTO v FROM public.assessment_jobs WHERE id=p_job FOR UPDATE;
  IF NOT FOUND OR v.assessment_kind <> 'api_spec_offline'
    OR v.job_state NOT IN ('queued','running') THEN RETURN false; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.organization_memberships m
      WHERE m.organization_id=v.organization_id AND m.user_id=p_actor
        AND m.member_status='active' AND m.member_role IN ('owner','admin','analyst'))
    THEN RAISE EXCEPTION 'assessment access denied' USING ERRCODE='42501'; END IF;
  -- A failed state is written only by the trusted backend; both actions are service-role only.
  UPDATE public.assessment_jobs SET job_state=CASE WHEN p_failed THEN 'failed' ELSE 'cancelled' END,
    completed_at=now() WHERE id=p_job;
  INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
    VALUES(v.organization_id,p_actor,
      CASE WHEN p_failed THEN 'assessment.offline.failed' ELSE 'assessment.offline.cancelled' END,
      'Offline assessment stopped before completing results');
  RETURN true;
END $$;

-- Only backend service_role can execute these public RPC wrappers; no browser-generated evidence.
CREATE FUNCTION public.assessment_api_offline_queue(
  p_org uuid,p_asset uuid,p_actor uuid,p_scope text,p_fingerprint text,p_format text)
RETURNS uuid LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.offline_api_queue(p_org,p_asset,p_actor,p_scope,p_fingerprint,p_format) $$;
CREATE FUNCTION public.assessment_api_offline_begin(p_job uuid,p_actor uuid)
RETURNS boolean LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.offline_api_begin(p_job,p_actor) $$;
CREATE FUNCTION public.assessment_api_offline_complete(p_job uuid,p_actor uuid,p_items jsonb,p_coverage jsonb)
RETURNS boolean LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.offline_api_complete(p_job,p_actor,p_items,p_coverage) $$;
CREATE FUNCTION public.assessment_api_offline_stop(p_job uuid,p_actor uuid,p_failed boolean)
RETURNS boolean LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.offline_api_stop(p_job,p_actor,p_failed) $$;

REVOKE ALL ON FUNCTION
 lumicsec_private.offline_api_eligible(uuid,uuid,uuid),
 lumicsec_private.offline_api_queue(uuid,uuid,uuid,text,text,text),
 lumicsec_private.offline_api_begin(uuid,uuid),
 lumicsec_private.offline_api_complete(uuid,uuid,jsonb,jsonb),
 lumicsec_private.offline_api_stop(uuid,uuid,boolean),
 public.assessment_api_offline_queue(uuid,uuid,uuid,text,text,text),
 public.assessment_api_offline_begin(uuid,uuid),
 public.assessment_api_offline_complete(uuid,uuid,jsonb,jsonb),
 public.assessment_api_offline_stop(uuid,uuid,boolean)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION
 lumicsec_private.offline_api_eligible(uuid,uuid,uuid),
 lumicsec_private.offline_api_queue(uuid,uuid,uuid,text,text,text),
 lumicsec_private.offline_api_begin(uuid,uuid),
 lumicsec_private.offline_api_complete(uuid,uuid,jsonb,jsonb),
 lumicsec_private.offline_api_stop(uuid,uuid,boolean),
 public.assessment_api_offline_queue(uuid,uuid,uuid,text,text,text),
 public.assessment_api_offline_begin(uuid,uuid),
 public.assessment_api_offline_complete(uuid,uuid,jsonb,jsonb),
 public.assessment_api_offline_stop(uuid,uuid,boolean)
 TO service_role;
