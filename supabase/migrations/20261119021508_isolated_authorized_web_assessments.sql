-- Development-only durable Web passive job contracts. Does NOT activate any scanner.
-- New functions only service_role, no browser direct mutations. Earlier migrations untouched.
ALTER TABLE public.assessment_jobs
  ADD COLUMN web_idempotency_key uuid,
  ADD COLUMN web_origin text,
  ADD COLUMN web_scope_expires_at timestamptz,
  ADD COLUMN web_lease_generation integer NOT NULL DEFAULT 0 CHECK (web_lease_generation BETWEEN 0 AND 3),
  ADD COLUMN web_lease_hash text CHECK (web_lease_hash IS NULL OR web_lease_hash ~ '^[0-9a-f]{64}$'),
  ADD COLUMN web_lease_until timestamptz,
  ADD COLUMN web_worker_id uuid,
  ADD COLUMN web_cancel_requested boolean NOT NULL DEFAULT false,
  ADD COLUMN web_report jsonb,
  ADD COLUMN web_error_code text CHECK (web_error_code IS NULL OR web_error_code ~ '^[A-Z0-9_]{3,80}$');

CREATE UNIQUE INDEX assessment_web_idempotency_idx
 ON public.assessment_jobs(organization_id, asset_id, web_idempotency_key)
 WHERE assessment_kind='web_passive' AND web_idempotency_key IS NOT NULL;

ALTER TABLE public.assessment_observations
 ADD COLUMN evidence_source jsonb,
 ADD COLUMN observation_classification text
    CHECK (observation_classification IS NULL OR observation_classification IN
      ('PASSIVE_OBSERVATION','DETERMINISTIC_CONFIGURATION_SIGNAL','INCONCLUSIVE')),
 ADD COLUMN remediation text CHECK (remediation IS NULL OR length(remediation)<=2000),
 ADD COLUMN limitation text CHECK (limitation IS NULL OR length(limitation)<=1000);

CREATE FUNCTION lumicsec_private.web_eligible(p_org uuid,p_asset uuid,p_actor uuid,p_origin text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=''
AS $$
 SELECT EXISTS(
 SELECT 1 FROM public.assets a JOIN public.organization_memberships m
   ON m.organization_id=a.organization_id
 WHERE a.organization_id=p_org AND a.id=p_asset AND a.asset_kind='website'
   AND a.canonical_origin=p_origin
   AND a.verification_status='verified' AND a.verification_expires_at>now()
   AND m.user_id=p_actor AND m.member_status='active'
   AND m.member_role IN ('owner','admin','analyst'))
$$;

CREATE FUNCTION lumicsec_private.web_enqueue(
 p_org uuid,p_asset uuid,p_actor uuid,p_origin text,p_scope text,p_key uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_job uuid; v_record record;
BEGIN
 IF p_actor IS NULL OR p_key IS NULL OR p_scope !~ '^[0-9a-f]{64}$'
   OR p_origin IS NULL OR p_origin !~ '^https://[a-z0-9.-]{4,240}$'
 THEN RAISE EXCEPTION 'invalid scope' USING ERRCODE='22023'; END IF;
 PERFORM 1 FROM public.assets WHERE id=p_asset AND organization_id=p_org FOR UPDATE;
 IF NOT FOUND OR NOT lumicsec_private.web_eligible(p_org,p_asset,p_actor,p_origin) THEN
  RAISE EXCEPTION 'authorized ownership required' USING ERRCODE='42501'; END IF;
 SELECT id,requested_by,scope_hash INTO v_record FROM public.assessment_jobs
 WHERE organization_id=p_org AND asset_id=p_asset AND assessment_kind='web_passive'
 AND web_idempotency_key=p_key FOR UPDATE;
 IF FOUND THEN
   IF v_record.requested_by<>p_actor OR v_record.scope_hash<>p_scope THEN
    RAISE EXCEPTION 'idempotency scope mismatch' USING ERRCODE='42501'; END IF;
   RETURN v_record.id;
 END IF;
 -- Lease expiry cannot leave active job slots occupied forever.
 UPDATE public.assessment_jobs SET job_state='cancelled',completed_at=now(),web_lease_hash=NULL
 WHERE organization_id=p_org AND asset_id=p_asset AND assessment_kind='web_passive'
   AND (job_state='queued' AND requested_at<now()-interval '5 minutes'
     OR job_state='running' AND web_lease_until<now());
 IF (SELECT count(*) FROM public.assessment_jobs WHERE organization_id=p_org AND asset_id=p_asset
    AND job_state IN ('queued','running'))>=2 THEN
   RAISE EXCEPTION 'active assessment capacity exceeded' USING ERRCODE='23514';
 END IF;
 INSERT INTO public.assessment_jobs(organization_id,asset_id,requested_by,assessment_kind,
  job_state,scope_hash,web_origin,web_idempotency_key,web_scope_expires_at,authorization_at)
 VALUES(p_org,p_asset,p_actor,'web_passive','queued',p_scope,p_origin,p_key,
  now()+interval '5 minutes',now()) RETURNING id INTO v_job;
 INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
 VALUES(p_org,p_actor,'assessment.web.queued','Explicit scoped passive Web assessment queued; customer scanning disabled');
 RETURN v_job;
END $$;

CREATE FUNCTION lumicsec_private.web_claim(
 p_job uuid,p_worker uuid,p_scope text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v public.assessment_jobs%ROWTYPE; v_token text; v_generation integer;
BEGIN
 IF p_worker IS NULL OR p_scope !~ '^[0-9a-f]{64}$' THEN
  RAISE EXCEPTION 'worker claim denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO v FROM public.assessment_jobs WHERE id=p_job FOR UPDATE;
 IF NOT FOUND OR v.assessment_kind<>'web_passive' OR v.scope_hash<>p_scope OR
    v.web_cancel_requested OR v.web_scope_expires_at<=now() OR
    v.job_state NOT IN ('queued','running') OR
    (v.job_state='running' AND (v.web_lease_until IS NULL OR v.web_lease_until>now())) OR
    v.web_lease_generation>=2 THEN RETURN NULL; END IF;
 -- Serialize current asset verification and memberships against concurrent revocation.
 PERFORM 1 FROM public.assets a WHERE a.id=v.asset_id AND
   a.organization_id=v.organization_id FOR SHARE;
 IF NOT FOUND OR NOT lumicsec_private.web_eligible(v.organization_id,v.asset_id,v.requested_by,v.web_origin) THEN
  UPDATE public.assessment_jobs SET job_state='cancelled',completed_at=now(),
    web_lease_hash=NULL WHERE id=p_job;
  RETURN NULL;
 END IF;
 v_token:=encode(extensions.gen_random_bytes(32),'hex');
 v_generation:=v.web_lease_generation+1;
 UPDATE public.assessment_jobs SET job_state='running',started_at=coalesce(started_at,now()),
   web_worker_id=p_worker,web_lease_generation=v_generation,
   web_lease_hash=encode(extensions.digest(v_token,'sha256'),'hex'),
   web_lease_until=now()+interval '20 seconds'
 WHERE id=p_job;
 INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
 VALUES(v.organization_id,v.requested_by,'assessment.web.claimed','Read-only worker lease claimed');
 RETURN jsonb_build_object('jobId',v.id,'organizationId',v.organization_id,
   'assetId',v.asset_id,'actorId',v.requested_by,'origin',v.web_origin,
   'scopeHash',v.scope_hash,'token',v_token,'generation',v_generation);
END $$;

CREATE FUNCTION lumicsec_private.web_heartbeat(p_job uuid,p_token text,p_generation integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v public.assessment_jobs%ROWTYPE;
BEGIN
 SELECT * INTO v FROM public.assessment_jobs WHERE id=p_job FOR UPDATE;
 IF NOT FOUND OR v.assessment_kind<>'web_passive' OR v.job_state<>'running'
 OR p_token !~ '^[0-9a-f]{64}$'
 OR v.web_lease_hash IS DISTINCT FROM encode(extensions.digest(p_token,'sha256'),'hex')
 OR v.web_lease_generation<>p_generation OR v.web_lease_until<=now()
 THEN RETURN false; END IF;
 PERFORM 1 FROM public.assets a WHERE a.id=v.asset_id AND a.organization_id=v.organization_id FOR SHARE;
 IF v.web_cancel_requested OR v.web_scope_expires_at<=now() OR NOT FOUND OR
 NOT lumicsec_private.web_eligible(v.organization_id,v.asset_id,v.requested_by,v.web_origin)
 THEN
   UPDATE public.assessment_jobs SET job_state='cancelled',completed_at=now(),
      web_lease_hash=NULL WHERE id=p_job;
   RETURN false;
 END IF;
 UPDATE public.assessment_jobs SET web_lease_until=now()+interval '20 seconds' WHERE id=p_job;
 RETURN true;
END $$;

CREATE FUNCTION lumicsec_private.web_complete(
 p_job uuid,p_token text,p_generation integer,p_items jsonb,p_report jsonb)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v public.assessment_jobs%ROWTYPE; item jsonb; v_count integer;
BEGIN
 SELECT * INTO v FROM public.assessment_jobs WHERE id=p_job FOR UPDATE;
 IF NOT FOUND OR v.assessment_kind<>'web_passive' OR v.job_state<>'running'
 OR p_token !~ '^[0-9a-f]{64}$'
 OR v.web_lease_hash IS DISTINCT FROM encode(extensions.digest(p_token,'sha256'),'hex')
 OR v.web_lease_generation<>p_generation OR v.web_lease_until<=now() THEN RETURN false; END IF;
 PERFORM 1 FROM public.assets a WHERE a.id=v.asset_id AND a.organization_id=v.organization_id FOR SHARE;
 IF NOT FOUND OR v.web_cancel_requested OR v.web_scope_expires_at<=now() OR
   NOT lumicsec_private.web_eligible(v.organization_id,v.asset_id,v.requested_by,v.web_origin)
 THEN
  UPDATE public.assessment_jobs SET job_state='cancelled',completed_at=now(),web_lease_hash=NULL WHERE id=p_job;
  RETURN false;
 END IF;
 IF p_items IS NULL OR jsonb_typeof(p_items)<>'array'
 OR jsonb_array_length(p_items)>60 OR pg_catalog.octet_length(p_items::text)>110000
 OR p_report IS NULL OR jsonb_typeof(p_report)<>'object'
 OR pg_catalog.octet_length(p_report::text)>12000
 THEN RAISE EXCEPTION 'invalid evidence bounds' USING ERRCODE='22023'; END IF;
 v_count:=jsonb_array_length(p_items);
 FOR item IN SELECT value FROM jsonb_array_elements(p_items) LOOP
  IF jsonb_typeof(item)<>'object'
    OR length(coalesce(item->>'ruleId','')) NOT BETWEEN 1 AND 100
    OR length(coalesce(item->>'title','')) NOT BETWEEN 1 AND 240
    OR length(coalesce(item->>'summary','')) NOT BETWEEN 1 AND 3000
    OR length(coalesce(item->>'remediation','')) NOT BETWEEN 1 AND 2000
    OR length(coalesce(item->>'limitation','')) NOT BETWEEN 1 AND 1000
    OR coalesce(item->>'classification','') NOT IN
      ('PASSIVE_OBSERVATION','DETERMINISTIC_CONFIGURATION_SIGNAL','INCONCLUSIVE')
    OR coalesce(item->>'severityEstimate','') NOT IN ('info','low','medium')
    OR jsonb_typeof(item->'evidenceSource')<>'object'
    OR pg_catalog.octet_length((item->'evidenceSource')::text)>1200
  THEN RAISE EXCEPTION 'invalid evidence row' USING ERRCODE='22023'; END IF;
  INSERT INTO public.assessment_observations(organization_id,job_id,rule_id,title,
    summary,severity_estimate,review_state,evidence_source,observation_classification,
    remediation,limitation)
  VALUES(v.organization_id,p_job,item->>'ruleId',item->>'title',item->>'summary',
    item->>'severityEstimate','review_required',item->'evidenceSource',
    item->>'classification',item->>'remediation',item->>'limitation');
 END LOOP;
 UPDATE public.assessment_jobs SET job_state='succeeded',completed_at=now(),
  web_lease_hash=NULL,web_lease_until=NULL,web_report=p_report,
  observation_count=v_count WHERE id=p_job;
 INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
 VALUES(v.organization_id,v.requested_by,'assessment.web.completed',
  'Bounded passive Web security observations stored for manual review');
 RETURN true;
END $$;

CREATE FUNCTION lumicsec_private.web_stop(
 p_job uuid,p_actor uuid,p_token text DEFAULT NULL,p_generation integer DEFAULT NULL,p_failed boolean DEFAULT false)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v public.assessment_jobs%ROWTYPE; v_is_worker boolean;
BEGIN
 SELECT * INTO v FROM public.assessment_jobs WHERE id=p_job FOR UPDATE;
 IF NOT FOUND OR v.assessment_kind<>'web_passive'
 OR v.job_state NOT IN ('queued','running') THEN RETURN false; END IF;
 v_is_worker:=(p_token IS NOT NULL AND p_token ~ '^[0-9a-f]{64}$'
   AND p_generation=v.web_lease_generation AND v.web_lease_hash=
   encode(extensions.digest(p_token,'sha256'),'hex'));
 IF p_token IS NOT NULL THEN
   IF NOT v_is_worker THEN RETURN false; END IF;
 ELSIF p_failed OR NOT EXISTS(SELECT 1 FROM public.organization_memberships m
 WHERE m.organization_id=v.organization_id AND m.user_id=p_actor AND m.member_status='active'
 AND m.member_role IN ('owner','admin','analyst')) THEN
   RAISE EXCEPTION 'cancellation access denied' USING ERRCODE='42501';
 END IF;
 UPDATE public.assessment_jobs SET job_state=CASE WHEN p_failed THEN 'failed' ELSE 'cancelled' END,
   completed_at=now(),web_cancel_requested=true,web_lease_hash=NULL,web_lease_until=NULL,
   web_error_code=CASE WHEN p_failed THEN 'WEB_WORKER_FAILED' ELSE NULL END WHERE id=p_job;
 INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
 VALUES(v.organization_id,p_actor,CASE WHEN p_failed THEN 'assessment.web.failed' ELSE 'assessment.web.cancelled' END,
   'Passive Web assessment terminated and worker lease revoked');
 RETURN true;
END $$;

CREATE FUNCTION public.web_assessment_enqueue(p_org uuid,p_asset uuid,p_actor uuid,p_origin text,p_scope text,p_key uuid)
RETURNS uuid LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.web_enqueue(p_org,p_asset,p_actor,p_origin,p_scope,p_key) $$;
CREATE FUNCTION public.web_assessment_claim(p_job uuid,p_worker uuid,p_scope text)
RETURNS jsonb LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.web_claim(p_job,p_worker,p_scope) $$;
CREATE FUNCTION public.web_assessment_heartbeat(p_job uuid,p_token text,p_generation integer)
RETURNS boolean LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.web_heartbeat(p_job,p_token,p_generation) $$;
CREATE FUNCTION public.web_assessment_complete(p_job uuid,p_token text,p_generation integer,p_items jsonb,p_report jsonb)
RETURNS boolean LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.web_complete(p_job,p_token,p_generation,p_items,p_report) $$;
CREATE FUNCTION public.web_assessment_stop(p_job uuid,p_actor uuid,p_token text,p_generation integer,p_failed boolean)
RETURNS boolean LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.web_stop(p_job,p_actor,p_token,p_generation,p_failed) $$;

REVOKE ALL ON FUNCTION
 lumicsec_private.web_eligible(uuid,uuid,uuid,text),
 lumicsec_private.web_enqueue(uuid,uuid,uuid,text,text,uuid),
 lumicsec_private.web_claim(uuid,uuid,text),
 lumicsec_private.web_heartbeat(uuid,text,integer),
 lumicsec_private.web_complete(uuid,text,integer,jsonb,jsonb),
 lumicsec_private.web_stop(uuid,uuid,text,integer,boolean),
 public.web_assessment_enqueue(uuid,uuid,uuid,text,text,uuid),
 public.web_assessment_claim(uuid,uuid,text),
 public.web_assessment_heartbeat(uuid,text,integer),
 public.web_assessment_complete(uuid,text,integer,jsonb,jsonb),
 public.web_assessment_stop(uuid,uuid,text,integer,boolean)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION
 lumicsec_private.web_eligible(uuid,uuid,uuid,text),
 lumicsec_private.web_enqueue(uuid,uuid,uuid,text,text,uuid),
 lumicsec_private.web_claim(uuid,uuid,text),
 lumicsec_private.web_heartbeat(uuid,text,integer),
 lumicsec_private.web_complete(uuid,text,integer,jsonb,jsonb),
 lumicsec_private.web_stop(uuid,uuid,text,integer,boolean),
 public.web_assessment_enqueue(uuid,uuid,uuid,text,text,uuid),
 public.web_assessment_claim(uuid,uuid,text),
 public.web_assessment_heartbeat(uuid,text,integer),
 public.web_assessment_complete(uuid,text,integer,jsonb,jsonb),
 public.web_assessment_stop(uuid,uuid,text,integer,boolean)
 TO service_role;
