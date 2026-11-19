-- Additive controlled API runtime evidence model.
-- No customer scanner queue, no network activation; this synthetic-only
-- service-role fixture recorder cannot accept ordinary customer API origins.
ALTER TABLE public.assessment_jobs DROP CONSTRAINT assessment_jobs_assessment_kind_check;
ALTER TABLE public.assessment_jobs ADD CONSTRAINT assessment_jobs_assessment_kind_check
 CHECK (assessment_kind IN ('web_passive','api_spec_offline','api_runtime_review'));
ALTER TABLE public.security_findings DROP CONSTRAINT security_findings_assessment_kind_check;
ALTER TABLE public.security_findings ADD CONSTRAINT security_findings_assessment_kind_check
 CHECK (assessment_kind IN ('web_passive','api_spec_offline','api_runtime_review'));
ALTER TABLE public.assessment_jobs
 ADD COLUMN runtime_fixture_only boolean NOT NULL DEFAULT false;
CREATE INDEX assessment_runtime_fixture_history ON public.assessment_jobs
 (organization_id,asset_id,requested_at DESC)
 WHERE assessment_kind='api_runtime_review';

CREATE FUNCTION lumicsec_private.runtime_fixture_record(
 p_org uuid,p_asset uuid,p_actor uuid,p_job uuid,p_scope text,
 p_items jsonb,p_report jsonb)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_asset public.assets%ROWTYPE; v_item jsonb;v_new uuid;
 v_count integer;v_prior public.assessment_jobs%ROWTYPE;
BEGIN
 IF p_actor IS NULL OR p_job IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR p_items IS NULL OR jsonb_typeof(p_items)<>'array'
 OR p_report IS NULL OR jsonb_typeof(p_report)<>'object'
 OR pg_catalog.octet_length(p_items::text)>40_000
 OR pg_catalog.octet_length(p_report::text)>4_000
 THEN RAISE EXCEPTION 'invalid synthetic runtime evidence' USING ERRCODE='22023'; END IF;
 v_count:=jsonb_array_length(p_items);
 IF v_count>10 OR p_report->>'classification'<>'RUNTIME_API_REVIEW'
 OR p_report->>'scopeHash'<>p_scope
 OR p_report->>'coverageState'<>'BOUNDED'
 OR coalesce(p_report->>'requests','')<>'3'
 OR (p_report->>'bytes') !~ '^[0-9]{1,6}$'
 OR (p_report->>'bytes')::int>240000
 OR coalesce(p_report->'statuses'->>'owner','') !~ '^[1-5][0-9]{2}$'
 OR coalesce(p_report->'statuses'->>'anonymous','') !~ '^[1-5][0-9]{2}$'
 OR coalesce(p_report->'statuses'->>'other','') !~ '^[1-5][0-9]{2}$'
 THEN RAISE EXCEPTION 'runtime report bounds failed' USING ERRCODE='22023'; END IF;
 SELECT * INTO v_asset FROM public.assets
  WHERE id=p_asset AND organization_id=p_org FOR UPDATE;
 IF NOT FOUND OR v_asset.asset_kind<>'api'
  OR v_asset.canonical_origin<>'https://controlled-api.fixture-api.net'
  OR v_asset.verification_status<>'verified'
  OR v_asset.verification_expires_at<=now()
  OR NOT EXISTS(SELECT 1 FROM public.organization_memberships m WHERE
   m.organization_id=p_org AND m.user_id=p_actor AND m.member_status='active'
   AND m.member_role IN ('owner','admin','analyst'))
 THEN RAISE EXCEPTION 'synthetic fixture ownership/role required' USING ERRCODE='42501'; END IF;
 SELECT * INTO v_prior FROM public.assessment_jobs WHERE id=p_job FOR UPDATE;
 IF FOUND THEN
  IF v_prior.organization_id=p_org AND v_prior.asset_id=p_asset
    AND v_prior.requested_by=p_actor AND v_prior.assessment_kind='api_runtime_review'
    AND v_prior.job_state='succeeded' AND v_prior.scope_hash=p_scope
    AND v_prior.runtime_fixture_only AND v_prior.result_coverage=p_report
    AND v_prior.observation_count=v_count
   THEN RETURN true; END IF;
  RAISE EXCEPTION 'runtime request id reused with different scope' USING ERRCODE='42501';
 END IF;
 FOR v_item IN SELECT * FROM jsonb_array_elements(p_items) LOOP
   IF jsonb_typeof(v_item)<>'object'
    OR coalesce(v_item->>'ruleId','') !~ '^API[.]RUNTIME[.][A-Z0-9._-]{4,80}$'
    OR length(v_item->>'title') NOT BETWEEN 1 AND 240
    OR length(v_item->>'summary') NOT BETWEEN 1 AND 3000
    OR length(v_item->>'remediation') NOT BETWEEN 1 AND 2000
    OR length(v_item->>'limitation') NOT BETWEEN 1 AND 1000
    OR v_item->>'severityEstimate' NOT IN ('info','low','medium')
    OR v_item->>'classification' NOT IN ('DETERMINISTIC_CONFIGURATION_SIGNAL','INCONCLUSIVE')
    OR jsonb_typeof(v_item->'evidenceSource')<>'object'
    OR v_item->'evidenceSource'->'paths'<> '["/v1/accounts/owner"]'::jsonb
    OR jsonb_typeof(v_item->'evidenceSource'->'fingerprints')<>'array'
    OR jsonb_array_length(v_item->'evidenceSource'->'fingerprints')<>3
    OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(
     v_item->'evidenceSource'->'fingerprints') AS x(hash)
     WHERE x.hash !~ '^[a-f0-9]{64}$')
   THEN RAISE EXCEPTION 'untrusted API runtime observation' USING ERRCODE='22023'; END IF;
 END LOOP;
 INSERT INTO public.assessment_jobs(
  id,organization_id,asset_id,requested_by,assessment_kind,job_state,
  scope_hash,authorization_at,started_at,completed_at,observation_count,
  result_coverage,runtime_fixture_only)
 VALUES(p_job,p_org,p_asset,p_actor,'api_runtime_review','succeeded',
  p_scope,now(),now(),now(),v_count,p_report,true) RETURNING id INTO v_new;
 FOR v_item IN SELECT * FROM jsonb_array_elements(p_items) LOOP
  INSERT INTO public.assessment_observations(
   organization_id,job_id,rule_id,title,summary,severity_estimate,
   review_state,evidence_source,observation_classification,remediation,limitation)
  VALUES(p_org,v_new,v_item->>'ruleId',v_item->>'title',v_item->>'summary',
   v_item->>'severityEstimate','review_required',v_item->'evidenceSource',
   v_item->>'classification',v_item->>'remediation',v_item->>'limitation');
 END LOOP;
 INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
 VALUES(p_org,p_actor,'assessment.runtime.fixture.completed',
  'Bounded synthetic-only API HTTPS fixture evidence recorded; no customer scan enabled');
 RETURN true;
END $$;
CREATE FUNCTION public.api_runtime_fixture_record(
 p_org uuid,p_asset uuid,p_actor uuid,p_job uuid,p_scope text,
 p_items jsonb,p_report jsonb)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=''
AS $$ SELECT lumicsec_private.runtime_fixture_record(
  p_org,p_asset,p_actor,p_job,p_scope,p_items,p_report) $$;
REVOKE ALL ON FUNCTION
 lumicsec_private.runtime_fixture_record(uuid,uuid,uuid,uuid,text,jsonb,jsonb),
 public.api_runtime_fixture_record(uuid,uuid,uuid,uuid,text,jsonb,jsonb)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION
 public.api_runtime_fixture_record(uuid,uuid,uuid,uuid,text,jsonb,jsonb)
 TO service_role;

-- Reuse canonical findings model with actual runtime observation provenance.
CREATE OR REPLACE FUNCTION lumicsec_private.findings_import(p_org uuid,p_job uuid,p_request uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_actor uuid; v_job public.assessment_jobs%ROWTYPE; ob record;
 v_finding uuid; v_link uuid; v_locator text; v_hash text; v_added int:=0; v_linked int:=0;
BEGIN
 v_actor:=lumicsec_private.require_google_aal2();
 PERFORM lumicsec_private.require_org_role(p_org,ARRAY['owner','admin','analyst']);
 IF p_request IS NULL THEN RAISE EXCEPTION 'idempotency key required' USING ERRCODE='22023'; END IF;
 SELECT * INTO v_job FROM public.assessment_jobs
  WHERE id=p_job AND organization_id=p_org AND job_state='succeeded'
   AND assessment_kind IN ('web_passive','api_spec_offline','api_runtime_review') FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'completed assessment not accessible' USING ERRCODE='42501'; END IF;
 FOR ob IN SELECT * FROM public.assessment_observations
  WHERE job_id=p_job AND organization_id=p_org ORDER BY id LIMIT 100 LOOP
  v_locator:=CASE WHEN v_job.assessment_kind IN ('web_passive','api_runtime_review')
    THEN COALESCE(NULLIF(ob.evidence_source #>> '{paths,0}',''),'/')
    ELSE left(lower(btrim(ob.title)),160) END;
  v_hash:=encode(extensions.digest((v_job.assessment_kind||':'||ob.rule_id||':'||v_locator)::bytea,'sha256'),'hex');
  INSERT INTO public.security_findings(organization_id,asset_id,assessment_kind,rule_id,
   dedupe_key,source_locator,title,summary,remediation,severity_estimate,source_classification,
   first_job_id,first_observation_id,first_seen_at,last_seen_at)
  VALUES(p_org,v_job.asset_id,v_job.assessment_kind,ob.rule_id,
   v_hash,v_locator,ob.title,ob.summary,ob.remediation,ob.severity_estimate,
   CASE WHEN v_job.assessment_kind='api_spec_offline' THEN 'SPEC_ONLY'
        ELSE coalesce(ob.observation_classification,'INCONCLUSIVE') END,
   p_job,ob.id,ob.created_at,ob.created_at)
  ON CONFLICT (organization_id,asset_id,assessment_kind,rule_id,dedupe_key) DO NOTHING
  RETURNING id INTO v_finding;
  IF v_finding IS NOT NULL THEN v_added:=v_added+1;
  ELSE SELECT id INTO v_finding FROM public.security_findings
    WHERE organization_id=p_org AND asset_id=v_job.asset_id
      AND assessment_kind=v_job.assessment_kind AND rule_id=ob.rule_id AND dedupe_key=v_hash;
  END IF;
  INSERT INTO public.finding_evidence_links(organization_id,finding_id,job_id,observation_id,
    scope_hash,source_fingerprint,evidence_source)
   VALUES(p_org,v_finding,p_job,ob.id,v_job.scope_hash,v_job.source_fingerprint,ob.evidence_source)
   ON CONFLICT (observation_id) DO NOTHING RETURNING id INTO v_link;
  IF v_link IS NOT NULL THEN
    v_linked:=v_linked+1;
    UPDATE public.security_findings SET
      last_seen_at=GREATEST(last_seen_at,ob.created_at),updated_at=now()
      WHERE id=v_finding AND organization_id=p_org;
    INSERT INTO public.finding_events(organization_id,finding_id,actor_id,event_type,details)
    VALUES(p_org,v_finding,v_actor,'imported',jsonb_build_object(
      'observationId',ob.id,'jobId',p_job,'ruleId',ob.rule_id,
      'sourceClassification',CASE WHEN v_job.assessment_kind='api_spec_offline'
       THEN 'SPEC_ONLY' ELSE coalesce(ob.observation_classification,'INCONCLUSIVE') END));
  END IF;
  v_finding:=NULL;v_link:=NULL;
 END LOOP;
 RETURN jsonb_build_object('newFindings',v_added,'linkedObservations',v_linked,
  'assessmentId',p_job,'readOnly',true);
END $$;

-- No automatic VERIFIED_RESOLVED result; existing reviewer decisions remain intact.
CREATE OR REPLACE FUNCTION lumicsec_private.finding_action(
 p_org uuid,p_finding uuid,p_action text,p_payload jsonb,p_request uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_actor uuid; v_role text; f public.security_findings%ROWTYPE;
 v_existing public.finding_events%ROWTYPE; v_event bigint; v_details jsonb;
 v_decision text;v_reason text;v_status text;v_assignee uuid;v_ref text;
 v_job public.assessment_jobs%ROWTYPE;v_retest public.finding_retests%ROWTYPE;
 v_match uuid;v_match_locator text;v_match_hash text;v_matched boolean:=false;
 v_comp_state text;v_coverage text;
BEGIN
 v_actor:=lumicsec_private.require_google_aal2();
 v_role:=lumicsec_private.require_org_role(p_org,ARRAY['owner','admin','analyst']);
 IF p_request IS NULL OR p_action NOT IN ('classify','assign','status','comment','reference','retest_request','retest_compare')
 OR p_payload IS NULL OR jsonb_typeof(p_payload)<>'object'
 OR pg_catalog.octet_length(p_payload::text)>3000
 THEN RAISE EXCEPTION 'invalid finding operation' USING ERRCODE='22023'; END IF;
 SELECT * INTO f FROM public.security_findings
 WHERE id=p_finding AND organization_id=p_org FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'finding access denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO v_existing FROM public.finding_events
 WHERE finding_id=p_finding AND request_id=p_request;
 IF FOUND THEN
  IF v_existing.details->>'operation' IS DISTINCT FROM p_action
   OR v_existing.details->'input' IS DISTINCT FROM p_payload
  THEN RAISE EXCEPTION 'idempotency conflict' USING ERRCODE='22023'; END IF;
  RETURN jsonb_build_object('eventId',v_existing.id,'findingId',p_finding,'replayed',true);
 END IF;
 v_details:=jsonb_build_object('operation',p_action,'input',p_payload);
 CASE p_action
 WHEN 'classify' THEN
  v_decision:=p_payload->>'conclusion';v_reason:=btrim(coalesce(p_payload->>'reason',''));
  IF v_decision IS NULL OR v_decision NOT IN ('configuration_review','needs_evidence','false_positive','accepted_risk')
    OR (v_decision IN ('false_positive','accepted_risk') AND length(v_reason)<12)
    OR length(v_reason)>1500
    OR (v_decision='accepted_risk' AND v_role NOT IN ('owner','admin'))
    OR (f.reviewer_conclusion='accepted_risk' AND v_decision<>'accepted_risk'
      AND v_role NOT IN ('owner','admin'))
  THEN RAISE EXCEPTION 'classification reason or authority invalid' USING ERRCODE='42501'; END IF;
  UPDATE public.security_findings SET reviewer_conclusion=v_decision,review_reason=NULLIF(v_reason,''),
   reviewer_id=v_actor,reviewed_at=now(),updated_at=now() WHERE id=p_finding;
  v_details:=v_details||jsonb_build_object('previousConclusion',f.reviewer_conclusion,
   'newConclusion',v_decision);
 WHEN 'assign' THEN
  IF v_role NOT IN ('owner','admin') THEN
   RAISE EXCEPTION 'assignment requires organization manager' USING ERRCODE='42501'; END IF;
  IF p_payload->>'userId' IS NOT NULL THEN
   BEGIN v_assignee:=(p_payload->>'userId')::uuid;
   EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'invalid assignment' USING ERRCODE='22023'; END;
   IF NOT EXISTS(SELECT 1 FROM public.organization_memberships m WHERE
    m.organization_id=p_org AND m.user_id=v_assignee AND m.member_status='active'
    AND m.member_role IN ('owner','admin','analyst'))
   THEN RAISE EXCEPTION 'assignee not authorized' USING ERRCODE='42501'; END IF;
  END IF;
  UPDATE public.security_findings SET assigned_to=v_assignee,updated_at=now() WHERE id=p_finding;
  v_details:=v_details||jsonb_build_object('previousAssignee',f.assigned_to,'newAssignee',v_assignee);
 WHEN 'status' THEN
  v_status:=p_payload->>'status';
  IF v_status IS NULL OR v_status NOT IN ('open','in_progress','ready_for_retest','reopened')
    OR (f.workflow_status='verified_resolved' AND v_status<>'reopened')
  THEN RAISE EXCEPTION 'resolution requires independently qualifying evidence' USING ERRCODE='42501'; END IF;
  UPDATE public.security_findings SET workflow_status=v_status,updated_at=now() WHERE id=p_finding;
  v_details:=v_details||jsonb_build_object('previousStatus',f.workflow_status,'newStatus',v_status);
 WHEN 'comment' THEN
  IF length(btrim(coalesce(p_payload->>'message',''))) NOT BETWEEN 3 AND 1500
  THEN RAISE EXCEPTION 'comment bounds invalid' USING ERRCODE='22023'; END IF;
 WHEN 'reference' THEN
  v_ref:=p_payload->>'uri';
  IF v_ref IS NULL OR length(v_ref)>500 OR v_ref !~ '^https://[a-z0-9.-]+(/[a-zA-Z0-9._~/-]*)?$'
    OR NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.id=f.asset_id AND
      a.organization_id=p_org AND (v_ref=a.canonical_origin OR
       left(v_ref,length(a.canonical_origin)+1)=a.canonical_origin||'/'))
    OR length(btrim(coalesce(p_payload->>'note',''))) NOT BETWEEN 3 AND 500
  THEN RAISE EXCEPTION 'same-origin sanitized reference required' USING ERRCODE='22023'; END IF;
 WHEN 'retest_request' THEN
  IF NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.organization_id=p_org AND a.id=f.asset_id
    AND a.verification_status='verified' AND a.verification_expires_at>now())
  THEN RAISE EXCEPTION 'current ownership required to request retest' USING ERRCODE='42501'; END IF;
  IF EXISTS(SELECT 1 FROM public.finding_retests WHERE finding_id=p_finding
    AND comparison_state='awaiting_execution')
  THEN RAISE EXCEPTION 'retest already awaiting evidence' USING ERRCODE='23505'; END IF;
  INSERT INTO public.finding_retests(organization_id,finding_id,requested_by)
   VALUES(p_org,p_finding,v_actor);
  UPDATE public.security_findings SET workflow_status='ready_for_retest',updated_at=now()
   WHERE id=p_finding;
 WHEN 'retest_compare' THEN
  BEGIN v_match:=(p_payload->>'jobId')::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
   RAISE EXCEPTION 'retest evidence id required' USING ERRCODE='22023'; END;
  SELECT * INTO v_retest FROM public.finding_retests
   WHERE organization_id=p_org AND finding_id=p_finding AND
    comparison_state='awaiting_execution' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'no pending retest request' USING ERRCODE='42501'; END IF;
  SELECT * INTO v_job FROM public.assessment_jobs
   WHERE id=v_match AND organization_id=p_org AND asset_id=f.asset_id
    AND assessment_kind=f.assessment_kind AND job_state='succeeded'
    AND completed_at>v_retest.requested_at AND id<>f.first_job_id FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'no new authorized completed assessment evidence' USING ERRCODE='42501'; END IF;
  FOR v_match_locator IN SELECT
   CASE WHEN f.assessment_kind IN ('web_passive','api_runtime_review')
    THEN coalesce(nullif(o.evidence_source #>> '{paths,0}',''),'/')
    ELSE left(lower(btrim(o.title)),160) END
   FROM public.assessment_observations o WHERE o.job_id=v_match AND
    o.organization_id=p_org AND o.rule_id=f.rule_id LOOP
    v_match_hash:=encode(extensions.digest(
      (f.assessment_kind||':'||f.rule_id||':'||v_match_locator)::bytea,'sha256'),'hex');
    IF v_match_hash=f.dedupe_key THEN v_matched:=true;EXIT;END IF;
  END LOOP;
  v_coverage:=CASE WHEN f.assessment_kind IN ('web_passive','api_runtime_review')
   THEN coalesce(v_job.web_report->>'coverageState','UNKNOWN')
   ELSE coalesce(v_job.result_coverage->>'classification','UNKNOWN') END;
  v_comp_state:=CASE WHEN v_matched THEN 'observed_again'
   WHEN f.assessment_kind IN ('web_passive','api_runtime_review') AND
     (v_coverage<>'BOUNDED' OR
       CASE WHEN jsonb_typeof(v_job.web_report->'fetched')='number'
        THEN (v_job.web_report->>'fetched')::int ELSE 0 END<1) THEN 'inconclusive'
   WHEN f.assessment_kind='api_spec_offline' AND
     v_coverage<>'SPEC_ONLY' THEN 'inconclusive'
   WHEN f.assessment_kind='api_runtime_review' AND
     (v_coverage<>'RUNTIME_API_REVIEW' OR
       COALESCE(v_job.result_coverage->>'requests','')<>'3') THEN 'inconclusive'
   ELSE 'not_observed_in_review' END;
  UPDATE public.finding_retests SET comparison_job_id=v_match,compared_at=now(),
   comparison_state=v_comp_state,details=jsonb_build_object('coverage',v_coverage,
     'note','Comparison only. Absence does not verify exploit remediation.')
   WHERE id=v_retest.id;
  v_details:=v_details||jsonb_build_object('comparisonJobId',v_match,
   'result',v_comp_state,'coverage',v_coverage,
   'verifiedResolved',false);
 END CASE;
 INSERT INTO public.finding_events(organization_id,finding_id,actor_id,event_type,
    details,request_id)
 VALUES(p_org,p_finding,v_actor,CASE p_action
  WHEN 'classify' THEN 'classified'
  WHEN 'assign' THEN 'assigned'
  WHEN 'status' THEN 'status_changed'
  WHEN 'comment' THEN 'commented'
  WHEN 'reference' THEN 'reference_added'
  WHEN 'retest_request' THEN 'retest_requested'
  ELSE 'retest_compared' END,v_details,p_request)
 RETURNING id INTO v_event;
 INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
 VALUES(p_org,v_actor,'finding.'||left(p_action,50),
  'Finding workflow updated with immutable history');
 RETURN jsonb_build_object('eventId',v_event,'findingId',p_finding,'replayed',false,
  'verifiedResolved',false);
END $$;
