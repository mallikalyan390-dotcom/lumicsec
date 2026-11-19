-- Forward-only fixture-only timestamp fix: a new comparator can be
-- completed after a retest request even within one rollback-only QA transaction.
-- Original evidence and current customer scan restrictions unchanged.
CREATE OR REPLACE FUNCTION lumicsec_private.runtime_fixture_record(
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
  p_scope,now(),now(),clock_timestamp(),v_count,p_report,true) RETURNING id INTO v_new;
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
