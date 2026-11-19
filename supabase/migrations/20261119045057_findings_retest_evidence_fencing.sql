-- Forward-only security refinement following accepted findings migrations.
-- A retest comparison must postdate the explicit retest request, never reuse
-- older assessment evidence. No status auto-resolution or new network traffic.
-- Workflow audit and original observations remain unchanged.
ALTER TABLE public.security_findings ADD COLUMN severity_rank smallint
 GENERATED ALWAYS AS (CASE severity_estimate
  WHEN 'high' THEN 4 WHEN 'medium' THEN 3
  WHEN 'low' THEN 2 ELSE 1 END) STORED;
CREATE INDEX security_findings_severity_order_idx ON public.security_findings
 (organization_id,severity_rank DESC,updated_at DESC);
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
   CASE WHEN f.assessment_kind='web_passive'
    THEN coalesce(nullif(o.evidence_source #>> '{paths,0}',''),'/')
    ELSE left(lower(btrim(o.title)),160) END
   FROM public.assessment_observations o WHERE o.job_id=v_match AND
    o.organization_id=p_org AND o.rule_id=f.rule_id LOOP
    v_match_hash:=encode(extensions.digest(
      (f.assessment_kind||':'||f.rule_id||':'||v_match_locator)::bytea,'sha256'),'hex');
    IF v_match_hash=f.dedupe_key THEN v_matched:=true;EXIT;END IF;
  END LOOP;
  v_coverage:=CASE WHEN f.assessment_kind='web_passive'
   THEN coalesce(v_job.web_report->>'coverageState','UNKNOWN')
   ELSE coalesce(v_job.result_coverage->>'classification','UNKNOWN') END;
  v_comp_state:=CASE WHEN v_matched THEN 'observed_again'
   WHEN f.assessment_kind='web_passive' AND
     (v_coverage<>'BOUNDED' OR
       CASE WHEN jsonb_typeof(v_job.web_report->'fetched')='number'
        THEN (v_job.web_report->>'fetched')::int ELSE 0 END<1) THEN 'inconclusive'
   WHEN f.assessment_kind='api_spec_offline' AND
     v_coverage<>'SPEC_ONLY' THEN 'inconclusive'
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
COMMENT ON FUNCTION lumicsec_private.finding_action(uuid,uuid,text,jsonb,uuid)
 IS 'AAL2 signed tenant reviewer workflow: strict post-request retest evidence, owner/admin risk authorization, and no fabricated verified resolution';
