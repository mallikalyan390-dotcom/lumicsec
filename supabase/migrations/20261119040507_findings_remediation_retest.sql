-- Additive commercial review-only findings workflow. No scanner activation.
-- Every SQL caller must have a signed current Google OAuth + TOTP AAL2 JWT.
CREATE TABLE public.security_findings (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id) on delete cascade,
 asset_id uuid not null,
 assessment_kind text not null check (assessment_kind in ('web_passive','api_spec_offline')),
 rule_id text not null check (length(rule_id) between 1 and 100),
 dedupe_key text not null check (dedupe_key ~ '^[0-9a-f]{64}$'),
 source_locator text not null check (length(source_locator) between 1 and 160),
 title text not null check (length(title) between 1 and 240),
 summary text not null check (length(summary) between 1 and 3000),
 remediation text not null check (remediation is null or length(remediation)<=2000),
 severity_estimate text not null check (severity_estimate in ('info','low','medium','high')),
 source_classification text not null check (source_classification in ('SPEC_ONLY','PASSIVE_OBSERVATION','DETERMINISTIC_CONFIGURATION_SIGNAL','INCONCLUSIVE')),
 reviewer_conclusion text not null default 'unreviewed'
   check (reviewer_conclusion in ('unreviewed','configuration_review','needs_evidence','false_positive','accepted_risk')),
 review_reason text check (review_reason is null or length(review_reason)<=1500),
 reviewer_id uuid references auth.users(id) on delete set null,
 reviewed_at timestamptz,
 workflow_status text not null default 'open'
   check (workflow_status in ('open','in_progress','ready_for_retest','reopened','verified_resolved')),
 assigned_to uuid references auth.users(id) on delete set null,
 first_job_id uuid not null,
 first_observation_id uuid not null,
 first_seen_at timestamptz not null,
 last_seen_at timestamptz not null,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 unique(organization_id,asset_id,assessment_kind,rule_id,dedupe_key),
 unique(id,organization_id),
 foreign key(asset_id,organization_id) references public.assets(id,organization_id),
 foreign key(first_job_id,organization_id) references public.assessment_jobs(id,organization_id),
 foreign key(first_observation_id) references public.assessment_observations(id)
);
CREATE INDEX security_findings_query_idx ON public.security_findings(organization_id,workflow_status,severity_estimate,updated_at desc);
CREATE INDEX security_findings_asset_idx ON public.security_findings(organization_id,asset_id,updated_at desc);

CREATE TABLE public.finding_evidence_links (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id) on delete cascade,
 finding_id uuid not null,
 job_id uuid not null,
 observation_id uuid not null unique references public.assessment_observations(id) on delete restrict,
 scope_hash text check(scope_hash is null or scope_hash ~ '^[0-9a-f]{64}$'),
 source_fingerprint text check(source_fingerprint is null or source_fingerprint ~ '^[0-9a-f]{64}$'),
 evidence_source jsonb,
 linked_at timestamptz not null default now(),
 foreign key(finding_id,organization_id) references public.security_findings(id,organization_id) on delete cascade,
 foreign key(job_id,organization_id) references public.assessment_jobs(id,organization_id) on delete restrict
);
CREATE INDEX finding_evidence_find_idx ON public.finding_evidence_links(organization_id,finding_id,linked_at desc);

CREATE TABLE public.finding_events (
 id bigint generated always as identity primary key,
 organization_id uuid not null references public.organizations(id) on delete cascade,
 finding_id uuid not null,
 actor_id uuid not null references auth.users(id) on delete restrict,
 event_type text not null check(event_type in ('imported','classified','assigned','status_changed','commented','reference_added','retest_requested','retest_compared')),
 details jsonb not null default '{}'::jsonb check(pg_catalog.octet_length(details::text)<=3500),
 request_id uuid,
 occurred_at timestamptz not null default now(),
 foreign key(finding_id,organization_id) references public.security_findings(id,organization_id) on delete cascade,
 unique(finding_id,request_id)
);
CREATE INDEX finding_events_timeline_idx ON public.finding_events(organization_id,finding_id,occurred_at desc);

CREATE TABLE public.finding_retests (
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id) on delete cascade,
 finding_id uuid not null,
 requested_by uuid not null references auth.users(id) on delete restrict,
 requested_at timestamptz not null default now(),
 comparison_job_id uuid,
 compared_at timestamptz,
 comparison_state text not null default 'awaiting_execution' check(comparison_state in
  ('awaiting_execution','observed_again','not_observed_in_review','inconclusive')),
 details jsonb check(details is null or pg_catalog.octet_length(details::text)<=1500),
 foreign key(finding_id,organization_id) references public.security_findings(id,organization_id) on delete cascade,
 foreign key(comparison_job_id,organization_id) references public.assessment_jobs(id,organization_id) on delete restrict
);
CREATE UNIQUE INDEX finding_one_open_retest ON public.finding_retests(finding_id)
 WHERE comparison_state='awaiting_execution';
CREATE INDEX finding_retests_org_idx ON public.finding_retests(organization_id,finding_id,requested_at desc);

ALTER TABLE public.security_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.finding_evidence_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.finding_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.finding_retests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.security_findings,public.finding_evidence_links,
 public.finding_events,public.finding_retests FROM PUBLIC,anon,authenticated;
GRANT SELECT ON public.security_findings,public.finding_evidence_links,
 public.finding_events,public.finding_retests TO authenticated;
-- A permissive membership policy PLUS a restrictive Google/AAL2 guard.
CREATE POLICY findings_member_read ON public.security_findings FOR SELECT TO authenticated
 USING (EXISTS(SELECT 1 FROM public.organization_memberships m WHERE
 m.organization_id=security_findings.organization_id AND m.user_id=(SELECT auth.uid())
 AND m.member_status='active'));
CREATE POLICY findings_aal2_guard ON public.security_findings AS RESTRICTIVE FOR ALL TO authenticated
 USING ((SELECT lumicsec_private.has_google_totp_aal2()))
 WITH CHECK ((SELECT lumicsec_private.has_google_totp_aal2()));

CREATE POLICY findings_evidence_member_read ON public.finding_evidence_links FOR SELECT TO authenticated
 USING (EXISTS(SELECT 1 FROM public.organization_memberships m WHERE
 m.organization_id=finding_evidence_links.organization_id AND m.user_id=(SELECT auth.uid())
 AND m.member_status='active'));
CREATE POLICY findings_evidence_aal2_guard ON public.finding_evidence_links AS RESTRICTIVE FOR ALL TO authenticated
 USING ((SELECT lumicsec_private.has_google_totp_aal2()))
 WITH CHECK ((SELECT lumicsec_private.has_google_totp_aal2()));

CREATE POLICY findings_events_member_read ON public.finding_events FOR SELECT TO authenticated
 USING (EXISTS(SELECT 1 FROM public.organization_memberships m WHERE
 m.organization_id=finding_events.organization_id AND m.user_id=(SELECT auth.uid())
 AND m.member_status='active'));
CREATE POLICY findings_events_aal2_guard ON public.finding_events AS RESTRICTIVE FOR ALL TO authenticated
 USING ((SELECT lumicsec_private.has_google_totp_aal2()))
 WITH CHECK ((SELECT lumicsec_private.has_google_totp_aal2()));

CREATE POLICY findings_retests_member_read ON public.finding_retests FOR SELECT TO authenticated
 USING (EXISTS(SELECT 1 FROM public.organization_memberships m WHERE
 m.organization_id=finding_retests.organization_id AND m.user_id=(SELECT auth.uid())
 AND m.member_status='active'));
CREATE POLICY findings_retests_aal2_guard ON public.finding_retests AS RESTRICTIVE FOR ALL TO authenticated
 USING ((SELECT lumicsec_private.has_google_totp_aal2()))
 WITH CHECK ((SELECT lumicsec_private.has_google_totp_aal2()));

-- Once written, source link evidence and decisions cannot be silently revised.
CREATE FUNCTION lumicsec_private.immutable_findings_provenance()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=''
AS $$ BEGIN RAISE EXCEPTION 'historical finding provenance is immutable' USING ERRCODE='42501'; END $$;
CREATE TRIGGER immutable_finding_evidence BEFORE UPDATE OR DELETE ON public.finding_evidence_links
 FOR EACH ROW EXECUTE FUNCTION lumicsec_private.immutable_findings_provenance();
CREATE TRIGGER immutable_finding_events BEFORE UPDATE OR DELETE ON public.finding_events
 FOR EACH ROW EXECUTE FUNCTION lumicsec_private.immutable_findings_provenance();
-- Retest status is mutable only inside the signed reviewer RPC. Immutable
-- comparison events and original observation links record each transition.

CREATE FUNCTION lumicsec_private.findings_import(p_org uuid,p_job uuid,p_request uuid)
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
   AND assessment_kind IN ('web_passive','api_spec_offline') FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'completed assessment not accessible' USING ERRCODE='42501'; END IF;
 FOR ob IN SELECT * FROM public.assessment_observations
  WHERE job_id=p_job AND organization_id=p_org ORDER BY id LIMIT 100 LOOP
  v_locator:=CASE WHEN v_job.assessment_kind='web_passive'
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

CREATE FUNCTION lumicsec_private.finding_action(
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
  IF v_decision NOT IN ('configuration_review','needs_evidence','false_positive','accepted_risk')
    OR (v_decision IN ('false_positive','accepted_risk') AND length(v_reason)<12)
    OR length(v_reason)>1500
    OR (v_decision='accepted_risk' AND v_role NOT IN ('owner','admin'))
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
  IF v_status NOT IN ('open','in_progress','ready_for_retest','reopened')
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
    AND completed_at>f.first_seen_at AND id<>f.first_job_id FOR SHARE;
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
     v_coverage<>'BOUNDED' THEN 'inconclusive'
   WHEN f.assessment_kind='api_spec_offline' AND
     v_coverage NOT IN ('SPEC_ONLY','INVENTORY_ONLY') THEN 'inconclusive'
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

CREATE FUNCTION public.findings_import(p_org uuid,p_job uuid,p_request uuid)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=''
AS $$ SELECT lumicsec_private.findings_import(p_org,p_job,p_request) $$;
CREATE FUNCTION public.finding_action(p_org uuid,p_finding uuid,p_action text,p_payload jsonb,p_request uuid)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=''
AS $$ SELECT lumicsec_private.finding_action(p_org,p_finding,p_action,p_payload,p_request) $$;
REVOKE ALL ON FUNCTION
 lumicsec_private.immutable_findings_provenance(),
 lumicsec_private.findings_import(uuid,uuid,uuid),
 lumicsec_private.finding_action(uuid,uuid,text,jsonb,uuid),
 public.findings_import(uuid,uuid,uuid),
 public.finding_action(uuid,uuid,text,jsonb,uuid)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION
 public.findings_import(uuid,uuid,uuid),
 public.finding_action(uuid,uuid,text,jsonb,uuid)
 TO authenticated;
-- Private schema USAGE and private-function EXECUTE remain revoked from authenticated.
-- Public wrappers use SECURITY DEFINER but private logic enforces JWT AAL2 + role.
