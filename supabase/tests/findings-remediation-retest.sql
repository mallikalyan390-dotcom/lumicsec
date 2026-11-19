-- Transactional synthetic PostgreSQL acceptance. No persistent test users/data.
BEGIN;
DO $$ BEGIN
 IF has_table_privilege('authenticated','public.security_findings','INSERT') OR
   has_table_privilege('authenticated','public.finding_events','UPDATE') OR
   has_function_privilege('anon','public.finding_action(uuid,uuid,text,jsonb,uuid)','EXECUTE') OR
   has_function_privilege('authenticated','lumicsec_private.finding_action(uuid,uuid,text,jsonb,uuid)','EXECUTE')
 THEN RAISE EXCEPTION 'FINDING_ACCESS_BOUNDARY_BROKEN'; END IF;
END $$;
INSERT INTO auth.users(id,instance_id,aud,role,email,email_confirmed_at,created_at,updated_at)
VALUES
 ('00000000-0000-4000-8000-00000000e901','00000000-0000-0000-0000-000000000000','authenticated','authenticated','synthetic-find-owner@example.test',now(),now(),now()),
 ('00000000-0000-4000-8000-00000000e902','00000000-0000-0000-0000-000000000000','authenticated','authenticated','synthetic-find-outsider@example.test',now(),now(),now()),
 ('00000000-0000-4000-8000-00000000e903','00000000-0000-0000-0000-000000000000','authenticated','authenticated','synthetic-find-analyst@example.test',now(),now(),now());
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e901',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e901","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
INSERT INTO public.organizations(display_name,created_by)
 VALUES('Findings bounded synthetic rollback','00000000-0000-4000-8000-00000000e901');
SELECT set_config('fqa.org',(SELECT id::text FROM public.organizations WHERE display_name='Findings bounded synthetic rollback'),true);
INSERT INTO public.assets(organization_id,asset_kind,display_name,canonical_origin,created_by)
 VALUES(current_setting('fqa.org')::uuid,'website','Synthetic website','https://synthetic-findings.example.net',
 '00000000-0000-4000-8000-00000000e901');
SELECT set_config('fqa.asset',(SELECT id::text FROM public.assets WHERE organization_id=current_setting('fqa.org')::uuid),true);
RESET ROLE;
INSERT INTO public.organization_memberships(organization_id,user_id,member_role)
 VALUES(current_setting('fqa.org')::uuid,'00000000-0000-4000-8000-00000000e903','analyst');
UPDATE public.assets SET verification_status='verified',verified_at=now(),verification_expires_at=now()+interval '1 day'
 WHERE id=current_setting('fqa.asset')::uuid;
INSERT INTO public.assessment_jobs(organization_id,asset_id,requested_by,assessment_kind,job_state,scope_hash,requested_at,completed_at,web_report)
 VALUES
 (current_setting('fqa.org')::uuid,current_setting('fqa.asset')::uuid,'00000000-0000-4000-8000-00000000e901',
  'web_passive','succeeded',repeat('a',64),now()-interval '2 minutes',now()-interval '110 seconds',
  '{"coverageState":"BOUNDED","fetched":1}'::jsonb),
 (current_setting('fqa.org')::uuid,current_setting('fqa.asset')::uuid,'00000000-0000-4000-8000-00000000e901',
  'web_passive','succeeded',repeat('b',64),now()-interval '1 minute',now()-interval '15 seconds',
  '{"coverageState":"BOUNDED","fetched":1}'::jsonb);
SELECT set_config('fqa.old', (SELECT id::text FROM public.assessment_jobs
 WHERE organization_id=current_setting('fqa.org')::uuid ORDER BY requested_at LIMIT 1),true);
SELECT set_config('fqa.new', (SELECT id::text FROM public.assessment_jobs
 WHERE organization_id=current_setting('fqa.org')::uuid ORDER BY requested_at DESC LIMIT 1),true);
INSERT INTO public.assessment_observations(organization_id,job_id,rule_id,title,summary,
 severity_estimate,observation_classification,remediation,limitation,evidence_source,created_at)
 VALUES(current_setting('fqa.org')::uuid,current_setting('fqa.old')::uuid,
 'P09.HSTS.ABSENT','Synthetic missing HSTS','Synthetic response lacked HSTS',
 'low','DETERMINISTIC_CONFIGURATION_SIGNAL','Review HSTS policy',
 'Passive signal only, not exploit validation',
 jsonb_build_object('paths',jsonb_build_array('/'),
   'fingerprints',jsonb_build_array(repeat('c',64)),
   'nodeIds',jsonb_build_array('wdn_0123456789abcdef01234567')),now()-interval '100 seconds');
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e901',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e901","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
DECLARE v uuid; x jsonb;
BEGIN
 x:=public.findings_import(current_setting('fqa.org')::uuid,current_setting('fqa.old')::uuid,
   '00000000-0000-4000-8000-00000000e911');
 IF (x->>'newFindings')::int<>1 THEN RAISE EXCEPTION 'IMPORT_FAILED';END IF;
 x:=public.findings_import(current_setting('fqa.org')::uuid,current_setting('fqa.old')::uuid,
   '00000000-0000-4000-8000-00000000e911');
 IF (x->>'newFindings')::int<>0 OR
   (SELECT count(*) FROM public.finding_evidence_links WHERE organization_id=current_setting('fqa.org')::uuid)<>1
 THEN RAISE EXCEPTION 'DUPLICATE_FINDING_OR_EVIDENCE';END IF;
 SELECT id INTO v FROM public.security_findings WHERE organization_id=current_setting('fqa.org')::uuid;
 PERFORM set_config('fqa.finding',v::text,true);
 PERFORM public.finding_action(current_setting('fqa.org')::uuid,v,'classify',
  '{"conclusion":"false_positive","reason":"Synthetic fixture intentionally omitted HSTS."}'::jsonb,
  '00000000-0000-4000-8000-00000000e912');
 PERFORM public.finding_action(current_setting('fqa.org')::uuid,v,'classify',
  '{"conclusion":"accepted_risk","reason":"Owner explicitly accepts this controlled synthetic configuration signal."}'::jsonb,
  '00000000-0000-4000-8000-00000000e913');
 PERFORM public.finding_action(current_setting('fqa.org')::uuid,v,'comment',
  '{"message":"Remediation plan will enable HSTS."}'::jsonb,'00000000-0000-4000-8000-00000000e914');
 PERFORM public.finding_action(current_setting('fqa.org')::uuid,v,'assign',
  '{"userId":"00000000-0000-4000-8000-00000000e903"}'::jsonb,
  '00000000-0000-4000-8000-00000000e915');
 PERFORM public.finding_action(current_setting('fqa.org')::uuid,v,'status',
  '{"status":"in_progress"}'::jsonb,'00000000-0000-4000-8000-00000000e916');
 BEGIN
  PERFORM public.finding_action(current_setting('fqa.org')::uuid,v,'status',
   '{"status":"verified_resolved"}'::jsonb,'00000000-0000-4000-8000-00000000e917');
  RAISE EXCEPTION 'FABRICATED_VERIFIED_RESOLUTION';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 PERFORM public.finding_action(current_setting('fqa.org')::uuid,v,'retest_request','{}'::jsonb,
  '00000000-0000-4000-8000-00000000e918');
 -- A job completed before the retest request is deliberately refused.
 BEGIN
  PERFORM public.finding_action(current_setting('fqa.org')::uuid,v,'retest_compare',
   jsonb_build_object('jobId',current_setting('fqa.new')),
   '00000000-0000-4000-8000-00000000e919');
  RAISE EXCEPTION 'PRE_REQUEST_EVIDENCE_ACCEPTED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
RESET ROLE;
-- Fresh synthetic-only assessment completed AFTER the explicit retest request.
-- No worker or external network is initiated.
INSERT INTO public.assessment_jobs(organization_id,asset_id,requested_by,assessment_kind,
 job_state,scope_hash,requested_at,completed_at,web_report)
 VALUES(current_setting('fqa.org')::uuid,current_setting('fqa.asset')::uuid,
 '00000000-0000-4000-8000-00000000e901','web_passive','succeeded',
 repeat('d',64),clock_timestamp(),clock_timestamp(),
 '{"coverageState":"BOUNDED","fetched":1}'::jsonb);
SELECT set_config('fqa.fresh',(SELECT id::text FROM public.assessment_jobs
 WHERE organization_id=current_setting('fqa.org')::uuid AND scope_hash=repeat('d',64)),true);
SET LOCAL ROLE authenticated;
DO $$
DECLARE v uuid:=current_setting('fqa.finding')::uuid;
BEGIN
 PERFORM public.finding_action(current_setting('fqa.org')::uuid,v,'retest_compare',
  jsonb_build_object('jobId',current_setting('fqa.fresh')),
  '00000000-0000-4000-8000-00000000e91a');
 IF (SELECT comparison_state FROM public.finding_retests WHERE finding_id=v)<>'not_observed_in_review'
  OR (SELECT workflow_status FROM public.security_findings WHERE id=v)='verified_resolved'
  OR (SELECT count(*) FROM public.finding_events WHERE finding_id=v)<7
 THEN RAISE EXCEPTION 'RETEST_OR_AUDIT_HISTORY_INVALID';END IF;
END $$;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e903',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e903","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.security_findings WHERE organization_id=current_setting('fqa.org')::uuid)<>1
 THEN RAISE EXCEPTION 'ANALYST_READER_DENIED';END IF;
 BEGIN
  PERFORM public.finding_action(current_setting('fqa.org')::uuid,current_setting('fqa.finding')::uuid,
   'classify','{"conclusion":"accepted_risk","reason":"Analyst cannot authorize this accepted risk."}'::jsonb,
   '00000000-0000-4000-8000-00000000e920');
  RAISE EXCEPTION 'ANALYST_RISK_ACCEPTANCE_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
  PERFORM public.finding_action(current_setting('fqa.org')::uuid,
   current_setting('fqa.finding')::uuid,'classify',
   '{"conclusion":"needs_evidence","reason":"Analyst must not reverse a manager accepted-risk decision."}'::jsonb,
   '00000000-0000-4000-8000-00000000e921');
  RAISE EXCEPTION 'ANALYST_REVOKED_MANAGER_ACCEPTED_RISK';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e902',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e902","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.security_findings WHERE organization_id=current_setting('fqa.org')::uuid)
 OR EXISTS(SELECT 1 FROM public.finding_evidence_links WHERE organization_id=current_setting('fqa.org')::uuid)
 OR EXISTS(SELECT 1 FROM public.finding_events WHERE organization_id=current_setting('fqa.org')::uuid)
 OR EXISTS(SELECT 1 FROM public.finding_retests WHERE organization_id=current_setting('fqa.org')::uuid)
 THEN RAISE EXCEPTION 'CROSS_TENANT_DATA_EXPOSED';END IF;
END $$;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e901',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e901","role":"authenticated","aal":"aal1","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"}]}',true);
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.security_findings WHERE organization_id=current_setting('fqa.org')::uuid)
 THEN RAISE EXCEPTION 'AAL1_FINDINGS_VISIBLE';END IF;
END $$;
ROLLBACK;
SELECT 'ROLLBACK_ONLY_FINDINGS_LIFECYCLE_RLS_PASS' AS test_result;
