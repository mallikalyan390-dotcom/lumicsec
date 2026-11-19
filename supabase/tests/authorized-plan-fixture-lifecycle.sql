-- ROLLBACK-ONLY real PostgreSQL and RLS security tests. No permanent fixtures.
BEGIN;
DO $$ BEGIN
 IF has_function_privilege('anon','public.plan_fixture_enqueue(uuid,uuid,uuid,uuid)','EXECUTE')
 OR has_function_privilege('authenticated','public.plan_fixture_claim(uuid,uuid,text)','EXECUTE')
 OR has_function_privilege('authenticated','public.plan_fixture_complete(uuid,text,integer,jsonb,jsonb)','EXECUTE')
 OR NOT has_function_privilege('service_role','public.plan_fixture_claim(uuid,uuid,text)','EXECUTE')
 OR has_table_privilege('authenticated','public.assessment_plan_executions','INSERT')
 OR has_table_privilege('authenticated','public.assessment_plan_executions','UPDATE')
 OR has_table_privilege('anon','public.assessment_plan_executions','SELECT')
 OR has_function_privilege('authenticated','public.plan_fixture_stop(uuid,text,integer,text)','EXECUTE')
 OR has_function_privilege('anon','public.plan_fixture_current_snapshot(uuid,uuid,uuid)','EXECUTE')
 OR has_table_privilege('authenticated','public.assessment_plan_executions','DELETE')
 THEN RAISE EXCEPTION 'PLAN_FIXTURE_PRIVILEGE_LEAK'; END IF;
END $$;
INSERT INTO auth.users(id,instance_id,aud,role,email,email_confirmed_at,created_at,updated_at)
VALUES
('00000000-0000-4000-8000-00000000e6a1',
 '00000000-0000-0000-0000-000000000000','authenticated','authenticated',
 'rollback-execution-owner@example.test',now(),now(),now()),
('00000000-0000-4000-8000-00000000e6a2',
 '00000000-0000-0000-0000-000000000000','authenticated','authenticated',
 'rollback-execution-viewer@example.test',now(),now(),now()),
('00000000-0000-4000-8000-00000000e6a3',
 '00000000-0000-0000-0000-000000000000','authenticated','authenticated',
 'rollback-execution-outsider@example.test',now(),now(),now());
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e6a1',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e6a1","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
INSERT INTO public.organizations(display_name,created_by)
 VALUES('Rollback Controlled Fixture Job','00000000-0000-4000-8000-00000000e6a1');
SELECT set_config('fixture.org',(SELECT id::text FROM public.organizations
 WHERE display_name='Rollback Controlled Fixture Job'),true);
INSERT INTO public.assets(organization_id,asset_kind,display_name,canonical_origin,created_by)
VALUES(current_setting('fixture.org')::uuid,'website','Local Synthetic Web',
 'https://controlled-web.fixture-web.net','00000000-0000-4000-8000-00000000e6a1');
SELECT set_config('fixture.asset',(SELECT id::text FROM public.assets
 WHERE organization_id=current_setting('fixture.org')::uuid),true);
RESET ROLE;
INSERT INTO public.organization_memberships(organization_id,user_id,member_role,member_status)
VALUES(current_setting('fixture.org')::uuid,'00000000-0000-4000-8000-00000000e6a2','viewer','active');
UPDATE public.assets SET verification_status='verified',
 verified_at=clock_timestamp(),verification_expires_at=now()+interval '1 day'
 WHERE id=current_setting('fixture.asset')::uuid;
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e6a1',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e6a1","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$ DECLARE v uuid;BEGIN
 v:=public.assessment_plan_create(current_setting('fixture.org')::uuid,
  current_setting('fixture.asset')::uuid,'web_readonly',ARRAY['/'],
  now()+interval '1 hour',1,60000,240000,15000,
  'Synthetic-only controlled fixture scope',
  '00000000-0000-4000-8000-00000000f6a1'::uuid);
 PERFORM set_config('fixture.plan',v::text,true);
END $$;
RESET ROLE;
SET LOCAL ROLE service_role;
DO $$
DECLARE v_job uuid;v_same uuid;v_claim jsonb;v_scope text;v_items jsonb;
BEGIN
 v_scope:=public.plan_fixture_current_snapshot(current_setting('fixture.org')::uuid,
 current_setting('fixture.plan')::uuid,
 '00000000-0000-4000-8000-00000000e6a1')->>'scopeHash';
 v_job:=public.plan_fixture_enqueue(current_setting('fixture.org')::uuid,
   current_setting('fixture.plan')::uuid,
   '00000000-0000-4000-8000-00000000e6a1',
   '00000000-0000-4000-8000-00000000f6b1');
 PERFORM set_config('fixture.job',v_job::text,true);
 v_same:=public.plan_fixture_enqueue(current_setting('fixture.org')::uuid,
   current_setting('fixture.plan')::uuid,
   '00000000-0000-4000-8000-00000000e6a1',
   '00000000-0000-4000-8000-00000000f6b1');
 IF v_job<>v_same THEN RAISE EXCEPTION 'EXECUTION_IDEMPOTENCY_FAILED';END IF;
 v_claim:=public.plan_fixture_claim(v_job,'00000000-0000-4000-8000-00000000f6c1',v_scope);
 IF v_claim->>'jobId'<>v_job::text
    OR v_claim->>'scopeHash'<>v_scope
    OR (v_claim->>'generation')::integer<>1
 THEN RAISE EXCEPTION 'EXECUTION_CLAIM_FAILED';END IF;
 IF NOT public.plan_fixture_heartbeat(v_job,v_claim->>'leaseToken',1)
 OR public.plan_fixture_heartbeat(v_job,repeat('f',64),1)
 THEN RAISE EXCEPTION 'EXECUTION_LEASE_FENCING_FAILED';END IF;
 v_items:=jsonb_build_array(jsonb_build_object(
  'ruleId','P09.HSTS.ABSENT','title','Controlled HTTPS missing HSTS',
  'summary','Controlled synthetic response absent HSTS response header.',
  'remediation','Add reviewed Strict-Transport-Security policy.',
  'limitation','Passive local synthetic HTTPS; not exploitable vulnerability.',
  'severityEstimate','low','classification','DETERMINISTIC_CONFIGURATION_SIGNAL',
  'evidenceSource',jsonb_build_object(
    'paths',jsonb_build_array('/'),
    'fingerprints',jsonb_build_array(repeat('c',64)),
    'nodeIds',jsonb_build_array('wdn_'||repeat('a',24)))));
 -- A trusted controller bug cannot put out-of-scope evidence or forged
 -- hashes into the authoritative assessment and Findings tables.
 BEGIN
   PERFORM public.plan_fixture_complete(v_job,v_claim->>'leaseToken',1,
     jsonb_set(v_items,'{0,evidenceSource,paths}','["/admin"]'::jsonb),
     jsonb_build_object('classification','PASSIVE_WEB_REVIEW',
      'scopeHash',v_scope,'requests',1,'bytes',100));
   RAISE EXCEPTION 'OUT_OF_SCOPE_EVIDENCE_ACCEPTED';
 EXCEPTION WHEN invalid_parameter_value THEN NULL;END;
 BEGIN
   PERFORM public.plan_fixture_complete(v_job,v_claim->>'leaseToken',1,
     jsonb_set(v_items,'{0,evidenceSource,fingerprints}','["not-a-hash"]'::jsonb),
     jsonb_build_object('classification','PASSIVE_WEB_REVIEW',
      'scopeHash',v_scope,'requests',1,'bytes',100));
   RAISE EXCEPTION 'FORGED_EVIDENCE_FINGERPRINT_ACCEPTED';
 EXCEPTION WHEN invalid_parameter_value THEN NULL;END;
 BEGIN
   PERFORM public.plan_fixture_complete(v_job,v_claim->>'leaseToken',1,v_items,
     jsonb_build_object('classification','PASSIVE_WEB_REVIEW',
      'scopeHash',v_scope,'requests',7,'bytes',100));
   RAISE EXCEPTION 'EVIDENCE_REQUEST_BUDGET_EXCEEDED';
 EXCEPTION WHEN invalid_parameter_value THEN NULL;END;
 IF NOT public.plan_fixture_complete(v_job,v_claim->>'leaseToken',1,v_items,
    jsonb_build_object('classification','PASSIVE_WEB_REVIEW',
     'scopeHash',v_scope,'requests',1,'bytes',100,'fetched',1,
     'coverageState','BOUNDED'))
 THEN RAISE EXCEPTION 'EXECUTION_COMPLETION_FAILED'; END IF;
 IF public.plan_fixture_claim(v_job,'00000000-0000-4000-8000-00000000f6c1',v_scope)
    IS NOT NULL THEN RAISE EXCEPTION 'COMPLETED_FIXTURE_JOB_RECLAIMED'; END IF;
 IF public.plan_fixture_complete(v_job,v_claim->>'leaseToken',1,'[]'::jsonb,
    jsonb_build_object('classification','PASSIVE_WEB_REVIEW',
     'scopeHash',v_scope,'requests',1,'bytes',100))
 THEN RAISE EXCEPTION 'DUPLICATE_COMPLETION_ALLOWED';END IF;

END $$;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT count(*) FROM public.assessment_jobs
    WHERE id=current_setting('fixture.job')::uuid
      AND job_state='succeeded' AND runtime_fixture_only=true)<>1
 OR (SELECT count(*) FROM public.assessment_plan_executions
    WHERE id=current_setting('fixture.job')::uuid
      AND status='succeeded' AND result_count=1)<>1
 OR (SELECT count(*) FROM public.assessment_observations
   WHERE job_id=current_setting('fixture.job')::uuid
     AND rule_id='P09.HSTS.ABSENT'
     AND evidence_source->'paths'='["/"]'::jsonb)<>1
 THEN RAISE EXCEPTION 'ATOMIC_EVIDENCE_NOT_PERSISTED'; END IF;
END $$;
-- Signed Google+TOTP reviewer imports actual persisted fixture provenance
-- into existing canonical findings. Nothing becomes a verified exploit.
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e6a1',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e6a1","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$DECLARE out jsonb;BEGIN
 out:=public.findings_import(current_setting('fixture.org')::uuid,
  current_setting('fixture.job')::uuid,
  '00000000-0000-4000-8000-00000000f6d1'::uuid);
 IF (out->>'newFindings')::int<>1
 OR (out->>'linkedObservations')::int<>1
 THEN RAISE EXCEPTION 'FIXTURE_SAVED_EVIDENCE_FINDINGS_IMPORT_FAILED';END IF;
 IF (SELECT count(*) FROM public.security_findings
   WHERE organization_id=current_setting('fixture.org')::uuid
     AND first_job_id=current_setting('fixture.job')::uuid
     AND reviewer_conclusion='unreviewed'
     AND source_classification='DETERMINISTIC_CONFIGURATION_SIGNAL')<>1
 THEN RAISE EXCEPTION 'FIXTURE_FINDING_AUTO_PROMOTED_EXPLOIT';END IF;
 IF (SELECT count(*) FROM public.finding_evidence_links
   WHERE job_id=current_setting('fixture.job')::uuid
     AND organization_id=current_setting('fixture.org')::uuid)<>1
 THEN RAISE EXCEPTION 'FIXTURE_PROVENANCE_LINK_MISSING';END IF;
END $$;
RESET ROLE;
SET LOCAL ROLE service_role;
DO $$
DECLARE v_job uuid;v_claim jsonb;v_scope text;
BEGIN
 v_scope:=public.plan_fixture_current_snapshot(current_setting('fixture.org')::uuid,
 current_setting('fixture.plan')::uuid,
 '00000000-0000-4000-8000-00000000e6a1')->>'scopeHash';
 v_job:=public.plan_fixture_enqueue(current_setting('fixture.org')::uuid,
  current_setting('fixture.plan')::uuid,
  '00000000-0000-4000-8000-00000000e6a1',
  '00000000-0000-4000-8000-00000000f6b2');
 PERFORM set_config('fixture.revoked_job',v_job::text,true);
 v_claim:=public.plan_fixture_claim(v_job,'00000000-0000-4000-8000-00000000f6c2',v_scope);
 PERFORM set_config('fixture.revoked_token',v_claim->>'leaseToken',true);
 IF v_claim IS NULL THEN RAISE EXCEPTION 'SECOND_CLAIM_FAILED'; END IF;
END $$;
-- Stale lease after first claim may be reclaimed once, but previous token
-- must never be able to renew or complete. Exhausted second lease fails closed.
SET LOCAL ROLE service_role;
DO $$
DECLARE j uuid;v1 jsonb;v2 jsonb;h text;
BEGIN
 h:=public.plan_fixture_current_snapshot(current_setting('fixture.org')::uuid,
   current_setting('fixture.plan')::uuid,
   '00000000-0000-4000-8000-00000000e6a1')->>'scopeHash';
 j:=public.plan_fixture_enqueue(current_setting('fixture.org')::uuid,
   current_setting('fixture.plan')::uuid,
   '00000000-0000-4000-8000-00000000e6a1',
   '00000000-0000-4000-8000-00000000f6b3');
 PERFORM set_config('fixture.stale_job',j::text,true);
 v1:=public.plan_fixture_claim(j,'00000000-0000-4000-8000-00000000f6c3',h);
 IF v1 IS NULL THEN RAISE EXCEPTION 'STALE_INITIAL_CLAIM_FAILED';END IF;
 PERFORM set_config('fixture.old_token',v1->>'leaseToken',true);
END $$;
RESET ROLE;
UPDATE public.assessment_plan_executions
 SET lease_until=clock_timestamp()-interval '1 second'
 WHERE id=current_setting('fixture.stale_job')::uuid;
SET LOCAL ROLE service_role;
DO $$ DECLARE v jsonb;h text;BEGIN
 h:=public.plan_fixture_current_snapshot(current_setting('fixture.org')::uuid,
   current_setting('fixture.plan')::uuid,
   '00000000-0000-4000-8000-00000000e6a1')->>'scopeHash';
 v:=public.plan_fixture_claim(current_setting('fixture.stale_job')::uuid,
   '00000000-0000-4000-8000-00000000f6c4',h);
 IF v IS NULL OR (v->>'generation')::int<>2
 THEN RAISE EXCEPTION 'STALE_RECLAIM_FENCING_FAILED';END IF;
 IF public.plan_fixture_heartbeat(current_setting('fixture.stale_job')::uuid,
     current_setting('fixture.old_token'),1)
 THEN RAISE EXCEPTION 'STALE_OLD_TOKEN_RENEWED';END IF;
END $$;
RESET ROLE;
UPDATE public.assessment_plan_executions
 SET lease_until=clock_timestamp()-interval '1 second'
 WHERE id=current_setting('fixture.stale_job')::uuid;
SET LOCAL ROLE service_role;
DO $$ DECLARE v jsonb;h text;BEGIN
 h:=public.plan_fixture_current_snapshot(current_setting('fixture.org')::uuid,
   current_setting('fixture.plan')::uuid,
   '00000000-0000-4000-8000-00000000e6a1')->>'scopeHash';
 v:=public.plan_fixture_claim(current_setting('fixture.stale_job')::uuid,
   '00000000-0000-4000-8000-00000000f6c5',h);
 IF v IS NOT NULL THEN RAISE EXCEPTION 'EXHAUSTED_LEASE_RECLAIMED';END IF;
END $$;
RESET ROLE;
DO $$BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.assessment_plan_executions
   WHERE id=current_setting('fixture.stale_job')::uuid
     AND status='failed' AND error_code='STALE_LEASE')
 THEN RAISE EXCEPTION 'EXHAUSTED_LEASE_NOT_FENCED';END IF;
 IF EXISTS(SELECT 1 FROM public.assessment_jobs
   WHERE id=current_setting('fixture.stale_job')::uuid)
 THEN RAISE EXCEPTION 'STALE_LEASE_FABRICATED_EVIDENCE';END IF;
END $$;
UPDATE public.assets SET verification_status='revoked',verification_expires_at=NULL
 WHERE id=current_setting('fixture.asset')::uuid;
SET LOCAL ROLE service_role;
DO $$ BEGIN
 IF public.plan_fixture_heartbeat(current_setting('fixture.revoked_job')::uuid,
   current_setting('fixture.revoked_token'),1)
 THEN RAISE EXCEPTION 'REVOKED_OWNERSHIP_HEARTBEAT_ALLOWED'; END IF;

END $$;
RESET ROLE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.assessment_jobs
   WHERE id=current_setting('fixture.revoked_job')::uuid)
 THEN RAISE EXCEPTION 'REVOKED_JOB_EVIDENCE_FABRICATED'; END IF;
END $$;
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e6a2',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e6a2","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$ BEGIN
 IF (SELECT count(*) FROM public.assessment_plan_executions
 WHERE organization_id=current_setting('fixture.org')::uuid)<>3
 THEN RAISE EXCEPTION 'PLAN_FIXTURE_VIEWER_RLS_MISSING'; END IF;
END $$;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e6a3',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e6a3","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.assessment_plan_executions
  WHERE organization_id=current_setting('fixture.org')::uuid)
 THEN RAISE EXCEPTION 'PLAN_FIXTURE_CROSS_TENANT_LEAK'; END IF;
END $$;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e6a1',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e6a1","role":"authenticated","aal":"aal1","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"}]}',true);
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.assessment_plan_executions
  WHERE organization_id=current_setting('fixture.org')::uuid)
 THEN RAISE EXCEPTION 'PLAN_FIXTURE_AAL1_LEAK'; END IF;
END $$;
ROLLBACK;
SELECT 'ROLLBACK_ONLY_PLAN_FIXTURE_LIFECYCLE_PASS' AS test_result;
