-- Actual controlled Docker TLS API observations, persisted through trusted
-- service-role fixture recorder, read through signed AAL2 tenant RLS, and
-- imported into existing commercial Findings; 100% rolled back.
-- Generated from apps/api/tests/fixtures/controlled-runtime-actual-results.json
BEGIN;
DO $$ BEGIN
 IF has_function_privilege('authenticated',
 'public.api_runtime_fixture_record(uuid,uuid,uuid,uuid,text,jsonb,jsonb)','EXECUTE')
 OR has_function_privilege('anon',
 'public.api_runtime_fixture_record(uuid,uuid,uuid,uuid,text,jsonb,jsonb)','EXECUTE')
 OR NOT has_function_privilege('service_role',
 'public.api_runtime_fixture_record(uuid,uuid,uuid,uuid,text,jsonb,jsonb)','EXECUTE')
 THEN RAISE EXCEPTION 'RUNTIME_FIXTURE_BROWSER_WRITE_PERMISSION'; END IF;
END $$;
INSERT INTO auth.users(id,instance_id,aud,role,email,email_confirmed_at,created_at,updated_at)
VALUES
('00000000-0000-4000-8000-00000000eaa1','00000000-0000-0000-0000-000000000000','authenticated','authenticated','runtime-fixture-owner@example.test',now(),now(),now()),
('00000000-0000-4000-8000-00000000eaa2','00000000-0000-0000-0000-000000000000','authenticated','authenticated','runtime-fixture-outsider@example.test',now(),now(),now());
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000eaa1',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000eaa1","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
INSERT INTO public.organizations(display_name,created_by)
 VALUES('Rollback Controlled API Runtime','00000000-0000-4000-8000-00000000eaa1');
SELECT set_config('rta.org',(
 SELECT id::text FROM public.organizations
 WHERE display_name='Rollback Controlled API Runtime'),true);
INSERT INTO public.assets(organization_id,asset_kind,display_name,canonical_origin,created_by)
 VALUES(current_setting('rta.org')::uuid,'api','Isolated fixture API',
 'https://controlled-api.fixture-api.net','00000000-0000-4000-8000-00000000eaa1');
SELECT set_config('rta.asset',(
 SELECT id::text FROM public.assets WHERE organization_id=current_setting('rta.org')::uuid),true);
RESET ROLE;
UPDATE public.assets SET verification_status='verified',
 verified_at=now(),verification_expires_at=now()+interval '1 day'
 WHERE id=current_setting('rta.asset')::uuid;
SET LOCAL ROLE service_role;
DO $$
DECLARE v_items jsonb;v_report jsonb;
BEGIN
 v_items:='[{"ruleId":"API.RUNTIME.AUTH.ANON_SUCCESS","title":"Anonymous protected-route response","summary":"Controlled protected resource responded successfully without synthetic identity.","remediation":"Require server-side authentication for every protected object.","limitation":"Synthetic read-only response comparison; no confirmed exploit or generalizable authorization verdict.","classification":"INCONCLUSIVE","severityEstimate":"medium","evidenceSource":{"paths":["/v1/accounts/owner"],"fingerprints":["7c26c4182a2021b59d7933aebff8c60a3649030782c714655d34525bfa8ede92","1d7aa661da27010ff599df504f72f144cbd81d4f3d19bb9768106742ad716f48","81eb779bfdc152c8a300068a143c4d62399987eb28a78965ca8b19d9a0294a3e"],"nodeIds":["wdn_6f0b6892db5db7025d8fb0ea"]}},{"ruleId":"API.RUNTIME.AUTHZ.OTHER_SUCCESS","title":"Synthetic cross-identity response","summary":"The same controlled owner object responded successfully for the other synthetic identity.","remediation":"Enforce object ownership checks on every protected resource.","limitation":"Synthetic read-only response comparison; no confirmed exploit or generalizable authorization verdict.","classification":"INCONCLUSIVE","severityEstimate":"medium","evidenceSource":{"paths":["/v1/accounts/owner"],"fingerprints":["7c26c4182a2021b59d7933aebff8c60a3649030782c714655d34525bfa8ede92","1d7aa661da27010ff599df504f72f144cbd81d4f3d19bb9768106742ad716f48","81eb779bfdc152c8a300068a143c4d62399987eb28a78965ca8b19d9a0294a3e"],"nodeIds":["wdn_6f0b6892db5db7025d8fb0ea"]}},{"ruleId":"API.RUNTIME.HEADER.HSTS_ABSENT","title":"Missing HSTS response policy","summary":"Controlled HTTPS resource did not return a Strict-Transport-Security header.","remediation":"Review and configure an appropriate HSTS policy.","limitation":"Synthetic read-only response comparison; no confirmed exploit or generalizable authorization verdict.","classification":"DETERMINISTIC_CONFIGURATION_SIGNAL","severityEstimate":"low","evidenceSource":{"paths":["/v1/accounts/owner"],"fingerprints":["7c26c4182a2021b59d7933aebff8c60a3649030782c714655d34525bfa8ede92","1d7aa661da27010ff599df504f72f144cbd81d4f3d19bb9768106742ad716f48","81eb779bfdc152c8a300068a143c4d62399987eb28a78965ca8b19d9a0294a3e"],"nodeIds":["wdn_6f0b6892db5db7025d8fb0ea"]}},{"ruleId":"API.RUNTIME.HEADER.NOSNIFF_ABSENT","title":"Missing nosniff protection","summary":"Controlled API resource did not return X-Content-Type-Options: nosniff.","remediation":"Add the nosniff response header.","limitation":"Synthetic read-only response comparison; no confirmed exploit or generalizable authorization verdict.","classification":"DETERMINISTIC_CONFIGURATION_SIGNAL","severityEstimate":"low","evidenceSource":{"paths":["/v1/accounts/owner"],"fingerprints":["7c26c4182a2021b59d7933aebff8c60a3649030782c714655d34525bfa8ede92","1d7aa661da27010ff599df504f72f144cbd81d4f3d19bb9768106742ad716f48","81eb779bfdc152c8a300068a143c4d62399987eb28a78965ca8b19d9a0294a3e"],"nodeIds":["wdn_6f0b6892db5db7025d8fb0ea"]}}]'::jsonb;
 v_report:='{"classification":"RUNTIME_API_REVIEW","scopeHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","coverageState":"BOUNDED","requests":3,"bytes":138,"limitations":["Three bounded GET requests to one controlled object only.","All identities and account content synthetic; no customer credentials.","Successful responses are review signals, not proven data exposure.","Not observed never proves general API security.","Authentication and authorization policy inferred from explicit controlled fixture expectation."],"statuses":{"anonymous":200,"owner":200,"other":200}}'::jsonb;
 IF NOT public.api_runtime_fixture_record(
  current_setting('rta.org')::uuid,current_setting('rta.asset')::uuid,
  '00000000-0000-4000-8000-00000000eaa1',
  'b4e6525f-9cb8-4eec-b00e-cf77e65db6c9'::uuid,repeat('a',64),v_items,v_report)
 THEN RAISE EXCEPTION 'ACTUAL_DOCKER_API_EVIDENCE_NOT_PERSISTED'; END IF;
 IF NOT public.api_runtime_fixture_record(
  current_setting('rta.org')::uuid,current_setting('rta.asset')::uuid,
  '00000000-0000-4000-8000-00000000eaa1',
  'b4e6525f-9cb8-4eec-b00e-cf77e65db6c9'::uuid,repeat('a',64),v_items,v_report)
 THEN RAISE EXCEPTION 'RUNTIME_IDEMPOTENCY_MISSING'; END IF;
 BEGIN
  PERFORM public.api_runtime_fixture_record(
   current_setting('rta.org')::uuid,current_setting('rta.asset')::uuid,
   '00000000-0000-4000-8000-00000000eaa1',
   'b4e6525f-9cb8-4eec-b00e-cf77e65db6c9'::uuid,repeat('f',64),v_items,v_report);
  RAISE EXCEPTION 'RUNTIME_REPLAY_CHANGED_SCOPE';
 EXCEPTION WHEN insufficient_privilege OR invalid_parameter_value THEN NULL;
 END;
END $$;
RESET ROLE;
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000eaa1',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000eaa1","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
DECLARE v jsonb;v_id uuid;
BEGIN
 IF (SELECT count(*) FROM public.assessment_observations WHERE
     job_id='b4e6525f-9cb8-4eec-b00e-cf77e65db6c9'::uuid)<>4
 THEN RAISE EXCEPTION 'ACTUAL_API_EVIDENCE_COUNT_MISSING'; END IF;
 IF (SELECT count(*) FROM public.assessment_observations WHERE
     job_id='b4e6525f-9cb8-4eec-b00e-cf77e65db6c9'::uuid
     AND (observation_classification NOT IN ('INCONCLUSIVE',
       'DETERMINISTIC_CONFIGURATION_SIGNAL') OR
       jsonb_array_length(evidence_source->'fingerprints')<>3))<>0
 THEN RAISE EXCEPTION 'RUNTIME_API_SOURCE_PROVENANCE_INVALID'; END IF;
 v:=public.findings_import(current_setting('rta.org')::uuid,
  'b4e6525f-9cb8-4eec-b00e-cf77e65db6c9'::uuid,'00000000-0000-4000-8000-00000000eab1');
 IF (v->>'newFindings')::int<>4 OR (v->>'linkedObservations')::int<>4
 THEN RAISE EXCEPTION 'RUNTIME_API_FINDINGS_IMPORT_FAILED'; END IF;
 v:=public.findings_import(current_setting('rta.org')::uuid,
  'b4e6525f-9cb8-4eec-b00e-cf77e65db6c9'::uuid,'00000000-0000-4000-8000-00000000eab1');
 IF (v->>'newFindings')::int<>0 OR (v->>'linkedObservations')::int<>0
 THEN RAISE EXCEPTION 'RUNTIME_API_FINDINGS_NOT_IDEMPOTENT'; END IF;
 IF (SELECT count(*) FROM public.security_findings
  WHERE organization_id=current_setting('rta.org')::uuid
   AND assessment_kind='api_runtime_review' AND reviewer_conclusion='unreviewed'
   AND workflow_status='open')<>4
 THEN RAISE EXCEPTION 'RUNTIME_API_AUTO_PROMOTED_VULNERABILITY'; END IF;
 IF (SELECT count(*) FROM public.finding_evidence_links
  WHERE organization_id=current_setting('rta.org')::uuid AND
   job_id='b4e6525f-9cb8-4eec-b00e-cf77e65db6c9'::uuid)<>4
 THEN RAISE EXCEPTION 'RUNTIME_API_SOURCE_LINKS_MISSING'; END IF;
 SELECT id INTO v_id FROM public.security_findings
 WHERE organization_id=current_setting('rta.org')::uuid
 AND rule_id='API.RUNTIME.AUTH.ANON_SUCCESS';
 PERFORM set_config('rta.finding',v_id::text,true);
 PERFORM public.finding_action(current_setting('rta.org')::uuid,
  v_id,'classify', '{"conclusion":"needs_evidence","reason":"Controlled API response is a synthetic review signal."}'::jsonb,
  '00000000-0000-4000-8000-00000000eab2');
 PERFORM public.finding_action(current_setting('rta.org')::uuid,
  v_id,'retest_request','{}'::jsonb,'00000000-0000-4000-8000-00000000eab3');
 IF (SELECT comparison_state FROM public.finding_retests
 WHERE finding_id=v_id)<>'awaiting_execution'
 THEN RAISE EXCEPTION 'RUNTIME_API_RETEST_NOT_AWAITING_EVIDENCE'; END IF;
END $$;
RESET ROLE;
-- Secure comparator: actually observed no four targeted runtime signals.
-- This later assessment is only a bounded comparison, not verified resolution.
SET LOCAL ROLE service_role;
DO $$
BEGIN
 IF NOT public.api_runtime_fixture_record(
  current_setting('rta.org')::uuid,current_setting('rta.asset')::uuid,
  '00000000-0000-4000-8000-00000000eaa1',
  'dfe28062-0e96-4a9c-8467-ff1fafd20b7e'::uuid,repeat('a',64),
  '[]'::jsonb,'{"classification":"RUNTIME_API_REVIEW","scopeHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","coverageState":"BOUNDED","requests":3,"bytes":103,"limitations":["Three bounded GET requests to one controlled object only.","All identities and account content synthetic; no customer credentials.","Successful responses are review signals, not proven data exposure.","Not observed never proves general API security.","Authentication and authorization policy inferred from explicit controlled fixture expectation."],"statuses":{"anonymous":401,"owner":200,"other":403}}'::jsonb)
 THEN RAISE EXCEPTION 'SECURE_API_COMPARATOR_NOT_SAVED'; END IF;
END $$;
RESET ROLE;
SET LOCAL ROLE authenticated;
DO $$ BEGIN
 PERFORM public.finding_action(current_setting('rta.org')::uuid,
  current_setting('rta.finding')::uuid,'retest_compare',
  jsonb_build_object('jobId','dfe28062-0e96-4a9c-8467-ff1fafd20b7e'),
  '00000000-0000-4000-8000-00000000eab4');
 IF (SELECT comparison_state FROM public.finding_retests
  WHERE finding_id=current_setting('rta.finding')::uuid)<>'not_observed_in_review'
 OR (SELECT workflow_status FROM public.security_findings
  WHERE id=current_setting('rta.finding')::uuid)='verified_resolved'
 THEN RAISE EXCEPTION 'RUNTIME_API_RETEST_FABRICATED_RESOLUTION'; END IF;
END $$;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000eaa2',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000eaa2","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.assessment_jobs
   WHERE organization_id=current_setting('rta.org')::uuid)
 OR EXISTS(SELECT 1 FROM public.security_findings
   WHERE organization_id=current_setting('rta.org')::uuid)
 OR EXISTS(SELECT 1 FROM public.finding_evidence_links
   WHERE organization_id=current_setting('rta.org')::uuid)
 THEN RAISE EXCEPTION 'CROSS_TENANT_RUNTIME_DATA_LEAK'; END IF;
END $$;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000eaa1',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000eaa1","role":"authenticated","aal":"aal1","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"}]}',true);
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.security_findings
  WHERE organization_id=current_setting('rta.org')::uuid)
 THEN RAISE EXCEPTION 'AAL1_RUNTIME_FINDINGS_READ'; END IF;
END $$;
RESET ROLE;
-- A revoked proof blocks any new synthetic fixture recording as well.
UPDATE public.assets SET verification_status='revoked',verification_expires_at=NULL
 WHERE id=current_setting('rta.asset')::uuid;
SET LOCAL ROLE service_role;
DO $$ BEGIN
 BEGIN
  PERFORM public.api_runtime_fixture_record(
   current_setting('rta.org')::uuid,current_setting('rta.asset')::uuid,
   '00000000-0000-4000-8000-00000000eaa1',
   '00000000-0000-4000-8000-00000000eaf1'::uuid,repeat('a',64),
   '[]'::jsonb,'{"classification":"RUNTIME_API_REVIEW","scopeHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","coverageState":"BOUNDED","requests":3,"bytes":2,"statuses":{"anonymous":401,"owner":200,"other":403}}'::jsonb);
  RAISE EXCEPTION 'REVOKED_RUNTIME_FIXTURE_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
RESET ROLE;
ROLLBACK;
SELECT 'ROLLBACK_ONLY_ACTUAL_RUNTIME_API_FINDINGS_PASS' AS test_result;
