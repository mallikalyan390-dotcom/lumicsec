-- DEVELOPMENT-only synthetic regression for offline API assessment lifecycle.
-- Both Auth users and all tenant rows are rolled back. No external API traffic.
BEGIN;

DO $$
BEGIN
 IF has_function_privilege('authenticated',
   'public.assessment_api_offline_queue(uuid,uuid,uuid,text,text,text)','EXECUTE')
 OR has_function_privilege('authenticated',
   'public.assessment_api_offline_complete(uuid,uuid,jsonb,jsonb)','EXECUTE')
 OR has_function_privilege('anon',
   'public.assessment_api_offline_stop(uuid,uuid,boolean)','EXECUTE')
 OR NOT has_function_privilege('service_role',
   'public.assessment_api_offline_queue(uuid,uuid,uuid,text,text,text)','EXECUTE')
 THEN RAISE EXCEPTION 'BROWSER_PRIVILEGED_JOB_WRITE_GRANT'; END IF;
END $$;

INSERT INTO auth.users (id,instance_id,aud,role,email,email_confirmed_at,created_at,updated_at)
VALUES
('00000000-0000-4000-8000-00000000b901','00000000-0000-0000-0000-000000000000',
'authenticated','authenticated','offline-synthetic-owner@example.test',now(),now(),now()),
('00000000-0000-4000-8000-00000000b902','00000000-0000-0000-0000-000000000000',
'authenticated','authenticated','offline-synthetic-outsider@example.test',now(),now(),now());

SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000b901',true);
SELECT set_config('request.jwt.claims',
'{"sub":"00000000-0000-4000-8000-00000000b901","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);

INSERT INTO public.organizations(display_name,created_by)
VALUES('Temporary Offline API QA','00000000-0000-4000-8000-00000000b901');
SELECT set_config('app.qa_org',
 (SELECT id::text FROM public.organizations WHERE display_name='Temporary Offline API QA'),true);
INSERT INTO public.assets(organization_id,asset_kind,display_name,canonical_origin,created_by)
VALUES(current_setting('app.qa_org')::uuid,'api','Offline QA asset',
'https://api.offline-qatest.example.com','00000000-0000-4000-8000-00000000b901');
SELECT set_config('app.qa_asset',
 (SELECT id::text FROM public.assets WHERE organization_id=current_setting('app.qa_org')::uuid),true);

-- Unauthenticated/browser-level RPC is not available even at AAL2.
DO $$
BEGIN
 BEGIN
  PERFORM public.assessment_api_offline_queue(current_setting('app.qa_org')::uuid,
  current_setting('app.qa_asset')::uuid,'00000000-0000-4000-8000-00000000b901',
  repeat('a',64),repeat('b',64),'OPENAPI_3_1');
  RAISE EXCEPTION 'AUTHENTICATED_BROWSER_QUEUED_JOB';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;

RESET ROLE;
SET LOCAL ROLE service_role;
-- Proof is pending => no job even though actor is current organization owner.
DO $$
BEGIN
 BEGIN
  PERFORM public.assessment_api_offline_queue(current_setting('app.qa_org')::uuid,
  current_setting('app.qa_asset')::uuid,'00000000-0000-4000-8000-00000000b901',
  repeat('a',64),repeat('b',64),'OPENAPI_3_1');
  RAISE EXCEPTION 'PENDING_ASSET_QUEUE_BYPASS';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
RESET ROLE;

-- Only test superuser manipulates synthetic proof state. Not a customer route.
UPDATE public.assets SET verification_status='verified',
 verified_at=now(),verification_expires_at=now()+interval '1 day'
WHERE id=current_setting('app.qa_asset')::uuid;
SET LOCAL ROLE service_role;
DO $$
DECLARE v_job uuid; v_result boolean;
BEGIN
 v_job:=public.assessment_api_offline_queue(current_setting('app.qa_org')::uuid,
   current_setting('app.qa_asset')::uuid,'00000000-0000-4000-8000-00000000b901',
   repeat('a',64),repeat('b',64),'OPENAPI_3_1');
 PERFORM set_config('app.qa_success_job',v_job::text,true);
 v_result:=public.assessment_api_offline_begin(v_job,'00000000-0000-4000-8000-00000000b901');
 IF NOT v_result THEN RAISE EXCEPTION 'AUTHORIZED_JOB_WOULD_NOT_BEGIN'; END IF;
 v_result:=public.assessment_api_offline_complete(v_job,
  '00000000-0000-4000-8000-00000000b901',
  '[{"ruleId":"AUTH_UNDECLARED","title":"Spec declaration requires review","summary":"Synthetic read-only metadata.","severityEstimate":"low"},{"ruleId":"DOC_GAP","title":"Documented error coverage","summary":"Review response contract.","severityEstimate":"info"}]'::jsonb,
  '{"classification":"SPEC_ONLY","operationCount":2,"truncated":false}'::jsonb);
 IF NOT v_result THEN RAISE EXCEPTION 'AUTHORIZED_JOB_WOULD_NOT_COMPLETE'; END IF;
 IF public.assessment_api_offline_complete(v_job,
   '00000000-0000-4000-8000-00000000b901','[]'::jsonb,'{}'::jsonb)
 THEN RAISE EXCEPTION 'DOUBLE_COMPLETION_ALLOWED'; END IF;
END $$;
RESET ROLE;
DO $$
BEGIN
 IF (SELECT job_state FROM public.assessment_jobs WHERE id=current_setting('app.qa_success_job')::uuid)<>'succeeded'
  OR (SELECT observation_count FROM public.assessment_jobs WHERE id=current_setting('app.qa_success_job')::uuid)<>2
  OR (SELECT count(*) FROM public.assessment_observations WHERE job_id=current_setting('app.qa_success_job')::uuid)<>2
 THEN RAISE EXCEPTION 'JOB_RESULT_PERSISTENCE_FAILURE'; END IF;
END $$;

-- Direct Data API access to job and result cannot bypass AAL2.
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000b901',true);
SELECT set_config('request.jwt.claims',
'{"sub":"00000000-0000-4000-8000-00000000b901","role":"authenticated","aal":"aal1","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.assessment_jobs WHERE id=current_setting('app.qa_success_job')::uuid)<>0
 OR (SELECT count(*) FROM public.assessment_observations WHERE job_id=current_setting('app.qa_success_job')::uuid)<>0
 THEN RAISE EXCEPTION 'AAL1_RESULT_DISCLOSURE'; END IF;
END $$;
SELECT set_config('request.jwt.claims',
'{"sub":"00000000-0000-4000-8000-00000000b901","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.assessment_jobs WHERE id=current_setting('app.qa_success_job')::uuid)<>1
 OR (SELECT count(*) FROM public.assessment_observations WHERE job_id=current_setting('app.qa_success_job')::uuid)<>2
 THEN RAISE EXCEPTION 'AUTHORIZED_JOB_VISIBILITY_FAILED'; END IF;
END $$;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000b902',true);
SELECT set_config('request.jwt.claims',
'{"sub":"00000000-0000-4000-8000-00000000b902","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.assessment_jobs WHERE id=current_setting('app.qa_success_job')::uuid)<>0
 OR (SELECT count(*) FROM public.assessment_observations WHERE job_id=current_setting('app.qa_success_job')::uuid)<>0
 THEN RAISE EXCEPTION 'CROSS_TENANT_RESULT_DISCLOSURE'; END IF;
END $$;
RESET ROLE;

-- Revocation between queue and execution must cancel without writing observations.
SET LOCAL ROLE service_role;
SELECT set_config('app.qa_revocation_job',
 public.assessment_api_offline_queue(current_setting('app.qa_org')::uuid,
  current_setting('app.qa_asset')::uuid,'00000000-0000-4000-8000-00000000b901',
  repeat('c',64),repeat('d',64),'OPENAPI_3_1')::text,true);
RESET ROLE;
UPDATE public.assets SET verification_status='revoked',verification_expires_at=NULL
 WHERE id=current_setting('app.qa_asset')::uuid;
SET LOCAL ROLE service_role;
DO $$
BEGIN
 IF public.assessment_api_offline_begin(current_setting('app.qa_revocation_job')::uuid,
   '00000000-0000-4000-8000-00000000b901')
 THEN RAISE EXCEPTION 'REVOCATION_BEFORE_EXECUTION_BYPASS'; END IF;
 BEGIN
  PERFORM public.assessment_api_offline_queue(current_setting('app.qa_org')::uuid,
   current_setting('app.qa_asset')::uuid,'00000000-0000-4000-8000-00000000b901',
   repeat('a',64),repeat('b',64),'OPENAPI_3_1');
  RAISE EXCEPTION 'REVOKED_ASSET_QUEUE_BYPASS';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
RESET ROLE;
DO $$
BEGIN
 IF (SELECT job_state FROM public.assessment_jobs WHERE id=current_setting('app.qa_revocation_job')::uuid)<>'cancelled'
 THEN RAISE EXCEPTION 'REVOCATION_DID_NOT_CANCEL_JOB'; END IF;
END $$;

-- Restored synthetic ownership, now revoke between begin and result commit.
UPDATE public.assets SET verification_status='verified',
 verification_expires_at=now()+interval '1 day'
WHERE id=current_setting('app.qa_asset')::uuid;
SET LOCAL ROLE service_role;
SELECT set_config('app.qa_recheck_job',
 public.assessment_api_offline_queue(current_setting('app.qa_org')::uuid,
  current_setting('app.qa_asset')::uuid,'00000000-0000-4000-8000-00000000b901',
  repeat('c',64),repeat('d',64),'OPENAPI_3_1')::text,true);
SELECT public.assessment_api_offline_begin(current_setting('app.qa_recheck_job')::uuid,
 '00000000-0000-4000-8000-00000000b901') AS began;
RESET ROLE;
UPDATE public.assets SET verification_status='revoked',verification_expires_at=NULL
 WHERE id=current_setting('app.qa_asset')::uuid;
SET LOCAL ROLE service_role;
DO $$
BEGIN
 IF public.assessment_api_offline_complete(current_setting('app.qa_recheck_job')::uuid,
  '00000000-0000-4000-8000-00000000b901',
  '[{"ruleId":"RULE","title":"Should not persist","summary":"Not authorized","severityEstimate":"low"}]'::jsonb,'{}'::jsonb)
 THEN RAISE EXCEPTION 'REVOCATION_BEFORE_RESULT_PERSISTENCE_BYPASS'; END IF;
END $$;
RESET ROLE;
DO $$
BEGIN
 IF (SELECT count(*) FROM public.assessment_observations WHERE job_id=current_setting('app.qa_recheck_job')::uuid)<>0
 THEN RAISE EXCEPTION 'REVOCATION_RESULT_SAVED'; END IF;
END $$;

-- 100-observation ceiling and malformed evidence blocked, no partial inserts.
UPDATE public.assets SET verification_status='verified',
 verification_expires_at=now()+interval '1 day'
WHERE id=current_setting('app.qa_asset')::uuid;
SET LOCAL ROLE service_role;
SELECT set_config('app.qa_limits_job',
 public.assessment_api_offline_queue(current_setting('app.qa_org')::uuid,
  current_setting('app.qa_asset')::uuid,'00000000-0000-4000-8000-00000000b901',
  repeat('e',64),repeat('f',64),'OPENAPI_3_1')::text,true);
SELECT public.assessment_api_offline_begin(current_setting('app.qa_limits_job')::uuid,
 '00000000-0000-4000-8000-00000000b901') AS began;
DO $$
BEGIN
 BEGIN
  PERFORM public.assessment_api_offline_complete(current_setting('app.qa_limits_job')::uuid,
    '00000000-0000-4000-8000-00000000b901',
    (SELECT jsonb_agg(jsonb_build_object('ruleId','x','title','x','summary','x','severityEstimate','info'))
     FROM generate_series(1,101)),'{}'::jsonb);
  RAISE EXCEPTION 'OBSERVATION_CEILING_BYPASS';
 EXCEPTION WHEN invalid_parameter_value THEN NULL;
 END;
END $$;
RESET ROLE;
DO $$
BEGIN
 IF (SELECT count(*) FROM public.assessment_observations WHERE job_id=current_setting('app.qa_limits_job')::uuid)<>0
 THEN RAISE EXCEPTION 'PARTIAL_INVALID_OBSERVATIONS_COMMITTED'; END IF;
END $$;

ROLLBACK;
SELECT 'ROLLBACK_ONLY_OFFLINE_API_ASSESSMENT_PASS' AS test_result;
