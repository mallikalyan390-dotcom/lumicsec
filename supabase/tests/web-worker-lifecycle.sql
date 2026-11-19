-- DEVELOPMENT-only synthetic Web job authorization and fencing regression.
-- All synthetic rows rolled back; no DNS, HTTPS or customer traffic.
BEGIN;
DO $$
BEGIN
 IF has_function_privilege('authenticated',
   'public.web_assessment_enqueue(uuid,uuid,uuid,text,text,uuid)','EXECUTE')
 OR has_function_privilege('authenticated',
   'public.web_assessment_claim(uuid,uuid,text)','EXECUTE')
 OR has_function_privilege('anon',
   'public.web_assessment_complete(uuid,text,integer,jsonb,jsonb)','EXECUTE')
 OR NOT has_function_privilege('service_role',
   'public.web_assessment_claim(uuid,uuid,text)','EXECUTE')
 THEN RAISE EXCEPTION 'WEB_BROWSER_WRITE_PRIVILEGE'; END IF;
END $$;

INSERT INTO auth.users(id,instance_id,aud,role,email,email_confirmed_at,created_at,updated_at)
VALUES
('00000000-0000-4000-8000-00000000c901','00000000-0000-0000-0000-000000000000',
 'authenticated','authenticated','web-owner-synthetic@example.test',now(),now(),now()),
('00000000-0000-4000-8000-00000000c902','00000000-0000-0000-0000-000000000000',
 'authenticated','authenticated','web-outsider-synthetic@example.test',now(),now(),now());

SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000c901',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000c901","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
INSERT INTO public.organizations(display_name,created_by)
VALUES('Temporary Web Worker QA','00000000-0000-4000-8000-00000000c901');
SELECT set_config('qa.org',(
 SELECT id::text FROM public.organizations WHERE display_name='Temporary Web Worker QA'),true);
INSERT INTO public.assets(organization_id,asset_kind,display_name,canonical_origin,created_by)
VALUES(current_setting('qa.org')::uuid,'website','Private synthetic Web QA',
 'https://qa-web-controlled.example.net','00000000-0000-4000-8000-00000000c901');
SELECT set_config('qa.asset',(
 SELECT id::text FROM public.assets WHERE organization_id=current_setting('qa.org')::uuid),true);

DO $$
BEGIN
 BEGIN
  PERFORM public.web_assessment_enqueue(current_setting('qa.org')::uuid,
   current_setting('qa.asset')::uuid,'00000000-0000-4000-8000-00000000c901',
   'https://qa-web-controlled.example.net',repeat('a',64),
   '00000000-0000-4000-8000-00000000c911');
  RAISE EXCEPTION 'AUTHENTICATED_QUEUED_WEB_ASSESSMENT';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
RESET ROLE;
SET LOCAL ROLE service_role;
-- Pending ownership denies service role too, regardless of actor membership.
DO $$
BEGIN
 BEGIN
  PERFORM public.web_assessment_enqueue(current_setting('qa.org')::uuid,
   current_setting('qa.asset')::uuid,'00000000-0000-4000-8000-00000000c901',
   'https://qa-web-controlled.example.net',repeat('a',64),
   '00000000-0000-4000-8000-00000000c911');
  RAISE EXCEPTION 'PENDING_ASSET_QUEUED_WEB_ASSESSMENT';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
RESET ROLE;

-- Synthetic proof state is test-only SQL; hosted ownership verification remains separate.
UPDATE public.assets SET verification_status='verified',verified_at=now(),
 verification_expires_at=now()+interval '1 day'
 WHERE id=current_setting('qa.asset')::uuid;

SET LOCAL ROLE service_role;
DO $$
DECLARE v_job uuid; v_dup uuid; v_claim jsonb; v_token text;
BEGIN
 BEGIN
  PERFORM public.web_assessment_enqueue(current_setting('qa.org')::uuid,
   current_setting('qa.asset')::uuid,'00000000-0000-4000-8000-00000000c902',
   'https://qa-web-controlled.example.net',repeat('a',64),
   '00000000-0000-4000-8000-00000000c912');
  RAISE EXCEPTION 'CROSS_TENANT_ACTOR_QUEUED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 v_job:=public.web_assessment_enqueue(current_setting('qa.org')::uuid,
   current_setting('qa.asset')::uuid,'00000000-0000-4000-8000-00000000c901',
   'https://qa-web-controlled.example.net',repeat('a',64),
   '00000000-0000-4000-8000-00000000c911');
 PERFORM set_config('qa.job',v_job::text,true);
 v_dup:=public.web_assessment_enqueue(current_setting('qa.org')::uuid,
   current_setting('qa.asset')::uuid,'00000000-0000-4000-8000-00000000c901',
   'https://qa-web-controlled.example.net',repeat('a',64),
   '00000000-0000-4000-8000-00000000c911');
 IF v_dup<>v_job THEN RAISE EXCEPTION 'WEB_IDEMPOTENCY_FAILED'; END IF;
 BEGIN
  PERFORM public.web_assessment_enqueue(current_setting('qa.org')::uuid,
   current_setting('qa.asset')::uuid,'00000000-0000-4000-8000-00000000c901',
   'https://qa-web-controlled.example.net',repeat('f',64),
   '00000000-0000-4000-8000-00000000c911');
  RAISE EXCEPTION 'IDEMPOTENCY_SCOPE_REASSIGN_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 v_claim:=public.web_assessment_claim(v_job,'00000000-0000-4000-8000-00000000c921',repeat('a',64));
 IF v_claim IS NULL OR (v_claim->>'generation')::int<>1
 OR length(v_claim->>'token')<>64 THEN
  RAISE EXCEPTION 'VALID_WEB_CLAIM_FAILED'; END IF;
 v_token:=v_claim->>'token';
 PERFORM set_config('qa.token',v_token,true);
 IF public.web_assessment_claim(v_job,'00000000-0000-4000-8000-00000000c922',repeat('a',64)) IS NOT NULL
 THEN RAISE EXCEPTION 'DUPLICATE_LIVE_WEB_WORKER_CLAIM'; END IF;
 IF NOT public.web_assessment_heartbeat(v_job,v_token,1)
 THEN RAISE EXCEPTION 'VALID_WORKER_LEASE_REJECTED'; END IF;
 IF public.web_assessment_heartbeat(v_job,repeat('e',64),1)
 THEN RAISE EXCEPTION 'INVALID_WORKER_LEASE_ACCEPTED'; END IF;
END $$;
RESET ROLE;

-- Revoking real (synthetic) ownership between claim and read cancels the job.
UPDATE public.assets SET verification_status='revoked',verification_expires_at=NULL
 WHERE id=current_setting('qa.asset')::uuid;
SET LOCAL ROLE service_role;
DO $$
BEGIN
 IF public.web_assessment_heartbeat(current_setting('qa.job')::uuid,
  current_setting('qa.token'),1)
 THEN RAISE EXCEPTION 'WEB_REVOKED_OWNERSHIP_HEARTBEAT_ALLOWED'; END IF;
 IF public.web_assessment_complete(current_setting('qa.job')::uuid,
  current_setting('qa.token'),1,'[]'::jsonb,'{}'::jsonb)
 THEN RAISE EXCEPTION 'WEB_REVOKED_OWNERSHIP_PERSISTED'; END IF;
END $$;
RESET ROLE;
DO $$
BEGIN
 IF (SELECT job_state FROM public.assessment_jobs
   WHERE id=current_setting('qa.job')::uuid)<>'cancelled'
 THEN RAISE EXCEPTION 'REVOCATION_DID_NOT_CANCEL_RUNNING_WEB_JOB'; END IF;
END $$;

UPDATE public.assets SET verification_status='verified',
 verification_expires_at=now()+interval '1 day'
 WHERE id=current_setting('qa.asset')::uuid;
SET LOCAL ROLE service_role;
DO $$
DECLARE v_job uuid; v_claim jsonb; v_items jsonb;
BEGIN
 v_job:=public.web_assessment_enqueue(current_setting('qa.org')::uuid,
   current_setting('qa.asset')::uuid,'00000000-0000-4000-8000-00000000c901',
   'https://qa-web-controlled.example.net',repeat('a',64),
   '00000000-0000-4000-8000-00000000c913');
 PERFORM set_config('qa.success_job',v_job::text,true);
 v_claim:=public.web_assessment_claim(v_job,'00000000-0000-4000-8000-00000000c921',repeat('a',64));
 PERFORM set_config('qa.success_token',v_claim->>'token',true);
 v_items:='[{"ruleId":"P09.HSTS.ABSENT","title":"Synthetic HSTS signal",
   "summary":"Controlled synthetic response lacks HSTS.",
   "remediation":"Review the configured HSTS header on approved HTTPS targets.",
   "limitation":"Passive response only; not confirmed vulnerability.",
   "classification":"DETERMINISTIC_CONFIGURATION_SIGNAL",
   "severityEstimate":"low",
   "evidenceSource":{"nodeIds":["wdn_0123456789abcdef01234567"],"fingerprints":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}]'::jsonb;
 BEGIN
  PERFORM public.web_assessment_complete(v_job,v_claim->>'token',1,
    (SELECT jsonb_agg(v_items->0) FROM generate_series(1,61)),
    '{"classification":"PASSIVE_WEB_REVIEW"}'::jsonb);
  RAISE EXCEPTION 'WEB_OBSERVATION_CEILING_BYPASS';
 EXCEPTION WHEN invalid_parameter_value THEN NULL;
 END;
 IF NOT public.web_assessment_complete(v_job,v_claim->>'token',1,v_items,
   '{"classification":"PASSIVE_WEB_REVIEW","requests":2,"bytes":800,"fetched":2}'::jsonb)
 THEN RAISE EXCEPTION 'VALID_WEB_RESULT_PERSISTENCE_DENIED'; END IF;
 IF public.web_assessment_complete(v_job,v_claim->>'token',1,'[]'::jsonb,'{}'::jsonb)
 THEN RAISE EXCEPTION 'DUPLICATE_WEB_RESULT_COMMIT'; END IF;
END $$;
RESET ROLE;
DO $$
BEGIN
 IF (SELECT observation_count FROM public.assessment_jobs
   WHERE id=current_setting('qa.success_job')::uuid)<>1 OR
   (SELECT count(*) FROM public.assessment_observations
   WHERE job_id=current_setting('qa.success_job')::uuid)<>1
 THEN RAISE EXCEPTION 'WEB_RESULT_OR_OBSERVATION_NOT_SAVED'; END IF;
END $$;

-- Browser direct Data API reads remain Google+TOTP AAL2 and tenant isolated.
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000c901',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000c901","role":"authenticated","aal":"aal1","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.assessment_jobs WHERE id=current_setting('qa.success_job')::uuid)<>0
 OR (SELECT count(*) FROM public.assessment_observations WHERE job_id=current_setting('qa.success_job')::uuid)<>0
 THEN RAISE EXCEPTION 'WEB_AAL1_RESULT_BYPASS'; END IF;
END $$;
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000c901","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.assessment_jobs WHERE id=current_setting('qa.success_job')::uuid)<>1
 OR (SELECT count(*) FROM public.assessment_observations WHERE job_id=current_setting('qa.success_job')::uuid)<>1
 THEN RAISE EXCEPTION 'WEB_AUTHORIZED_AAL2_RESULT_MISSING'; END IF;
END $$;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000c902',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000c902","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.assessment_jobs WHERE id=current_setting('qa.success_job')::uuid)<>0
 OR (SELECT count(*) FROM public.assessment_observations WHERE job_id=current_setting('qa.success_job')::uuid)<>0
 THEN RAISE EXCEPTION 'WEB_CROSS_TENANT_RESULT_READ'; END IF;
END $$;
RESET ROLE;

-- An expired lease may be reclaimed once, invalidating the old generation.
SET LOCAL ROLE service_role;
DO $$
DECLARE v_job uuid; v_claim jsonb;
BEGIN
 v_job:=public.web_assessment_enqueue(current_setting('qa.org')::uuid,
   current_setting('qa.asset')::uuid,'00000000-0000-4000-8000-00000000c901',
   'https://qa-web-controlled.example.net',repeat('a',64),
   '00000000-0000-4000-8000-00000000c914');
 PERFORM set_config('qa.stale_job',v_job::text,true);
 v_claim:=public.web_assessment_claim(v_job,'00000000-0000-4000-8000-00000000c921',repeat('a',64));
 PERFORM set_config('qa.stale_token',v_claim->>'token',true);
END $$;
RESET ROLE;
UPDATE public.assessment_jobs SET web_lease_until=now()-interval '1 second'
 WHERE id=current_setting('qa.stale_job')::uuid;
SET LOCAL ROLE service_role;
DO $$
DECLARE v_claim jsonb;
BEGIN
 v_claim:=public.web_assessment_claim(current_setting('qa.stale_job')::uuid,
  '00000000-0000-4000-8000-00000000c922',repeat('a',64));
 IF v_claim IS NULL OR (v_claim->>'generation')::int<>2 THEN
  RAISE EXCEPTION 'LEASE_RECOVERY_DID_NOT_RECLAIM'; END IF;
 IF public.web_assessment_heartbeat(current_setting('qa.stale_job')::uuid,
   current_setting('qa.stale_token'),1)
 THEN RAISE EXCEPTION 'STALE_HEARTBEAT_ACCEPTED'; END IF;
 IF public.web_assessment_stop(current_setting('qa.stale_job')::uuid,
  '00000000-0000-4000-8000-00000000c901',current_setting('qa.stale_token'),1,true)
 THEN RAISE EXCEPTION 'STALE_WORKER_CANCELLED_NEW_LEASE'; END IF;
 IF NOT public.web_assessment_heartbeat(current_setting('qa.stale_job')::uuid,v_claim->>'token',2)
 THEN RAISE EXCEPTION 'RECOVERED_WORKER_HEARTBEAT_DENIED'; END IF;
END $$;
RESET ROLE;

-- The test connection deliberately never sends an HTTP request.
ROLLBACK;
SELECT 'ROLLBACK_ONLY_WEB_WORKER_LIFECYCLE_PASS' AS test_result;
