-- Real evidence bytes originated from restricted Docker --network none worker
-- and ephemeral local HTTPS fixture, NOT from a mock analyzer.
-- This transaction genuinely exercises the development Supabase atomic
-- queue/claim/complete/RLS path, but intentionally ROLLBACKs test customers.
BEGIN;
INSERT INTO auth.users(id,instance_id,aud,role,email,email_confirmed_at,created_at,updated_at)
VALUES('00000000-0000-4000-8000-00000000d901',
 '00000000-0000-0000-0000-000000000000','authenticated','authenticated',
 'isolated-worker-real-evidence@example.test',now(),now(),now());
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000d901',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000d901","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
INSERT INTO public.organizations(display_name,created_by)
VALUES('Isolated Real TLS Evidence QA','00000000-0000-4000-8000-00000000d901');
SELECT set_config('isolated.qa.org',(
 SELECT id::text FROM public.organizations
 WHERE display_name='Isolated Real TLS Evidence QA'),true);
INSERT INTO public.assets(organization_id,asset_kind,display_name,canonical_origin,created_by)
VALUES(current_setting('isolated.qa.org')::uuid,'website','Insecure isolated local fixture',
 'https://insecure.fixture-web.net','00000000-0000-4000-8000-00000000d901');
SELECT set_config('isolated.qa.asset',(
 SELECT id::text FROM public.assets
 WHERE organization_id=current_setting('isolated.qa.org')::uuid),true);
RESET ROLE;
UPDATE public.assets SET verification_status='verified',verified_at=now(),
 verification_expires_at=now()+interval '1 day'
 WHERE id=current_setting('isolated.qa.asset')::uuid;

SET LOCAL ROLE service_role;
DO $$
DECLARE v_job uuid; v_claim jsonb; v_items jsonb := '[{"ruleId":"P09.COOKIE.SECURE_AGG","title":"Observed cookie attributes need Secure review","summary":"At least one observed Set-Cookie entry lacks Secure in an aggregate; cookie purpose is unknown.","severityEstimate":"low","classification":"PASSIVE_OBSERVATION","remediation":"Classify cookie purpose, and enforce Secure on cookies that must only travel over HTTPS.","limitation":"Passive evidence only; exploitability and whole-site coverage unverified.","evidenceSource":{"nodeIds":["wdn_397e2fa22e0d651dfe339823"],"fingerprints":["c765661ca74c57e6e5f20a840f6cd3b3ea5cf5ab420a8ff107aeb6e375e06e88"],"paths":["/"]}},{"ruleId":"P09.XCTO.CONFIG","title":"MIME sniffing defense needs review","summary":"The observed response did not include an effective X-Content-Type-Options: nosniff value.","severityEstimate":"low","classification":"DETERMINISTIC_CONFIGURATION_SIGNAL","remediation":"Consider X-Content-Type-Options: nosniff with correct Content-Type.","limitation":"Passive evidence only; exploitability and whole-site coverage unverified.","evidenceSource":{"nodeIds":["wdn_397e2fa22e0d651dfe339823"],"fingerprints":["c765661ca74c57e6e5f20a840f6cd3b3ea5cf5ab420a8ff107aeb6e375e06e88"],"paths":["/"]}},{"ruleId":"P09.HSTS.ABSENT","title":"HSTS header absent on observed HTTPS response","summary":"A complete captured response header set did not include HSTS; this is a hardening signal, not proof of downgrade exploitation.","severityEstimate":"low","classification":"DETERMINISTIC_CONFIGURATION_SIGNAL","remediation":"Evaluate enabling Strict-Transport-Security with a tested max-age on HTTPS.","limitation":"Passive evidence only; exploitability and whole-site coverage unverified.","evidenceSource":{"nodeIds":["wdn_397e2fa22e0d651dfe339823"],"fingerprints":["c765661ca74c57e6e5f20a840f6cd3b3ea5cf5ab420a8ff107aeb6e375e06e88"],"paths":["/"]}},{"ruleId":"P09.FRAME.NO_POLICY","title":"Observed HTML response has no framing policy","summary":"Neither X-Frame-Options nor enforced CSP frame-ancestors was captured; this is not clickjacking proof.","severityEstimate":"low","classification":"DETERMINISTIC_CONFIGURATION_SIGNAL","remediation":"Consider frame-ancestors in enforced CSP or X-Frame-Options according to compatibility.","limitation":"Passive evidence only; exploitability and whole-site coverage unverified.","evidenceSource":{"nodeIds":["wdn_397e2fa22e0d651dfe339823"],"fingerprints":["c765661ca74c57e6e5f20a840f6cd3b3ea5cf5ab420a8ff107aeb6e375e06e88"],"paths":["/"]}},{"ruleId":"P09.CSP.ABSENT","title":"No enforced Content Security Policy on observed HTML response","summary":"The fully captured response lacks an enforced CSP; this does not prove XSS.","severityEstimate":"info","classification":"DETERMINISTIC_CONFIGURATION_SIGNAL","remediation":"Introduce and validate a restrictive policy incrementally, using report-only during rollout.","limitation":"Passive evidence only; exploitability and whole-site coverage unverified.","evidenceSource":{"nodeIds":["wdn_397e2fa22e0d651dfe339823"],"fingerprints":["c765661ca74c57e6e5f20a840f6cd3b3ea5cf5ab420a8ff107aeb6e375e06e88"],"paths":["/"]}}]'::jsonb;
        v_report jsonb := '{"classification":"PASSIVE_WEB_REVIEW","analysisVersion":"web-assessment-analysis-v1","scopeHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","snapshotFingerprint":"5c7cf14877021c5012103f6b5c45ea8285988c73d324a5325b6781bfd0c234a4","requests":1,"fetched":1,"bytes":49,"failed":0,"coverageState":"BOUNDED","candidateCount":2,"observationCount":5,"limitations":["Passive observations, not confirmed vulnerabilities.","Credential-free GET-only within a bounded isolated execution namespace."]}'::jsonb;
BEGIN
 v_job:=public.web_assessment_enqueue(current_setting('isolated.qa.org')::uuid,
  current_setting('isolated.qa.asset')::uuid,
  '00000000-0000-4000-8000-00000000d901',
  'https://insecure.fixture-web.net',repeat('a',64),
  '00000000-0000-4000-8000-00000000d911');
 PERFORM set_config('isolated.qa.job',v_job::text,true);
 v_claim:=public.web_assessment_claim(v_job,
  '00000000-0000-4000-8000-00000000d921',repeat('a',64));
 IF v_claim IS NULL OR (v_claim->>'generation')::int<>1
 THEN RAISE EXCEPTION 'ISOLATED_RUNTIME_CLAIM_NOT_GRANTED'; END IF;
 IF NOT public.web_assessment_complete(v_job,v_claim->>'token',1,v_items,v_report)
 THEN RAISE EXCEPTION 'ISOLATED_RUNTIME_EVIDENCE_NOT_SAVED'; END IF;
 IF public.web_assessment_complete(v_job,v_claim->>'token',1,v_items,v_report)
 THEN RAISE EXCEPTION 'ISOLATED_RUNTIME_DUPLICATE_SUBMISSION_ACCEPTED'; END IF;
END $$;
RESET ROLE;
-- Postgres test owner validates stored rows, not direct service_role SELECT grants.
DO $$
BEGIN
 IF (SELECT count(*) FROM public.assessment_observations
    WHERE job_id=current_setting('isolated.qa.job')::uuid)<>5
 OR (SELECT count(*) FROM public.assessment_observations
     WHERE job_id=current_setting('isolated.qa.job')::uuid
     AND rule_id IN ('P09.HSTS.ABSENT','P09.CSP.ABSENT',
       'P09.FRAME.NO_POLICY','P09.COOKIE.SECURE_AGG'))<>4
 THEN RAISE EXCEPTION 'ISOLATED_REAL_TLS_DETECTION_LOST_IN_PERSISTENCE'; END IF;
END $$;

SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000d901',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000d901","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.assessment_jobs WHERE id=current_setting('isolated.qa.job')::uuid)<>1
 OR (SELECT count(*) FROM public.assessment_observations
   WHERE job_id=current_setting('isolated.qa.job')::uuid)<>5
 THEN RAISE EXCEPTION 'AAL2_WEB_REAL_EVIDENCE_NOT_VISIBLE'; END IF;
END $$;
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000d901","role":"authenticated","aal":"aal1","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.assessment_observations
 WHERE job_id=current_setting('isolated.qa.job')::uuid)<>0
 THEN RAISE EXCEPTION 'AAL1_SEES_REAL_EVIDENCE'; END IF;
END $$;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000d902',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000d902","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.assessment_jobs
 WHERE id=current_setting('isolated.qa.job')::uuid)<>0
 OR (SELECT count(*) FROM public.assessment_observations
 WHERE job_id=current_setting('isolated.qa.job')::uuid)<>0
 THEN RAISE EXCEPTION 'CROSS_TENANT_REAL_EVIDENCE_READ'; END IF;
END $$;
RESET ROLE;
ROLLBACK;
SELECT 'ROLLBACK_ONLY_ACTUAL_CONTAINER_TLS_EVIDENCE_PASS' AS test_result;
