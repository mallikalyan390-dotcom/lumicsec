-- Real dev PostgreSQL offline API job -> review-only canonical finding, rollback.
BEGIN;
INSERT INTO auth.users(id,instance_id,aud,role,email,email_confirmed_at,created_at,updated_at)
 VALUES('00000000-0000-4000-8000-00000000e971',
 '00000000-0000-0000-0000-000000000000','authenticated','authenticated',
 'synthetic-api-finding@example.test',now(),now(),now());
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e971',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e971","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
INSERT INTO public.organizations(display_name,created_by)
 VALUES('Offline API findings rollback','00000000-0000-4000-8000-00000000e971');
SELECT set_config('fqa2.org',(SELECT id::text FROM public.organizations WHERE display_name='Offline API findings rollback'),true);
INSERT INTO public.assets(organization_id,asset_kind,display_name,canonical_origin,created_by)
 VALUES(current_setting('fqa2.org')::uuid,'api','Offline API synthetic','https://api-spec-fixture.example.net',
 '00000000-0000-4000-8000-00000000e971');
SELECT set_config('fqa2.asset',(SELECT id::text FROM public.assets WHERE organization_id=current_setting('fqa2.org')::uuid),true);
RESET ROLE;
UPDATE public.assets SET verification_status='verified',verified_at=now(),
 verification_expires_at=now()+interval '1 day'
 WHERE id=current_setting('fqa2.asset')::uuid;
SET LOCAL ROLE service_role;
DO $$
DECLARE v_job uuid;
BEGIN
 v_job:=public.assessment_api_offline_queue(current_setting('fqa2.org')::uuid,
  current_setting('fqa2.asset')::uuid,'00000000-0000-4000-8000-00000000e971',
  repeat('a',64),repeat('b',64),'OPENAPI_3_0');
 PERFORM set_config('fqa2.job',v_job::text,true);
 IF NOT public.assessment_api_offline_begin(v_job,'00000000-0000-4000-8000-00000000e971')
 THEN RAISE EXCEPTION 'API_SPEC_BEGIN_DENIED'; END IF;
 IF NOT public.assessment_api_offline_complete(v_job,
  '00000000-0000-4000-8000-00000000e971',
  jsonb_build_array(jsonb_build_object(
  'ruleId','API.SPEC.REVIEW','title','Review offline API specification',
  'summary','Synthetic specification requires structural review','severityEstimate','medium')),
  '{"classification":"SPEC_ONLY","limitations":["Offline parser only. No runtime requests."]}'::jsonb)
 THEN RAISE EXCEPTION 'API_SPEC_COMPLETE_DENIED'; END IF;
END $$;
RESET ROLE;
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000e971',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000e971","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
DECLARE v jsonb;
BEGIN
 v:=public.findings_import(current_setting('fqa2.org')::uuid,
  current_setting('fqa2.job')::uuid,'00000000-0000-4000-8000-00000000e981');
 IF (v->>'newFindings')::int<>1 OR
 (SELECT count(*) FROM public.security_findings WHERE
  organization_id=current_setting('fqa2.org')::uuid
  AND assessment_kind='api_spec_offline' AND source_classification='SPEC_ONLY'
  AND remediation IS NULL AND reviewer_conclusion='unreviewed'
  AND workflow_status='open')<>1
 THEN RAISE EXCEPTION 'OFFLINE_API_FINDING_PROVENANCE_OR_NULL_GUIDANCE_INVALID';END IF;
 v:=public.findings_import(current_setting('fqa2.org')::uuid,
  current_setting('fqa2.job')::uuid,'00000000-0000-4000-8000-00000000e981');
 IF (v->>'newFindings')::int<>0 THEN
  RAISE EXCEPTION 'OFFLINE_API_DUPLICATE_FINDING'; END IF;
END $$;
ROLLBACK;
SELECT 'ROLLBACK_ONLY_OFFLINE_API_FINDINGS_PASS' AS test_result;
