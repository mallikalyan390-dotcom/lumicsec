-- Development-only signed AAL2, current asset ownership, tenant, scope
-- and revocation acceptance. All synthetic user/tenant/plan rows ROLLBACK.
BEGIN;
DO $$ BEGIN
 IF has_table_privilege('authenticated','public.assessment_plans','INSERT')
 OR has_table_privilege('authenticated','public.assessment_plans','UPDATE')
 OR has_table_privilege('authenticated','public.assessment_plans','DELETE')
 OR has_table_privilege('authenticated','public.assessment_plan_events','INSERT')
 OR has_table_privilege('anon','public.assessment_plans','SELECT')
 OR has_function_privilege('anon',
   'public.assessment_plan_create(uuid,uuid,text,text[],timestamptz,integer,integer,integer,integer,text,uuid)','EXECUTE')
 OR NOT has_function_privilege('authenticated',
   'public.assessment_plan_create(uuid,uuid,text,text[],timestamptz,integer,integer,integer,integer,text,uuid)','EXECUTE')
 THEN RAISE EXCEPTION 'PLAN_PERMISSION_LEAK';END IF;
END $$;
INSERT INTO auth.users(id,instance_id,aud,role,email,email_confirmed_at,created_at,updated_at)
VALUES
('00000000-0000-4000-8000-00000000eec1','00000000-0000-0000-0000-000000000000','authenticated','authenticated','runtime-plan-owner@example.test',now(),now(),now()),
('00000000-0000-4000-8000-00000000eec2','00000000-0000-0000-0000-000000000000','authenticated','authenticated','runtime-plan-viewer@example.test',now(),now(),now()),
('00000000-0000-4000-8000-00000000eec3','00000000-0000-0000-0000-000000000000','authenticated','authenticated','runtime-plan-outsider@example.test',now(),now(),now());
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000eec1',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000eec1","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
INSERT INTO public.organizations(display_name,created_by)
 VALUES('Rollback Plan Authorization One','00000000-0000-4000-8000-00000000eec1');
SELECT set_config('pl.org',(SELECT id::text FROM public.organizations
 WHERE display_name='Rollback Plan Authorization One'),true);
INSERT INTO public.assets(organization_id,asset_kind,display_name,canonical_origin,created_by)
 VALUES(current_setting('pl.org')::uuid,'website','Owned Plan Web Asset',
 'https://controlled-plan.fixture-web.net','00000000-0000-4000-8000-00000000eec1');
SELECT set_config('pl.asset',(SELECT id::text FROM public.assets
 WHERE organization_id=current_setting('pl.org')::uuid),true);
RESET ROLE;
INSERT INTO public.organization_memberships(organization_id,user_id,member_role,member_status)
 VALUES(current_setting('pl.org')::uuid,'00000000-0000-4000-8000-00000000eec2','viewer','active');
UPDATE public.assets SET verification_status='verified',
 verified_at=clock_timestamp(),verification_expires_at=now()+interval '1 day'
 WHERE id=current_setting('pl.asset')::uuid;
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000eec1',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000eec1","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
DECLARE v_id uuid;v_other uuid;v_result jsonb;v_err boolean;
BEGIN
 v_id:=public.assessment_plan_create(current_setting('pl.org')::uuid,
  current_setting('pl.asset')::uuid,'web_readonly',
  ARRAY['/','/health'],now()+interval '1 hour',3,60000,240000,15000,
  'Synthetic authorized ticket PLAN-1201',
  '00000000-0000-4000-8000-00000000ef01'::uuid);
 PERFORM set_config('pl.plan',v_id::text,true);
 IF (SELECT count(*) FROM public.assessment_plans WHERE id=v_id
   AND approved_paths=ARRAY['/','/health'] AND max_requests=3
   AND exact_origin='https://controlled-plan.fixture-web.net'
   AND scope_sha256 ~ '^[a-f0-9]{64}$')<>1
 THEN RAISE EXCEPTION 'PLAN_SCOPE_NOT_PERSISTED';END IF;
 IF (SELECT count(*) FROM public.assessment_plan_events WHERE plan_id=v_id
  AND event_type='scope_authorized')<>1
 THEN RAISE EXCEPTION 'PLAN_AUDIT_MISSING';END IF;
 v_other:=public.assessment_plan_create(current_setting('pl.org')::uuid,
  current_setting('pl.asset')::uuid,'web_readonly',
  ARRAY['/','/health'],now()+interval '1 hour',3,60000,240000,15000,
  'Synthetic authorized ticket PLAN-1201',
  '00000000-0000-4000-8000-00000000ef01'::uuid);
 -- now()+interval fixed transaction time, idempotency replay must be same.
 IF v_id<>v_other OR (SELECT count(*) FROM public.assessment_plan_events
   WHERE plan_id=v_id)<>1
 THEN RAISE EXCEPTION 'PLAN_IDEMPOTENCY_DUPLICATION';END IF;
 v_result:=public.assessment_plan_check(current_setting('pl.org')::uuid,v_id);
 IF v_result->>'eligibility'<>'ELIGIBLE_FOR_FUTURE_REVIEW'
   OR (v_result->>'executionAllowed')::boolean
 THEN RAISE EXCEPTION 'PLAN_CHECK_INCORRECT_OR_SCAN_ENABLED';END IF;
 -- Exact scope replay mutation fails, with no appended audit event.
 BEGIN
  PERFORM public.assessment_plan_create(current_setting('pl.org')::uuid,
   current_setting('pl.asset')::uuid,'web_readonly',
   ARRAY['/private'],now()+interval '1 hour',3,60000,240000,15000,
   'Synthetic authorized ticket PLAN-1201',
   '00000000-0000-4000-8000-00000000ef01'::uuid);
  RAISE EXCEPTION 'SCOPE_REPLAY_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;END;
 FOR v_err IN SELECT true LOOP
  BEGIN
   PERFORM public.assessment_plan_create(current_setting('pl.org')::uuid,
    current_setting('pl.asset')::uuid,'web_readonly',
    ARRAY['/../admin'],now()+interval '1 hour',3,60000,240000,15000,
    'Synthetic authorized ticket PLAN-1202',
    '00000000-0000-4000-8000-00000000ef02'::uuid);
   RAISE EXCEPTION 'TRAVERSAL_ALLOWED';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;END;
  BEGIN
   PERFORM public.assessment_plan_create(current_setting('pl.org')::uuid,
    current_setting('pl.asset')::uuid,'api_readonly',
    ARRAY['/'],now()+interval '1 hour',3,60000,240000,15000,
    'Synthetic authorized ticket PLAN-1203',
    '00000000-0000-4000-8000-00000000ef03'::uuid);
   RAISE EXCEPTION 'ASSET_PROFILE_MISMATCH_ALLOWED';
  EXCEPTION WHEN insufficient_privilege THEN NULL;END;
 END LOOP;
END $$;
-- A member viewer may read signed tenant plans but cannot approve or revoke.
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000eec2',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000eec2","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$ BEGIN
 IF (SELECT count(*) FROM public.assessment_plans
  WHERE id=current_setting('pl.plan')::uuid)<>1
 THEN RAISE EXCEPTION 'PLAN_VIEWER_SIGNED_READ_MISSING';END IF;
 BEGIN
  PERFORM public.assessment_plan_revoke(current_setting('pl.org')::uuid,
   current_setting('pl.plan')::uuid);
  RAISE EXCEPTION 'VIEWER_PLAN_REVOKE_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;END;
 BEGIN
  PERFORM public.assessment_plan_create(current_setting('pl.org')::uuid,
   current_setting('pl.asset')::uuid,'web_readonly',ARRAY['/'],
   now()+interval '1 hour',3,60000,240000,15000,
   'Viewer forbidden ticket 1204',
   '00000000-0000-4000-8000-00000000ef04'::uuid);
  RAISE EXCEPTION 'VIEWER_PLAN_CREATE_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;END;
END $$;
-- True outsider cannot directly see plan or audit rows or invoke check.
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000eec3',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000eec3","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.assessment_plans
  WHERE organization_id=current_setting('pl.org')::uuid)
 OR EXISTS(SELECT 1 FROM public.assessment_plan_events
  WHERE organization_id=current_setting('pl.org')::uuid)
 THEN RAISE EXCEPTION 'PLAN_CROSS_TENANT_LEAK';END IF;
 BEGIN
  PERFORM public.assessment_plan_check(current_setting('pl.org')::uuid,
   current_setting('pl.plan')::uuid);
  RAISE EXCEPTION 'PLAN_CROSS_TENANT_RPC_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;END;
END $$;
-- AAL1, non-Google identity and AAL2 without TOTP must deny reads & RPCs.
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000eec1',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000eec1","role":"authenticated","aal":"aal1","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"}]}',true);
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.assessment_plans WHERE id=current_setting('pl.plan')::uuid)
 THEN RAISE EXCEPTION 'PLAN_AAL1_READ_LEAK'; END IF;
 BEGIN
  PERFORM public.assessment_plan_revoke(current_setting('pl.org')::uuid,
   current_setting('pl.plan')::uuid);
  RAISE EXCEPTION 'PLAN_AAL1_REVOKE';
 EXCEPTION WHEN insufficient_privilege THEN NULL;END;
END $$;
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000eec1","role":"authenticated","aal":"aal2","app_metadata":{"provider":"email"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.assessment_plans WHERE id=current_setting('pl.plan')::uuid)
 THEN RAISE EXCEPTION 'PLAN_NON_GOOGLE_READ_LEAK';END IF;
END $$;
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000eec1","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"}]}',true);
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.assessment_plans WHERE id=current_setting('pl.plan')::uuid)
 THEN RAISE EXCEPTION 'PLAN_MISSING_TOTP_READ_LEAK';END IF;
END $$;
-- Revocation and proof invalidation are independently rechecked by signed RPC.
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000eec1","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$ DECLARE v jsonb;BEGIN
 IF NOT public.assessment_plan_revoke(current_setting('pl.org')::uuid,
  current_setting('pl.plan')::uuid)
 THEN RAISE EXCEPTION 'PLAN_REVOKE_FAILED';END IF;
 v:=public.assessment_plan_check(current_setting('pl.org')::uuid,
  current_setting('pl.plan')::uuid);
 IF v->>'eligibility'<>'REVOKED' OR (v->>'executionAllowed')::boolean
 THEN RAISE EXCEPTION 'REVOKED_PLAN_STILL_ELIGIBLE';END IF;
 IF (SELECT count(*) FROM public.assessment_plan_events
  WHERE plan_id=current_setting('pl.plan')::uuid)<>2
 THEN RAISE EXCEPTION 'REVOCATION_AUDIT_NOT_APPEND_ONLY';END IF;
 IF NOT public.assessment_plan_revoke(current_setting('pl.org')::uuid,
  current_setting('pl.plan')::uuid)
 OR (SELECT count(*) FROM public.assessment_plan_events
  WHERE plan_id=current_setting('pl.plan')::uuid)<>2
 THEN RAISE EXCEPTION 'REPEATED_REVOKE_AUDIT_DUPLICATE';END IF;
END $$;
DO $$
DECLARE v_id uuid;BEGIN
 v_id:=public.assessment_plan_create(current_setting('pl.org')::uuid,
  current_setting('pl.asset')::uuid,'web_readonly',ARRAY['/'],
  now()+interval '1 hour',3,60000,240000,15000,
  'New synthetic reference PLAN-1210',
  '00000000-0000-4000-8000-00000000ef10'::uuid);
 PERFORM set_config('pl.plan2',v_id::text,true);
END $$;
RESET ROLE;
UPDATE public.assets SET verification_status='revoked',
 verification_expires_at=NULL WHERE id=current_setting('pl.asset')::uuid;
SET LOCAL ROLE authenticated;
DO $$DECLARE v jsonb;BEGIN
 v:=public.assessment_plan_check(current_setting('pl.org')::uuid,
  current_setting('pl.plan2')::uuid);
 IF v->>'eligibility'<>'OWNERSHIP_CHANGED'
 THEN RAISE EXCEPTION 'REVOKED_ASSET_PROOF_DID_NOT_REVOKE_PLAN_ELIGIBILITY';END IF;
END $$;
ROLLBACK;
SELECT 'ROLLBACK_ONLY_ASSESSMENT_PLANS_AAL2_RLS_PASS' AS test_result;
