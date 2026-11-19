-- Transaction-only regression; zero permanent rows or factor changes.
-- Execute on DEVELOPMENT database with the forward-only org/asset migration.
BEGIN;

INSERT INTO auth.users (id, instance_id, aud, role, email, email_confirmed_at, created_at, updated_at)
VALUES
 ('00000000-0000-4000-8000-00000000a101','00000000-0000-0000-0000-000000000000',
  'authenticated','authenticated','synthetic-owner-a@example.test',now(),now(),now()),
 ('00000000-0000-4000-8000-00000000a102','00000000-0000-0000-0000-000000000000',
  'authenticated','authenticated','synthetic-owner-b@example.test',now(),now(),now()),
 ('00000000-0000-4000-8000-00000000a103','00000000-0000-0000-0000-000000000000',
  'authenticated','authenticated','synthetic-invitee-c@example.test',now(),now(),now()),
 ('00000000-0000-4000-8000-00000000a104','00000000-0000-0000-0000-000000000000',
  'authenticated','authenticated','synthetic-expired-d@example.test',now(),now(),now());

SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000a101',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a101","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);

INSERT INTO public.organizations(display_name,created_by)
VALUES('Temporary QA Tenant A','00000000-0000-4000-8000-00000000a101');
DO $$
DECLARE v_org uuid; v_row record;
BEGIN
 SELECT id INTO v_org FROM public.organizations WHERE display_name='Temporary QA Tenant A';
 PERFORM set_config('app.qa_org_a',v_org::text,true);
 SELECT * INTO v_row FROM public.org_issue_invite(v_org,'synthetic-invitee-c@example.test','member');
 PERFORM set_config('app.qa_invite_token',v_row.invite_token,true);
 IF char_length(v_row.invite_token)<>64 OR v_row.expires_at<=now() THEN
   RAISE EXCEPTION 'INVITE_TOKEN_ISSUE_FAILED';
 END IF;
 IF (SELECT count(*) FROM public.org_list_invites(v_org))<>1 THEN
   RAISE EXCEPTION 'INVITE_LIST_FAILED';
 END IF;
 IF (SELECT count(*) FROM public.org_list_members(v_org))<>1 THEN
   RAISE EXCEPTION 'OWNER_BOOTSTRAP_MISSING';
 END IF;
 BEGIN
  PERFORM public.org_remove_member(v_org,'00000000-0000-4000-8000-00000000a101');
  RAISE EXCEPTION 'LAST_OWNER_REMOVAL_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;

INSERT INTO public.assets(organization_id,asset_kind,display_name,canonical_origin,created_by)
VALUES(current_setting('app.qa_org_a')::uuid,'website','Temporary QA website',
 'https://qa-a.example.test','00000000-0000-4000-8000-00000000a101');
DO $$
DECLARE v_org uuid:=current_setting('app.qa_org_a')::uuid; v_asset uuid; v_row record;
BEGIN
 SELECT a.id INTO v_asset FROM public.assets a WHERE a.organization_id=v_org;
 PERFORM set_config('app.qa_asset',v_asset::text,true);
 SELECT * INTO v_row FROM public.asset_issue_challenge(v_org,v_asset,'dns_txt');
 PERFORM set_config('app.qa_challenge',v_row.challenge_id::text,true);
 PERFORM set_config('app.qa_asset_token',v_row.verification_token,true);
 IF v_row.verification_host<>'qa-a.example.test'
   OR v_row.verification_path<>'_lumicsec-challenge.qa-a.example.test'
   OR char_length(v_row.verification_token)<>64
 THEN RAISE EXCEPTION 'UNEXPECTED_BOUND_CHALLENGE'; END IF;
 IF public.asset_ownership_is_current(v_org,v_asset) THEN
   RAISE EXCEPTION 'REGISTRATION_GRANTED_SCANNING';
 END IF;
 BEGIN
  PERFORM public.asset_finalize_proof(v_row.challenge_id,v_row.verification_token,
    '00000000-0000-4000-8000-00000000a101');
  RAISE EXCEPTION 'AUTHENTICATED_USER_SELF_CERTIFIED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;

-- Direct Supabase Data API reads MUST obey Google+TOTP AAL2 as well as
-- Fastify. Existing membership alone must never grant AAL1 asset visibility.
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a101","role":"authenticated","aal":"aal1","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.organizations)<>0 THEN
   RAISE EXCEPTION 'AAL1_DIRECT_ORGANIZATION_READ_BYPASS';
 END IF;
 IF (SELECT count(*) FROM public.assets)<>0 THEN
   RAISE EXCEPTION 'AAL1_DIRECT_ASSET_READ_BYPASS';
 END IF;
 IF (SELECT count(*) FROM public.organization_memberships)<>0 THEN
   RAISE EXCEPTION 'AAL1_DIRECT_MEMBERSHIP_READ_BYPASS';
 END IF;
 IF (SELECT count(*) FROM public.asset_verification_challenges)<>0 THEN
   RAISE EXCEPTION 'AAL1_DIRECT_OWNERSHIP_CHALLENGE_READ_BYPASS';
 END IF;
END $$;
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a101","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.organizations)<>0
   OR (SELECT count(*) FROM public.assets)<>0 THEN
  RAISE EXCEPTION 'MISSING_TOTP_AMR_DIRECT_DATA_API_BYPASS';
 END IF;
END $$;
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a101","role":"authenticated","aal":"aal2","app_metadata":{"provider":"email"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.organizations)<>0
   OR (SELECT count(*) FROM public.assets)<>0 THEN
  RAISE EXCEPTION 'NON_GOOGLE_DIRECT_DATA_API_BYPASS';
 END IF;
END $$;
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a101","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.organizations)<>1
   OR (SELECT count(*) FROM public.assets)<>1 THEN
  RAISE EXCEPTION 'AUTHORIZED_AAL2_MEMBERSHIP_REGRESSION';
 END IF;
END $$;

-- An unrelated AAL2 Google account cannot read or mutate Tenant A.
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000a102',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a102","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM public.organizations)<>0 THEN
   RAISE EXCEPTION 'CROSS_TENANT_ORGANIZATIONS';
 END IF;
 IF (SELECT count(*) FROM public.assets)<>0 THEN
   RAISE EXCEPTION 'CROSS_TENANT_ASSETS';
 END IF;
 IF (SELECT count(*) FROM public.asset_verification_challenges)<>0 THEN
   RAISE EXCEPTION 'CROSS_TENANT_CHALLENGES';
 END IF;
 BEGIN
   PERFORM * FROM public.org_list_members(current_setting('app.qa_org_a')::uuid);
   RAISE EXCEPTION 'CROSS_TENANT_MEMBER_LIST';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
   PERFORM * FROM public.asset_issue_challenge(current_setting('app.qa_org_a')::uuid,
    current_setting('app.qa_asset')::uuid,'dns_txt');
   RAISE EXCEPTION 'CROSS_TENANT_ASSET_CHALLENGE';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
   PERFORM public.org_accept_invite(current_setting('app.qa_invite_token'));
   RAISE EXCEPTION 'INVITE_EMAIL_BINDING_BYPASSED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;

INSERT INTO public.organizations(display_name,created_by)
VALUES('Temporary QA Tenant B','00000000-0000-4000-8000-00000000a102');
DO $$
BEGIN
 IF (SELECT count(*) FROM public.organizations)<>1 THEN
  RAISE EXCEPTION 'TENANT_B_ISOLATION_FAILED';
 END IF;
END $$;

-- AAL1 and email-first-factor identities cannot accept invitations.
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000a103',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a103","role":"authenticated","aal":"aal1","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"}]}',true);
DO $$
BEGIN
 BEGIN
  PERFORM public.org_accept_invite(current_setting('app.qa_invite_token'));
  RAISE EXCEPTION 'AAL1_INVITATION_ACCEPTED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a103","role":"authenticated","aal":"aal2","app_metadata":{"provider":"email"},"amr":[{"method":"password"},{"method":"totp"}]}',true);
DO $$
BEGIN
 BEGIN
  PERFORM public.org_accept_invite(current_setting('app.qa_invite_token'));
  RAISE EXCEPTION 'NON_GOOGLE_INVITATION_ACCEPTED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;

-- Correct user can accept once, no cross-tenant overwrite or double redemption.
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a103","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
DECLARE v_org uuid:=current_setting('app.qa_org_a')::uuid;
BEGIN
 IF public.org_accept_invite(current_setting('app.qa_invite_token'))<>v_org THEN
  RAISE EXCEPTION 'INVITATION_ACCEPTANCE_WRONG_ORG';
 END IF;
 BEGIN
  PERFORM public.org_accept_invite(current_setting('app.qa_invite_token'));
  RAISE EXCEPTION 'INVITATION_REPLAY_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 IF (SELECT count(*) FROM public.organizations)<>1 THEN
  RAISE EXCEPTION 'MEMBER_TENANT_ISOLATION';
 END IF;
 BEGIN
  PERFORM * FROM public.org_issue_invite(v_org,'other@example.test','admin');
  RAISE EXCEPTION 'MEMBER_ESCALATION_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
  PERFORM * FROM public.asset_issue_challenge(v_org,current_setting('app.qa_asset')::uuid,'dns_txt');
  RAISE EXCEPTION 'MEMBER_ISSUED_CHALLENGE';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;

-- Owner upgrades invitee, but owner safety is preserved.
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000a101',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a101","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 PERFORM public.org_set_member_role(current_setting('app.qa_org_a')::uuid,
 '00000000-0000-4000-8000-00000000a103','admin');
 IF (SELECT count(*) FROM public.org_list_members(current_setting('app.qa_org_a')::uuid)
    WHERE member_role='admin')<>1 THEN
  RAISE EXCEPTION 'OWNER_ROLE_CHANGE_FAILED';
 END IF;
 IF (SELECT count(*) FROM public.audit_events
  WHERE organization_id=current_setting('app.qa_org_a')::uuid)<3 THEN
  RAISE EXCEPTION 'AUDIT_MISSING';
 END IF;
END $$;

-- Admin can invite members but cannot promote, invite another admin or remove owners.
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000a103',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a103","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
DECLARE v_inv record; v_org uuid:=current_setting('app.qa_org_a')::uuid;
BEGIN
 SELECT * INTO v_inv FROM public.org_issue_invite(v_org,'synthetic-admin-invited@example.test','member');
 IF v_inv.invitation_id IS NULL THEN RAISE EXCEPTION 'ADMIN_MEMBER_INVITATION_FAILED'; END IF;
 BEGIN
  PERFORM * FROM public.org_issue_invite(v_org,'synthetic-admin-escalation@example.test','admin');
  RAISE EXCEPTION 'ADMIN_INVITED_ANOTHER_ADMIN';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
  PERFORM public.org_set_member_role(v_org,'00000000-0000-4000-8000-00000000a101','member');
  RAISE EXCEPTION 'ADMIN_DEMOTED_OWNER';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
  PERFORM public.org_remove_member(v_org,'00000000-0000-4000-8000-00000000a101');
  RAISE EXCEPTION 'ADMIN_REMOVED_OWNER';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;

-- Service-role proof completion is a simulation of a trusted backend event.
SET LOCAL ROLE service_role;
SELECT public.asset_finalize_proof(current_setting('app.qa_challenge')::uuid,
 current_setting('app.qa_asset_token'),'00000000-0000-4000-8000-00000000a101');
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000a101',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a101","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.assets a
   WHERE a.id=current_setting('app.qa_asset')::uuid
     AND a.verification_status='verified' AND a.verification_expires_at>now()) THEN
  RAISE EXCEPTION 'SERVER_PROOF_FINALIZATION_FAILED';
 END IF;
END $$;
DO $$
BEGIN
 IF NOT public.asset_ownership_is_current(current_setting('app.qa_org_a')::uuid,
    current_setting('app.qa_asset')::uuid) THEN
  RAISE EXCEPTION 'CURRENT_OWNERSHIP_NOT_VISIBLE';
 END IF;
 PERFORM public.asset_revoke_ownership(current_setting('app.qa_org_a')::uuid,
   current_setting('app.qa_asset')::uuid);
 IF public.asset_ownership_is_current(current_setting('app.qa_org_a')::uuid,
    current_setting('app.qa_asset')::uuid) THEN
  RAISE EXCEPTION 'REVOKED_ASSET_AUTHORIZED';
 END IF;
END $$;


-- Expiry tests must fail even when the exact original token is known.
-- Mint new tokens under AAL2, then age ONLY synthetic rows within this rollback.
DO $$
DECLARE v_inv record; v_challenge record;
BEGIN
 SELECT * INTO v_inv FROM public.org_issue_invite(
   current_setting('app.qa_org_a')::uuid,'synthetic-expired-d@example.test','member');
 PERFORM set_config('app.qa_expired_invitation_id',v_inv.invitation_id::text,true);
 PERFORM set_config('app.qa_expired_invitation_token',v_inv.invite_token,true);
 SELECT * INTO v_challenge FROM public.asset_issue_challenge(
   current_setting('app.qa_org_a')::uuid,current_setting('app.qa_asset')::uuid,'https_file');
 PERFORM set_config('app.qa_expired_challenge_id',v_challenge.challenge_id::text,true);
 PERFORM set_config('app.qa_expired_challenge_token',v_challenge.verification_token,true);
 IF v_challenge.verification_path <> '/.well-known/lumicsec-verification.txt' THEN
   RAISE EXCEPTION 'HTTPS_CHALLENGE_PATH_MISMATCH';
 END IF;
END $$;
SET LOCAL ROLE postgres;
UPDATE public.organization_invitations
 SET created_at=now()-interval '8 days',expires_at=now()-interval '2 days'
 WHERE id=current_setting('app.qa_expired_invitation_id')::uuid;
UPDATE public.asset_verification_challenges
 SET created_at=now()-interval '60 minutes',expires_at=now()-interval '45 minutes'
 WHERE id=current_setting('app.qa_expired_challenge_id')::uuid;

SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claim.sub','00000000-0000-4000-8000-00000000a104',true);
SELECT set_config('request.jwt.claims',
 '{"sub":"00000000-0000-4000-8000-00000000a104","role":"authenticated","aal":"aal2","app_metadata":{"provider":"google"},"amr":[{"method":"oauth"},{"method":"totp"}]}',true);
DO $$
BEGIN
 BEGIN
  PERFORM public.org_accept_invite(current_setting('app.qa_expired_invitation_token'));
  RAISE EXCEPTION 'EXPIRED_INVITATION_ACCEPTED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;

SET LOCAL ROLE service_role;
DO $$
BEGIN
 BEGIN
  PERFORM public.asset_finalize_proof(current_setting('app.qa_expired_challenge_id')::uuid,
    current_setting('app.qa_expired_challenge_token'),
    '00000000-0000-4000-8000-00000000a101');
  RAISE EXCEPTION 'EXPIRED_CHALLENGE_VERIFIED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
  PERFORM public.asset_finalize_proof(current_setting('app.qa_expired_challenge_id')::uuid,
    repeat('f',64),'00000000-0000-4000-8000-00000000a101');
  RAISE EXCEPTION 'WRONG_CHALLENGE_TOKEN_ACCEPTED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;

ROLLBACK;
SELECT 'ROLLBACK_ONLY_RBAC_OWNERSHIP_TESTS_PASS' AS test_result;
