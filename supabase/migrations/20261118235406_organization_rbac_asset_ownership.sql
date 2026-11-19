-- Forward-only extension of the existing LumicSec tenant schema.
-- Keep all old rows, original owner bootstrap, and historical role assignments.
-- All mutating Data API RPC wrappers delegate to private, narrow, authenticated routines.
-- NEVER use these functions to enable scanners or customer billing.

ALTER TABLE public.organization_memberships
  DROP CONSTRAINT IF EXISTS organization_memberships_member_role_check;
ALTER TABLE public.organization_memberships
  ADD CONSTRAINT organization_memberships_member_role_check
  CHECK (member_role IN ('owner','admin','member','analyst','viewer'));
-- analyst/viewer are read-only legacy values; only owner/admin/member can be newly assigned.

CREATE TABLE public.organization_invitations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  invite_email text NOT NULL CHECK (
    invite_email = lower(btrim(invite_email))
    AND char_length(invite_email) BETWEEN 5 AND 254
    AND invite_email ~ '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}$'
  ),
  invite_role text NOT NULL CHECK (invite_role IN ('admin','member')),
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  invited_by uuid NOT NULL REFERENCES auth.users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  accepted_at timestamptz,
  revoked_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '7 days'),
  CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);
CREATE INDEX organization_invitations_org_idx
  ON public.organization_invitations (organization_id, created_at DESC);
CREATE INDEX organization_invitations_pending_idx
  ON public.organization_invitations (organization_id, invite_email)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;
ALTER TABLE public.organization_invitations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.organization_invitations FROM PUBLIC, anon, authenticated;
-- No column grants for direct invite selection; all safe data comes from RPC.

-- Every private function validates signed, current Google AAL2 identity.
-- The Fastify BFF additionally verifies user identity and session assurance.
CREATE OR REPLACE FUNCTION lumicsec_private.require_google_aal2()
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE v_uid uuid := auth.uid(); v_claims jsonb := auth.jwt();
BEGIN
  IF v_uid IS NULL
    OR v_claims ->> 'aal' IS DISTINCT FROM 'aal2'
    OR v_claims -> 'app_metadata' ->> 'provider' IS DISTINCT FROM 'google'
    OR NOT coalesce((v_claims -> 'amr') @> '[{"method":"oauth"}]'::jsonb, false)
    OR NOT coalesce((v_claims -> 'amr') @> '[{"method":"totp"}]'::jsonb, false)
  THEN
    RAISE EXCEPTION 'Google TOTP AAL2 required' USING ERRCODE='42501';
  END IF;
  RETURN v_uid;
END $$;

CREATE OR REPLACE FUNCTION lumicsec_private.require_org_role(p_org uuid, p_roles text[])
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE v_uid uuid; v_role text;
BEGIN
  v_uid := lumicsec_private.require_google_aal2();
  SELECT m.member_role INTO v_role
  FROM public.organization_memberships m
  WHERE m.organization_id = p_org AND m.user_id = v_uid AND m.member_status='active';
  IF v_role IS NULL OR NOT (v_role = ANY(p_roles)) THEN
    RAISE EXCEPTION 'organization access denied' USING ERRCODE='42501';
  END IF;
  RETURN v_role;
END $$;

CREATE OR REPLACE FUNCTION lumicsec_private.issue_invite(p_org uuid, p_email text, p_role text)
RETURNS TABLE(invitation_id uuid, invite_token text, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE v_actor uuid; v_actor_role text; v_email text; v_token text; v_id uuid; v_expires timestamptz;
BEGIN
  v_actor := lumicsec_private.require_google_aal2();
  v_actor_role := lumicsec_private.require_org_role(p_org, ARRAY['owner','admin']);
  v_email := lower(btrim(p_email));
  IF p_email IS NULL OR v_email !~ '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}$'
    OR char_length(v_email)>254 OR p_role NOT IN ('admin','member')
    OR (v_actor_role='admin' AND p_role <> 'member')
  THEN
    RAISE EXCEPTION 'invalid or unauthorized invitation' USING ERRCODE='42501';
  END IF;

  PERFORM 1 FROM public.organizations o WHERE o.id = p_org FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'organization not found' USING ERRCODE='42501'; END IF;

  UPDATE public.organization_invitations i SET revoked_at=now()
  WHERE i.organization_id=p_org AND i.invite_email=v_email
    AND i.accepted_at IS NULL AND i.revoked_at IS NULL;

  v_token := encode(extensions.gen_random_bytes(32), 'hex');
  v_expires := now() + interval '7 days';
  INSERT INTO public.organization_invitations
    (organization_id, invite_email, invite_role, token_hash, invited_by, expires_at)
  VALUES (p_org, v_email, p_role,
    extensions.digest(convert_to(v_token, 'UTF8'), 'sha256'), v_actor, v_expires)
  RETURNING id INTO v_id;

  INSERT INTO public.audit_events(organization_id, actor_id, action, event_summary)
  VALUES (p_org, v_actor, 'organization.invite.issued', 'Invitation issued for ' || p_role);
  RETURN QUERY SELECT v_id, v_token, v_expires;
END $$;

CREATE OR REPLACE FUNCTION lumicsec_private.accept_invite(p_token text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE v_actor uuid; v_email text; v_inv public.organization_invitations%ROWTYPE;
BEGIN
  v_actor := lumicsec_private.require_google_aal2();
  IF p_token IS NULL OR p_token !~ '^[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'invitation invalid or expired' USING ERRCODE='42501';
  END IF;
  SELECT lower(u.email) INTO v_email FROM auth.users u
  WHERE u.id=v_actor AND u.email_confirmed_at IS NOT NULL;
  IF v_email IS NULL THEN RAISE EXCEPTION 'confirmed email required' USING ERRCODE='42501'; END IF;

  SELECT i.* INTO v_inv FROM public.organization_invitations i
  WHERE i.token_hash=extensions.digest(convert_to(p_token,'UTF8'),'sha256')
  FOR UPDATE;
  IF NOT FOUND OR v_inv.accepted_at IS NOT NULL OR v_inv.revoked_at IS NOT NULL
    OR v_inv.expires_at <= now() OR v_inv.invite_email <> v_email
  THEN
    RAISE EXCEPTION 'invitation invalid or expired' USING ERRCODE='42501';
  END IF;
  IF EXISTS (SELECT 1 FROM public.organization_memberships m
    WHERE m.organization_id=v_inv.organization_id AND m.user_id=v_actor)
  THEN
    RAISE EXCEPTION 'membership already exists' USING ERRCODE='23505';
  END IF;

  INSERT INTO public.organization_memberships (organization_id,user_id,member_role,member_status)
  VALUES (v_inv.organization_id,v_actor,v_inv.invite_role,'active');
  UPDATE public.organization_invitations SET accepted_at=now() WHERE id=v_inv.id;
  INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
  VALUES (v_inv.organization_id,v_actor,'organization.invite.accepted','Invitation accepted');
  RETURN v_inv.organization_id;
END $$;

CREATE OR REPLACE FUNCTION lumicsec_private.revoke_invite(p_org uuid, p_invite uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE v_actor uuid;
BEGIN
  v_actor := lumicsec_private.require_google_aal2();
  PERFORM lumicsec_private.require_org_role(p_org,ARRAY['owner','admin']);
  UPDATE public.organization_invitations SET revoked_at=now()
  WHERE organization_id=p_org AND id=p_invite
    AND revoked_at IS NULL AND accepted_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'invitation not pending' USING ERRCODE='42501'; END IF;
  INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
  VALUES(p_org,v_actor,'organization.invite.revoked','Pending invitation revoked');
END $$;

CREATE OR REPLACE FUNCTION lumicsec_private.list_members(p_org uuid)
RETURNS TABLE(user_id uuid, member_role text, member_status text, member_email text, joined_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  PERFORM lumicsec_private.require_org_role(p_org,ARRAY['owner','admin']);
  RETURN QUERY SELECT m.user_id,m.member_role,m.member_status,coalesce(u.email,''),
    m.created_at FROM public.organization_memberships m
    LEFT JOIN auth.users u ON u.id=m.user_id
    WHERE m.organization_id=p_org ORDER BY m.created_at DESC LIMIT 100;
END $$;

CREATE OR REPLACE FUNCTION lumicsec_private.list_invites(p_org uuid)
RETURNS TABLE(id uuid, invite_email text, invite_role text, expires_at timestamptz,
  created_at timestamptz, invite_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  PERFORM lumicsec_private.require_org_role(p_org,ARRAY['owner','admin']);
  RETURN QUERY SELECT i.id,i.invite_email,i.invite_role,i.expires_at,i.created_at,
  CASE WHEN i.accepted_at IS NOT NULL THEN 'accepted'
       WHEN i.revoked_at IS NOT NULL THEN 'revoked'
       WHEN i.expires_at <= now() THEN 'expired'
       ELSE 'pending' END::text
  FROM public.organization_invitations i WHERE i.organization_id=p_org
  ORDER BY i.created_at DESC LIMIT 100;
END $$;

CREATE OR REPLACE FUNCTION lumicsec_private.set_member_role(p_org uuid,p_user uuid,p_role text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE v_actor uuid; v_old text; v_owners integer;
BEGIN
  v_actor := lumicsec_private.require_google_aal2();
  PERFORM lumicsec_private.require_org_role(p_org,ARRAY['owner']);
  IF p_role NOT IN ('owner','admin','member') THEN
    RAISE EXCEPTION 'unsupported role' USING ERRCODE='42501';
  END IF;
  PERFORM 1 FROM public.organizations o WHERE o.id=p_org FOR UPDATE;
  SELECT m.member_role INTO v_old FROM public.organization_memberships m
    WHERE m.organization_id=p_org AND m.user_id=p_user AND m.member_status='active'
    FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'member not found' USING ERRCODE='42501'; END IF;
  IF v_old='owner' AND p_role<>'owner' THEN
    SELECT count(*) INTO v_owners FROM public.organization_memberships m
    WHERE m.organization_id=p_org AND m.member_role='owner' AND m.member_status='active';
    IF v_owners<=1 THEN RAISE EXCEPTION 'last owner protected' USING ERRCODE='42501'; END IF;
  END IF;
  UPDATE public.organization_memberships SET member_role=p_role
    WHERE organization_id=p_org AND user_id=p_user;
  INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
  VALUES(p_org,v_actor,'organization.member.role_changed','Member role changed to ' || p_role);
END $$;

CREATE OR REPLACE FUNCTION lumicsec_private.remove_member(p_org uuid,p_user uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE v_actor uuid; v_old text; v_owners integer;
BEGIN
  v_actor := lumicsec_private.require_google_aal2();
  PERFORM lumicsec_private.require_org_role(p_org,ARRAY['owner']);
  PERFORM 1 FROM public.organizations o WHERE o.id=p_org FOR UPDATE;
  SELECT m.member_role INTO v_old FROM public.organization_memberships m
    WHERE m.organization_id=p_org AND m.user_id=p_user AND m.member_status='active'
    FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'member not found' USING ERRCODE='42501'; END IF;
  IF v_old='owner' THEN
    SELECT count(*) INTO v_owners FROM public.organization_memberships m
    WHERE m.organization_id=p_org AND m.member_role='owner' AND m.member_status='active';
    IF v_owners<=1 THEN RAISE EXCEPTION 'last owner protected' USING ERRCODE='42501'; END IF;
  END IF;
  DELETE FROM public.organization_memberships
    WHERE organization_id=p_org AND user_id=p_user;
  INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
  VALUES(p_org,v_actor,'organization.member.removed','Membership removed by owner');
END $$;

-- A read-only manager inventory; no key material, hashes, invite tokens.
CREATE OR REPLACE FUNCTION public.org_issue_invite(p_org uuid,p_email text,p_role text)
RETURNS TABLE(invitation_id uuid,invite_token text,expires_at timestamptz)
LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT * FROM lumicsec_private.issue_invite(p_org,p_email,p_role) $$;
CREATE OR REPLACE FUNCTION public.org_accept_invite(p_token text)
RETURNS uuid LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.accept_invite(p_token) $$;
CREATE OR REPLACE FUNCTION public.org_revoke_invite(p_org uuid,p_invite uuid)
RETURNS void LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.revoke_invite(p_org,p_invite) $$;
CREATE OR REPLACE FUNCTION public.org_list_members(p_org uuid)
RETURNS TABLE(user_id uuid,member_role text,member_status text,member_email text,joined_at timestamptz)
LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT * FROM lumicsec_private.list_members(p_org) $$;
CREATE OR REPLACE FUNCTION public.org_list_invites(p_org uuid)
RETURNS TABLE(id uuid,invite_email text,invite_role text,expires_at timestamptz,
  created_at timestamptz,invite_status text)
LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT * FROM lumicsec_private.list_invites(p_org) $$;
CREATE OR REPLACE FUNCTION public.org_set_member_role(p_org uuid,p_user uuid,p_role text)
RETURNS void LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.set_member_role(p_org,p_user,p_role) $$;
CREATE OR REPLACE FUNCTION public.org_remove_member(p_org uuid,p_user uuid)
RETURNS void LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.remove_member(p_org,p_user) $$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA lumicsec_private FROM PUBLIC,anon,authenticated;
GRANT USAGE ON SCHEMA lumicsec_private TO authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.require_google_aal2() TO authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.require_org_role(uuid,text[]) TO authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.issue_invite(uuid,text,text) TO authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.accept_invite(text) TO authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.revoke_invite(uuid,uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.list_members(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.list_invites(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.set_member_role(uuid,uuid,text) TO authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.remove_member(uuid,uuid) TO authenticated;

REVOKE ALL ON FUNCTION
 public.org_issue_invite(uuid,text,text),public.org_accept_invite(text),
 public.org_revoke_invite(uuid,uuid),public.org_list_members(uuid),
 public.org_list_invites(uuid),public.org_set_member_role(uuid,uuid,text),
 public.org_remove_member(uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION
 public.org_issue_invite(uuid,text,text),public.org_accept_invite(text),
 public.org_revoke_invite(uuid,uuid),public.org_list_members(uuid),
 public.org_list_invites(uuid),public.org_set_member_role(uuid,uuid,text),
 public.org_remove_member(uuid,uuid) TO authenticated;

-- Asset proof is independent from registration. No scanner grant is introduced.
ALTER TABLE public.assets ADD COLUMN verification_expires_at timestamptz;
-- A historical verified row with NULL expiry is NOT accepted as current proof.

CREATE TABLE public.asset_verification_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  asset_id uuid NOT NULL,
  method text NOT NULL CHECK (method IN ('dns_txt','https_file')),
  token_hash bytea NOT NULL CHECK (octet_length(token_hash)=32),
  issued_by uuid NOT NULL REFERENCES auth.users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  verified_at timestamptz,
  revoked_at timestamptz,
  FOREIGN KEY (asset_id,organization_id) REFERENCES public.assets(id,organization_id) ON DELETE CASCADE,
  CHECK(expires_at > created_at AND expires_at <= created_at + interval '30 minutes'),
  CHECK(verified_at IS NULL OR revoked_at IS NULL)
);
CREATE INDEX asset_challenges_org_asset_idx
  ON public.asset_verification_challenges (organization_id,asset_id,created_at DESC);
ALTER TABLE public.asset_verification_challenges ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.asset_verification_challenges FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION lumicsec_private.org_manager(p_org uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
BEGIN
  IF auth.uid() IS NULL OR auth.jwt() ->> 'aal' IS DISTINCT FROM 'aal2'
    OR auth.jwt() -> 'app_metadata' ->> 'provider' IS DISTINCT FROM 'google'
    OR NOT coalesce((auth.jwt() -> 'amr') @> '[{"method":"totp"}]'::jsonb,false)
    OR NOT coalesce((auth.jwt() -> 'amr') @> '[{"method":"oauth"}]'::jsonb,false)
  THEN RETURN false; END IF;
  RETURN EXISTS(SELECT 1 FROM public.organization_memberships m
    WHERE m.organization_id=p_org AND m.user_id=auth.uid()
      AND m.member_status='active' AND m.member_role IN ('owner','admin'));
END $$;
REVOKE ALL ON FUNCTION lumicsec_private.org_manager(uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.org_manager(uuid) TO authenticated;

GRANT SELECT (id,organization_id,asset_id,method,created_at,expires_at,verified_at,revoked_at)
  ON public.asset_verification_challenges TO authenticated;
CREATE POLICY asset_challenges_manager_read ON public.asset_verification_challenges
  FOR SELECT TO authenticated USING (lumicsec_private.org_manager(organization_id));

CREATE OR REPLACE FUNCTION lumicsec_private.issue_asset_challenge(
 p_org uuid,p_asset uuid,p_method text)
RETURNS TABLE(challenge_id uuid,verification_token text,verification_host text,
  verification_path text,expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_actor uuid; v_origin text; v_host text; v_token text; v_id uuid; v_exp timestamptz;
BEGIN
  v_actor := lumicsec_private.require_google_aal2();
  PERFORM lumicsec_private.require_org_role(p_org,ARRAY['owner','admin']);
  IF p_method NOT IN ('dns_txt','https_file') THEN
    RAISE EXCEPTION 'unsupported verification method' USING ERRCODE='42501';
  END IF;
  SELECT a.canonical_origin INTO v_origin FROM public.assets a
    WHERE a.organization_id=p_org AND a.id=p_asset FOR UPDATE;
  IF v_origin IS NULL THEN RAISE EXCEPTION 'asset not found' USING ERRCODE='42501'; END IF;
  v_host := substring(v_origin FROM 9);
  IF char_length(v_host)>220 THEN
    RAISE EXCEPTION 'verification hostname too long' USING ERRCODE='22023';
  END IF;

  UPDATE public.asset_verification_challenges
    SET revoked_at=now()
    WHERE organization_id=p_org AND asset_id=p_asset AND verified_at IS NULL
      AND revoked_at IS NULL;

  v_token := encode(extensions.gen_random_bytes(32),'hex');
  v_exp := now()+ interval '30 minutes';
  INSERT INTO public.asset_verification_challenges
    (organization_id,asset_id,method,token_hash,issued_by,expires_at)
  VALUES (p_org,p_asset,p_method,extensions.digest(convert_to(v_token,'UTF8'),'sha256'),
    v_actor,v_exp)
  RETURNING id INTO v_id;

  INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
  VALUES (p_org,v_actor,'asset.verification.requested','Ownership challenge created: '||p_method);

  RETURN QUERY SELECT v_id,v_token,v_host,
    CASE WHEN p_method='dns_txt' THEN '_lumicsec-challenge.'||v_host
      ELSE '/.well-known/lumicsec-verification.txt' END::text,v_exp;
END $$;

CREATE OR REPLACE FUNCTION lumicsec_private.read_asset_challenge(
 p_org uuid,p_asset uuid,p_challenge uuid)
RETURNS TABLE(challenge_id uuid,asset_id uuid,organization_id uuid,canonical_origin text,
  method text,expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
BEGIN
  PERFORM lumicsec_private.require_org_role(p_org,ARRAY['owner','admin']);
  RETURN QUERY SELECT c.id,c.asset_id,c.organization_id,a.canonical_origin,c.method,c.expires_at
    FROM public.asset_verification_challenges c
    JOIN public.assets a ON a.id=c.asset_id AND a.organization_id=c.organization_id
    WHERE c.organization_id=p_org AND c.asset_id=p_asset AND c.id=p_challenge
      AND c.verified_at IS NULL AND c.revoked_at IS NULL AND c.expires_at>now()
    LIMIT 1;
END $$;

-- This is a separate capability: ONLY the server's service-role client can
-- call this exposed wrapper, after DNS or SSRF-safe HTTPS verification.
-- Authenticated users cannot provide a plaintext token to self-certify.
CREATE OR REPLACE FUNCTION lumicsec_private.finalize_asset_challenge(
 p_challenge uuid,p_token text,p_actor uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_org uuid; v_asset uuid; v_row public.asset_verification_challenges%ROWTYPE;
BEGIN
  IF p_token IS NULL OR p_token !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid proof' USING ERRCODE='42501';
  END IF;
  SELECT c.organization_id,c.asset_id INTO v_org,v_asset
    FROM public.asset_verification_challenges c WHERE c.id=p_challenge;
  IF v_org IS NULL THEN RAISE EXCEPTION 'challenge not found' USING ERRCODE='42501'; END IF;
  PERFORM 1 FROM public.assets a WHERE a.id=v_asset AND a.organization_id=v_org FOR UPDATE;
  SELECT c.* INTO v_row FROM public.asset_verification_challenges c
    WHERE c.id=p_challenge FOR UPDATE;
  IF v_row.verified_at IS NOT NULL OR v_row.revoked_at IS NOT NULL
    OR v_row.expires_at<=now()
    OR v_row.token_hash<>extensions.digest(convert_to(p_token,'UTF8'),'sha256')
    OR NOT EXISTS(SELECT 1 FROM public.organization_memberships m
      WHERE m.organization_id=v_org AND m.user_id=p_actor AND m.member_status='active'
        AND m.member_role IN ('owner','admin'))
  THEN
    RAISE EXCEPTION 'proof rejected or expired' USING ERRCODE='42501';
  END IF;

  UPDATE public.asset_verification_challenges SET verified_at=now()
    WHERE id=p_challenge;
  UPDATE public.assets
    SET verification_status='verified',verified_at=now(),
      verification_expires_at=now()+interval '30 days'
    WHERE id=v_asset AND organization_id=v_org;
  INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
  VALUES(v_org,p_actor,'asset.verification.confirmed','Bound challenge verified by backend');
  RETURN v_asset;
END $$;

CREATE OR REPLACE FUNCTION lumicsec_private.revoke_asset_ownership(
 p_org uuid,p_asset uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE v_actor uuid;
BEGIN
  v_actor := lumicsec_private.require_google_aal2();
  PERFORM lumicsec_private.require_org_role(p_org,ARRAY['owner','admin']);
  PERFORM 1 FROM public.assets a WHERE a.id=p_asset AND a.organization_id=p_org FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'asset unavailable' USING ERRCODE='42501'; END IF;
  UPDATE public.asset_verification_challenges SET revoked_at=now()
    WHERE asset_id=p_asset AND organization_id=p_org
      AND verified_at IS NULL AND revoked_at IS NULL;
  UPDATE public.assets SET verification_status='revoked',
    verification_expires_at=now() WHERE id=p_asset AND organization_id=p_org;
  INSERT INTO public.audit_events(organization_id,actor_id,action,event_summary)
  VALUES(p_org,v_actor,'asset.verification.revoked','Ownership verification revoked; scans forbidden');
END $$;

-- History can be read by a manager; only public-safe, non-secret fields.
CREATE OR REPLACE FUNCTION public.asset_issue_challenge(p_org uuid,p_asset uuid,p_method text)
RETURNS TABLE(challenge_id uuid,verification_token text,verification_host text,
 verification_path text,expires_at timestamptz)
LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT * FROM lumicsec_private.issue_asset_challenge(p_org,p_asset,p_method) $$;
CREATE OR REPLACE FUNCTION public.asset_read_challenge(p_org uuid,p_asset uuid,p_challenge uuid)
RETURNS TABLE(challenge_id uuid,asset_id uuid,organization_id uuid,canonical_origin text,
 method text,expires_at timestamptz)
LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT * FROM lumicsec_private.read_asset_challenge(p_org,p_asset,p_challenge) $$;
CREATE OR REPLACE FUNCTION public.asset_revoke_ownership(p_org uuid,p_asset uuid)
RETURNS void LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.revoke_asset_ownership(p_org,p_asset) $$;
CREATE OR REPLACE FUNCTION public.asset_finalize_proof(p_challenge uuid,p_token text,p_actor uuid)
RETURNS uuid LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$ SELECT lumicsec_private.finalize_asset_challenge(p_challenge,p_token,p_actor) $$;

-- Even if legacy status=verified, expiry=NULL does not authorize scanning.
CREATE OR REPLACE FUNCTION public.asset_ownership_is_current(p_org uuid,p_asset uuid)
RETURNS boolean LANGUAGE sql SECURITY INVOKER SET search_path=''
AS $$
 SELECT EXISTS(SELECT 1 FROM public.assets a WHERE a.id=p_asset
   AND a.organization_id=p_org AND a.verification_status='verified'
   AND a.verification_expires_at>now())
$$;

REVOKE ALL ON FUNCTION
 lumicsec_private.issue_asset_challenge(uuid,uuid,text),
 lumicsec_private.read_asset_challenge(uuid,uuid,uuid),
 lumicsec_private.finalize_asset_challenge(uuid,text,uuid),
 lumicsec_private.revoke_asset_ownership(uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION
 lumicsec_private.issue_asset_challenge(uuid,uuid,text),
 lumicsec_private.read_asset_challenge(uuid,uuid,uuid),
 lumicsec_private.revoke_asset_ownership(uuid,uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.finalize_asset_challenge(uuid,text,uuid)
  TO service_role;

REVOKE ALL ON FUNCTION
 public.asset_issue_challenge(uuid,uuid,text),
 public.asset_read_challenge(uuid,uuid,uuid),
 public.asset_revoke_ownership(uuid,uuid),
 public.asset_finalize_proof(uuid,text,uuid),
 public.asset_ownership_is_current(uuid,uuid)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION
 public.asset_issue_challenge(uuid,uuid,text),
 public.asset_read_challenge(uuid,uuid,uuid),
 public.asset_revoke_ownership(uuid,uuid),
 public.asset_ownership_is_current(uuid,uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.asset_finalize_proof(uuid,text,uuid) TO service_role;
GRANT USAGE ON SCHEMA lumicsec_private TO service_role;

-- Nothing here schedules or runs a scan. All assessment_job INSERT privileges
-- and other existing tenant RLS guards remain unchanged.
