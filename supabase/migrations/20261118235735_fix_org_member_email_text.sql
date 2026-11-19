-- Follow-up to 20261118235406: auth.users.email is varchar, but the
-- public org member inventory deliberately returns TEXT.
CREATE OR REPLACE FUNCTION lumicsec_private.list_members(p_org uuid)
RETURNS TABLE(user_id uuid, member_role text, member_status text, member_email text, joined_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  PERFORM lumicsec_private.require_org_role(p_org,ARRAY['owner','admin']);
  RETURN QUERY SELECT m.user_id,m.member_role,m.member_status,
    coalesce(u.email,'')::text,m.created_at
    FROM public.organization_memberships m
    LEFT JOIN auth.users u ON u.id=m.user_id
    WHERE m.organization_id=p_org ORDER BY m.created_at DESC LIMIT 100;
END $$;

REVOKE ALL ON FUNCTION lumicsec_private.list_members(uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION lumicsec_private.list_members(uuid) TO authenticated;
