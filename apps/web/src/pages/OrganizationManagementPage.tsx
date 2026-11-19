import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, KeyRound, LockKeyhole, Mail, ShieldCheck, Users } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Badge } from "../components/ui/Badge.js";
import { Button } from "../components/ui/Button.js";
import { Card, CardContent, CardHeader } from "../components/ui/Card.js";
import { Input } from "../components/ui/Input.js";
import {
  getAuthSession, getOrganizationAudit, getOrganizationInvitations,
  getOrganizationMembers, getOrganizations, postJson,
  type OrganizationRole,
} from "../lib/api.js";
import { useOrganizationSelection } from "../lib/organization-selection.js";

const selectClass = "h-11 w-full rounded-xl border border-white/15 bg-slate-950/70 px-3 text-sm text-white";

export function OrganizationManagementPage() {
  const client = useQueryClient();
  const auth = useQuery({ queryKey: ["auth-session"], queryFn: getAuthSession });
  const organizationsQuery = useQuery({ queryKey: ["organizations"], queryFn: getOrganizations });
  const organizations = organizationsQuery.data?.organizations ?? [];
  const { activeOrganizationId, selectOrganization } = useOrganizationSelection(organizations);
  const activeMembership = organizationsQuery.data?.memberships.find(
    (item) => item.organization_id === activeOrganizationId);
  const isOwner = activeMembership?.member_role === "owner";
  const isManager = isOwner || activeMembership?.member_role === "admin";

  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"admin" | "member">("member");
  const [oneTimeToken, setOneTimeToken] = useState("");
  const [acceptToken, setAcceptToken] = useState("");
  const csrf = auth.data?.csrfToken ?? "";

  const members = useQuery({
    queryKey: ["org-members", activeOrganizationId],
    queryFn: () => getOrganizationMembers(activeOrganizationId),
    enabled: !!activeOrganizationId && isManager,
    retry: false,
  });
  const invitations = useQuery({
    queryKey: ["org-invitations", activeOrganizationId],
    queryFn: () => getOrganizationInvitations(activeOrganizationId),
    enabled: !!activeOrganizationId && isManager,
    retry: false,
  });
  const audit = useQuery({
    queryKey: ["org-audit", activeOrganizationId],
    queryFn: () => getOrganizationAudit(activeOrganizationId),
    enabled: !!activeOrganizationId && isManager,
    retry: false,
  });

  const issueInvite = useMutation({
    mutationFn: (payload: { email: string; role: "admin" | "member" }) =>
      postJson<{ invitation: { invitation_id: string; invite_token: string; expires_at: string } }>(
        "/v1/organizations/" + activeOrganizationId + "/invitations", payload, csrf),
    onSuccess: async (result) => {
      setOneTimeToken(result.invitation.invite_token);
      setInviteEmail("");
      await client.invalidateQueries({ queryKey: ["org-invitations", activeOrganizationId] });
      await client.invalidateQueries({ queryKey: ["org-audit", activeOrganizationId] });
    },
  });
  const accept = useMutation({
    mutationFn: (token: string) => postJson<{ organizationId: string; joined: true }>(
      "/v1/organizations/invitations/accept", { token }, csrf),
    onSuccess: async ({ organizationId }) => {
      setAcceptToken("");
      await client.invalidateQueries({ queryKey: ["organizations"] });
      await client.invalidateQueries({ queryKey: ["org-members", organizationId] });
    },
  });
  const revokeInvite = useMutation({
    mutationFn: (invitationId: string) => postJson<{ revoked: true }>(
      "/v1/organizations/" + activeOrganizationId + "/invitations/" + invitationId + "/revoke", {}, csrf),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["org-invitations", activeOrganizationId] });
      await client.invalidateQueries({ queryKey: ["org-audit", activeOrganizationId] });
    },
  });
  const changeRole = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: "owner" | "admin" | "member" }) =>
      postJson<{ updated: true }>("/v1/organizations/" + activeOrganizationId
        + "/members/" + userId + "/role", { role }, csrf),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["org-members", activeOrganizationId] });
      await client.invalidateQueries({ queryKey: ["organizations"] });
      await client.invalidateQueries({ queryKey: ["org-audit", activeOrganizationId] });
    },
  });
  const removeMember = useMutation({
    mutationFn: (userId: string) => postJson<{ removed: true }>(
      "/v1/organizations/" + activeOrganizationId + "/members/" + userId + "/remove", {}, csrf),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["org-members", activeOrganizationId] });
      await client.invalidateQueries({ queryKey: ["org-audit", activeOrganizationId] });
    },
  });

  const issue = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!isManager || !csrf) return;
    setOneTimeToken("");
    issueInvite.mutate({ email: inviteEmail, role: inviteRole });
  };
  const acceptInvitation = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!csrf || !/^[a-f0-9]{64}$/.test(acceptToken)) return;
    accept.mutate(acceptToken);
  };

  const selectedOrganization = organizations.find((org) => org.id === activeOrganizationId);
  const formatted = (date: string) => new Date(date).toLocaleString();

  return (
    <div className="space-y-6">
      <header>
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-200">Customer organizations</div>
        <h1 className="mt-2 text-3xl font-semibold text-white">Team & access management</h1>
        <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-400">
          Organization roles are enforced by Supabase and server-side Google TOTP AAL2.
          Each invitation is bound to the intended account email and expires after seven days.
        </p>
      </header>
      <Card>
        <CardHeader className="flex items-center gap-3">
          <Building2 size={19} className="text-cyan-200" />
          <div>
            <h2 className="font-semibold text-white">Active organization</h2>
            <p className="text-xs text-slate-400">Switching changes the UI selection, never database authorization.</p>
          </div>
        </CardHeader>
        <CardContent>
          {organizationsQuery.isError && <p role="alert" className="text-rose-300">{organizationsQuery.error.message}</p>}
          {organizations.length > 0 ? (
            <div className="space-y-2">
              <label htmlFor="manage-org-select" className="text-xs text-slate-300">Organization</label>
              <select className={selectClass} id="manage-org-select" value={activeOrganizationId}
                onChange={(event) => { setOneTimeToken(""); selectOrganization(event.target.value); }}>
                {organizations.map((organization) => (
                  <option value={organization.id} key={organization.id}>{organization.display_name}</option>
                ))}
              </select>
              <p className="text-xs text-slate-400">Your role: {activeMembership?.member_role ?? "unknown"}</p>
            </div>
          ) : <p className="text-sm text-slate-400">No organization yet. You can accept an invitation below.</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex items-center gap-3">
          <Mail size={18} className="text-cyan-200" /><h2 className="font-semibold text-white">Accept an invitation</h2>
        </CardHeader>
        <CardContent>
          <form onSubmit={acceptInvitation} className="space-y-3">
            <p className="text-xs text-slate-400">Ask an organization owner for the single-use invitation code. It works only for the confirmed email of your signed-in Google account.</p>
            <label htmlFor="invitation-code" className="block text-xs text-slate-300">Invitation code</label>
            <Input id="invitation-code" type="password" autoComplete="off" maxLength={64}
              value={acceptToken} onChange={(event) => setAcceptToken(event.target.value.trim().toLowerCase())}
              placeholder="Paste the private 64-character invitation code" />
            <Button type="submit" disabled={!csrf || accept.isPending || !/^[a-f0-9]{64}$/.test(acceptToken)}>
              <KeyRound size={15} /> Join organization
            </Button>
            {accept.isError && <p role="alert" className="text-xs text-rose-300">{accept.error.message}</p>}
            {accept.isSuccess && <p className="text-xs text-emerald-200">Invitation accepted. Organization membership updated.</p>}
          </form>
        </CardContent>
      </Card>

      {isManager && activeOrganizationId && (
        <>
          <Card>
            <CardHeader className="flex items-center gap-3">
              <Users size={19} className="text-cyan-200" />
              <h2 className="font-semibold text-white">Invite a member to {selectedOrganization?.display_name}</h2>
            </CardHeader>
            <CardContent className="space-y-4">
              <form onSubmit={issue} className="grid gap-3 sm:grid-cols-[1fr_170px_auto] sm:items-end">
                <div>
                  <label htmlFor="invite-email" className="mb-2 block text-xs text-slate-300">Confirmed Google email</label>
                  <Input id="invite-email" type="email" maxLength={254} required
                    value={inviteEmail} onChange={(event) => setInviteEmail(event.target.value)} />
                </div>
                <div>
                  <label htmlFor="invite-role" className="mb-2 block text-xs text-slate-300">Role</label>
                  <select id="invite-role" className={selectClass} value={inviteRole}
                    onChange={(event) => setInviteRole(event.target.value as "admin" | "member")}>
                    <option value="member">Member</option>
                    {isOwner && <option value="admin">Admin</option>}
                  </select>
                </div>
                <Button type="submit" disabled={issueInvite.isPending || !csrf}>Create invite</Button>
              </form>
              {issueInvite.isError && <p role="alert" className="text-xs text-rose-300">{issueInvite.error.message}</p>}
              {oneTimeToken && (
                <div className="rounded-xl border border-amber-300/25 bg-slate-950/65 p-4">
                  <p className="text-xs font-semibold text-amber-200">Single-use invite code — shown only now</p>
                  <code className="mt-3 block break-all select-all text-xs text-white">{oneTimeToken}</code>
                  <p className="mt-3 text-xs text-slate-400">Share privately with the intended account owner. Never publish it. It is not stored in browser storage.</p>
                  <Button type="button" size="sm" variant="secondary" onClick={() => setOneTimeToken("")}>Hide code</Button>
                </div>
              )}
              <h3 className="text-sm font-semibold text-slate-200">Invitations</h3>
              {invitations.isLoading && <p className="text-xs text-slate-400">Loading invitations…</p>}
              {invitations.isError && <p role="alert" className="text-xs text-rose-300">{invitations.error.message}</p>}
              {invitations.data?.invitations.map((invitation) => (
                <div key={invitation.id} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/10 p-3">
                  <div>
                    <p className="text-sm text-white">{invitation.invite_email}</p>
                    <p className="text-xs text-slate-400">{invitation.invite_role} · {invitation.invite_status} · Expires {formatted(invitation.expires_at)}</p>
                  </div>
                  {invitation.invite_status === "pending" && (
                    <Button variant="secondary" size="sm" disabled={revokeInvite.isPending}
                      onClick={() => revokeInvite.mutate(invitation.id)}>Revoke invite</Button>
                  )}
                </div>
              ))}
              {revokeInvite.isError && <p role="alert" className="text-xs text-rose-300">{revokeInvite.error.message}</p>}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex items-center gap-3">
              <ShieldCheck size={19} className="text-cyan-200" /><h2 className="font-semibold text-white">Team memberships</h2>
            </CardHeader>
            <CardContent className="space-y-3">
              {members.isLoading && <p className="text-xs text-slate-400">Loading members…</p>}
              {members.isError && <p role="alert" className="text-xs text-rose-300">{members.error.message}</p>}
              {members.data?.members.map((member) => (
                <div key={member.user_id} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/10 bg-slate-950/50 p-3">
                  <div className="min-w-0">
                    <p className="break-all text-sm text-white">{member.member_email || "Member"}</p>
                    <p className="mt-1 text-xs text-slate-500">{member.member_status} · Joined {formatted(member.joined_at)}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {isOwner && member.member_status === "active" ? (
                      <>
                        <select aria-label={"Role for " + member.member_email} className={selectClass}
                          value={member.member_role}
                          disabled={changeRole.isPending || member.user_id === auth.data?.user?.id}
                          onChange={(event) => changeRole.mutate({
                            userId: member.user_id,
                            role: event.target.value as "owner" | "admin" | "member",
                          })}>
                          {!["owner", "admin", "member"].includes(member.member_role)
                            && <option value={member.member_role}>{member.member_role} (legacy)</option>}
                          <option value="owner">Owner</option><option value="admin">Admin</option>
                          <option value="member">Member</option>
                        </select>
                        {member.user_id !== auth.data?.user?.id && (
                          <Button type="button" variant="danger" size="sm" disabled={removeMember.isPending}
                            onClick={() => {
                              if (window.confirm("Remove this member? This cannot be undone automatically.")) {
                                removeMember.mutate(member.user_id);
                              }
                            }}>Remove</Button>
                        )}
                      </>
                    ) : <Badge>{member.member_role}</Badge>}
                  </div>
                </div>
              ))}
              {changeRole.isError && <p role="alert" className="text-xs text-rose-300">{changeRole.error.message}</p>}
              {removeMember.isError && <p role="alert" className="text-xs text-rose-300">{removeMember.error.message}</p>}
              <p className="text-xs text-slate-500">The database prevents removing or demoting the final owner.</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex items-center gap-3">
              <LockKeyhole size={19} className="text-cyan-200" /><h2 className="font-semibold text-white">Audit history</h2>
            </CardHeader>
            <CardContent className="space-y-3">
              {audit.isLoading && <p className="text-xs text-slate-400">Loading audit events…</p>}
              {audit.isError && <p role="alert" className="text-xs text-rose-300">{audit.error.message}</p>}
              {audit.data?.events.length === 0 && <p className="text-xs text-slate-400">No audit events yet.</p>}
              {audit.data?.events.map((event) => (
                <div key={event.id} className="rounded-xl border border-white/10 p-3">
                  <p className="text-sm text-slate-200">{event.event_summary}</p>
                  <p className="mt-1 text-xs text-slate-500">{event.action} · {formatted(event.created_at)}</p>
                </div>
              ))}
            </CardContent>
          </Card>
        </>
      )}
      {!isManager && activeOrganizationId && (
        <Card><CardContent className="p-5 text-sm leading-6 text-slate-400">
          Your {activeMembership?.member_role as OrganizationRole} role can view permitted organization assets,
          but cannot invite people, change roles, or initiate ownership verification.
        </CardContent></Card>
      )}
    </div>
  );
}
