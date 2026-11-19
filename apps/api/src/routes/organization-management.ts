import type { FastifyInstance, FastifyReply } from "fastify";
import {
  invitationAcceptSchema, invitationPathSchema, memberPathSchema, memberRoleSchema,
  organizationInviteSchema, organizationPathSchema,
} from "@lumicsec/validation";
import { requireGoogleAal2 } from "../lib/auth-guard.js";
import { createSupabaseForRequest } from "../lib/supabase.js";

function databaseRejection(reply: FastifyReply, code: string | undefined, label: string) {
  const http = code === "42501" ? 403 : code === "23505" ? 409 : 503;
  return reply.code(http).send({ error: label });
}

export async function organizationManagementRoutes(app: FastifyInstance) {
  app.get("/v1/organizations/:organizationId/members", {
    preHandler: requireGoogleAal2,
  }, async (request, reply) => {
    const input = organizationPathSchema.safeParse(request.params);
    if (!input.success) return reply.code(400).send({ error: "INVALID_ORGANIZATION_ID" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const { data, error } = await client.rpc("org_list_members", { p_org: input.data.organizationId });
    if (error) return databaseRejection(reply, error.code, "ORGANIZATION_ACCESS_DENIED");
    reply.header("cache-control", "no-store");
    return { members: data ?? [] };
  });

  app.get("/v1/organizations/:organizationId/invitations", {
    preHandler: requireGoogleAal2,
  }, async (request, reply) => {
    const input = organizationPathSchema.safeParse(request.params);
    if (!input.success) return reply.code(400).send({ error: "INVALID_ORGANIZATION_ID" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const { data, error } = await client.rpc("org_list_invites", { p_org: input.data.organizationId });
    if (error) return databaseRejection(reply, error.code, "INVITATIONS_UNAVAILABLE");
    reply.header("cache-control", "no-store");
    return { invitations: data ?? [] };
  });

  app.post("/v1/organizations/:organizationId/invitations", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 5, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const path = organizationPathSchema.safeParse(request.params);
    const input = organizationInviteSchema.safeParse(request.body);
    if (!path.success || !input.success) return reply.code(400).send({ error: "INVALID_INVITATION" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const { data, error } = await client.rpc("org_issue_invite", {
      p_org: path.data.organizationId, p_email: input.data.email, p_role: input.data.role,
    });
    if (error || !data?.[0]) return databaseRejection(reply, error?.code, "INVITATION_REJECTED");
    // One-time token appears ONLY in this explicit owner's response, never in logs,
    // query parameters, database SELECT grants, audit events, or outgoing emails.
    reply.header("cache-control", "no-store");
    return reply.code(201).send({ invitation: data[0] });
  });

  app.post("/v1/organizations/invitations/accept", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 5, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const input = invitationAcceptSchema.safeParse(request.body);
    if (!input.success) return reply.code(400).send({ error: "INVALID_INVITATION" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const { data, error } = await client.rpc("org_accept_invite", { p_token: input.data.token });
    if (error || typeof data !== "string") {
      return databaseRejection(reply, error?.code, "INVITATION_INVALID_EXPIRED_OR_EMAIL_MISMATCH");
    }
    reply.header("cache-control", "no-store");
    return { organizationId: data, joined: true };
  });

  app.post("/v1/organizations/:organizationId/invitations/:invitationId/revoke", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 15, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const input = invitationPathSchema.safeParse(request.params);
    if (!input.success) return reply.code(400).send({ error: "INVALID_INVITATION" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const { error } = await client.rpc("org_revoke_invite", {
      p_org: input.data.organizationId, p_invite: input.data.invitationId,
    });
    if (error) return databaseRejection(reply, error.code, "INVITATION_REVOCATION_DENIED");
    reply.header("cache-control", "no-store");
    return { revoked: true };
  });

  app.post("/v1/organizations/:organizationId/members/:userId/role", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 15, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const path = memberPathSchema.safeParse(request.params);
    const input = memberRoleSchema.safeParse(request.body);
    if (!path.success || !input.success) return reply.code(400).send({ error: "INVALID_ROLE_CHANGE" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const { error } = await client.rpc("org_set_member_role", {
      p_org: path.data.organizationId, p_user: path.data.userId, p_role: input.data.role,
    });
    if (error) return databaseRejection(reply, error.code, "ROLE_CHANGE_DENIED");
    reply.header("cache-control", "no-store");
    return { updated: true };
  });

  app.post("/v1/organizations/:organizationId/members/:userId/remove", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 15, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const input = memberPathSchema.safeParse(request.params);
    if (!input.success) return reply.code(400).send({ error: "INVALID_MEMBERSHIP" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const { error } = await client.rpc("org_remove_member", {
      p_org: input.data.organizationId, p_user: input.data.userId,
    });
    if (error) return databaseRejection(reply, error.code, "MEMBER_REMOVAL_DENIED");
    reply.header("cache-control", "no-store");
    return { removed: true };
  });

  app.get("/v1/organizations/:organizationId/audit", {
    preHandler: requireGoogleAal2,
  }, async (request, reply) => {
    const input = organizationPathSchema.safeParse(request.params);
    if (!input.success) return reply.code(400).send({ error: "INVALID_ORGANIZATION_ID" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    // Enforce manager status explicitly instead of returning ambiguous empty rows.
    const permission = await client.rpc("org_list_members", { p_org: input.data.organizationId });
    if (permission.error) return databaseRejection(reply, permission.error.code, "AUDIT_ACCESS_DENIED");
    const { data, error } = await client.from("audit_events")
      .select("id,actor_id,action,event_summary,created_at")
      .eq("organization_id", input.data.organizationId)
      .order("created_at", { ascending: false }).limit(100);
    if (error) return databaseRejection(reply, error.code, "AUDIT_UNAVAILABLE");
    reply.header("cache-control", "no-store");
    return { events: data ?? [] };
  });
}
