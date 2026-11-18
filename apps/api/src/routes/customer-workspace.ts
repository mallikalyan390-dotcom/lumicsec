import type { FastifyInstance } from "fastify";
import {
  assetCreateSchema,
  organizationCreateSchema,
  organizationIdQuerySchema,
} from "@lumicsec/validation";
import { requireGoogleAal2 } from "../lib/auth-guard.js";
import { canonicalAssetOrigin } from "../lib/asset-origin.js";
import { createSupabaseForRequest } from "../lib/supabase.js";

export async function customerWorkspaceRoutes(app: FastifyInstance) {
  app.get("/v1/organizations", { preHandler: requireGoogleAal2 }, async (request, reply) => {
    const supabase = createSupabaseForRequest(request, reply);
    if (!supabase || !request.authUser) {
      return reply.code(401).send({ error: "AUTHENTICATION_REQUIRED" });
    }

    const [organizations, memberships] = await Promise.all([
      supabase.from("organizations")
        .select("id,display_name,created_at,created_by")
        .order("created_at", { ascending: false })
        .limit(100),
      supabase.from("organization_memberships")
        .select("organization_id,member_role,member_status")
        .eq("user_id", request.authUser.id)
        .eq("member_status", "active")
        .limit(100),
    ]);

    if (organizations.error || memberships.error) {
      request.log.warn({
        orgErrorCode: organizations.error?.code,
        membershipErrorCode: memberships.error?.code,
      }, "Tenant-scoped organization query failed");
      return reply.code(503).send({ error: "WORKSPACE_UNAVAILABLE" });
    }

    reply.header("cache-control", "no-store");
    return { organizations: organizations.data ?? [], memberships: memberships.data ?? [] };
  });

  app.post("/v1/organizations", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 5, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const parsed = organizationCreateSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "INVALID_ORGANIZATION" });

    const supabase = createSupabaseForRequest(request, reply);
    if (!supabase || !request.authUser) {
      return reply.code(401).send({ error: "AUTHENTICATION_REQUIRED" });
    }
    const { data, error } = await supabase.from("organizations")
      .insert({
        display_name: parsed.data.displayName,
        created_by: request.authUser.id,
      })
      .select("id,display_name,created_at,created_by")
      .single();

    if (error || !data) {
      request.log.warn({ code: error?.code }, "Organization creation rejected");
      return reply.code(error?.code === "42501" ? 403 : 503)
        .send({ error: "ORGANIZATION_CREATION_REJECTED" });
    }
    reply.header("cache-control", "no-store");
    return reply.code(201).send({ organization: data });
  });

  app.get("/v1/assets", { preHandler: requireGoogleAal2 }, async (request, reply) => {
    const parsed = organizationIdQuerySchema.safeParse(request.query);
    if (!parsed.success) return reply.code(400).send({ error: "INVALID_ORGANIZATION_ID" });

    const supabase = createSupabaseForRequest(request, reply);
    if (!supabase || !request.authUser) {
      return reply.code(401).send({ error: "AUTHENTICATION_REQUIRED" });
    }
    const { data, error } = await supabase.from("assets")
      .select("id,organization_id,asset_kind,display_name,canonical_origin,verification_status,created_at")
      .eq("organization_id", parsed.data.organizationId)
      .order("created_at", { ascending: false })
      .limit(100);

    if (error) {
      request.log.warn({ code: error.code }, "Tenant-scoped asset listing failed");
      return reply.code(503).send({ error: "ASSET_LIST_UNAVAILABLE" });
    }
    reply.header("cache-control", "no-store");
    return { assets: data ?? [] };
  });

  app.post("/v1/assets", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const parsed = assetCreateSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "INVALID_ASSET" });

    let origin: string;
    try {
      origin = canonicalAssetOrigin(parsed.data.origin);
    } catch {
      return reply.code(400).send({ error: "PUBLIC_HTTPS_ORIGIN_REQUIRED" });
    }
    const supabase = createSupabaseForRequest(request, reply);
    if (!supabase || !request.authUser) {
      return reply.code(401).send({ error: "AUTHENTICATION_REQUIRED" });
    }

    // A customer can register only a PENDING asset. Ownership verification
    // is a separate milestone. This route NEVER invokes a network scanner.
    const { data, error } = await supabase.from("assets")
      .insert({
        organization_id: parsed.data.organizationId,
        asset_kind: parsed.data.kind,
        display_name: parsed.data.displayName,
        canonical_origin: origin,
        created_by: request.authUser.id,
      })
      .select("id,organization_id,asset_kind,display_name,canonical_origin,verification_status,created_at")
      .single();

    if (error || !data) {
      request.log.warn({ code: error?.code }, "Pending asset registration rejected");
      return reply
        .code(error?.code === "23505" ? 409 : error?.code === "42501" || error?.code === "23503" ? 403 : 503)
        .send({ error: "ASSET_REGISTRATION_REJECTED" });
    }

    reply.header("cache-control", "no-store");
    return reply.code(201).send({ asset: data, scanningEnabled: false });
  });
}
