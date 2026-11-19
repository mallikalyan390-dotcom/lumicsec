import { createClient } from "@supabase/supabase-js";
import type { FastifyInstance, FastifyReply } from "fastify";
import {
  assetVerificationCheckSchema, assetVerificationIssueSchema,
  assetVerificationListSchema, assetVerificationRevokeSchema,
} from "@lumicsec/validation";
import { env } from "../env.js";
import { requireGoogleAal2 } from "../lib/auth-guard.js";
import { discoverAssetOwnershipProof } from "../lib/ownership-proof.js";
import { createSupabaseForRequest } from "../lib/supabase.js";

function rejectDb(reply: FastifyReply, code: string | undefined, label: string) {
  return reply.code(code === "42501" ? 403 : code === "23505" ? 409 : 503)
    .send({ error: label });
}

function trustedVerificationClient() {
  // The publishable key has no permission to complete ownership verification.
  // No secret in developer .env => 503, NEVER grant browser users update access.
  if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY
    || env.SUPABASE_SECRET_KEY.includes("REPLACE_ME")) return null;
  return createClient(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}

export async function assetVerificationRoutes(app: FastifyInstance) {
  app.post("/v1/assets/verification/challenges", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 4, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const input = assetVerificationIssueSchema.safeParse(request.body);
    if (!input.success) return reply.code(400).send({ error: "INVALID_CHALLENGE_REQUEST" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const { data, error } = await client.rpc("asset_issue_challenge", {
      p_org: input.data.organizationId,
      p_asset: input.data.assetId,
      p_method: input.data.method,
    });
    if (error || !data?.[0]) return rejectDb(reply, error?.code, "CHALLENGE_CREATION_DENIED");
    reply.header("cache-control", "no-store");
    return reply.code(201).send({ challenge: data[0], scanningEnabled: false });
  });

  app.get("/v1/assets/verification/challenges", {
    preHandler: requireGoogleAal2,
  }, async (request, reply) => {
    const input = assetVerificationListSchema.safeParse(request.query);
    if (!input.success) return reply.code(400).send({ error: "INVALID_ASSET" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const { data, error } = await client.from("asset_verification_challenges")
      // Never request or return token_hash; PostgreSQL grants also forbid it.
      .select("id,organization_id,asset_id,method,created_at,expires_at,verified_at,revoked_at")
      .eq("organization_id", input.data.organizationId)
      .eq("asset_id", input.data.assetId)
      .order("created_at", { ascending: false }).limit(50);
    if (error) return rejectDb(reply, error.code, "CHALLENGES_UNAVAILABLE");
    reply.header("cache-control", "no-store");
    return { challenges: data ?? [] };
  });

  app.post("/v1/assets/verification/check", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 5, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const input = assetVerificationCheckSchema.safeParse(request.body);
    if (!input.success) return reply.code(400).send({ error: "INVALID_CHALLENGE_REQUEST" });
    if (!request.authUser) return reply.code(401).send({ error: "AUTHENTICATION_REQUIRED" });

    const trustedClient = trustedVerificationClient();
    if (!trustedClient) {
      return reply.code(503).send({ error: "TRUSTED_VERIFICATION_BACKEND_NOT_CONFIGURED" });
    }
    const userClient = createSupabaseForRequest(request, reply);
    if (!userClient) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });

    // Database RPC verifies manager status and binds org + asset + unexpired
    // challenge. The browser cannot supply its own proof text or destination.
    const { data: details, error: readError } = await userClient.rpc("asset_read_challenge", {
      p_org: input.data.organizationId,
      p_asset: input.data.assetId,
      p_challenge: input.data.challengeId,
    });
    if (readError) return rejectDb(reply, readError.code, "VERIFICATION_ACCESS_DENIED");
    const detail = details?.[0];
    if (!detail) return reply.code(409).send({ error: "CHALLENGE_EXPIRED_OR_UNAVAILABLE" });
    if (detail.method !== "dns_txt" && detail.method !== "https_file") {
      return reply.code(503).send({ error: "UNSUPPORTED_VERIFICATION_METHOD" });
    }

    let observedToken: string | null;
    try {
      observedToken = await discoverAssetOwnershipProof(detail.canonical_origin, detail.method);
    } catch (error) {
      if (error instanceof Error
        && ["PRIVATE_ADDRESS_BLOCKED", "IP_LITERAL_BLOCKED", "DNS_RESOLUTION_UNSAFE",
          "PUBLIC_DNS_HOSTNAME_REQUIRED", "PUBLIC_HTTPS_ORIGIN_REQUIRED", "HOSTNAME_MISMATCH"].includes(error.message)) {
        return reply.code(403).send({ error: "VERIFICATION_TARGET_BLOCKED" });
      }
      // No remote body, IP, DNS record, URL or token leaves this handler.
      return reply.code(409).send({ error: "VERIFICATION_PROOF_NOT_FOUND" });
    }
    if (!observedToken) return reply.code(409).send({ error: "VERIFICATION_PROOF_NOT_FOUND" });

    // The service-role-only RPC checks the observed token hash again,
    // expiration, challenge reuse, asset binding and current actor membership
    // atomically. This cannot be called with the browser's authenticated key.
    const { data: verifiedId, error: finishError } = await trustedClient.rpc("asset_finalize_proof", {
      p_challenge: input.data.challengeId,
      p_token: observedToken,
      p_actor: request.authUser.id,
    });
    if (finishError || verifiedId !== input.data.assetId) {
      return rejectDb(reply, finishError?.code, "VERIFICATION_PROOF_REJECTED");
    }
    reply.header("cache-control", "no-store");
    return { verified: true, assetId: verifiedId, scanningEnabled: false };
  });

  app.post("/v1/assets/verification/revoke", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const input = assetVerificationRevokeSchema.safeParse(request.body);
    if (!input.success) return reply.code(400).send({ error: "INVALID_ASSET" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const { error } = await client.rpc("asset_revoke_ownership", {
      p_org: input.data.organizationId, p_asset: input.data.assetId,
    });
    if (error) return rejectDb(reply, error.code, "OWNERSHIP_REVOCATION_DENIED");
    reply.header("cache-control", "no-store");
    return { revoked: true, scanningEnabled: false };
  });
}
