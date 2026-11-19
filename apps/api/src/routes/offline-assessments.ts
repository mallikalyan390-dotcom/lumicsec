import { createHash } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { detectInventory, importOfflineDocument } from "@lumicsec/api-security-engine";
import { MAX_SPEC_BYTES } from "@lumicsec/validation";
import { requireGoogleAal2 } from "../lib/auth-guard.js";
import { createSupabaseForRequest } from "../lib/supabase.js";
import { createTrustedSupabase } from "../lib/trusted-supabase.js";

const uuid = z.string().uuid();
const startSchema = z.object({
  organizationId: uuid,
  assetId: uuid,
  content: z.string().min(2).max(MAX_SPEC_BYTES),
  filename: z.string().max(160).optional(),
  authorization: z.literal("I_AM_AUTHORIZED_FOR_OFFLINE_SPEC_REVIEW"),
}).strict();
const orgQuerySchema = z.object({ organizationId: uuid }).strict();
const jobQuerySchema = z.object({ organizationId: uuid, jobId: uuid }).strict();
const stopSchema = jobQuerySchema;
const MAX_SAVED_OBSERVATIONS = 100;
const MAX_OFFLINE_OPERATIONS = 400;

function clean(value: string, limit: number) {
  return Array.from(value, (char) => {
    const code = char.charCodeAt(0);
    return code < 32 || code === 127 ? " " : char;
  }).join("").slice(0, limit);
}
export function deterministicOfflineScope(organizationId: string, assetId: string, origin: string, fingerprint: string) {
  return createHash("sha256")
    .update(JSON.stringify(["lumicsec-api-spec-offline-v1", organizationId, assetId, origin, fingerprint]))
    .digest("hex");
}

/** Persist strictly limited, review-only metadata. Never store imported raw documents, keys or schema examples. */
export function boundedOfflineEvidence(
  observations: ReadonlyArray<{ ruleId: string; explanation: string; remediation: string; impact: string }>,
) {
  return observations.slice(0, MAX_SAVED_OBSERVATIONS).map((item) => ({
    ruleId: clean(item.ruleId, 100),
    title: clean(item.ruleId.replace(/_/g, " "), 240),
    summary: clean(item.explanation + " Suggested review: " + item.remediation, 3000),
    severityEstimate: (["LOW", "MEDIUM", "HIGH"].includes(item.impact) ? item.impact.toLowerCase() : "info"),
  }));
}

function dbStatus(code?: string) {
  if (code === "42501" || code === "PGRST116") return 403;
  if (code === "23514") return 429;
  if (code === "22023") return 400;
  return 503;
}

/**
 * Only specification import/inspection is executable here. No HTTP client, DNS,
 * socket, web passive transport or generic network job dispatcher is registered.
 */
export async function offlineAssessmentRoutes(app: FastifyInstance) {
  app.post("/v1/assessments/api-spec", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 3, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    reply.header("cache-control", "no-store");
    const input = startSchema.safeParse(request.body);
    if (!input.success) return reply.code(400).send({ error: "INVALID_ASSESSMENT_AUTHORIZATION_OR_SCOPE" });
    if (Buffer.byteLength(input.data.content, "utf8") > MAX_SPEC_BYTES)
      return reply.code(413).send({ error: "SPECIFICATION_TOO_LARGE" });
    if (!request.authUser) return reply.code(401).send({ error: "AUTHENTICATION_REQUIRED" });
    const userClient = createSupabaseForRequest(request, reply);
    if (!userClient) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const trusted = createTrustedSupabase();
    if (!trusted) return reply.code(503).send({ error: "TRUSTED_ASSESSMENT_BACKEND_NOT_CONFIGURED" });

    // User-context RLS read is an early denial. The database RPC independently
    // rechecks current ownership + role under a transaction on every transition.
    const { data: asset, error: assetError } = await userClient.from("assets")
      .select("id,organization_id,asset_kind,canonical_origin,verification_status,verification_expires_at")
      .eq("id", input.data.assetId).eq("organization_id", input.data.organizationId).single();
    if (assetError || !asset || asset.asset_kind !== "api")
      return reply.code(403).send({ error: "API_ASSET_ACCESS_DENIED" });
    if (asset.verification_status !== "verified" ||
       !asset.verification_expires_at || Date.parse(asset.verification_expires_at) <= Date.now())
      return reply.code(409).send({ error: "CURRENT_ASSET_OWNERSHIP_REQUIRED" });

    let inventory: Awaited<ReturnType<typeof importOfflineDocument>>;
    try {
      inventory = await importOfflineDocument(input.data.content);
      if (inventory.operations.length > MAX_OFFLINE_OPERATIONS) {
        return reply.code(422).send({ error: "OFFLINE_OPERATION_LIMIT_EXCEEDED" });
      }
    } catch {
      return reply.code(422).send({ error: "OFFLINE_SPECIFICATION_REJECTED" });
    }

    const scope = deterministicOfflineScope(input.data.organizationId, input.data.assetId,
      asset.canonical_origin, inventory.normalizedFingerprint);
    const actor = request.authUser.id;
    const { data: jobId, error: queueError } = await trusted.rpc("assessment_api_offline_queue", {
      p_org: input.data.organizationId,
      p_asset: input.data.assetId,
      p_actor: actor,
      p_scope: scope,
      p_fingerprint: inventory.normalizedFingerprint,
      p_format: inventory.format,
    });
    if (queueError || typeof jobId !== "string")
      return reply.code(dbStatus(queueError?.code)).send({ error: "ASSESSMENT_QUEUE_DENIED" });

    const { data: begun, error: beginError } = await trusted.rpc("assessment_api_offline_begin",
      { p_job: jobId, p_actor: actor });
    if (beginError || begun !== true)
      return reply.code(beginError ? dbStatus(beginError.code) : 409)
        .send({ error: "ASSESSMENT_EXECUTION_AUTHORIZATION_EXPIRED" });

    try {
      const detection = inventory.assessmentSource ? detectInventory(inventory) : null;
      const observations = boundedOfflineEvidence(detection?.observations ?? []);
      const warnings = inventory.metadata.warnings.slice(0, 20).map((text) => clean(text, 160));
      const coverage = {
        classification: detection ? "SPEC_ONLY" : "INVENTORY_ONLY",
        operationCount: inventory.operations.length,
        totalObservations: detection?.observations.length ?? 0,
        savedObservations: observations.length,
        truncated: (detection?.observations.length ?? 0) > MAX_SAVED_OBSERVATIONS,
        warnings,
        // Full rules not stored to keep the evidence payload bounded and non-sensitive.
        limitations: [
          "Document-derived observations only; no runtime vulnerabilities verified.",
          "No network request was sent to the API origin.",
          "Imported raw specification and credentials are not persisted.",
        ],
      };
      const { data: completed, error: completeError } = await trusted.rpc("assessment_api_offline_complete", {
        p_job: jobId, p_actor: actor, p_items: observations, p_coverage: coverage,
      });
      if (completeError || completed !== true)
        return reply.code(completeError ? dbStatus(completeError.code) : 409)
          .send({ error: "ASSESSMENT_RESULT_COMMIT_REJECTED" });
      return reply.code(201).send({
        jobId, organizationId: input.data.organizationId, assetId: input.data.assetId,
        state: "succeeded",
        source: { format: inventory.format, fingerprint: inventory.normalizedFingerprint },
        ...coverage, networkRequestsSent: 0, reviewRequired: true,
      });
    } catch {
      // A failed offline analyzer never leaves a job running indefinitely.
      // Sensitive document contents/errors are not logged.
      try {
        await trusted.rpc("assessment_api_offline_stop",
          { p_job: jobId, p_actor: actor, p_failed: true });
      } catch { /* Leave the persisted job for authorized recovery; never change an unrelated row. */ }
      return reply.code(503).send({ error: "OFFLINE_ASSESSMENT_FAILED" });
    }
  });

  app.get("/v1/assessments/api-spec", { preHandler: requireGoogleAal2 }, async (request, reply) => {
    const input = orgQuerySchema.safeParse(request.query);
    if (!input.success) return reply.code(400).send({ error: "INVALID_ORGANIZATION_ID" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const { data, error } = await client.from("assessment_jobs")
      .select("id,organization_id,asset_id,assessment_kind,job_state,source_format,source_fingerprint,scope_hash,authorization_at,requested_at,started_at,completed_at,observation_count,result_coverage")
      .eq("organization_id", input.data.organizationId).eq("assessment_kind", "api_spec_offline")
      .order("requested_at", { ascending: false }).limit(30);
    if (error) return reply.code(503).send({ error: "ASSESSMENT_HISTORY_UNAVAILABLE" });
    reply.header("cache-control", "no-store");
    return { jobs: data ?? [] };
  });

  app.get("/v1/assessments/api-spec/observations", {
    preHandler: requireGoogleAal2,
  }, async (request, reply) => {
    const input = jobQuerySchema.safeParse(request.query);
    if (!input.success) return reply.code(400).send({ error: "INVALID_ASSESSMENT_ID" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    // Both clauses are tenant-bound; the existing AAL2 RLS policies still apply.
    const { data, error } = await client.from("assessment_observations")
      .select("id,rule_id,title,summary,severity_estimate,review_state,created_at")
      .eq("organization_id", input.data.organizationId).eq("job_id", input.data.jobId)
      .order("created_at", { ascending: true }).limit(100);
    if (error) return reply.code(503).send({ error: "ASSESSMENT_OBSERVATIONS_UNAVAILABLE" });
    reply.header("cache-control", "no-store");
    return { observations: data ?? [] };
  });

  app.post("/v1/assessments/api-spec/cancel", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const input = stopSchema.safeParse(request.body);
    if (!input.success) return reply.code(400).send({ error: "INVALID_ASSESSMENT_ID" });
    if (!request.authUser) return reply.code(401).send({ error: "AUTHENTICATION_REQUIRED" });
    const client = createSupabaseForRequest(request, reply);
    const trusted = createTrustedSupabase();
    if (!client || !trusted) return reply.code(503).send({ error: "TRUSTED_ASSESSMENT_BACKEND_NOT_CONFIGURED" });
    // The signed user gets an RLS-constrained job lookup; the backend never
    // takes actor identity from request body or from an unverified session.
    const { data: job } = await client.from("assessment_jobs").select("id")
      .eq("id", input.data.jobId).eq("organization_id", input.data.organizationId).single();
    if (!job) return reply.code(403).send({ error: "ASSESSMENT_ACCESS_DENIED" });
    const { data: stopped, error } = await trusted.rpc("assessment_api_offline_stop",
      { p_job: input.data.jobId, p_actor: request.authUser.id, p_failed: false });
    if (error || stopped !== true) return reply.code(error ? dbStatus(error.code) : 409)
      .send({ error: "ASSESSMENT_CANCELLATION_REJECTED" });
    reply.header("cache-control", "no-store");
    return { cancelled: true };
  });
}
