import { createHash } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { requireGoogleAal2 } from "../lib/auth-guard.js";
import { createSupabaseForRequest } from "../lib/supabase.js";
import { createTrustedSupabase } from "../lib/trusted-supabase.js";

const uuid = z.string().uuid();
const orgSchema = z.object({ organizationId: uuid }).strict();
const jobSchema = orgSchema.extend({ jobId: uuid }).strict();
const queueSchema = orgSchema.extend({
  assetId: uuid, requestId: uuid,
  authorization: z.literal("I_HAVE_EXPLICIT_PERMISSION_TO_PASSIVELY_REVIEW_THIS_OWNED_WEBSITE"),
}).strict();

/** Server-side deterministic scope contract. Browser cannot authorize a larger URL. */
export function authorizedWebScope(org: string, asset: string, origin: string) {
  return createHash("sha256").update(JSON.stringify([
    "lumicsec-web-passive-readonly-v1", org, asset, origin, "GET", 6, 240000,
  ])).digest("hex");
}
export const PUBLIC_WEB_SCANNING_ENABLED = false as const;

/** No caller or environment variable may enable public customer Web traffic.
 * The exact scope/DB queue API can be qualified separately with synthetic fixtures.
 */
export async function authorizedWebAssessmentRoutes(app: FastifyInstance) {
  app.post("/v1/assessments/web", {
    preHandler: requireGoogleAal2, config: { rateLimit: { max: 2, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    reply.header("cache-control", "no-store");
    const parsed = queueSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "INVALID_WEB_AUTHORIZATION_OR_SCOPE" });
    // Hard disabled in customer-facing product until independent hosted worker
    // qualification + explicit founder approval. No scan or queue created.
    return reply.code(423).send({
      error: "CUSTOMER_WEB_EXECUTION_NOT_APPROVED",
      scanningEnabled: PUBLIC_WEB_SCANNING_ENABLED,
      explanation: "Only isolated, synthetic worker qualification is enabled.",
    });
  });

  app.get("/v1/assessments/web", { preHandler: requireGoogleAal2 }, async (request, reply) => {
    reply.header("cache-control", "no-store");
    const parsed = orgSchema.safeParse(request.query);
    if (!parsed.success) return reply.code(400).send({ error: "INVALID_ORGANIZATION_ID" });
    const client = createSupabaseForRequest(request, reply);
    if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    const { data, error } = await client.from("assessment_jobs")
      .select("id,organization_id,asset_id,job_state,scope_hash,requested_at,started_at,completed_at,authorization_at,web_origin,web_report,web_error_code,observation_count")
      .eq("organization_id", parsed.data.organizationId)
      .eq("assessment_kind", "web_passive").order("requested_at", { ascending: false }).limit(30);
    if (error) return reply.code(503).send({ error: "WEB_HISTORY_UNAVAILABLE" });
    return { jobs: data ?? [], scanningEnabled: PUBLIC_WEB_SCANNING_ENABLED };
  });

  app.get("/v1/assessments/web/observations", { preHandler: requireGoogleAal2 },
    async (request, reply) => {
      reply.header("cache-control", "no-store");
      const parsed = jobSchema.safeParse(request.query);
      if (!parsed.success) return reply.code(400).send({ error: "INVALID_ASSESSMENT_ID" });
      const client = createSupabaseForRequest(request, reply);
      if (!client) return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
      const { data, error } = await client.from("assessment_observations")
        .select("id,rule_id,title,summary,severity_estimate,review_state,observation_classification,evidence_source,remediation,limitation,created_at")
        .eq("organization_id", parsed.data.organizationId)
        .eq("job_id", parsed.data.jobId)
        .order("created_at", { ascending: true }).limit(60);
      if (error) return reply.code(503).send({ error: "WEB_EVIDENCE_UNAVAILABLE" });
      return { observations: data ?? [] };
    });

  app.post("/v1/assessments/web/cancel", {
    preHandler: requireGoogleAal2, config: { rateLimit: { max: 6, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    reply.header("cache-control", "no-store");
    const parsed = jobSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "INVALID_ASSESSMENT_ID" });
    if (!request.authUser) return reply.code(401).send({ error: "AUTHENTICATION_REQUIRED" });
    const client = createSupabaseForRequest(request, reply);
    const trusted = createTrustedSupabase();
    if (!client || !trusted) return reply.code(503).send({ error: "TRUSTED_WEB_WORKER_NOT_CONFIGURED" });
    const { data: job, error: lookupError } = await client.from("assessment_jobs").select("id")
      .eq("id", parsed.data.jobId).eq("organization_id", parsed.data.organizationId)
      .eq("assessment_kind", "web_passive").single();
    if (!job || lookupError) return reply.code(403).send({ error: "WEB_JOB_ACCESS_DENIED" });
    const { data: stopped, error } = await trusted.rpc("web_assessment_stop", {
      p_job: parsed.data.jobId, p_actor: request.authUser.id,
      p_token: null, p_generation: null, p_failed: false,
    });
    if (error || stopped !== true)
      return reply.code(error?.code === "42501" ? 403 : 409)
        .send({ error: "WEB_CANCELLATION_DENIED" });
    return { cancelled: true };
  });
}
