import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { detectInventory, importOfflineDocument } from "@lumicsec/api-security-engine";
import { apiSpecAssessmentRequestSchema, MAX_SPEC_BYTES } from "@lumicsec/validation";
import { requireGoogleAal2 } from "../lib/auth-guard.js";

function safeFilename(value: string | undefined): string | null {
  if (!value) {
    return null;
  }
  return value.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 120);
}

export async function apiSpecRoutes(app: FastifyInstance) {
  app.post("/v1/api-specs/assess", {
    preHandler: requireGoogleAal2,
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const parsed = apiSpecAssessmentRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({
        error: "INVALID_SPEC_REQUEST",
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.map(String),
          message: issue.message,
        })),
      });
    }

    if (Buffer.byteLength(parsed.data.content, "utf8") > MAX_SPEC_BYTES) {
      return reply.code(413).send({ error: "SPECIFICATION_TOO_LARGE" });
    }

    try {
      const inventory = await importOfflineDocument(parsed.data.content);
      const detection = inventory.assessmentSource ? detectInventory(inventory) : null;

      reply.header("cache-control", "no-store");
      return {
        runId: randomUUID(),
        classification: detection ? "SPEC_ONLY" : "INVENTORY_ONLY",
        source: {
          filename: safeFilename(parsed.data.filename),
          format: inventory.format,
          fingerprint: inventory.normalizedFingerprint,
        },
        operationCount: inventory.operations.length,
        findings: detection?.observations ?? [],
        coverage: detection?.coverage ?? [],
        warnings: inventory.metadata.warnings,
        limitations: [
          ...(detection?.limitations ?? ["Assessment rules are not qualified for this imported format."]),
          "No network requests were sent to the declared API servers.",
          "Runtime authentication, authorization, schema enforcement and exploitability remain UNKNOWN.",
        ],
        reviewRequired: true,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "SPECIFICATION_REJECTED";
      return reply.code(422).send({
        error: "SPECIFICATION_REJECTED",
        message: message.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 240),
      });
    }
  });
}
