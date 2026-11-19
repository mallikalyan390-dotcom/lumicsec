/* Reviewed IPC contract; no credentials, lease token, cookies or raw HTTP bodies.
 * JSONL messages are bounded and schema-validated by BOTH processes.
 */
import { z } from "zod";
const uuid = z.string().uuid();
const hex = z.string().regex(/^[a-f0-9]{64}$/);
const origin = z.string().max(250).regex(/^https:\/\/[a-z0-9.-]{4,240}$/);
export const MAX_WEB_IPC_INPUT = 2_048;
export const MAX_WEB_IPC_OUTPUT = 120_000;
export const WEB_IPC_VERSION = "WEB_READONLY_V1" as const;
export const webIpcStartSchema = z.strictObject({
  protocol: z.literal(WEB_IPC_VERSION), type: z.literal("START"),
  executionId: uuid,
  scope: z.strictObject({ jobId: uuid, organizationId: uuid, assetId: uuid,
    actorId: uuid, origin, scopeHash: hex }),
  // No alternate arbitrary target input. Only an offline test container can
  // activate these ephemeral fixtures, never the customer API.
  fixture: z.enum(["none", "insecure", "secure", "slow", "oversize", "redirect", "crash"]),
});
export type WebIpcStart = z.infer<typeof webIpcStartSchema>;
const sourceSchema = z.strictObject({
  nodeIds: z.array(z.string().regex(/^wdn_[a-f0-9]{24}$/)).max(4),
  fingerprints: z.array(hex).max(4),
  paths: z.array(z.string().max(160).regex(/^\/(?!\/)[^?#]*$/)
    .refine(value => [...value].every(ch => ch.charCodeAt(0) >= 32 && ch.charCodeAt(0) !== 127))).max(3),
});
const evidenceSchema = z.strictObject({
  ruleId: z.string().regex(/^P09\.[A-Z0-9._-]{3,95}$/),
  title: z.string().min(1).max(240),
  summary: z.string().min(1).max(3_000),
  remediation: z.string().min(1).max(2_000),
  limitation: z.string().min(1).max(1_000),
  severityEstimate: z.enum(["info", "low", "medium"]),
  classification: z.enum([
    "PASSIVE_OBSERVATION", "DETERMINISTIC_CONFIGURATION_SIGNAL", "INCONCLUSIVE",
  ]),
  evidenceSource: sourceSchema,
});
const reportSchema = z.strictObject({
  classification: z.literal("PASSIVE_WEB_REVIEW"),
  analysisVersion: z.literal("web-assessment-analysis-v1"),
  scopeHash: hex, snapshotFingerprint: hex,
  requests: z.number().int().min(1).max(6),
  fetched: z.number().int().min(1).max(6),
  bytes: z.number().int().min(0).max(240_000),
  failed: z.number().int().min(0).max(6),
  coverageState: z.enum(["BOUNDED", "PARTIAL", "INSUFFICIENT_EVIDENCE"]),
  candidateCount: z.number().int().min(0).max(120),
  observationCount: z.number().int().min(0).max(60),
  limitations: z.array(z.string().max(200)).max(12),
});
export const webIpcResultSchema = z.strictObject({
  protocol: z.literal(WEB_IPC_VERSION), type: z.literal("RESULT"),
  executionId: uuid, jobId: uuid, scopeHash: hex,
  report: reportSchema, observations: z.array(evidenceSchema).max(60),
});
export type WebIpcResult = z.infer<typeof webIpcResultSchema>;
export function parseWebIpcStart(text: string) {
  if (Buffer.byteLength(text) > MAX_WEB_IPC_INPUT) throw Error("WEB_IPC_INPUT_OVERSIZE");
  const parsed: unknown = JSON.parse(text);
  return webIpcStartSchema.parse(parsed);
}
export function parseWebIpcResult(text: string, request: WebIpcStart) {
  if (Buffer.byteLength(text) > MAX_WEB_IPC_OUTPUT) throw Error("WEB_IPC_OUTPUT_OVERSIZE");
  const payload: unknown = JSON.parse(text);
  const result = webIpcResultSchema.parse(payload);
  if (result.executionId !== request.executionId || result.jobId !== request.scope.jobId ||
    result.scopeHash !== request.scope.scopeHash ||
    result.report.scopeHash !== request.scope.scopeHash ||
    result.report.observationCount !== result.observations.length)
    throw Error("WEB_IPC_SCOPE_OR_COUNT_MISMATCH");
  if (result.observations.some(item =>
    item.evidenceSource.nodeIds.length === 0 ||
    item.evidenceSource.fingerprints.length === 0))
    throw Error("WEB_IPC_MISSING_EVIDENCE");
  return result;
}
