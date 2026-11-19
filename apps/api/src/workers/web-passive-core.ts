/* Unprivileged network worker: never import Supabase, OAuth, DB keys, or job leases.
 * This module processes only a bounded exact-origin scope already claimed by
 * an external trusted controller. The controller owns authorization and commits.
 */
import { createHash, randomUUID } from "node:crypto";
import { analyzeWebAssessmentSnapshot, crawlWebAssessment, DISCOVERY_DEFAULTS,
  type AnalysisSnapshot } from "@lumicsec/web-security-engine";
import { PublicPinnedWebTransport, WEB_READ_LIMITS, requireExactWebUrl } from "../lib/web-pinned-transport.js";
import { mapWebEvidence, type WebAssessmentEvidence,
  type WebAssessmentReport } from "./web-assessment-worker.js";

export type UnprivilegedWebScope = Readonly<{
  jobId: string; organizationId: string; assetId: string; actorId: string;
  origin: string; scopeHash: string;
}>;
export type UnprivilegedWebResult = Readonly<{
  report: WebAssessmentReport; observations: readonly WebAssessmentEvidence[];
}>;

export async function executeUnprivilegedWebRead(input: Readonly<{
  scope: UnprivilegedWebScope; transport?: PublicPinnedWebTransport; signal: AbortSignal;
}>): Promise<UnprivilegedWebResult> {
  const { scope, signal } = input;
  if (signal.aborted || !/^[a-f0-9]{64}$/.test(scope.scopeHash))
    throw Error("WEB_UNPRIVILEGED_SCOPE_DENIED");
  requireExactWebUrl(scope.origin + "/", scope.origin);
  let requests = 0, bytes = 0;
  let fatalRead: Error | null = null;
  const transport = input.transport ?? new PublicPinnedWebTransport();
  const discovery = await crawlWebAssessment({
    origin: scope.origin, scopeHash: scope.scopeHash,
    limits: { ...DISCOVERY_DEFAULTS,
      maxRequests: WEB_READ_LIMITS.maxRequests, maxBytes: WEB_READ_LIMITS.maxTotalBytes,
      maxResponseBytes: WEB_READ_LIMITS.maxResponseBytes,
      deadlineMs: WEB_READ_LIMITS.maxRuntimeMs,
      maxDepth: 1, maxNodes: 100, maxEdges: 150, maxParserBytes: 60_000 },
    signal,
    assertAuthorized: async url => {
      requireExactWebUrl(url, scope.origin);
      if (signal.aborted) throw Error("WEB_UNPRIVILEGED_CANCELLED");
    },
    read: async (url, options) => {
      if (signal.aborted || requests >= WEB_READ_LIMITS.maxRequests
        || bytes >= WEB_READ_LIMITS.maxTotalBytes) throw Error("WEB_UNPRIVILEGED_BUDGET");
      requests++;
      try {
        const response = await transport.read(scope.origin, url, {
          signal, maxBytes: Math.min(options.maxBytes, WEB_READ_LIMITS.maxTotalBytes - bytes),
        });
        bytes += response.bodyBytes.byteLength;
        if (signal.aborted) throw Error("WEB_UNPRIVILEGED_CANCELLED");
        return response;
      } catch (error) {
        fatalRead = error instanceof Error ? error : Error("WEB_UNPRIVILEGED_READ_FAILED");
        throw fatalRead;
      }
    },
  });
  if (fatalRead) throw fatalRead;
  if (signal.aborted || discovery.coverage.state === "CANCELLED" ||
    discovery.coverage.fetched === 0) throw Error("WEB_UNPRIVILEGED_INCONCLUSIVE");
  const snapshotFingerprint = createHash("sha256")
    .update(JSON.stringify([discovery.nodes,discovery.edges,discovery.coverage])).digest("hex");
  const snapshot: AnalysisSnapshot = {
    analysisId: randomUUID(), jobId: scope.jobId, organizationId: scope.organizationId,
    websiteId: scope.assetId, actorId: scope.actorId, origin: scope.origin,
    scopeHash: scope.scopeHash, snapshotFingerprint,
    coverageState: discovery.coverage.state,
    coverage: discovery.coverage as unknown as Record<string,unknown>,
    nodes: discovery.nodes, edges: discovery.edges,
  };
  const analysis = analyzeWebAssessmentSnapshot(snapshot);
  const observations = mapWebEvidence(analysis.observations, discovery.nodes);
  const report: WebAssessmentReport = {
    classification: "PASSIVE_WEB_REVIEW", analysisVersion: analysis.analyzerVersion,
    scopeHash: scope.scopeHash, snapshotFingerprint,
    requests, bytes, failed: discovery.coverage.failed, fetched: discovery.coverage.fetched,
    coverageState: analysis.coverageState, candidateCount: analysis.candidates.length,
    observationCount: observations.length,
    limitations: ["Passive observations, not confirmed vulnerabilities.",
      "Credential-free GET-only within a bounded isolated execution namespace.",
      ...discovery.coverage.limitations.slice(0,8)],
  };
  return { report, observations };
}
