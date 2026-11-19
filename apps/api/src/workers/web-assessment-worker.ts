/* Deliberately not imported by the Fastify customer server.
 * Only an isolated worker/fixture harness may run this module. Public scanning disabled.
 */
import { createHash, randomUUID } from "node:crypto";
import { analyzeWebAssessmentSnapshot, crawlWebAssessment, DISCOVERY_DEFAULTS,
  type AnalysisSnapshot, type SecurityObservation } from "@lumicsec/web-security-engine";
import { PublicPinnedWebTransport, WEB_READ_LIMITS, requireExactWebUrl } from "../lib/web-pinned-transport.js";

export type WebWorkerClaim = Readonly<{
  jobId: string; organizationId: string; assetId: string; actorId: string;
  origin: string; scopeHash: string; token: string; generation: number;
}>;
export type WebAssessmentEvidence = Readonly<{
  ruleId: string; title: string; summary: string; remediation: string; limitation: string;
  severityEstimate: "info" | "low" | "medium";
  classification: "PASSIVE_OBSERVATION" | "DETERMINISTIC_CONFIGURATION_SIGNAL" | "INCONCLUSIVE";
  evidenceSource: Readonly<{ nodeIds: readonly string[]; fingerprints: readonly string[]; paths: readonly string[] }>;
}>;
export type WebAssessmentReport = Readonly<{
  classification: "PASSIVE_WEB_REVIEW"; analysisVersion: string; scopeHash: string;
  snapshotFingerprint: string; requests: number; fetched: number; bytes: number;
  failed: number; coverageState: string; candidateCount: number;
  observationCount: number; limitations: readonly string[];
}>;
export interface WebWorkerStore {
  claim(input: Readonly<{ jobId: string; workerId: string; scopeHash: string }>): Promise<WebWorkerClaim | null>;
  heartbeat(claim: WebWorkerClaim): Promise<boolean>;
  complete(claim: WebWorkerClaim, evidence: readonly WebAssessmentEvidence[], report: WebAssessmentReport): Promise<boolean>;
  stop(claim: WebWorkerClaim, failed: boolean): Promise<boolean>;
}
export type WebWorkerResult = Readonly<{ jobId: string; state: "succeeded";
  report: WebAssessmentReport; observations: readonly WebAssessmentEvidence[] }>;

export function mapWebEvidence(items: readonly SecurityObservation[],
  sources: readonly { id: string; path: string }[] = []): WebAssessmentEvidence[] {
  const pathById = new Map(sources.map(source => [source.id, source.path]));
  return items.filter(item => ["RISK_SIGNAL", "REVIEW_REQUIRED"].includes(item.outcome))
    .slice(0, 60).map(item => ({
      ruleId: item.ruleId.slice(0, 100), title: item.title.slice(0, 240),
      summary: item.explanation.slice(0, 3000), remediation: item.remediation.slice(0, 2000),
      limitation: (item.limitation || "Passive signal, not confirmed exploitability").slice(0, 1000),
      severityEstimate: item.severity.toLowerCase() as "info" | "low" | "medium",
      classification: item.evidenceStrength === "DETERMINISTIC_CONFIGURATION_SIGNAL"
        ? "DETERMINISTIC_CONFIGURATION_SIGNAL" : item.evidenceStrength === "PASSIVE_OBSERVATION"
          ? "PASSIVE_OBSERVATION" : "INCONCLUSIVE",
      evidenceSource: { nodeIds: item.sourceNodeIds.slice(0, 4),
        fingerprints: item.sourceFingerprints.slice(0, 4),
        paths: item.sourceNodeIds.slice(0, 3)
          .flatMap(id => {
            const path = pathById.get(id);
            return path && path.startsWith("/") && !path.includes("?") && !path.includes("#")
              ? [path.slice(0, 160)] : [];
          }),
      },
    }));
}

export async function executeClaimedWebAssessment(input: Readonly<{
  jobId: string; scopeHash: string; store: WebWorkerStore;
  transport?: PublicPinnedWebTransport; signal?: AbortSignal; workerId?: string;
}>): Promise<WebWorkerResult> {
  const claim = await input.store.claim({
    jobId: input.jobId, workerId: input.workerId ?? randomUUID(), scopeHash: input.scopeHash,
  });
  if (!claim) throw Error("WEB_WORKER_ADMISSION_DENIED");
  const controller = new AbortController();
  const abort = () => controller.abort();
  input.signal?.addEventListener("abort", abort, { once: true });
  if (input.signal?.aborted) abort();
  const deadline = setTimeout(abort, WEB_READ_LIMITS.maxRuntimeMs);
  let inFlight: Promise<void> | null = null;
  let revoked = false;
  const heartbeat = async () => {
    if (controller.signal.aborted) throw Error("WEB_AUTHORIZATION_LOST");
    if (inFlight) return inFlight;
    const pending = (async () => {
      try {
        if (!await input.store.heartbeat(claim)) { revoked = true; abort(); }
      } catch { revoked = true; abort(); }
    })();
    inFlight = pending;
    try { await pending; } finally { inFlight = null; }
  };
  const pulse = setInterval(() => { void heartbeat(); }, 750);
  let requests = 0, bytes = 0;
  let fatalRead: Error | null = null;
  const transport = input.transport ?? new PublicPinnedWebTransport();
  try {
    if (claim.jobId !== input.jobId || claim.scopeHash !== input.scopeHash ||
      !/^[a-f0-9]{64}$/.test(claim.scopeHash) ||
      !/^[a-f0-9]{64}$/.test(claim.token) || claim.generation < 1 || claim.generation > 2)
      throw Error("WEB_CLAIM_INVALID");
    requireExactWebUrl(claim.origin + "/", claim.origin);
    await heartbeat();
    if (revoked || controller.signal.aborted) throw Error("WEB_AUTHORIZATION_LOST");
    const discovery = await crawlWebAssessment({
      origin: claim.origin, scopeHash: claim.scopeHash,
      limits: { ...DISCOVERY_DEFAULTS, maxRequests: WEB_READ_LIMITS.maxRequests,
        maxBytes: WEB_READ_LIMITS.maxTotalBytes, maxResponseBytes: WEB_READ_LIMITS.maxResponseBytes,
        deadlineMs: WEB_READ_LIMITS.maxRuntimeMs, maxDepth: 1,
        maxNodes: 100, maxEdges: 150, maxParserBytes: 60_000 },
      signal: controller.signal,
      assertAuthorized: async url => {
        requireExactWebUrl(url, claim.origin);
        await heartbeat();
        if (revoked || controller.signal.aborted) throw Error("WEB_AUTHORIZATION_LOST");
      },
      read: async (url, opts) => {
        if (requests >= WEB_READ_LIMITS.maxRequests || bytes >= WEB_READ_LIMITS.maxTotalBytes)
          throw Error("WEB_REQUEST_BUDGET");
        requests++;
        try {
          const response = await transport.read(claim.origin, url, { signal: controller.signal,
            maxBytes: Math.min(opts.maxBytes, WEB_READ_LIMITS.maxTotalBytes - bytes) });
          bytes += response.bodyBytes.byteLength;
          await heartbeat();
          if (revoked || controller.signal.aborted) throw Error("WEB_AUTHORIZATION_LOST");
          return response;
        } catch (reason) {
          fatalRead = reason instanceof Error ? reason : Error("WEB_READ_FAILED");
          throw fatalRead;
        }
      },
    });
    if (fatalRead) throw fatalRead;
    if (revoked || controller.signal.aborted || discovery.coverage.state === "CANCELLED")
      throw Error("WEB_AUTHORIZATION_LOST");
    if (discovery.coverage.fetched === 0) throw Error("WEB_NO_OBSERVED_RESPONSE");
    const snapshotFingerprint = createHash("sha256")
      .update(JSON.stringify([discovery.nodes, discovery.edges, discovery.coverage])).digest("hex");
    const snapshot: AnalysisSnapshot = {
      analysisId: randomUUID(), jobId: claim.jobId, organizationId: claim.organizationId,
      websiteId: claim.assetId, actorId: claim.actorId, origin: claim.origin,
      scopeHash: claim.scopeHash, snapshotFingerprint, coverageState: discovery.coverage.state,
      coverage: discovery.coverage as unknown as Record<string, unknown>,
      nodes: discovery.nodes, edges: discovery.edges,
    };
    const analysis = analyzeWebAssessmentSnapshot(snapshot);
    const observations = mapWebEvidence(analysis.observations, discovery.nodes);
    const report: WebAssessmentReport = {
      classification: "PASSIVE_WEB_REVIEW", analysisVersion: analysis.analyzerVersion,
      scopeHash: claim.scopeHash, snapshotFingerprint,
      requests, fetched: discovery.coverage.fetched, bytes, failed: discovery.coverage.failed,
      coverageState: analysis.coverageState, candidateCount: analysis.candidates.length,
      observationCount: observations.length,
      limitations: ["Passive signals only, not confirmed vulnerabilities.",
        "GET-only; no user credentials, cookies, browser execution or active exploitation.",
        ...discovery.coverage.limitations.slice(0, 8)],
    };
    await heartbeat();
    if (revoked || controller.signal.aborted) throw Error("WEB_AUTHORIZATION_LOST");
    if (!await input.store.complete(claim, observations, report)) throw Error("WEB_RESULT_COMMIT_DENIED");
    return { jobId: claim.jobId, state: "succeeded", report, observations };
  } catch (error) {
    // DB stop is fenced; a stale token cannot terminate a replacement worker.
    await input.store.stop(claim, true).catch(() => false);
    throw error;
  } finally {
    clearInterval(pulse); clearTimeout(deadline);
    input.signal?.removeEventListener("abort", abort);
    abort();
  }
}
