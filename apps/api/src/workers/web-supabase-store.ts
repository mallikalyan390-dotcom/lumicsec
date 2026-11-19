import { createTrustedSupabase } from "../lib/trusted-supabase.js";
import type { WebAssessmentEvidence, WebAssessmentReport,
  WebWorkerClaim, WebWorkerStore } from "./web-assessment-worker.js";

/** A separate worker process only; never mounted in the Fastify router. */
export function createWebWorkerSupabaseStore(): WebWorkerStore {
  const supabase = createTrustedSupabase();
  if (!supabase) throw Error("WEB_WORKER_TRUSTED_CREDENTIAL_MISSING");
  const mustSucceed = <T>(data: T, error: { code?: string } | null): T => {
    if (error) throw Error("WEB_WORKER_DATABASE_REJECTED");
    return data;
  };
  return {
    async claim({ jobId, workerId, scopeHash }) {
      const { data, error } = await supabase.rpc("web_assessment_claim",
        { p_job: jobId, p_worker: workerId, p_scope: scopeHash });
      const claim = mustSucceed(data, error) as WebWorkerClaim | null;
      if (!claim) return null;
      if (typeof claim.token !== "string" || claim.jobId !== jobId ||
        claim.scopeHash !== scopeHash || claim.generation < 1 || claim.generation > 2)
        throw Error("WEB_WORKER_CLAIM_CONTRACT_INVALID");
      return claim;
    },
    async heartbeat(claim: WebWorkerClaim) {
      const { data, error } = await supabase.rpc("web_assessment_heartbeat",
        { p_job: claim.jobId, p_token: claim.token, p_generation: claim.generation });
      return mustSucceed(data, error) === true;
    },
    async complete(claim: WebWorkerClaim, evidence: readonly WebAssessmentEvidence[],
      report: WebAssessmentReport) {
      const { data, error } = await supabase.rpc("web_assessment_complete",
        { p_job: claim.jobId, p_token: claim.token, p_generation: claim.generation,
          p_items: evidence, p_report: report });
      return mustSucceed(data, error) === true;
    },
    async stop(claim: WebWorkerClaim, failed: boolean) {
      const { data, error } = await supabase.rpc("web_assessment_stop",
        { p_job: claim.jobId, p_actor: claim.actorId, p_token: claim.token,
          p_generation: claim.generation, p_failed: failed });
      return mustSucceed(data, error) === true;
    },
  };
}
