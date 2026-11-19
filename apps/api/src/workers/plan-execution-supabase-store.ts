/* Trusted controller only. Do not import from Fastify routes or frontend.
 * Privileged credential stays in this process; never passed to Docker.
 */
import {createTrustedSupabase} from "../lib/trusted-supabase.js";
import {runControlledRuntimeFixture} from "./controlled-runtime-runner.js";
import type {ControlledProfile} from "./controlled-runtime-broker.js";
import type {ControlledResult} from "./controlled-runtime-contract.js";
import {executeAuthorizedControlledFixture,
 type PlanExecutionStore,type PlanExecutionClaim,type CurrentPlan,type SecurityActor}
 from "./authorized-plan-controller.js";

export function createPlanExecutionSupabaseStore():PlanExecutionStore{
 const client=createTrustedSupabase();
 if(!client)throw Error("PLAN_FIXTURE_TRUSTED_DATABASE_NOT_CONFIGURED");
 const requireOk=<T>(data:T,error:{code?:string}|null):T=>{
  if(error)throw Error("PLAN_FIXTURE_TRUSTED_DATABASE_REJECTED");
  return data;
 };
 return {
  async current(organizationId,planId,actorId):Promise<CurrentPlan|null>{
   const {data,error}=await client.rpc("plan_fixture_current_snapshot",{
     p_org:organizationId,p_plan:planId,p_actor:actorId,
   });
   if(error)throw Error("PLAN_FIXTURE_CURRENT_SNAPSHOT_REJECTED");
   return data as CurrentPlan|null;
  },
  async enqueue({snapshot,requestId}){
   const {data,error}=await client.rpc("plan_fixture_enqueue",{
     p_org:snapshot.organizationId,p_plan:snapshot.planId,
     p_actor:snapshot.actorId,p_request:requestId,
   });
   return requireOk(data,error) as string;
  },
  async claim({jobId,workerId,scopeHash}){
   const {data,error}=await client.rpc("plan_fixture_claim",{
     p_job:jobId,p_worker:workerId,p_scope:scopeHash,
   });
   return requireOk(data,error) as PlanExecutionClaim|null;
  },
  async heartbeat(claim){
   const {data,error}=await client.rpc("plan_fixture_heartbeat",{
     p_job:claim.jobId,p_token:claim.leaseToken,p_generation:claim.generation,
   });
   return requireOk(data,error)===true;
  },
  async complete(claim,evidence){
   const {data,error}=await client.rpc("plan_fixture_complete",{
     p_job:claim.jobId,p_token:claim.leaseToken,p_generation:claim.generation,
     p_items:evidence.observations,p_report:evidence.report,
   });
   return requireOk(data,error)===true;
  },
  async stopQueued(jobId){
   const {data,error}=await client.rpc("plan_fixture_stop",{
     p_job:jobId,p_token:null,p_generation:0,p_code:"CANCELLED",
   });
   requireOk(data,error);
  },
  async stop(claim,code){
   const {data,error}=await client.rpc("plan_fixture_stop",{
     p_job:claim.jobId,p_token:claim.leaseToken,p_generation:claim.generation,p_code:code,
   });
   requireOk(data,error);
  },
 };
}
export async function runTrustedPlanFixture(input:Readonly<{
 planId:string;organizationId:string;actor:SecurityActor;
 requestId:string;workerId:string;profile:ControlledProfile;
 bundlePath:string;signal:AbortSignal;
 store?:PlanExecutionStore;
}>):Promise<Readonly<{jobId:string;observations:number;result:ControlledResult}>>{
 // Explicit, ephemeral local-development fixture only. No public URL accepted.
 return executeAuthorizedControlledFixture({
   store:input.store??createPlanExecutionSupabaseStore(),
   planId:input.planId,organizationId:input.organizationId,
   actor:input.actor,requestId:input.requestId,workerId:input.workerId,
   profile:input.profile,signal:input.signal,
   runner:async({profile,mode,scope,signal,authorized,
     claimGeneration,workerId})=>{
     const run=await runControlledRuntimeFixture({
       profile,mode,scope,bundlePath:input.bundlePath,signal,
       brokerIsolation:"confined_fixture",
       planScope:{
         approvedPaths:authorized.approvedPaths,maxRequests:authorized.maxRequests,
         maxResponseBytes:authorized.maxResponseBytes,
         maxTotalBytes:authorized.maxTotalBytes,
         maxExecutionMs:authorized.maxExecutionMs,
       },
       brokerClaim:{planId:authorized.planId,workerId,
         generation:claimGeneration,
         notAfterMs:Math.min(Date.parse(authorized.planExpiresAt),
           Date.parse(authorized.proofExpiresAt))},
     });
     if(run.brokerNetworkMode!=="none"||run.externalRequests!==0||
        run.requests>authorized.maxRequests||run.bytes>authorized.maxTotalBytes||
        run.requests!==run.result.report.requests||
        run.bytes!==run.result.report.bytes)
       throw Error("PLAN_FIXTURE_BROKER_ACCOUNTING_DENIED");
     return run.result;
   },
 });
}
