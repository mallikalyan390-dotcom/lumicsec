/* Trusted development-only assessment-plan execution coordinator.
 * No Fastify route, production entrypoint, or public target transport uses this.
 * Only the explicitly confined local fixture runner may be supplied.
 */
import {createHmac,randomBytes,timingSafeEqual} from "node:crypto";
import {z} from "zod";
import {controlledResultSchema,
  type ControlledResult} from "./controlled-runtime-contract.js";
import {fixtureOrigin,type ControlledProfile} from "./controlled-runtime-broker.js";

const uuid=z.string().uuid();
const hex=z.string().regex(/^[a-f0-9]{64}$/);
const safePath=z.string().regex(/^\/(?!\/)[a-zA-Z0-9._~/-]{0,119}$/);
const origin=z.string().regex(/^https:\/\/[a-z0-9.-]{4,240}$/);
const snapshotSchema=z.strictObject({
  organizationId:uuid,assetId:uuid,planId:uuid,actorId:uuid,
  scopeHash:hex,origin,approvedPaths:z.array(safePath).min(1).max(6),
  profile:z.enum(["web_readonly","api_readonly"]),
  maxRequests:z.number().int().min(1).max(6),
  maxResponseBytes:z.number().int().min(1024).max(60000),
  maxTotalBytes:z.number().int().min(1024).max(240000),
  maxExecutionMs:z.number().int().min(1000).max(15000),
  proofVerifiedAt:z.string().datetime({offset:true}),
  proofExpiresAt:z.string().datetime({offset:true}),
  planExpiresAt:z.string().datetime({offset:true}),
});
export type PlanExecutionSnapshot=z.infer<typeof snapshotSchema>;
const ticketSchema=z.strictObject({
  version:z.literal("LUMICSEC_FIXTURE_TICKET_V1"),
  mode:z.literal("confined_fixture"),
  jobId:uuid,requestId:uuid,workerId:uuid,generation:z.number().int().min(1).max(3),
  issuedAt:z.number().int(),expiresAt:z.number().int(),
  nonce:hex,scope:snapshotSchema,
});
type TicketBody=z.infer<typeof ticketSchema>;
export type SignedFixtureTicket=Readonly<{body:string;mac:string}>;
export type PlanExecutionClaim=Readonly<{
  jobId:string;organizationId:string;assetId:string;planId:string;
  actorId:string;scopeHash:string;workerId:string;generation:number;
  leaseToken:string;
}>;
export type SecurityActor=Readonly<{
  id:string;organizationId:string;provider:"google";aal:"aal2";verifiedTotp:true;
  role:"owner"|"admin"|"analyst";
}>;
export type CurrentPlan=Readonly<{
  planId:string;organizationId:string;assetId:string;createdBy:string;
  assetKind:"website"|"api";origin:string;scopeHash:string;approvedPaths:readonly string[];
  profile:"web_readonly"|"api_readonly";state:"active"|"revoked";
  maxRequests:number;maxResponseBytes:number;maxTotalBytes:number;maxExecutionMs:number;
  proofVerifiedAt:string;proofExpiresAt:string;expiresAt:string;
  assetVerification:"verified"|"pending"|"revoked";
  assetOrigin:string;assetProofVerifiedAt:string;assetProofExpiresAt:string;
  actorMembership:"active"|"suspended";actorRole:"owner"|"admin"|"analyst"|"viewer";
}>;
export interface PlanExecutionStore {
  current(organizationId:string,planId:string,actorId:string):Promise<CurrentPlan|null>;
  enqueue(input:{snapshot:PlanExecutionSnapshot;requestId:string}):Promise<string>;
  claim(input:{jobId:string;workerId:string;scopeHash:string}):Promise<PlanExecutionClaim|null>;
  heartbeat(claim:PlanExecutionClaim):Promise<boolean>;
  complete(claim:PlanExecutionClaim,evidence:ControlledResult):Promise<boolean>;
  stop(claim:PlanExecutionClaim,code:"CANCELLED"|"FAILED"):Promise<void>;
  stopQueued(jobId:string):Promise<void>;
}
function deny(code:string):never{throw Error(code);}
export function planSnapshot(plan:CurrentPlan,actor:SecurityActor,nowMs=Date.now()):
  PlanExecutionSnapshot{
  if(!uuid.safeParse(actor.id).success||
     actor.provider!=="google"||actor.aal!=="aal2"||
     actor.verifiedTotp!==true||actor.organizationId!==plan.organizationId||
     plan.actorRole!==actor.role||
     plan.actorMembership!=="active")
    deny("PLAN_EXECUTION_ACTOR_DENIED");
  if(plan.state!=="active"||plan.assetVerification!=="verified"||
     plan.assetProofVerifiedAt!==plan.proofVerifiedAt||
     plan.assetOrigin!==plan.origin||
     Date.parse(plan.proofExpiresAt)<=nowMs||
     Date.parse(plan.assetProofExpiresAt)<=nowMs||
     Date.parse(plan.expiresAt)<=nowMs||
     Date.parse(plan.expiresAt)>Date.parse(plan.proofExpiresAt)||
     plan.assetKind!==(plan.profile==="web_readonly"?"website":"api"))
    deny("PLAN_EXECUTION_CURRENT_PROOF_DENIED");
  const scope=snapshotSchema.parse({
    organizationId:plan.organizationId,assetId:plan.assetId,
    planId:plan.planId,actorId:actor.id,
    scopeHash:plan.scopeHash,origin:plan.origin,
    approvedPaths:[...plan.approvedPaths],profile:plan.profile,
    maxRequests:plan.maxRequests,maxResponseBytes:plan.maxResponseBytes,
    maxTotalBytes:plan.maxTotalBytes,maxExecutionMs:plan.maxExecutionMs,
    proofVerifiedAt:plan.proofVerifiedAt,proofExpiresAt:plan.proofExpiresAt,
    planExpiresAt:plan.expiresAt,
  });
  if(new Set(scope.approvedPaths).size!==scope.approvedPaths.length||
     scope.approvedPaths.some(x=>x.includes("//")||/(^|\/)\.{1,2}(\/|$)/.test(x))||
     scope.maxTotalBytes<scope.maxResponseBytes)
    deny("PLAN_EXECUTION_SCOPE_DENIED");
  return scope;
}
const mac=(body:string,key:Buffer)=>
  createHmac("sha256",key).update(body,"utf8").digest("hex");
export function signFixtureTicket(
 scope:PlanExecutionSnapshot,jobId:string,requestId:string,workerId:string,
 generation:number,key:Buffer,nowMs=Date.now()):SignedFixtureTicket{
 if(key.length!==32)deny("PLAN_TICKET_KEY_REQUIRED");
 const ticket=ticketSchema.parse({
  version:"LUMICSEC_FIXTURE_TICKET_V1",mode:"confined_fixture",
  jobId,requestId,workerId,generation,issuedAt:nowMs,
  expiresAt:Math.min(nowMs+20_000,Date.parse(scope.planExpiresAt),
    Date.parse(scope.proofExpiresAt)),
  nonce:randomBytes(32).toString("hex"),scope,
 });
 if(ticket.expiresAt<=nowMs)deny("PLAN_TICKET_EXPIRED");
 const body=JSON.stringify(ticket);
 return {body,mac:mac(body,key)};
}
export function verifyFixtureTicket(
 signed:SignedFixtureTicket,key:Buffer,nowMs=Date.now()):TicketBody{
 if(key.length!==32||Buffer.byteLength(signed.body)>2200||
    !hex.safeParse(signed.mac).success)deny("PLAN_TICKET_INVALID");
 const expected=Buffer.from(mac(signed.body,key),"hex");
 if(!timingSafeEqual(expected,Buffer.from(signed.mac,"hex")))
   deny("PLAN_TICKET_SIGNATURE_INVALID");
 const ticket=ticketSchema.parse(JSON.parse(signed.body) as unknown);
 if(ticket.issuedAt>nowMs||ticket.expiresAt<=nowMs||
   ticket.expiresAt-ticket.issuedAt>20_000||
   ticket.expiresAt>Date.parse(ticket.scope.planExpiresAt)||
   ticket.expiresAt>Date.parse(ticket.scope.proofExpiresAt))
   deny("PLAN_TICKET_EXPIRED");
 return ticket;
}
/** One-shot, host-side ticket consumption. No HMAC key, Supabase token or
 * SQL lease token is ever passed to a Docker worker or its broker.
 * Database generation+hashed-lease fencing remains authoritative after restart.
 */
export function consumeFixtureTicket(
 signed:SignedFixtureTicket,key:Buffer,used:Set<string>,
 expected:Readonly<{jobId:string;requestId:string;workerId:string;
   generation:number;scope:PlanExecutionSnapshot}>,nowMs=Date.now(),
):TicketBody{
 const ticket=verifyFixtureTicket(signed,key,nowMs);
 if(ticket.jobId!==expected.jobId||ticket.requestId!==expected.requestId||
    ticket.workerId!==expected.workerId||
    ticket.generation!==expected.generation||
    JSON.stringify(ticket.scope)!==JSON.stringify(expected.scope))
   deny("PLAN_TICKET_SCOPE_DENIED");
 if(used.has(ticket.nonce))deny("PLAN_TICKET_REPLAY_DENIED");
 used.add(ticket.nonce);
 return ticket;
}
function sameSnapshot(a:PlanExecutionSnapshot,b:PlanExecutionSnapshot){
 return JSON.stringify(a)===JSON.stringify(b);
}
export async function executeAuthorizedControlledFixture(input:Readonly<{
 store:PlanExecutionStore;planId:string;organizationId:string;actor:SecurityActor;
 requestId:string;workerId:string;profile:ControlledProfile;
 signal:AbortSignal;
 runner:(args:{profile:ControlledProfile;mode:"web"|"api";
   scope:{jobId:string;organizationId:string;assetId:string;actorId:string;
     origin:string;scopeHash:string};signal:AbortSignal;
     authorized:PlanExecutionSnapshot;claimGeneration:number;
     workerId:string})=>Promise<ControlledResult>;
 now?:()=>number;
}>):Promise<Readonly<{jobId:string;observations:number;result:ControlledResult}>>{
 const now=input.now??Date.now;
 if(input.signal.aborted)deny("PLAN_EXECUTION_CANCELLED");
 if(!uuid.safeParse(input.requestId).success||!uuid.safeParse(input.workerId).success)
   deny("PLAN_EXECUTION_REQUEST_INVALID");
 const current=await input.store.current(input.organizationId,input.planId,input.actor.id);
 if(!current)deny("PLAN_EXECUTION_PLAN_NOT_FOUND");
 const scope=planSnapshot(current,input.actor,now());
 // Prevent any use against public/customer destinations, even if the plan is valid.
 if(scope.origin!==fixtureOrigin(input.profile)||
    (scope.profile==="web_readonly")!==input.profile.startsWith("web_"))
   deny("PLAN_EXECUTION_FIXTURE_ONLY");
 // This fixture implementation has only one controlled read path per mode.
 // Additional plan paths may be authorized, but each actually fetched path
 // MUST be explicitly present in the persisted consent snapshot.
 const requiredPath=scope.profile==="web_readonly"?"/":"/v1/accounts/owner";
 if(!scope.approvedPaths.includes(requiredPath))
   deny("PLAN_EXECUTION_ENDPOINT_NOT_APPROVED");
 const jobId=await input.store.enqueue({snapshot:scope,requestId:input.requestId});
 let claim:PlanExecutionClaim|null;
 try{
   if(input.signal.aborted)deny("PLAN_EXECUTION_CANCELLED");
   claim=await input.store.claim({jobId,workerId:input.workerId,scopeHash:scope.scopeHash});
 }catch(error){
   await input.store.stopQueued(jobId).catch(()=>undefined);
   throw error;
 }
 if(!claim||claim.jobId!==jobId||claim.planId!==scope.planId||
    claim.organizationId!==scope.organizationId||claim.assetId!==scope.assetId||
    claim.actorId!==scope.actorId||claim.scopeHash!==scope.scopeHash||
    claim.workerId!==input.workerId||claim.generation<1||
    claim.generation>2||!hex.safeParse(claim.leaseToken).success){
   await input.store.stopQueued(jobId).catch(()=>undefined);
   deny("PLAN_EXECUTION_CLAIM_DENIED");
 }
 const controller=new AbortController();
 const abort=()=>controller.abort();
 input.signal.addEventListener("abort",abort,{once:true});
 if(input.signal.aborted)controller.abort();
 const key=randomBytes(32),seenNonces=new Set<string>();
 const recheck=async()=>{
   if(controller.signal.aborted)deny("PLAN_EXECUTION_CANCELLED");
   const fresh=await input.store.current(input.organizationId,input.planId,input.actor.id);
   if(!fresh||!sameSnapshot(scope,planSnapshot(fresh,input.actor,now()))||
     !(await input.store.heartbeat(claim))){
     controller.abort();
     deny("PLAN_EXECUTION_AUTHORIZATION_REVOKED");
   }
 };
 let ping:ReturnType<typeof setInterval>|null=null;
 let ticking=false;
 try{
   await recheck();
   const signed=signFixtureTicket(scope,jobId,input.requestId,
     input.workerId,claim.generation,key,now());
   const verified=consumeFixtureTicket(signed,key,seenNonces,{
     jobId:claim.jobId,requestId:input.requestId,workerId:claim.workerId,
     generation:claim.generation,scope,
   },now());
   if(verified.scope.scopeHash!==scope.scopeHash)
     deny("PLAN_EXECUTION_TICKET_SCOPE_DENIED");
   ping=setInterval(()=>{
     if(ticking||controller.signal.aborted)return;
     ticking=true;
     void recheck().catch(()=>controller.abort()).finally(()=>{ticking=false;});
   },200);
   const result=await input.runner({
     profile:input.profile,mode:scope.profile==="web_readonly"?"web":"api",
     scope:{jobId:claim.jobId,organizationId:scope.organizationId,
       assetId:scope.assetId,actorId:scope.actorId,origin:scope.origin,
       scopeHash:scope.scopeHash},signal:controller.signal,
     authorized:verified.scope,claimGeneration:claim.generation,
     workerId:claim.workerId,
   });
   if(controller.signal.aborted)deny("PLAN_EXECUTION_CANCELLED");
   await recheck();
   const validated=controlledResultSchema.parse(result);
   if(validated.jobId!==jobId||validated.scopeHash!==scope.scopeHash||
      validated.report.scopeHash!==scope.scopeHash||
      validated.mode!==(scope.profile==="web_readonly"?"web":"api")||
      validated.report.classification!==(scope.profile==="web_readonly"?
        "PASSIVE_WEB_REVIEW":"RUNTIME_API_REVIEW")||
      validated.observations.some(o=>o.evidenceSource.paths.some(
        p=>!scope.approvedPaths.includes(p)))||
      validated.observations.length>60||
      Buffer.byteLength(JSON.stringify(validated))>120_000||
      validated.report.requests>scope.maxRequests||
      validated.report.bytes>scope.maxTotalBytes)
     deny("PLAN_EXECUTION_EVIDENCE_DENIED");
   if(ping){clearInterval(ping);ping=null;}
   if(!(await input.store.complete(claim,validated)))
     deny("PLAN_EXECUTION_RESULT_REJECTED");
   return {jobId,observations:validated.observations.length,result:validated};
 }catch(error){
   controller.abort();
   await input.store.stop(claim,input.signal.aborted?"CANCELLED":"FAILED").catch(()=>undefined);
   throw error;
 }finally{
   if(ping)clearInterval(ping);
   input.signal.removeEventListener("abort",abort);
   controller.abort();key.fill(0);
 }
}
