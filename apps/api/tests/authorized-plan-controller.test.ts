import {createHmac,randomBytes,randomUUID} from "node:crypto";
import {describe,it,expect,vi} from "vitest";
import {fixtureOrigin,type ControlledProfile} from "../src/workers/controlled-runtime-broker.js";
import {executeAuthorizedControlledFixture,planSnapshot,signFixtureTicket,
 verifyFixtureTicket,consumeFixtureTicket,type CurrentPlan,type PlanExecutionStore,type SecurityActor,
 type PlanExecutionClaim} from "../src/workers/authorized-plan-controller.js";
import type {ControlledResult} from "../src/workers/controlled-runtime-contract.js";

const org="00000000-0000-4000-8000-000000000011";
const asset="00000000-0000-4000-8000-000000000022";
const user="00000000-0000-4000-8000-000000000033";
const planId="00000000-0000-4000-8000-000000000044";
const job="00000000-0000-4000-8000-000000000055";
const worker="00000000-0000-4000-8000-000000000066";
const hash="a".repeat(64);
const now=Date.now();
const before=new Date(now-10_000).toISOString();
const after=new Date(now+60_000).toISOString();
const actor:SecurityActor={
 id:user,organizationId:org,provider:"google",aal:"aal2",verifiedTotp:true,role:"owner",
};
function plan(profile:ControlledProfile="web_insecure"):CurrentPlan{
 const isWeb=profile.startsWith("web_");
 return {
  planId,organizationId:org,assetId:asset,createdBy:user,
  assetKind:isWeb?"website":"api",origin:fixtureOrigin(profile),
  scopeHash:hash,approvedPaths:["/"],profile:isWeb?"web_readonly":"api_readonly",
  state:"active",maxRequests:isWeb?1:3,maxResponseBytes:60000,
  maxTotalBytes:240000,maxExecutionMs:15000,
  proofVerifiedAt:before,proofExpiresAt:after,expiresAt:after,
  assetVerification:"verified",assetOrigin:fixtureOrigin(profile),
  assetProofVerifiedAt:before,assetProofExpiresAt:after,
  actorMembership:"active",actorRole:"owner",
 };
}
const claim:PlanExecutionClaim={
 jobId:job,planId,organizationId:org,assetId:asset,actorId:user,scopeHash:hash,
 workerId:worker,generation:1,leaseToken:"b".repeat(64),
};
function store(current=plan()){
 return {
  current:vi.fn(async()=>current as CurrentPlan|null),
  enqueue:vi.fn(async()=>job),
  claim:vi.fn(async()=>claim as PlanExecutionClaim|null),
  heartbeat:vi.fn(async()=>true),
  complete:vi.fn(async()=>true),
  stop:vi.fn(async()=>undefined),
  stopQueued:vi.fn(async()=>undefined),
 };
}
function webResult():ControlledResult{
 return {
  protocol:"CONTROLLED_RUNTIME_V1",type:"RESULT",
  executionId:randomUUID(),jobId:job,scopeHash:hash,mode:"web",
  report:{
    classification:"PASSIVE_WEB_REVIEW",analysisVersion:"web-assessment-analysis-v1",
    scopeHash:hash,snapshotFingerprint:"c".repeat(64),
    requests:1,fetched:1,bytes:200,failed:0,
    coverageState:"BOUNDED",candidateCount:1,observationCount:0,
    limitations:[],
  },
  observations:[],
 };
}
const params=(s=store(),profile:ControlledProfile="web_insecure")=>({
 store:s as PlanExecutionStore,planId,organizationId:org,actor,
 requestId:randomUUID(),workerId:worker,profile,signal:new AbortController().signal,
 runner:vi.fn(async()=>webResult()),
});
describe("signed, expiring, fixture-only plan controller",()=>{
 it("binds current AAL2, organization, proof, origin, budgets in immutable snapshot",()=>{
  const scope=planSnapshot(plan(),actor,now);
  expect(scope).toMatchObject({organizationId:org,planId,assetId:asset,
    actorId:user,scopeHash:hash,maxRequests:1});
 });
 it.each(["viewer","analyst"] as const)("rejects forged %s role mismatch",role=>{
  expect(()=>planSnapshot(plan(),{...actor,role},now)).toThrow("PLAN_EXECUTION_ACTOR_DENIED");
 });
 it("denies AAL1/non-Google even if caller forges application data",()=>{
  expect(()=>planSnapshot(plan(),{...actor,aal:"aal1"} as never,now))
    .toThrow("PLAN_EXECUTION_ACTOR_DENIED");
  expect(()=>planSnapshot(plan(),{...actor,provider:"email"} as never,now))
    .toThrow("PLAN_EXECUTION_ACTOR_DENIED");
 });
 it.each(["revoked","pending"] as const)("denies invalid current ownership: %s",status=>{
  expect(()=>planSnapshot({...plan(),assetVerification:status},actor,now))
    .toThrow("PLAN_EXECUTION_CURRENT_PROOF_DENIED");
 });
 it("denies expiry, proof rotation, origin changes and revoked plan",()=>{
  for(const change of [
   {state:"revoked"},{proofVerifiedAt:new Date(now-40000).toISOString()},
   {assetOrigin:"https://elsewhere.example"},{expiresAt:before},
  ]){
   expect(()=>planSnapshot({...plan(),...change} as CurrentPlan,actor,now)).toThrow();
  }
 });
 it("HMAC ticket has strict expiry, cannot be forged, extended or replayed after expiry",()=>{
  const key=randomBytes(32),scope=planSnapshot(plan(),actor,now);
  const signed=signFixtureTicket(scope,job,randomUUID(),worker,1,key,now);
  expect(verifyFixtureTicket(signed,key,now+3)).toMatchObject({jobId:job,
    mode:"confined_fixture",scope});
  expect(()=>verifyFixtureTicket(signed,randomBytes(32),now)).toThrow();
  expect(()=>verifyFixtureTicket(signed,key,now+20001)).toThrow("PLAN_TICKET_EXPIRED");
  const bad=signed.body.replace(job,asset);
  expect(()=>verifyFixtureTicket({...signed,body:bad},key,now)).toThrow();
  expect(signed.body).not.toContain("leaseToken");
 });
 it("refuses arbitrary public origins before any DB enqueue",async()=>{
  const s=store({...plan(),origin:"https://real.example",
    assetOrigin:"https://real.example"});
  const p=params(s);
  await expect(executeAuthorizedControlledFixture(p)).rejects
    .toThrow("PLAN_EXECUTION_FIXTURE_ONLY");
  expect(s.enqueue).not.toHaveBeenCalled();
 });
 it("refuses stale claim identity and does not call worker",async()=>{
  const s=store();s.claim.mockResolvedValue({...claim,organizationId:randomUUID()});
  const p=params(s);
  await expect(executeAuthorizedControlledFixture(p)).rejects
    .toThrow("PLAN_EXECUTION_CLAIM_DENIED");
  expect(p.runner).not.toHaveBeenCalled();
 });
 it("runs controlled fixture and completes only with valid scoped evidence",async()=>{
  const s=store();const p=params(s);
  const out=await executeAuthorizedControlledFixture(p);
  expect(out).toMatchObject({jobId:job,observations:0});
  expect(s.heartbeat).toHaveBeenCalled();
  expect(s.complete).toHaveBeenCalledTimes(1);
  expect(s.stop).not.toHaveBeenCalled();
 });
 it("rejects forged result tenant/job scope and never persists",async()=>{
  const s=store();const p=params(s);
  p.runner.mockResolvedValue({...webResult(),jobId:randomUUID()});
  await expect(executeAuthorizedControlledFixture(p)).rejects
    .toThrow("PLAN_EXECUTION_EVIDENCE_DENIED");
  expect(s.complete).not.toHaveBeenCalled();
  expect(s.stop).toHaveBeenCalledTimes(1);
 });
 it("rejects revoked plan after worker returns, discarding evidence",async()=>{
  const s=store();const p=params(s);
  p.runner.mockImplementation(async()=>{
   s.current.mockResolvedValueOnce({...plan(),state:"revoked"});
   return webResult();
  });
  await expect(executeAuthorizedControlledFixture(p)).rejects.toThrow();
  expect(s.complete).not.toHaveBeenCalled();
  expect(s.stop).toHaveBeenCalledTimes(1);
 });
 it("cancellation before enqueue prevents any worker effect",async()=>{
  const s=store();const ctl=new AbortController();ctl.abort();
  const p={...params(s),signal:ctl.signal};
  await expect(executeAuthorizedControlledFixture(p)).rejects
    .toThrow("PLAN_EXECUTION_CANCELLED");
  expect(s.enqueue).not.toHaveBeenCalled();
 });
 it("failed worker cannot fabricate completed evidence",async()=>{
  const s=store();const p=params(s);
  p.runner.mockRejectedValue(Error("CONFINED_BROKER_UNAVAILABLE"));
  await expect(executeAuthorizedControlledFixture(p)).rejects
    .toThrow("CONFINED_BROKER_UNAVAILABLE");
  expect(s.complete).not.toHaveBeenCalled();
  expect(s.stop).toHaveBeenCalledTimes(1);
 });
 it("consumes a signed lease-bound ticket at most once in the trusted coordinator",()=>{
   const key=randomBytes(32),scope=planSnapshot(plan(),actor,now);
   const id=randomUUID(),signed=signFixtureTicket(scope,job,id,worker,1,key,now);
   const used=new Set<string>();
   const expected={jobId:job,requestId:id,workerId:worker,generation:1,scope};
   expect(consumeFixtureTicket(signed,key,used,expected,now+5).jobId).toBe(job);
   expect(()=>consumeFixtureTicket(signed,key,used,expected,now+6))
     .toThrow("PLAN_TICKET_REPLAY_DENIED");
   expect(()=>consumeFixtureTicket(signed,key,new Set(),{
     ...expected,jobId:randomUUID()},now+5)).toThrow("PLAN_TICKET_SCOPE_DENIED");
   expect(()=>consumeFixtureTicket(signed,key,new Set(),expected,now+20_001))
     .toThrow("PLAN_TICKET_EXPIRED");
 });
 it("no enqueue unless actual Web/API fixture endpoint is consented",async()=>{
   for(const [profile,paths] of [
     ["web_insecure",["/documentation"]],["api_insecure",["/v1/health"]],
   ] as const){
     const s=store({...plan(profile),approvedPaths:[...paths]});
     await expect(executeAuthorizedControlledFixture(params(s,profile))).rejects
       .toThrow("PLAN_EXECUTION_ENDPOINT_NOT_APPROVED");
     expect(s.enqueue).not.toHaveBeenCalled();
   }
 });
 it("failed or invalid claim fences and cancels only queued job",async()=>{
   const s=store();s.claim.mockResolvedValue(null);
   const p=params(s);
   await expect(executeAuthorizedControlledFixture(p)).rejects
     .toThrow("PLAN_EXECUTION_CLAIM_DENIED");
   expect(s.stopQueued).toHaveBeenCalledWith(job);
   expect(p.runner).not.toHaveBeenCalled();
 });
 it("claim RPC failure attempts safe queued cleanup",async()=>{
   const s=store();s.claim.mockRejectedValue(Error("SQL_CLAIM_UNAVAILABLE"));
   await expect(executeAuthorizedControlledFixture(params(s))).rejects
     .toThrow("SQL_CLAIM_UNAVAILABLE");
   expect(s.stopQueued).toHaveBeenCalledWith(job);
 });
 it("runner receives exact signed consent budgets instead of arbitrary requested paths",async()=>{
   const s=store();const p=params(s);
   await executeAuthorizedControlledFixture(p);
   const arg=p.runner.mock.calls[0]?.[0] as {authorized: {approvedPaths:string[],
     maxRequests:number,maxResponseBytes:number,maxTotalBytes:number}}|undefined;
   expect(arg?.authorized).toMatchObject({approvedPaths:["/"],maxRequests:1,
     maxResponseBytes:60000,maxTotalBytes:240000});
 });
 it("denies forged observation source outside the approved endpoint",async()=>{
   const s=store();const p=params(s);
   const result=webResult();
   result.observations.push({
     ruleId:"P09.HSTS.ABSENT",title:"Out of scope",summary:"synthetic",
     severityEstimate:"low",classification:"DETERMINISTIC_CONFIGURATION_SIGNAL",
     remediation:"Review",limitation:"Synthetic only",
     evidenceSource:{paths:["/admin"],fingerprints:["c".repeat(64)],
       nodeIds:["wdn_"+"a".repeat(24)]},
   } as never);
   p.runner.mockResolvedValue(result);
   await expect(executeAuthorizedControlledFixture(p)).rejects
     .toThrow("PLAN_EXECUTION_EVIDENCE_DENIED");
   expect(s.complete).not.toHaveBeenCalled();
 });
 it("SQL-backed claim is not exposed to worker or ticket",()=>{
  const key=randomBytes(32),scope=planSnapshot(plan(),actor,now);
  const signed=signFixtureTicket(scope,job,randomUUID(),worker,1,key,now);
  expect(JSON.stringify(signed)).not.toContain(claim.leaseToken);
  const manual=createHmac("sha256",key).update(signed.body+"x").digest("hex");
  expect(()=>verifyFixtureTicket({...signed,mac:manual},key,now)).toThrow();
 });
});
