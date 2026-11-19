/* Opt-in real Docker: recovered signed-plan coordinator ->
 * one-shot authorized scope -> second network-none HTTPS broker ->
 * separate network-none credential-free worker -> checked result.
 * Test store is memory only; DB lifecycle is independently verified by SQL.
 * No customer network, service role token or public scanner route.
 */
import {randomUUID} from "node:crypto";
import {resolve} from "node:path";
import {describe,expect,it,vi} from "vitest";
import {fixtureOrigin,type ControlledProfile} from
  "../src/workers/controlled-runtime-broker.js";
import {runControlledRuntimeFixture} from
  "../src/workers/controlled-runtime-runner.js";
import {runTrustedPlanFixture} from
  "../src/workers/plan-execution-supabase-store.js";
import type {CurrentPlan,PlanExecutionStore,SecurityActor} from
  "../src/workers/authorized-plan-controller.js";

const only=process.env["LUMICSEC_RUN_AUTHORIZED_PLAN_DOCKER"]==="1"?describe:describe.skip;
const org="00000000-0000-4000-8000-000000000011";
const asset="00000000-0000-4000-8000-000000000022";
const user="00000000-0000-4000-8000-000000000033";
const planId="00000000-0000-4000-8000-000000000044";
const workerId="00000000-0000-4000-8000-000000000066";
const bundle=resolve(process.cwd(),"dist/isolated/runtime-worker.mjs");
const hash="a".repeat(64);
const actor:SecurityActor={
 id:user,organizationId:org,provider:"google",aal:"aal2",verifiedTotp:true,
 role:"owner",
};
function currentPlan(profile:ControlledProfile,patch:Partial<CurrentPlan>={}):CurrentPlan{
 const web=profile.startsWith("web_");
 const now=Date.now();
 const origin=fixtureOrigin(profile);
 const before=new Date(now-6000).toISOString();
 const after=new Date(now+75000).toISOString();
 return {...{
  planId,organizationId:org,assetId:asset,createdBy:user,
  assetKind:web?"website":"api",origin,scopeHash:hash,
  approvedPaths:web?["/"]:["/v1/accounts/owner"],
  profile:web?"web_readonly":"api_readonly",state:"active",
  maxRequests:web?1:3,maxResponseBytes:60000,maxTotalBytes:240000,
  maxExecutionMs:15000,proofVerifiedAt:before,proofExpiresAt:after,
  expiresAt:after,assetVerification:"verified",assetOrigin:origin,
  assetProofVerifiedAt:before,assetProofExpiresAt:after,
  actorMembership:"active",actorRole:"owner",
 } as CurrentPlan,...patch};
}
function memoryStore(record:CurrentPlan){
 const jobId=randomUUID();
 const completed:unknown[]=[];
 const state={revoked:false};
 const store:PlanExecutionStore={
  current:vi.fn(async()=>state.revoked?{...record,state:"revoked" as const}:record),
  enqueue:vi.fn(async()=>jobId),
  claim:vi.fn(async({workerId,scopeHash})=>({
    jobId,planId,organizationId:org,assetId:asset,actorId:user,
    scopeHash,workerId,generation:1,leaseToken:"f".repeat(64),
  })),
  heartbeat:vi.fn(async()=>!state.revoked),
  complete:vi.fn(async(_claim,evidence)=>{completed.push(evidence);return !state.revoked;}),
  stop:vi.fn(async()=>undefined),
  stopQueued:vi.fn(async()=>undefined),
 };
 return {store,completed,state};
}
function run(profile:ControlledProfile,fixture=memoryStore(currentPlan(profile)),
 signal=new AbortController().signal){
 return runTrustedPlanFixture({
   profile,planId,organizationId:org,actor,requestId:randomUUID(),
   workerId,bundlePath:bundle,store:fixture.store,signal,
 });
}
only("real signed-plan controller plus independently confined Web/API Docker",()=>{
 it("executes approved Web HTTPS response and saves five review-only observations",async()=>{
  const fixture=memoryStore(currentPlan("web_insecure"));
  const output=await run("web_insecure",fixture);
  expect(output.observations).toBe(5);
  expect(output.result.report.classification).toBe("PASSIVE_WEB_REVIEW");
  expect(output.result.report.requests).toBe(1);
  expect(output.result.observations.every(o=>
    o.evidenceSource.paths.every(p=>p==="/"))).toBe(true);
  expect(fixture.completed).toHaveLength(1);
  expect(fixture.store.heartbeat).toHaveBeenCalled();
  expect(fixture.store.stop).not.toHaveBeenCalled();
 },26_000);
 it("executes approved secure Web comparator with zero observations",async()=>{
  const fixture=memoryStore(currentPlan("web_secure"));
  const output=await run("web_secure",fixture);
  expect(output.result.observations).toHaveLength(0);
  expect(fixture.completed).toHaveLength(1);
 },26_000);
 it("executes exact approved API GET 3 synthetic identities with review-only observations",async()=>{
  const fixture=memoryStore(currentPlan("api_insecure"));
  const output=await run("api_insecure",fixture);
  expect(output.result.report.classification).toBe("RUNTIME_API_REVIEW");
  expect(output.result.report.requests).toBe(3);
  expect(output.result.observations.map(x=>x.ruleId)).toEqual([
    "API.RUNTIME.AUTH.ANON_SUCCESS","API.RUNTIME.AUTHZ.OTHER_SUCCESS",
    "API.RUNTIME.HEADER.HSTS_ABSENT","API.RUNTIME.HEADER.NOSNIFF_ABSENT",
  ]);
  expect(output.result.observations.every(x=>
    x.classification!=="CONFIRMED_VULNERABILITY")).toBe(true);
  expect(fixture.completed).toHaveLength(1);
 },26_000);
 it("executes secure API comparator with no false-positive observations",async()=>{
  const output=await run("api_secure");
  expect(output.result.observations).toHaveLength(0);
  if(output.result.report.classification!=="RUNTIME_API_REVIEW")
    throw Error("WRONG_REPORT");
  expect(output.result.report.statuses).toEqual({anonymous:401,owner:200,other:403});
 },26_000);
 it("does not enqueue an API target if scope excludes actual fixture endpoint",async()=>{
  const fixture=memoryStore(currentPlan("api_insecure",{
    approvedPaths:["/v1/health"],
  }));
  await expect(run("api_insecure",fixture))
    .rejects.toThrow("PLAN_EXECUTION_ENDPOINT_NOT_APPROVED");
  expect(fixture.store.enqueue).not.toHaveBeenCalled();
  expect(fixture.completed).toHaveLength(0);
 },12_000);
 it("real broker denies worker request outside signed consent; no evidence committed",async()=>{
  const fixture=memoryStore(currentPlan("api_insecure"));
  const source=new AbortController();
  await expect(runControlledRuntimeFixture({
    profile:"api_insecure",mode:"api",scope:{
      jobId:randomUUID(),organizationId:org,assetId:asset,actorId:user,
      origin:fixtureOrigin("api_insecure"),scopeHash:hash,
    },bundlePath:bundle,brokerIsolation:"confined_fixture",
    planScope:{approvedPaths:["/v1/health"],maxRequests:3,
      maxResponseBytes:60000,maxTotalBytes:240000,maxExecutionMs:15000},
    brokerClaim:{planId,workerId,generation:1,
      notAfterMs:Date.now()+60000},
    signal:source.signal,
  })).rejects.toThrow();
  expect(fixture.completed).toHaveLength(0);
 },26_000);
 it("actual API traffic cannot exceed signed request budget of two",async()=>{
  const fixture=memoryStore(currentPlan("api_insecure",{maxRequests:2}));
  await expect(run("api_insecure",fixture)).rejects.toThrow();
  expect(fixture.completed).toHaveLength(0);
  expect(fixture.store.stop).toHaveBeenCalledTimes(1);
 },26_000);
 it("live mid-run cancellation stops both containers without completed evidence",async()=>{
  const fixture=memoryStore(currentPlan("api_slow"));
  const aborter=new AbortController();
  const task=run("api_slow",fixture,aborter.signal);
  setTimeout(()=>aborter.abort(),1400).unref();
  await expect(task).rejects.toThrow();
  expect(fixture.completed).toHaveLength(0);
 },26_000);
});
