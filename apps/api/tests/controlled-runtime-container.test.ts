/** Opt-in actual Docker + host-only HTTPS fixture broker acceptance.
 * Default CI skip is intentional: pinned local Playwright test image absent.
 * These tests execute real Linux no-egress Docker worker, Unix socket and TLS.
 */
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { randomUUID } from "node:crypto";
import { executeWebSandboxController } from "../src/workers/web-isolated-controller.js";
import type { WebWorkerClaim, WebWorkerStore,
  WebAssessmentEvidence } from "../src/workers/web-assessment-worker.js";
import { fixtureOrigin, type ControlledProfile } from "../src/workers/controlled-runtime-broker.js";
import { runControlledRuntimeFixture, controlledWebFixtureRunner } from "../src/workers/controlled-runtime-runner.js";
import { isPublicWebAddress } from "../src/lib/web-pinned-transport.js";

const enabled=process.env["LUMICSEC_RUN_CONTROLLED_RUNTIME"]==="1";
const suite=enabled?describe:describe.skip;
const BUNDLE=resolve(process.cwd(),"dist/isolated/runtime-worker.mjs");
const ORG="00000000-0000-4000-8000-000000000011";
const ASSET="00000000-0000-4000-8000-000000000022";
const ACTOR="00000000-0000-4000-8000-000000000033";
const SCOPE="a".repeat(64);
const API_EXPECTED=[
  "API.RUNTIME.AUTH.ANON_SUCCESS","API.RUNTIME.AUTHZ.OTHER_SUCCESS",
  "API.RUNTIME.HEADER.HSTS_ABSENT","API.RUNTIME.HEADER.NOSNIFF_ABSENT",
];
function input(profile:ControlledProfile){
  const aborter=new AbortController();
  return {scope:{jobId:randomUUID(),organizationId:ORG,assetId:ASSET,actorId:ACTOR,
    origin:fixtureOrigin(profile),scopeHash:SCOPE},
    mode:profile.startsWith("web_")?"web" as const:"api" as const,
    profile,bundlePath:BUNDLE,signal:aborter.signal,aborter};
}
function webStore(profile:"web_insecure"|"web_secure"){
  const job=randomUUID();
  const claim:WebWorkerClaim={
    jobId:job,scopeHash:SCOPE,organizationId:ORG,assetId:ASSET,actorId:ACTOR,
    origin:fixtureOrigin(profile),token:"b".repeat(64),generation:1,
  };
  let saved:readonly WebAssessmentEvidence[]=[];
  const store:WebWorkerStore={
    claim:vi.fn(async()=>claim),
    heartbeat:vi.fn(async()=>true),
    complete:vi.fn(async(_claim,items)=>{saved=items;return true;}),
    stop:vi.fn(async()=>true),
  };
  return {job,store,saved:()=>saved};
}
suite("genuine network-none Docker + pinned controlled HTTPS broker",()=>{
  it("runs existing Web analyzer through AF_UNIX broker to insecure real TLS fixture",async()=>{
    const state=webStore("web_insecure");
    const result=await executeWebSandboxController({
      jobId:state.job,scopeHash:SCOPE,store:state.store,bundlePath:BUNDLE,
      runner:controlledWebFixtureRunner(BUNDLE,"web_insecure"),
    });
    const rules=result.observations.map(o=>o.ruleId);
    for(const expected of ["P09.COOKIE.SECURE_AGG","P09.HSTS.ABSENT",
      "P09.CSP.ABSENT","P09.FRAME.NO_POLICY"])expect(rules).toContain(expected);
    expect(result.report.fetched).toBeGreaterThan(0);
    expect(state.saved()).toEqual(result.observations);
    expect(state.store.complete).toHaveBeenCalledOnce();
    expect(JSON.stringify(result)).not.toContain("SYNTHETIC_OWNER_FIXTURE_ONLY");
    expect(JSON.stringify(result)).not.toContain("bbbbbbbb");
  },25_000);
  it("web secure controlled TLS comparator produces 0/4 targeted false alerts",async()=>{
    const state=webStore("web_secure");
    const result=await executeWebSandboxController({
      jobId:state.job,scopeHash:SCOPE,store:state.store,bundlePath:BUNDLE,
      runner:controlledWebFixtureRunner(BUNDLE,"web_secure"),
    });
    for(const expected of ["P09.COOKIE.SECURE_AGG","P09.HSTS.ABSENT",
      "P09.CSP.ABSENT","P09.FRAME.NO_POLICY"])
      expect(result.observations.map(o=>o.ruleId)).not.toContain(expected);
    expect(state.store.complete).toHaveBeenCalledOnce();
  },25_000);
  it("actual API anonymous/owner/other identities against insecure controlled TLS",async()=>{
    const args=input("api_insecure");
    const executed=await runControlledRuntimeFixture(args);
    const result=executed.result;
    expect(result.mode).toBe("api");
    expect(result.report.classification).toBe("RUNTIME_API_REVIEW");
    const rules=result.observations.map(o=>o.ruleId);
    for(const rule of API_EXPECTED)expect(rules).toContain(rule);
    expect(result.report.requests).toBe(3);
    expect(executed.requests).toBe(3);
    expect(executed.bytes).toBeGreaterThan(0);
    expect(executed.externalRequests).toBe(0);
    expect(result.observations.every(o=>o.evidenceSource.fingerprints.length===3)).toBe(true);
    expect(JSON.stringify(result)).not.toContain("SYNTHETIC_OWNER_FIXTURE_ONLY");
    expect(JSON.stringify(result)).not.toContain("synthetic-owner");
  },25_000);
  it("secure API comparator denies unauthenticated and other identity; 0/4 signals",async()=>{
    const executed=await runControlledRuntimeFixture(input("api_secure"));
    const report=executed.result.report;
    expect(report.classification).toBe("RUNTIME_API_REVIEW");
    if(report.classification!=="RUNTIME_API_REVIEW")throw Error("BAD_FIXTURE_CLASS");
    expect(report.statuses).toEqual({anonymous:401,owner:200,other:403});
    for(const rule of API_EXPECTED)
      expect(executed.result.observations.map(o=>o.ruleId)).not.toContain(rule);
  },25_000);
  it.each(["web_redirect","web_oversize","web_slow",
    "api_redirect","api_oversize","api_slow"] as ControlledProfile[])(
    "rejects actual broker TLS negative %s without evidence",async profile=>{
      await expect(runControlledRuntimeFixture(input(profile)))
        .rejects.toThrow(/CONTROLLED_RUNTIME_EXECUTION_FAILED|CONTROLLED_RUNTIME_CANCELLED/);
    },25_000);
  it("stops real Docker worker and broker on cancellation, no partial API evidence",async()=>{
    const task=input("api_slow");
    const start=Date.now();
    const result=runControlledRuntimeFixture(task);
    setTimeout(()=>task.aborter.abort(),800);
    await expect(result).rejects.toThrow("CONTROLLED_RUNTIME_CANCELLED");
    expect(Date.now()-start).toBeLessThan(6_000);
  },15_000);
  it("rejects duplicate live execution with the same job id",async()=>{
    const args=input("api_slow");
    let announce:()=>void=()=>undefined;
    const ready=new Promise<void>(ok=>{announce=ok;});
    const running=runControlledRuntimeFixture({...args,onReady:announce});
    await ready;
    await expect(runControlledRuntimeFixture({...args,
      signal:new AbortController().signal}))
      .rejects.toThrow("CONTROLLED_RUNTIME_DUPLICATE_OR_SCOPE_DENIED");
    args.aborter.abort();
    await expect(running).rejects.toThrow("CONTROLLED_RUNTIME_CANCELLED");
  },15_000);
  it("lost trusted Web lease prevents broker worker and result commit",async()=>{
    const state=webStore("web_insecure");
    vi.mocked(state.store.heartbeat).mockResolvedValue(false);
    await expect(executeWebSandboxController({
      jobId:state.job,scopeHash:SCOPE,store:state.store,
      bundlePath:BUNDLE,runner:controlledWebFixtureRunner(BUNDLE,"web_insecure"),
    })).rejects.toThrow("WEB_CONTROLLER_LEASE_LOST");
    expect(state.store.complete).not.toHaveBeenCalled();
  });
  it("preserves private and metadata IP denial; no network unrestricted on worker",()=>{
    for(const ip of ["127.0.0.1","10.0.0.8","169.254.169.254",
      "192.168.1.1","100.64.0.1","198.18.0.1"])
      expect(isPublicWebAddress(ip,4)).toBe(false);
    expect(isPublicWebAddress("8.8.8.8",4)).toBe(true);
  });
  it("rejects arbitrary origin and wrong mode before any Docker job is admitted",async()=>{
    const args=input("api_insecure");
    await expect(runControlledRuntimeFixture({...args,
      scope:{...args.scope,origin:"https://outside.fixture-api.net"}}))
      .rejects.toThrow("CONTROLLED_RUNTIME_DUPLICATE_OR_SCOPE_DENIED");
    await expect(runControlledRuntimeFixture({...args,mode:"web"}))
      .rejects.toThrow("CONTROLLED_RUNTIME_DUPLICATE_OR_SCOPE_DENIED");
  });
});
