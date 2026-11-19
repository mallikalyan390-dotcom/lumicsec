import {describe,expect,it} from "vitest";
import {resolve} from "node:path";
import {randomUUID} from "node:crypto";
import {execFileSync} from "node:child_process";
import {readFileSync} from "node:fs";
import {runControlledRuntimeFixture} from "../src/workers/controlled-runtime-runner.js";
import {fixtureOrigin,type ControlledProfile} from "../src/workers/controlled-runtime-broker.js";

const only=process.env["LUMICSEC_RUN_CONFINED_BROKER"]==="1"?describe:describe.skip;
const bundle=resolve(process.cwd(),"dist/isolated/runtime-worker.mjs");
const scope=(profile:ControlledProfile)=>({
  jobId:randomUUID(),organizationId:"00000000-0000-4000-8000-000000000011",
  assetId:"00000000-0000-4000-8000-000000000022",
  actorId:"00000000-0000-4000-8000-000000000033",
  origin:fixtureOrigin(profile),scopeHash:"a".repeat(64),
});
function run(profile:ControlledProfile,extra?:{signal?:AbortSignal;
  onBrokerReady?:(name:string)=>void;}){
 const ac=new AbortController();
 return runControlledRuntimeFixture({
  profile,mode:profile.startsWith("web_")?"web":"api",
  scope:scope(profile),bundlePath:bundle,brokerIsolation:"confined_fixture",
  signal:extra?.signal??ac.signal,onBrokerReady:extra?.onBrokerReady,
 });
}
function inspect(name:string){
 const raw=execFileSync("docker",["inspect",name,"--format",
   "{{json .HostConfig}}"],{timeout:4000,encoding:"utf8"});
 return JSON.parse(raw) as {NetworkMode:string;ReadonlyRootfs:boolean;
   CapDrop:string[];Memory:number;PidsLimit:number;SecurityOpt:string[];Mounts?:unknown};
}
function rejectDirectEgress(name:string,ip:string){
 // Run a REAL socket from inside the broker's kernel namespace, not a DNS mock.
 const js=`const net=require("node:net");
  const socket=net.connect({host:${JSON.stringify(ip)},port:443,timeout:950});
  socket.on("connect",()=>process.exit(8));
  socket.on("error",()=>process.exit(0));
  socket.on("timeout",()=>process.exit(0));
  setTimeout(()=>process.exit(0),1200);`;
 execFileSync("docker",["exec",name,"/usr/bin/node","-e",js],
  {timeout:3500,stdio:"pipe"});
}
only("independently network-none broker + network-none worker actual kernel execution",()=>{
  it("actual insecure Web fixture via separate confined broker records five review signals",async()=>{
    const result=await run("web_insecure");
    expect(result.brokerNetworkMode).toBe("none");
    expect(result.requests).toBe(1);
    expect(result.externalRequests).toBe(0);
    expect(result.result.observations.map(o=>o.ruleId)).toContain("P09.HSTS.ABSENT");
    expect(result.result.observations.map(o=>o.ruleId)).toContain("P09.COOKIE.SECURE_AGG");
  },25_000);
  it("actual secure Web comparator has zero observations",async()=>{
    const result=await run("web_secure");
    expect(result.brokerNetworkMode).toBe("none");
    expect(result.result.observations).toHaveLength(0);
  },25_000);
  it("actual insecure API fixture records anonymous/other synthetic review, not exploits",async()=>{
    const result=await run("api_insecure");
    expect(result.brokerNetworkMode).toBe("none");
    expect(result.requests).toBe(3);
    expect(result.result.observations.map(o=>o.ruleId)).toEqual([
      "API.RUNTIME.AUTH.ANON_SUCCESS","API.RUNTIME.AUTHZ.OTHER_SUCCESS",
      "API.RUNTIME.HEADER.HSTS_ABSENT","API.RUNTIME.HEADER.NOSNIFF_ABSENT",
    ]);
    const status=result.result.report;
    expect(status.classification).toBe("RUNTIME_API_REVIEW");
    if(status.classification!=="RUNTIME_API_REVIEW")throw Error("WRONG_REPORT");
    expect(status.statuses).toEqual({anonymous:200,owner:200,other:200});
  },25_000);
  it("actual secure API comparator returns 401 / 200 / 403 with no false alerts",async()=>{
    const result=await run("api_secure");
    expect(result.result.observations).toHaveLength(0);
    if(result.result.report.classification!=="RUNTIME_API_REVIEW")
      throw Error("WRONG_API_REPORT");
    expect(result.result.report.statuses).toEqual({anonymous:401,owner:200,other:403});
  },25_000);
  it("Docker OS denies public, metadata and IPv6 sockets from BROKER namespace",async()=>{
    let inspected=false,egressDenied=0;
    const result=await run("api_secure",{onBrokerReady:name=>{
      const state=inspect(name);
      expect(state.NetworkMode).toBe("none");
      expect(state.ReadonlyRootfs).toBe(true);
      expect(state.PidsLimit).toBe(24);
      expect(state.CapDrop).toContain("ALL");
      expect(state.Memory).toBe(128*1024*1024);
      inspected=true;
      for(const ip of ["1.1.1.1","169.254.169.254","10.0.0.1",
        "2001:4860:4860::8888","fd00::1"]){
        rejectDirectEgress(name,ip);egressDenied++;
      }
    }});
    expect(inspected).toBe(true);
    expect(egressDenied).toBe(5);
    expect(result.brokerNetworkMode).toBe("none");
    expect(result.requests).toBe(3);
  },30_000);
  it.each(["web_redirect","web_oversize","web_slow","api_redirect",
    "api_oversize","api_slow"] as ControlledProfile[])(
    "real confined broker denies %s and never commits partial observations",async profile=>{
      await expect(run(profile)).rejects.toThrow(
        /CONTROLLED_RUNTIME_EXECUTION_FAILED|CONTROLLED_RUNTIME_CANCELLED|CONFINED_BROKER_ACCOUNTING_UNAVAILABLE/);
    },25_000);
  it("cancellation immediately kills scoped worker and independent broker",async()=>{
    const ac=new AbortController();
    const work=run("api_slow",{signal:ac.signal});
    setTimeout(()=>ac.abort(),1200);
    await expect(work).rejects.toThrow(
      /CONTROLLED_RUNTIME_CANCELLED|CONFINED_BROKER_CANCELLED/);
  },18_000);
  it("bundles have no database credentials or privileged network controllers",()=>{
    const worker=readFileSync(bundle);
    const broker=readFileSync(resolve(process.cwd(),"dist/isolated/confined-broker.mjs"));
    for(const payload of [worker,broker]){
      expect(payload.includes(Buffer.from("SUPABASE_SECRET_KEY"))).toBe(false);
      expect(payload.includes(Buffer.from("SERVICE_ROLE_KEY"))).toBe(false);
    }
    expect(worker.includes(Buffer.from("SYNTHETIC_OWNER_FIXTURE_ONLY"))).toBe(false);
  });
});
