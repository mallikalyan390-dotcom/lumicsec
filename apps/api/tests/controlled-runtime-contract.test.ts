import { readFileSync } from "node:fs";
import { connect } from "node:net";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { describe,expect,it,vi } from "vitest";
import { controlledInputFromText, parseControlledResult,
  CONTROLLED_RUNTIME_VERSION } from "../src/workers/controlled-runtime-contract.js";
import { brokerRequestSchema,fixtureOrigin,openControlledRuntimeBroker } from "../src/workers/controlled-runtime-broker.js";
import { PublicPinnedWebTransport, requireExactWebUrl,
  isPublicWebAddress } from "../src/lib/web-pinned-transport.js";

const captured=JSON.parse(readFileSync(resolve(process.cwd(),
  "tests/fixtures/controlled-runtime-actual-results.json"),"utf8")) as {
  fixtures:Record<string,{result:Record<string,unknown>;requests:number;
    bytes:number;externalRequests:number}>;
};
function start(profile:string){
  const result=captured.fixtures[profile]!.result;
  return controlledInputFromText(JSON.stringify({
    protocol:CONTROLLED_RUNTIME_VERSION,type:"START",
    executionId:result["executionId"],
    mode:profile.startsWith("api")?"api":"web",
    scope:{jobId:result["jobId"],organizationId:"00000000-0000-4000-8000-000000000011",
      assetId:"00000000-0000-4000-8000-000000000022",
      actorId:"00000000-0000-4000-8000-000000000033",
      origin:fixtureOrigin(profile as Parameters<typeof fixtureOrigin>[0]),
      scopeHash:result["scopeHash"]},
  }));
}
describe("controlled runtime source evidence and hardened contract",()=>{
  it("validates exact saved Docker/TLS API insecure IPC, not fabricated user data",()=>{
    const result=parseControlledResult(JSON.stringify(captured.fixtures["api_insecure"]!.result),
      start("api_insecure"));
    expect(result.mode).toBe("api");
    expect(result.report.classification).toBe("RUNTIME_API_REVIEW");
    expect(result.observations.map(o=>o.ruleId)).toEqual([
      "API.RUNTIME.AUTH.ANON_SUCCESS","API.RUNTIME.AUTHZ.OTHER_SUCCESS",
      "API.RUNTIME.HEADER.HSTS_ABSENT","API.RUNTIME.HEADER.NOSNIFF_ABSENT",
    ]);
    expect(result.observations.every(o=>o.classification!=="SPEC_ONLY")).toBe(true);
    expect(captured.fixtures["api_insecure"]!.externalRequests).toBe(0);
  });
  it("validates actual secure comparator without same-target false signals",()=>{
    const result=parseControlledResult(JSON.stringify(captured.fixtures["api_secure"]!.result),
      start("api_secure"));
    expect(result.observations).toHaveLength(0);
    if(result.report.classification!=="RUNTIME_API_REVIEW")throw Error("BAD_CLASS");
    expect(result.report.statuses).toMatchObject({anonymous:401,owner:200,other:403});
  });
  it("validates actual controlled Web insecure and secure IPC snapshots",()=>{
    const insecure=parseControlledResult(JSON.stringify(captured.fixtures["web_insecure"]!.result),
      start("web_insecure"));
    const secure=parseControlledResult(JSON.stringify(captured.fixtures["web_secure"]!.result),
      start("web_secure"));
    expect(insecure.observations.map(o=>o.ruleId)).toContain("P09.HSTS.ABSENT");
    expect(insecure.observations.map(o=>o.ruleId)).toContain("P09.COOKIE.SECURE_AGG");
    expect(secure.observations).toHaveLength(0);
  });
  it("rejects tampered job ID, protocol, mode and source fingerprints",()=>{
    const sample=captured.fixtures["api_insecure"]!.result;
    for(const change of [
      {jobId:"00000000-0000-4000-8000-000000000099"},
      {protocol:"WRONG_PROTOCOL"},
      {mode:"web"},
      {observations:[{...(sample["observations"] as Record<string,unknown>[])[0],
        evidenceSource:{paths:["/admin"],fingerprints:["broken"],nodeIds:["broken"]}}]},
    ])expect(()=>parseControlledResult(JSON.stringify({...sample,...change}),
      start("api_insecure"))).toThrow();
  });
  it("broker protocol does not accept POST, arbitrary headers or bearer tokens",()=>{
    const valid={protocol:"CONTROLLED_RUNTIME_BROKER_V1",
      executionId:"00000000-0000-4000-8000-000000000044",
      origin:fixtureOrigin("api_insecure"),
      url:fixtureOrigin("api_insecure")+"/v1/accounts/owner",
      identity:"owner",method:"GET"};
    expect(brokerRequestSchema.parse(valid)).toEqual(valid);
    for(const change of [
      {method:"POST"},{headers:{authorization:"SYNTHETIC_NEVER_ALLOW"}},
      {identity:"external"},{origin:"http://127.0.0.1"}])
      expect(brokerRequestSchema.safeParse({...valid,...change}).success).toBe(false);
  });
  it("actual Unix broker rejects malformed URL without crashing and still serves scoped TLS",async()=>{
    const ac=new AbortController();
    const executionId=randomUUID(), origin=fixtureOrigin("api_secure");
    const broker=await openControlledRuntimeBroker({
      executionId,origin,profile:"api_secure",signal:ac.signal,maxRequests:2,
    });
    const send=async(url:string)=>new Promise<string>(resolve=>{
      const socket=connect(join(broker.socketDirectory,"request.sock"));
      let output="";
      const timeout=setTimeout(()=>socket.destroy(),3_000);
      socket.on("connect",()=>socket.write(JSON.stringify({
        protocol:"CONTROLLED_RUNTIME_BROKER_V1",executionId,origin,url,
        identity:"anonymous",method:"GET",
      })+"\n"));
      socket.on("data",part=>{output+=part.toString("utf8");});
      socket.on("error",()=>{});
      socket.on("close",()=>{clearTimeout(timeout);resolve(output);});
    });
    try{
      for(const invalid of ["not-a-url","https://other.example.net/",
        origin+"/v1/health?secret=1",origin+"/%2e%2e/private"]){
        expect(await send(invalid)).toBe("");
      }
      const approved=JSON.parse(await send(origin+"/v1/health")) as {
        status:number;sha256:string;
      };
      expect(approved.status).toBe(200);
      expect(approved.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(broker.stats().failures).toBeGreaterThanOrEqual(4);
      expect(broker.stats().requests).toBe(1);
      expect(broker.stats().externalRequests).toBe(0);
    }finally{ac.abort();await broker.close();}
  },10_000);
  it("public resolver refuses private, metadata and mixed rebinding answers before socket",async()=>{
    const request=vi.fn(()=>{throw Error("UNEXPECTED_OUTBOUND_SOCKET");});
    const transport=new PublicPinnedWebTransport(async()=>[
      {address:"8.8.8.8",family:4},{address:"169.254.169.254",family:4}],request);
    await expect(transport.read("https://controlled.example.net",
      "https://controlled.example.net/",{
        signal:new AbortController().signal,maxBytes:1000,
      })).rejects.toThrow("WEB_PRIVATE_ADDRESS_BLOCKED");
    expect(request).not.toHaveBeenCalled();
    for(const ip of ["0.0.0.1","127.0.0.1","10.1.1.1","172.16.1.2",
      "192.168.5.3","169.254.169.254","100.64.0.5","198.18.0.1"])
      expect(isPublicWebAddress(ip,4)).toBe(false);
  });
  it("scope guard blocks redirects, cross-origin, query, credentials and risky paths",()=>{
    const origin="https://controlled.example.net";
    for(const path of [
      "https://outside.example.net/","http://controlled.example.net/",
      origin+"/admin",origin+"/logout",origin+"/v1/accounts?other=1",
      origin+"/%2e%2e/private",origin+"/#fragment",
    ])expect(()=>requireExactWebUrl(path,origin)).toThrow();
    expect(requireExactWebUrl(origin+"/v1/accounts/owner",origin).pathname)
      .toBe("/v1/accounts/owner");
  });
});
