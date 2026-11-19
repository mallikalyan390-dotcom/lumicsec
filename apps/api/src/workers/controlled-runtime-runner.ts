/* Explicit opt-in controlled-fixture Docker runner.
 * NOT a production/hosted execution path. Never called from customer API.
 * The worker has --network none and a single read-only broker socket mount.
 */
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import { extname,dirname,join } from "node:path";
import { controlledStartSchema, parseControlledResult,
  CONTROLLED_RUNTIME_VERSION, type ControlledResult } from "./controlled-runtime-contract.js";
import { openControlledRuntimeBroker, fixtureOrigin,
  type ControlledProfile } from "./controlled-runtime-broker.js";
import { openConfinedRuntimeBroker } from "./confined-runtime-broker-controller.js";
import { WEB_IPC_VERSION, parseWebIpcResult,
  type WebIpcStart, type WebIpcResult } from "./web-worker-ipc-contract.js";

const PINNED_IMAGE="sha256:35e7c432242067a653e10bd96d9de5913ad35e60b884f2245ec7e43a41dc38f2";
const active=new Set<string>();
type Scope=Readonly<{
  jobId:string;organizationId:string;assetId:string;actorId:string;
  origin:string;scopeHash:string;
}>;
const boundedEnvironment={PATH:process.env["PATH"]??"/usr/bin:/bin",HOME:"/tmp"};
export async function runControlledRuntimeFixture(input:Readonly<{
  scope:Scope;mode:"web"|"api";profile:ControlledProfile;
  bundlePath:string;signal:AbortSignal;onReady?:()=>void;
  brokerIsolation?:"host_fixture"|"confined_fixture";
  planScope?:Readonly<{approvedPaths:readonly string[];maxRequests:number;
    maxResponseBytes:number;maxTotalBytes:number;maxExecutionMs:number}>;
  onBrokerReady?:(containerName:string)=>void;
}>):Promise<Readonly<{result:ControlledResult;requests:number;bytes:number;
  externalRequests:0;brokerNetworkMode:"host"|"none"}>>{
  if(input.planScope&&input.brokerIsolation!=="confined_fixture")
    throw Error("CONTROLLED_PLAN_REQUIRES_CONFINED_BROKER");
  if(active.has(input.scope.jobId)||active.size>=2||input.signal.aborted ||
    (input.mode==="web")!==(input.profile.startsWith("web_"))||
    input.scope.origin!==fixtureOrigin(input.profile))
    throw Error("CONTROLLED_RUNTIME_DUPLICATE_OR_SCOPE_DENIED");
  active.add(input.scope.jobId);
  const controller=new AbortController();
  const onAbort=()=>controller.abort();
  input.signal.addEventListener("abort",onAbort,{once:true});
  let broker:Awaited<ReturnType<typeof openControlledRuntimeBroker>>|
    Awaited<ReturnType<typeof openConfinedRuntimeBroker>>|null=null;
  let deadline:ReturnType<typeof setTimeout>|null=null;
  try{
    const bundle=await realpath(input.bundlePath);
    if(extname(bundle)!==".mjs"||!(await stat(bundle)).isFile()||
      !bundle.endsWith("/dist/isolated/runtime-worker.mjs"))
      throw Error("CONTROLLED_BUNDLE_DENIED");
    const start=controlledStartSchema.parse({
      protocol:CONTROLLED_RUNTIME_VERSION,type:"START",
      executionId:randomUUID(),mode:input.mode,scope:input.scope,
    });
    broker=input.brokerIsolation==="confined_fixture"
      ?await openConfinedRuntimeBroker({
        executionId:start.executionId,origin:input.scope.origin,
        profile:input.profile,signal:controller.signal,
        bundlePath:join(dirname(bundle),"confined-broker.mjs"),
        ...(input.planScope?{planScope:input.planScope}:{}),
      })
      :await openControlledRuntimeBroker({
        executionId:start.executionId,origin:input.scope.origin,
        profile:input.profile,signal:controller.signal,
      });
    if("containerName" in broker && typeof broker.containerName==="string")
      input.onBrokerReady?.(broker.containerName);
    if(controller.signal.aborted)throw Error("CONTROLLED_RUNTIME_CANCELLED");
    const socketDir=await realpath(broker.socketDirectory);
    if(controller.signal.aborted)throw Error("CONTROLLED_RUNTIME_CANCELLED");
    const containerName="lumicsec-runtime-fixture-"+randomUUID();
    const cmd=[
      "run","--rm","--interactive","--pull","never",
      "--name",containerName,
      "--network","none","--read-only",
      "--cap-drop","ALL","--security-opt","no-new-privileges",
      "--pids-limit","24","--memory","128m","--memory-swap","128m",
      "--cpus","0.5","--user","65534:65534",
      "--ulimit","nofile=64:64","--ulimit","nproc=24:24",
      "--tmpfs","/tmp:rw,noexec,nosuid,nodev,size=16m",
      "--workdir","/tmp","--hostname","lumicsec-runtime-restricted",
      "--mount","type=bind,src="+bundle+",dst=/opt/lumicsec-runtime/worker.mjs,readonly",
      "--mount","type=bind,src="+socketDir+",dst=/opt/lumicsec-broker,readonly",
      "--env","LUMICSEC_CONTROLLED_FIXTURE=yes",
      "--entrypoint","/usr/bin/node",
      PINNED_IMAGE,"/opt/lumicsec-runtime/worker.mjs",
    ];
    const serial=JSON.stringify(start)+"\n";
    const output=await new Promise<string>((resolve,reject)=>{
      let stdout="",stderrBytes=0,finished=false,cancelled=false;
      const child=spawn("docker",cmd,{env:boundedEnvironment,stdio:["pipe","pipe","pipe"]});
      const kill=()=>{
        if(finished)return;
        cancelled=true;
        const killer=spawn("docker",["kill","--signal","KILL",containerName],
          {env:boundedEnvironment,stdio:"ignore"});
        killer.on("error",()=>undefined);
        setTimeout(()=>{if(!finished)child.kill("SIGKILL");},1500).unref();
      };
      controller.signal.addEventListener("abort",kill,{once:true});
      // Abort might have fired between setup and registering the listener.
      if(controller.signal.aborted)kill();
      deadline=setTimeout(()=>controller.abort(),17_000);
      child.stdout.on("data",(buf:Buffer)=>{
        stdout+=buf.toString("utf8");
        if(Buffer.byteLength(stdout)>120_001)kill();
      });
      child.stderr.on("data",(buf:Buffer)=>{stderrBytes+=buf.length;if(stderrBytes>1024)kill();});
      child.stdin.on("error",()=>undefined);
      child.stdin.end(serial);
      child.on("error",kill);
      child.on("close",(exit,signal)=>{
        finished=true;
        controller.signal.removeEventListener("abort",kill);
        if(cancelled||controller.signal.aborted)return reject(Error("CONTROLLED_RUNTIME_CANCELLED"));
        if(exit!==0||signal||!stdout.endsWith("\n")||
          stdout.indexOf("\n")!==stdout.length-1)
          return reject(Error("CONTROLLED_RUNTIME_EXECUTION_FAILED"));
        resolve(stdout.slice(0,-1));
      });
      input.onReady?.();
    });
    const result=parseControlledResult(output,start);
    if(controller.signal.aborted)throw Error("CONTROLLED_RUNTIME_CANCELLED");
    const counters="networkMode" in broker
      ?await (broker as Awaited<ReturnType<typeof openConfinedRuntimeBroker>>)
        .awaitAccounting(result.report.requests)
      :broker.stats();
    if(counters.requests<1||counters.bytes>240_000||counters.externalRequests!==0)
      throw Error("CONTROLLED_BROKER_ACCOUNTING_DENIED");
    return {result,requests:counters.requests,bytes:counters.bytes,
      externalRequests:0,
      brokerNetworkMode:"networkMode" in broker?"none":"host"};
  }finally{
    if(deadline)clearTimeout(deadline);
    controller.abort();
    if(broker)await broker.close();
    input.signal.removeEventListener("abort",onAbort);
    active.delete(input.scope.jobId);
  }
}
export function controlledWebFixtureRunner(bundlePath:string,profile:ControlledProfile,
  brokerIsolation:"host_fixture"|"confined_fixture"="host_fixture"){
  if(!profile.startsWith("web_"))throw Error("WEB_PROFILE_REQUIRED");
  return async(input:Readonly<{request:WebIpcStart;bundlePath:string;signal:AbortSignal}>):Promise<WebIpcResult>=>{
    if(input.request.fixture!=="none"||input.bundlePath!==bundlePath)
      throw Error("WEB_CONTROLLED_INPUT_DENIED");
    const executed=await runControlledRuntimeFixture({
      mode:"web",profile,scope:input.request.scope,
      bundlePath,signal:input.signal,brokerIsolation,
    });
    return parseWebIpcResult(JSON.stringify({
      protocol:WEB_IPC_VERSION,type:"RESULT",
      executionId:input.request.executionId,jobId:input.request.scope.jobId,
      scopeHash:input.request.scope.scopeHash,report:executed.result.report,
      observations:executed.result.observations,
    }),input.request);
  };
}
