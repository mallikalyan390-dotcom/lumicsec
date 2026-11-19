/* Independent kernel namespace for controlled HTTPS broker, not a proxy
 * with public network access. The broker and unprivileged worker run in TWO
 * separate --network none containers. They share only one Unix socket dir.
 * This is a fail-closed foundation; not public-IP egress qualification.
 */
import {spawn,execFileSync,type ChildProcess} from "node:child_process";
import {randomUUID} from "node:crypto";
import {chmod,mkdir,mkdtemp,realpath,rm,stat} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {setTimeout as pause} from "node:timers/promises";
import {z} from "zod";
import {fixtureOrigin,type ControlledProfile} from "./controlled-runtime-broker.js";

const IMAGE="sha256:35e7c432242067a653e10bd96d9de5913ad35e60b884f2245ec7e43a41dc38f2";
const profiles=["web_insecure","web_secure","web_redirect","web_oversize","web_slow",
  "api_insecure","api_secure","api_redirect","api_oversize","api_slow"] as const;
type Metrics={requests:number;bytes:number;failures:number;active:number;
  externalRequests:0;profile:ControlledProfile};
const metricSchema=z.strictObject({
  requests:z.number().int().min(0).max(8),
  bytes:z.number().int().min(0).max(240000),
  failures:z.number().int().min(0).max(50),
  active:z.number().int().min(0).max(1),
  externalRequests:z.literal(0),
  profile:z.enum(profiles),
});
const limitedEnv={PATH:process.env["PATH"]??"/usr/bin:/bin",HOME:"/tmp"};
export async function openConfinedRuntimeBroker(input:Readonly<{
  executionId:string;origin:string;profile:ControlledProfile;
  bundlePath:string;signal:AbortSignal;
  planScope?:Readonly<{approvedPaths:readonly string[];maxRequests:number;
    maxResponseBytes:number;maxTotalBytes:number;maxExecutionMs:number}>;
}>){
  if(!z.string().uuid().safeParse(input.executionId).success||
    input.origin!==fixtureOrigin(input.profile)||input.signal.aborted)
    throw Error("CONFINED_BROKER_SCOPE_DENIED");
  const scoped=z.strictObject({
    approvedPaths:z.array(z.string().regex(/^\/[a-zA-Z0-9._~/-]{0,119}$/)).min(1).max(6),
    maxRequests:z.number().int().min(1).max(6),
    maxResponseBytes:z.number().int().min(1024).max(60000),
    maxTotalBytes:z.number().int().min(1024).max(240000),
    maxExecutionMs:z.number().int().min(1000).max(15000),
  }).optional().safeParse(input.planScope);
  if(!scoped.success||(scoped.data&&(
    new Set(scoped.data.approvedPaths).size!==scoped.data.approvedPaths.length||
    scoped.data.maxTotalBytes<scoped.data.maxResponseBytes)))
    throw Error("CONFINED_BROKER_PLAN_SCOPE_DENIED");
  const bundle=await realpath(input.bundlePath);
  if(!bundle.endsWith("/dist/isolated/confined-broker.mjs")||
    !(await stat(bundle)).isFile())throw Error("CONFINED_BROKER_BUNDLE_DENIED");
  const directory=await mkdtemp(join(tmpdir(),"lumicsec-confined-egress-"));
  const socketDirectory=join(directory,"socket");
  let container:ChildProcess|null=null;
  let stopped=false;
  let startupTimer:ReturnType<typeof setTimeout>|null=null;
  let lastMetrics:Metrics={requests:0,bytes:0,failures:0,active:0,
    externalRequests:0,profile:input.profile};
  const containerName="lumicsec-confined-broker-"+randomUUID();
  try{
    // The founder's host directory is private (0700), with an explicit
    // narrow POSIX ACL only for the two non-root container UIDs. Fail closed
    // if ACL provisioning is unavailable; never fall back to chmod 0777.
    await mkdir(socketDirectory,{mode:0o700});
    await chmod(socketDirectory,0o700);
    execFileSync("/bin/setfacl",["-m","u:65534:rwx",socketDirectory],{
      env:limitedEnv,stdio:"ignore",timeout:2500,
    });
    if(input.signal.aborted)throw Error("CONFINED_BROKER_CANCELLED");
    const args=[
      "run","--rm","--pull","never","--name",containerName,
      "--network","none","--read-only","--cap-drop","ALL",
      "--security-opt","no-new-privileges","--user","65534:65534",
      "--pids-limit","24","--cpus","0.5","--memory","128m","--memory-swap","128m",
      "--ulimit","nofile=64:64","--ulimit","nproc=24:24",
      "--tmpfs","/tmp:rw,nosuid,nodev,size=16m",
      "--workdir","/tmp","--hostname","lumicsec-broker-confined",
      "--mount","type=bind,src="+bundle+",dst=/opt/lumicsec-runtime/broker.mjs,readonly",
      "--mount","type=bind,src="+socketDirectory+",dst=/opt/lumicsec-broker",
      "--env","LUMICSEC_CONTROLLED_FIXTURE=yes",
      "--env","LUMICSEC_BROKER_PROFILE="+input.profile,
      "--env","LUMICSEC_BROKER_EXECUTION_ID="+input.executionId,
      ...(scoped.data?[ "--env","LUMICSEC_BROKER_SCOPED="+
        JSON.stringify(scoped.data) ]:[]),
      "--entrypoint","/usr/bin/node",IMAGE,"/opt/lumicsec-runtime/broker.mjs",
    ];
    container=spawn("docker",args,{env:limitedEnv,stdio:["ignore","pipe","pipe"]});
    const child=container;
    let ready=false,complete=false,lineBuffer="";
    const startup=await new Promise<boolean>((resolve,reject)=>{
      let finished=false;
      const fail=(error:Error)=>{
        if(finished)return;
        finished=true;reject(error);
      };
      startupTimer=setTimeout(()=>fail(Error("CONFINED_BROKER_START_TIMEOUT")),12_000);
      child.on("error",()=>fail(Error("CONFINED_BROKER_DOCKER_FAILED")));
      child.on("close",()=>{stopped=true;complete=true;
        if(!ready)fail(Error("CONFINED_BROKER_EXIT_BEFORE_READY"));});
      child.stderr?.on("data",()=>undefined); // never echo worker or credential data
      child.stdout?.on("data",(part:Buffer)=>{
        lineBuffer+=part.toString("utf8");
        if(Buffer.byteLength(lineBuffer)>4000)
          return fail(Error("CONFINED_BROKER_LOG_BOUNDS"));
        let newline;
        while((newline=lineBuffer.indexOf("\n"))>=0){
          const line=lineBuffer.slice(0,newline);
          lineBuffer=lineBuffer.slice(newline+1);
          if(line==="CONTROLLED_BROKER_READY"){
            ready=true;
            if(!finished){finished=true;resolve(true);}
          }else if(line.startsWith("CONTROLLED_BROKER_METRICS ")){
            const parsed=metricSchema.safeParse(
              (()=>{try{return JSON.parse(line.slice(26));}catch{return null;}})());
            if(parsed.success&&parsed.data.profile===input.profile)
              lastMetrics=parsed.data;
          }
        }
      });
    });
    if(startup!==true)throw Error("CONFINED_BROKER_UNAVAILABLE");
    if(startupTimer){clearTimeout(startupTimer);startupTimer=null;}
    if(input.signal.aborted)throw Error("CONFINED_BROKER_CANCELLED");
    const socketStat=await stat(join(socketDirectory,"request.sock")).catch(error=>{
      if(input.signal.aborted)throw Error("CONFINED_BROKER_CANCELLED");
      throw error;
    });
    if(input.signal.aborted)throw Error("CONFINED_BROKER_CANCELLED");
    if(!socketStat.isSocket()||complete)
      throw Error("CONFINED_BROKER_SOCKET_NOT_READY");
    const onAbort=()=>{
      const killer=spawn("docker",["kill","--signal","KILL",containerName],
        {env:limitedEnv,stdio:"ignore"});
      killer.on("error",()=>undefined);
    };
    input.signal.addEventListener("abort",onAbort,{once:true});
    if(input.signal.aborted)onAbort();
    let closing=false;
    return {
      socketDirectory,containerName,networkMode:"none" as const,
      stats:()=>Object.freeze({...lastMetrics}),
      async awaitAccounting(requests:number){
        for(let i=0;i<30;i++){
          if(lastMetrics.requests===requests&&lastMetrics.active===0)return {...lastMetrics};
          if(stopped||input.signal.aborted)break;
          await pause(20);
        }
        throw Error("CONFINED_BROKER_ACCOUNTING_UNAVAILABLE");
      },
      async close(){
        if(closing)return;
        closing=true;
        input.signal.removeEventListener("abort",onAbort);
        if(!stopped){
          const killer=spawn("docker",["kill","--signal","KILL",containerName],
            {env:limitedEnv,stdio:"ignore"});
          killer.on("error",()=>undefined);
          await Promise.race([
            new Promise<void>(ok=>child.once("close",()=>ok())),
            pause(2500).then(()=>{child.kill("SIGKILL");}),
          ]);
        }
        await rm(directory,{recursive:true,force:true});
      },
    };
  }catch(error){
    if(startupTimer)clearTimeout(startupTimer);
    if(container&&!stopped){
      const killer=spawn("docker",["kill","--signal","KILL",containerName],
        {env:limitedEnv,stdio:"ignore"});
      killer.on("error",()=>undefined);
      container.kill("SIGKILL");
    }
    await rm(directory,{recursive:true,force:true});
    if(input.signal.aborted)throw Error("CONFINED_BROKER_CANCELLED");
    throw error;
  }
}
