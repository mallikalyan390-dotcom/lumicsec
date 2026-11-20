/* LOCAL DEVELOPMENT-ONLY Linux network namespace acceptance.
 * Creates a uniquely named Docker --internal bridge and three pinned
 * non-root containers (two owned TLS fixtures and a broker namespace holder).
 * Applies nftables OUTPUT policy ONLY inside holder's network namespace with
 * a one-shot NET_ADMIN installer; no running broker/worker holds NET_ADMIN.
 * Never modifies host firewall, routable external DNS, or real customer URLs.
 * Complete cleanup in finally. Do not expose as Fastify route.
 */
import {execFileSync} from "node:child_process";
import {Buffer} from "node:buffer";
import {randomUUID,createHash} from "node:crypto";
import {mkdtempSync,mkdirSync,statSync,readFileSync,
  writeFileSync,chmodSync,rmSync} from "node:fs";
import {createBrokerSigningKeys,signControlledBrokerScope}
  from "../src/workers/broker-scope-ticket.ts";
import {CONTROLLED_RUNTIME_VERSION,parseControlledResult}
  from "../src/workers/controlled-runtime-contract.ts";
import {tmpdir} from "node:os";
import process from "node:process";
import {setTimeout} from "node:timers";
import {join,resolve} from "node:path";
import {compileNamespaceEgressPolicy} from "../src/workers/restricted-egress-firewall.ts";
const image="sha256:35e7c432242067a653e10bd96d9de5913ad35e60b884f2245ec7e43a41dc38f2";
const prefix="lumicsec-nft-"+randomUUID().slice(0,8);
const network=prefix+"-internal";
const guard=prefix+"-guard";
const allowed=prefix+"-allowed";
const forbidden=prefix+"-forbidden";
const work=mkdtempSync(join(tmpdir(),"lumicsec-nft-"));
const file=(name)=>join(work,name);
const cwd=resolve(process.cwd());
const fixtureScript=resolve(cwd,"scripts/restricted-egress-tls-fixture.mjs");
const probeScript=resolve(cwd,"scripts/restricted-egress-netns-probe.mjs");
let createdNetwork=false;
const started=[];
const docker=(args,timeout=15000)=>execFileSync("docker",args,{
  timeout,encoding:"utf8",maxBuffer:160000,env:{
    PATH:process.env.PATH??"/usr/bin:/bin",HOME:"/tmp",
  },
}).trim();
const start=(name,args)=>{
  docker(["run","--detach","--rm","--pull","never",
    "--name",name,...args]);
  started.push(name);
};
const mount=(source,target)=>["--mount",
  "type=bind,src="+source+",dst="+target+",readonly"];
const common=[
  "--read-only","--cap-drop","ALL","--security-opt","no-new-privileges",
  "--pids-limit","24","--memory","128m","--memory-swap","128m",
  "--cpus","0.5","--tmpfs","/tmp:rw,nosuid,nodev,size=16m",
];
const runProbe=(mode,ip,other)=>{
 const result=docker([
  "run","--rm","--pull","never","--network","container:"+guard,
  ...common,"--user","65534:65534",
  ...mount(probeScript,"/opt/fixture/probe.mjs"),
  ...mount(file("certificate.crt"),"/opt/fixture/certificate.crt"),
  "--env","LUMICSEC_ALLOWED_IP="+ip,"--env","LUMICSEC_DENIED_IP="+other,
  "--env","LUMICSEC_PROBE_MODE="+mode,
  "--entrypoint","/usr/bin/node",image,"/opt/fixture/probe.mjs",
 ],25000);
 const report=JSON.parse(result);
 if(report.status!=="PASS"||report.mode!==mode)throw Error("EGRESS_PROBE_FAILED");
 return report;
};
const runNetworkNoneWorker=(socketDir,executionId,jobId,scopeHash)=>{
 const input={
   protocol:CONTROLLED_RUNTIME_VERSION,type:"START",executionId,
   mode:"web",scope:{
     jobId,organizationId:randomUUID(),assetId:randomUUID(),
     actorId:randomUUID(),origin:"https://controlled-web.fixture-web.net",
     scopeHash,
   },
 };
 let raw;
 try{
   raw=execFileSync("docker",[
     "run","--rm","--interactive","--pull","never",
     "--network","none",...common,"--user","65534:65534",
     "--workdir","/tmp","--ulimit","nofile=64:64",
     ...mount(resolve(cwd,"dist/isolated/runtime-worker.mjs"),
       "/opt/lumicsec-runtime/worker.mjs"),
     ...mount(socketDir,"/opt/lumicsec-broker"),
     "--env","LUMICSEC_CONTROLLED_FIXTURE=yes",
     "--entrypoint","/usr/bin/node",image,
     "/opt/lumicsec-runtime/worker.mjs",
   ],{
     input:JSON.stringify(input)+"\n",encoding:"utf8",
     timeout:20000,maxBuffer:160000,
     env:{PATH:process.env.PATH??"/usr/bin:/bin",HOME:"/tmp"},
   });
 }catch{throw Error("EGRESS_SIGNED_REMOTE_WORKER_FAILED");}
 const result=parseControlledResult(raw.trim(),input);
 if(result.mode!=="web"||
   result.report.classification!=="PASSIVE_WEB_REVIEW"||
   result.report.requests!==1||
   result.observations.some(o=>o.evidenceSource.paths.some(p=>p!=="/"))||
   result.observations.some(o=>o.ruleId==="P09.HSTS.ABSENT"))
   throw Error("EGRESS_SIGNED_REMOTE_WORKER_EVIDENCE_DENIED");
 return {workerNetworkMode:"none",classification:result.report.classification,
   requests:result.report.requests,observations:result.observations.length,
   evidenceValidated:true};
};
const rejectOutOfScopeSocket=(socketDir,executionId)=>{
 const script=`const net=require("node:net");
 const s=net.connect({path:"/opt/lumicsec-broker/request.sock"});
 let received=false,connected=false;
 const timeout=setTimeout(()=>{s.destroy();process.exit(9);},1500);
 s.on("connect",()=>{
   connected=true;
   s.write(JSON.stringify({
     protocol:"CONTROLLED_RUNTIME_BROKER_V1",
     executionId:process.env.LUMICSEC_EXECUTION_ID,
     origin:"https://controlled-web.fixture-web.net",
     url:"https://controlled-web.fixture-web.net/redirect",
     identity:"anonymous",method:"GET",
   })+"\\n");
 });
 s.on("data",()=>{received=true;});
 s.on("error",()=>{clearTimeout(timeout);process.exit(9);});
 s.on("close",()=>{
   clearTimeout(timeout);
   if(!connected||received)process.exit(8);
   process.stdout.write("BROKER_OUT_OF_SCOPE_DENIED\\n");
 });`;
 let outcome;
 try{
   outcome=docker(["run","--rm","--pull","never","--network","none",
     ...common,"--user","65534:65534",
     ...mount(socketDir,"/opt/lumicsec-broker"),
     "--env","LUMICSEC_EXECUTION_ID="+executionId,
     "--entrypoint","/usr/bin/node",image,"-e",script],5000);
 }catch{throw Error("BROKER_OUT_OF_SCOPE_NOT_DENIED");}
 if(outcome!=="BROKER_OUT_OF_SCOPE_DENIED")
   throw Error("BROKER_OUT_OF_SCOPE_NOT_DENIED");
 return true;
};
const runSignedBrokerStartup=async(phase,remoteIp)=>{
 const name=prefix+"-signed-"+phase;
 const executionId=randomUUID(),jobId=randomUUID(),planId=randomUUID();
 const workerId=randomUUID(),scopeHash="c".repeat(64),generation=1;
 const socketDir=file("signed-socket-"+phase);
 const ledger=file("signed-ledger-"+phase);
 const publicKey=file("signed-public-"+phase+".pem");
 const bundle=resolve(cwd,"dist/isolated/confined-broker.mjs");
 mkdirSync(socketDir,{mode:0o700});
 mkdirSync(ledger,{mode:0o700});
 for(const dir of [socketDir,ledger]){
   execFileSync("/bin/setfacl",["-m","u:65534:rwx",dir],{
     timeout:2500,stdio:"ignore",
   });
 }
 const keys=createBrokerSigningKeys();
 writeFileSync(publicKey,keys.publicKeyPem,{mode:0o444,flag:"wx"});
 const scoped={approvedPaths:["/"],maxRequests:1,
   maxResponseBytes:60000,maxTotalBytes:240000,maxExecutionMs:15000};
 const expected={jobId,planId,workerId,generation,scopeHash};
 const signed=signControlledBrokerScope({
   executionId,...expected,origin:"https://controlled-web.fixture-web.net",
   profile:"web_insecure",...scoped,
   ...(remoteIp?{controlledFixtureDestination:{
     ipv4:remoteIp,caSha256:createHash("sha256")
       .update(readFileSync(file("certificate.crt"))).digest("hex"),
   }}:{}),
 },keys.privateKey);
 // Diagnostic reproduces signed broker startup before and after nft DROP.
 // The after-nft variant additionally performs ONE brokered remote fixture
 // GET from a separate network-none worker; never an external public target.
 docker(["run","--detach","--pull","never","--name",name,
   "--network","container:"+guard,...common,"--user","65534:65534",
   "--workdir","/tmp","--ulimit","nofile=64:64",
   "--mount","type=bind,src="+bundle+
     ",dst=/opt/lumicsec-runtime/broker.mjs,readonly",
   "--mount","type=bind,src="+socketDir+",dst=/opt/lumicsec-broker",
   ...mount(publicKey,"/opt/lumicsec-admission/public-key.pem"),
   "--mount","type=bind,src="+ledger+",dst=/opt/lumicsec-ticket-ledger",
   ...(remoteIp?[
     ...mount(file("certificate.crt"),
       "/opt/lumicsec-broker-ca/certificate.crt"),
     "--env","LUMICSEC_BROKER_REMOTE_FIXTURE_ACCEPTED=yes",
     "--env","LUMICSEC_BROKER_REMOTE_FIXTURE_IP="+remoteIp,
   ]:[]),
   "--env","LUMICSEC_CONTROLLED_FIXTURE=yes",
   "--env","LUMICSEC_BROKER_PROFILE=web_insecure",
   "--env","LUMICSEC_BROKER_EXECUTION_ID="+executionId,
   "--env","LUMICSEC_BROKER_REQUIRE_TICKET=yes",
   "--env","LUMICSEC_BROKER_SCOPED="+JSON.stringify(scoped),
   "--env","LUMICSEC_BROKER_EXPECTED="+Buffer.from(
     JSON.stringify(expected)).toString("base64url"),
   "--env","LUMICSEC_BROKER_SIGNED_TICKET="+Buffer.from(
     JSON.stringify(signed)).toString("base64url"),
   "--entrypoint","/usr/bin/node",image,
   "/opt/lumicsec-runtime/broker.mjs"],15000);
 started.push(name);
 let ready=false,exitCode=null;
 for(let i=0;i<55;i++){
   const logs=docker(["logs","--tail","10",name],3000);
   if(logs.split("\n").includes("CONTROLLED_BROKER_READY")){
     ready=true;break;
   }
   const state=docker(["inspect","--format",
     "{{.State.Running}}:{{.State.ExitCode}}",name]);
   if(!state.startsWith("true:")){
     exitCode=state.split(":")[1];break;
   }
   await new Promise(ok=>setTimeout(ok,100));
 }
 if(!ready){
   throw Error("SIGNED_BROKER_NAMESPACE_STARTUP_FAILED_"+(exitCode??"TIMEOUT"));
 }
 const mode=docker(["inspect","--format","{{.HostConfig.NetworkMode}}",name]);
 const guardId=docker(["inspect","--format","{{.Id}}",guard]);
 const user=docker(["inspect","--format","{{.Config.User}}",name]);
 if(mode!=="container:"+guard&&mode!=="container:"+guardId)
   throw Error("SIGNED_BROKER_NAMESPACE_MODE_MISMATCH");
 if(user!=="65534:65534")
   throw Error("SIGNED_BROKER_NAMESPACE_USER_MISMATCH");
 if(!statSync(join(socketDir,"request.sock")).isSocket())
   throw Error("SIGNED_BROKER_NAMESPACE_SOCKET_MISSING");
 const outOfScopeRejected=remoteIp?
   rejectOutOfScopeSocket(socketDir,executionId):false;
 const remoteWorker=remoteIp?
   runNetworkNoneWorker(socketDir,executionId,jobId,scopeHash):null;
 docker(["rm","--force",name],7000);
 started.splice(started.indexOf(name),1);
 return {phase,ready:true,exit139:false,signed:true,
   networkNamespaceRestricted:phase==="after_nft",nonRoot:true,
   ...(remoteWorker?{remoteWorker,outOfScopeRejected}:{}),
 };
};
try{
 if(process.env["LUMICSEC_RUN_RESTRICTED_EGRESS"]!=="1")
   throw Error("EXPLICIT_LOCAL_EGRESS_OPT_IN_REQUIRED");
 // 1) All actual TCP targets stay strictly within a temporary isolated
 // Docker-only network. Public destination rules are compiled but never
 // installed/called without explicit founder target authorization.
 const offlinePublic=compileNamespaceEgressPolicy({
   grants:[{address:"8.8.8.8",family:4,port:443},
     {address:"2606:4700:4700::1111",family:6,port:443}],
 });
 if(offlinePublic.controlledFixtureOnly||offlinePublic.executionAllowed!==false||
   !offlinePublic.nftSource.includes("ip6 daddr 2606:4700:4700::1111"))
   throw Error("EGRESS_PUBLIC_POLICY_OFFLINE_CONTRACT_FAILED");
 // Ephemeral synthetic certificate/key are not company credentials.
 // Parent directory is private (0700), mounts are read-only and restricted
 // to controlled fixture containers. Untrusted broker/worker NEVER mount key.
 execFileSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes",
   "-keyout",file("private.key"),"-out",file("certificate.crt"),
   "-days","1","-subj","/CN=controlled-web.fixture-web.net",
   "-addext","subjectAltName=DNS:controlled-web.fixture-web.net"],{
     stdio:"ignore",timeout:5000,
   });
 chmodSync(file("private.key"),0o444);
 chmodSync(file("certificate.crt"),0o444);
 docker(["network","create","--driver","bridge","--internal",network]);
 createdNetwork=true;
 for(const name of [allowed,forbidden]){
   start(name,[
    "--network",network,...common,"--user","65534:65534",
    ...mount(fixtureScript,"/opt/fixture/server.mjs"),
    ...mount(file("private.key"),"/opt/fixture/private.key"),
    ...mount(file("certificate.crt"),"/opt/fixture/certificate.crt"),
    "--entrypoint","/usr/bin/node",image,"/opt/fixture/server.mjs",
   ]);
 }
 start(guard,[
   "--network",network,...common,"--user","65534:65534",
   "--entrypoint","/bin/sleep",image,"100",
 ]);
 const ip=(name)=>docker(["inspect","--format",
   "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",name]);
 const allowedIp=ip(allowed),deniedIp=ip(forbidden);
 if(allowedIp===deniedIp||!/^172\.(1[6-9]|2\d|3[01])\.|^10\.|^192\.168\./.test(allowedIp))
   throw Error("TEST_DOCKER_SUBNET_UNEXPECTED");
 let baseline;
 for(let i=0;i<8;i++){
   try{baseline=runProbe("baseline",allowedIp,deniedIp);break;}
   catch(e){
     if(i===7)throw e;
     await new Promise(ok=>setTimeout(ok,180));
   }
 }
 const signedBefore=await runSignedBrokerStartup("before_nft");
 const policy=compileNamespaceEgressPolicy({controlledFixtureOnly:true,
   grants:[{address:allowedIp,family:4,port:443}]});
 writeFileSync(file("policy.nft"),policy.nftSource,{mode:0o444});
 // 2) One short-lived installer with NET_ADMIN, network namespace of ONLY
 // our newly created guard container; no host networking or privileged app.
 const nftArgs=[
   "run","--rm","--pull","never","--network","container:"+guard,
   "--read-only","--cap-drop","ALL","--cap-add","NET_ADMIN",
   "--security-opt","no-new-privileges","--user","0",
   ...mount("/lib/x86_64-linux-gnu","/compat/lib"),
   ...mount("/usr/sbin/nft","/compat/nft"),
   ...mount(file("policy.nft"),"/opt/policy.nft"),
   "--entrypoint","/compat/lib/ld-linux-x86-64.so.2",image,
   "--library-path","/compat/lib","/compat/nft",
 ];
 docker([...nftArgs,"-f","/opt/policy.nft"]);
 const rules=docker([...nftArgs,"list","table","inet","lumicsec_guard"]);
 if(!rules.includes("policy drop")||!rules.includes(allowedIp)||
    !rules.includes("tcp dport 443"))
   throw Error("EGRESS_NFT_POLICY_NOT_INSTALLED");
 // 3) Probe runs as unprivileged application container with ZERO NET_ADMIN
 // in the guard's already locked namespace. Private fixture excepted ONLY
 // for the isolated test; same-subnet unauthorized fixture is not reachable.
 const after=runProbe("enforced",allowedIp,deniedIp);
 const signedAfter=await runSignedBrokerStartup("after_nft",allowedIp);
 if(!after.attempts.find(x=>x.label==="listening_localhost_blocked"&&!x.ok)||
   !after.attempts.find(x=>x.label==="actual_pinned_tls_correct_hostname"&&x.ok))
   throw Error("EGRESS_NFT_NEGATIVE_OR_TLS_EVIDENCE_MISSING");
 const options=docker(["network","inspect",network,"--format","{{.Internal}}"]);
 if(options!=="true")throw Error("DOCKER_NETWORK_MUST_BE_INTERNAL");
 process.stdout.write(JSON.stringify({
   result:"RESTRICTED_EGRESS_LOCAL_NETWORK_NAMESPACE_PASS",
   policySha256:policy.sha256,networkInternal:true,
   fixtureOnly:true,actualPublicScans:0,publicEgressQualified:false,
   osExactDestinations:[allowedIp+":443"],baseline:baseline.attempts,
   enforced:after.attempts,nftRulesetInstalled:true,
   signedBrokerStartup:[signedBefore,signedAfter],
   unprivilegedRuntime:true,oneShotNetAdmin:true,
 })+"\n");
}catch(error){
 process.stderr.write("RESTRICTED_EGRESS_FAIL_CLOSED "+
   (error?.message??"UNKNOWN")+"\n");
 process.exitCode=1;
}finally{
 // Exact UUID names; do not touch the founder's unrelated Docker networks
 // or containers. Incomplete cleanup is an error, never silently ignored.
 for(const name of [...started].reverse()){
   try{docker(["rm","--force",name],7000);}catch{
     process.stderr.write("RESTRICTED_EGRESS_CLEANUP_CONTAINER_FAILED "+name+"\n");
     process.exitCode=1;
   }
 }
 if(createdNetwork){
   try{docker(["network","rm",network],7000);}catch{
     process.stderr.write("RESTRICTED_EGRESS_CLEANUP_NETWORK_FAILED "+network+"\n");
     process.exitCode=1;
   }
 }
 rmSync(work,{recursive:true,force:true});
}