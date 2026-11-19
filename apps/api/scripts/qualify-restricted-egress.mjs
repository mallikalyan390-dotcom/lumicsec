/* LOCAL DEVELOPMENT-ONLY Linux network namespace acceptance.
 * Creates a uniquely named Docker --internal bridge and three pinned
 * non-root containers (two owned TLS fixtures and a broker namespace holder).
 * Applies nftables OUTPUT policy ONLY inside holder's network namespace with
 * a one-shot NET_ADMIN installer; no running broker/worker holds NET_ADMIN.
 * Never modifies host firewall, routable external DNS, or real customer URLs.
 * Complete cleanup in finally. Do not expose as Fastify route.
 */
import {execFileSync} from "node:child_process";
import {randomUUID} from "node:crypto";
import {mkdtempSync,writeFileSync,chmodSync,rmSync} from "node:fs";
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