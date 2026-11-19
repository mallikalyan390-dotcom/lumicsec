/* Runs as non-root CAP_DROP=ALL with broker namespace network isolation.
 * All connection attempts occur on a Docker --internal bridge and cannot
 * reach actual public websites. Never accepts an arbitrary hostname or URL.
 */
import {request} from "node:https";
import {connect,createServer} from "node:net";
import {readFileSync} from "node:fs";
import process from "node:process";
const allow=process.env["LUMICSEC_ALLOWED_IP"];
const other=process.env["LUMICSEC_DENIED_IP"];
const mode=process.env["LUMICSEC_PROBE_MODE"];
if(!allow||!other||!["baseline","enforced"].includes(mode))
  throw Error("PROBE_MODE_MISSING");
const ca=readFileSync("/opt/fixture/certificate.crt");
const attempts=[];
async function socketAttempt(ip,port=443,family=4) {
 const start=Date.now();
 return await new Promise(resolve=>{
  const socket=connect({host:ip,port,family});
  let done=false;
  const finish=(ok,reason)=>{
   if(done)return;done=true;
   socket.destroy();resolve({ok,reason,elapsedMs:Date.now()-start});
  };
  socket.setTimeout(450,()=>finish(false,"TIMEOUT"));
  socket.once("connect",()=>finish(true,"CONNECTED"));
  socket.once("error",e=>finish(false,e.code??"SOCKET_ERROR"));
 });
}
async function tlsGet(host,path="/") {
 return await new Promise(resolve=>{
  let n=0,complete=false;
  const finish=(result)=>{
   if(complete)return;complete=true;
   requestObject.destroy();resolve(result);
  };
  const requestObject=request({
    hostname:"controlled-web.fixture-web.net",servername:host,port:443,
    method:"GET",path,ca,agent:false,rejectUnauthorized:true,
    headers:{host:"controlled-web.fixture-web.net"},
    lookup:(name,_opts,callback)=>{
      if(name!=="controlled-web.fixture-web.net"){
        callback(Error("DNS_PIN_HOST_MISMATCH"),"",4);return;
      }
      if(_opts.all)callback(null,[{address:allow,family:4}]);
      else callback(null,allow,4);
    },
  },response=>{
    if(response.statusCode>=300&&response.statusCode<400){
      finish({ok:false,code:"REDIRECT_DENIED",status:response.statusCode});
      return;
    }
    response.on("data",part=>{
      n+=part.length;
      if(n>60000)finish({ok:false,code:"RESPONSE_BUDGET"});
    });
    response.on("end",()=>finish({ok:true,status:response.statusCode,bytes:n}));
  });
  requestObject.setTimeout(1300,()=>finish({ok:false,code:"TIMEOUT"}));
  requestObject.on("error",error=>finish({ok:false,
    code:error.code??"TLS_OR_NETWORK_FAILED"}));
  requestObject.end();
 });
}
function emit(label,value){attempts.push({label,...value});}
try{
 const baseline=mode==="baseline";
 emit("allowed_tcp",await socketAttempt(allow));
 emit("same_bridge_unapproved_tcp",await socketAttempt(other));
 if(baseline){
  if(!attempts[0].ok||!attempts[1].ok)
    throw Error("UNPROTECTED_PRECONDITION_NOT_MET");
 }else{
  if(!attempts[0].ok||attempts[1].ok)
    throw Error("KERNEL_EXACT_IP_ALLOWLIST_FAILED");
  const allowedTls=await tlsGet("controlled-web.fixture-web.net");
  emit("actual_pinned_tls_correct_hostname",allowedTls);
  if(!allowedTls.ok||allowedTls.status!==200||allowedTls.bytes<10)
    throw Error("PINNED_SAN_TLS_FAILED");
  const badTls=await tlsGet("wrong.fixture-web.net");
  emit("wrong_tls_sni_and_certificate",badTls);
  if(badTls.ok||badTls.code!=="ERR_TLS_CERT_ALTNAME_INVALID")
    throw Error("TLS_HOSTNAME_VERIFICATION_BYPASSED");
  const redirect=await tlsGet("controlled-web.fixture-web.net","/redirect");
  emit("metadata_redirect_not_followed",redirect);
  if(redirect.ok||redirect.code!=="REDIRECT_DENIED")
    throw Error("OUT_OF_SCOPE_REDIRECT_FOLLOWED");
  const oversize=await tlsGet("controlled-web.fixture-web.net","/oversize");
  emit("response_limit",oversize);
  if(oversize.ok||oversize.code!=="RESPONSE_BUDGET")
    throw Error("UNBOUNDED_HTTPS_READ");
  for(const [name,address,port,family] of [
    ["allowed_ip_wrong_port",allow,8443,4],
    ["metadata_ipv4","169.254.169.254",443,4],
    ["private_ipv4","10.1.2.3",443,4],
    ["public_ipv4_blocked_by_internal_network","1.1.1.1",443,4],
    ["ipv6_public","2001:4860:4860::8888",443,6],
    ["ipv6_ula","fd00::1",443,6],
    ["ipv4_mapped_ipv6","::ffff:10.0.0.1",443,6],
  ]){
    const result=await socketAttempt(address,port,family);
    emit(name,result);
    if(result.ok)throw Error("KERNEL_NETWORK_DENIAL_FAILED_"+name);
  }
  // A listening local endpoint removes the "nothing bound there" ambiguity:
  // output policy must deny localhost even when a service is listening.
  const local=createServer(socket=>socket.end("unexpected_loopback"));
  await new Promise((ok,bad)=>{
    local.once("error",bad);local.listen(9443,"127.0.0.1",ok);
  });
  try{
    const loop=await socketAttempt("127.0.0.1",9443);
    emit("listening_localhost_blocked",loop);
    if(loop.ok)throw Error("KERNEL_LOOPBACK_DENIAL_FAILED");
  }finally{local.close();}
 }
 process.stdout.write(JSON.stringify({mode,status:"PASS",attempts})+"\n");
}catch(error){
 process.stderr.write(JSON.stringify({mode,status:"FAIL",
  message:error.message,attempts})+"\n");
 process.exitCode=1;
}