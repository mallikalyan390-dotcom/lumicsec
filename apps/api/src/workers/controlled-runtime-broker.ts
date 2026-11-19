/* CONTROLLED-FIXTURE ONLY host-side HTTPS request broker.
 * Worker remains in --network none and communicates over an AF_UNIX socket.
 * This module is deliberately NOT reachable from customer API routes or
 * runtime workers. No cloud, real domain, customer identities or secrets.
 */
import { createServer as createUnixServer, type Server as UnixServer } from "node:net";
import { createServer as createHttpsServer, request as httpsRequest,
  type Server as TlsServer, type RequestOptions } from "node:https";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { PublicPinnedWebTransport, requireExactWebUrl,
  type HttpsRequestFactory } from "../lib/web-pinned-transport.js";

export const BROKER_PROTOCOL = "CONTROLLED_RUNTIME_BROKER_V1";
export const brokerRequestSchema = z.strictObject({
  protocol:z.literal(BROKER_PROTOCOL),
  executionId:z.string().uuid(),
  origin:z.string().max(250).regex(/^https:\/\/[a-z0-9.-]{4,240}$/),
  url:z.string().max(400),
  identity:z.enum(["anonymous","owner","other"]),
  method:z.literal("GET"),
});
const brokerReplySchema=z.strictObject({
  status:z.number().int().min(100).max(599),
  headers:z.record(z.string(),z.string().max(1800)),
  body:z.string().max(80_000),
  sha256:z.string().regex(/^[a-f0-9]{64}$/),
});
export type BrokerReply=z.infer<typeof brokerReplySchema>;
export type ControlledProfile="web_insecure"|"web_secure"|"web_redirect"|"web_oversize"|
  "web_slow"|"api_insecure"|"api_secure"|"api_redirect"|"api_oversize"|"api_slow";
const apiProfiles=new Set(["api_insecure","api_secure","api_redirect","api_oversize","api_slow"]);
const secretSynthetic=Object.freeze({
  owner:"SYNTHETIC_OWNER_FIXTURE_ONLY",
  other:"SYNTHETIC_OTHER_FIXTURE_ONLY",
});
const strictHostname=(mode:ControlledProfile)=>mode.startsWith("web_")
  ?"controlled-web.fixture-web.net":"controlled-api.fixture-api.net";
function bounds(value:unknown,max:number) {
  const json=JSON.stringify(value);
  if(Buffer.byteLength(json)>max)throw Error("BROKER_BOUND_EXCEEDED");
  return json;
}
export function fixtureOrigin(profile:ControlledProfile){
  return "https://"+strictHostname(profile);
}
export async function openControlledRuntimeBroker(input:Readonly<{
  executionId:string; origin:string; profile:ControlledProfile; signal:AbortSignal;
  maxRequests?:number;
  /** Only the test-only broker container may mount this fixed AF_UNIX path. */
  socketDirectory?:"/opt/lumicsec-broker";
  onStatistics?:(stats:Readonly<{requests:number;bytes:number;failures:number;
    active:number;externalRequests:0;profile:ControlledProfile}>)=>void;
}>) {
  const origin=fixtureOrigin(input.profile);
  if(input.origin!==origin||!z.string().uuid().safeParse(input.executionId).success||
    input.signal.aborted)throw Error("BROKER_TEST_SCOPE_DENIED");
  const directory=await mkdtemp(join(tmpdir(),"lumicsec-controlled-broker-"));
  const socketDirectory=input.socketDirectory??join(directory,"broker-only");
  if(!input.socketDirectory)await mkdir(socketDirectory,{mode:0o755});
  const socketPath=join(socketDirectory,"request.sock");
  let tls:TlsServer|null=null;
  let unix:UnixServer|null=null;
  const sockets=new Set<import("node:net").Socket>();
  const aborters=new Set<AbortController>();
  let used=0,bytes=0,active=0;
  let failure=0;
  const maxRequests=Math.min(input.maxRequests??6,8);
  const started=Date.now();
  const keyPath=join(directory,"test-only.key"), certPath=join(directory,"test-only.crt");
  const failClosed=()=>{for(const a of aborters)a.abort();
    for(const socket of sockets)socket.destroy();tls?.closeAllConnections();};
  input.signal.addEventListener("abort",failClosed,{once:true});
  try{
    const hostname=new URL(origin).hostname;
    execFileSync("/usr/bin/openssl",["req","-x509","-newkey","rsa:2048","-nodes",
      "-keyout",keyPath,"-out",certPath,"-days","1","-subj","/CN="+hostname,
      "-addext","subjectAltName=DNS:"+hostname],{stdio:"ignore",timeout:4_000});
    const certificate=await readFile(certPath);
    const webSecure=input.profile==="web_secure";
    const apiSecure=input.profile==="api_secure";
    tls=createHttpsServer({key:await readFile(keyPath),cert:certificate},
      (request,response)=>{
        if(request.headers.host!==hostname || request.method!=="GET" ||
          request.url?.includes("?") || request.url?.includes("#")){
          response.writeHead(403).end();return;
        }
        if(input.profile.endsWith("_redirect")){
          response.writeHead(302,{location:"https://169.254.169.254/latest/meta-data/"});
          response.end();return;
        }
        if(input.profile.endsWith("_oversize")){
          response.writeHead(200,{"content-type":"text/html"});
          response.end("x".repeat(90_000));return;
        }
        if(input.profile.endsWith("_slow")){
          setTimeout(()=>{if(!response.writableEnded)response.end("controlled timeout");},5_000).unref();
          return;
        }
        const securityHeaders=webSecure||apiSecure?{
          "strict-transport-security":"max-age=31536000",
          "x-content-type-options":"nosniff",
          "x-frame-options":"DENY",
          "content-security-policy":"default-src 'self';frame-ancestors 'none'",
        }:{};
        if(!apiProfiles.has(input.profile)){
          response.writeHead(200,{"content-type":"text/html",
            "set-cookie":webSecure?"session=synthetic; Secure; HttpOnly; SameSite=Strict":
              "session=synthetic; Path=/",...securityHeaders});
          response.end("<html><body>controlled owned HTTPS fixture</body></html>");return;
        }
        const auth=request.headers.authorization??"";
        const isOwner=auth==="Bearer "+secretSynthetic.owner;
        const isOther=auth==="Bearer "+secretSynthetic.other;
        const path=request.url??"/";
        if(!["/v1/health","/v1/accounts/owner"].includes(path)){
          response.writeHead(404,securityHeaders).end();return;
        }
        if(path==="/v1/health"){
          response.writeHead(200,{"content-type":"application/json",...securityHeaders});
          response.end('{"status":"ok"}');return;
        }
        if(apiSecure && !isOwner&&!isOther){
          response.writeHead(401,{"content-type":"application/json",...securityHeaders});
          response.end('{"error":"AUTH_REQUIRED"}');return;
        }
        if(apiSecure && isOther){
          response.writeHead(403,{"content-type":"application/json",...securityHeaders});
          response.end('{"error":"OBJECT_ACCESS_DENIED"}');return;
        }
        response.writeHead(200,{"content-type":"application/json",...securityHeaders});
        response.end('{"account":"synthetic-owner","synthetic":true}');
      });
    await new Promise<void>((ok,bad)=>{
      tls!.once("error",bad);tls!.listen(0,"127.0.0.1",()=>{tls!.off("error",bad);ok();});
    });
    const address=tls.address();
    if(!address||typeof address==="string")throw Error("BROKER_FIXTURE_LISTEN_FAILED");
    const factory:HttpsRequestFactory=(opts:RequestOptions,callback)=>httpsRequest({
      ...opts,port:address.port,ca:certificate,
      lookup:(_host,settings,answer)=>{
        if(settings.all){
          const all=answer as (err:Error|null,values:{address:string;family:number}[])=>void;
          all(null,[{address:"127.0.0.1",family:4}]);
        }else answer(null,"127.0.0.1",4);
      },
    },callback);
    // Non-public test-only socket substitution (never available to customer).
    // Production PublicPinnedWebTransport retains its public-only DNS + IP pinning.
    const transport=new PublicPinnedWebTransport(
      async()=>[{address:"8.8.8.8",family:4}],factory);
    unix=createUnixServer(socket=>{
      sockets.add(socket);
      let text="",answered=false;
      socket.setTimeout(5_000,()=>socket.destroy());
      const reject=()=>{failure++;socket.destroy();};
      socket.on("data",part=>{
        if(answered)return reject();
        text+=part.toString("utf8");
        if(Buffer.byteLength(text)>1_500)return reject();
        const newline=text.indexOf("\n");
        if(newline<0)return;
        if(newline!==text.length-1)return reject();
        answered=true;
        let req:z.infer<typeof brokerRequestSchema>;
        try{req=brokerRequestSchema.parse(JSON.parse(text.slice(0,-1)));}
        catch{return reject();}
        if(req.protocol!==BROKER_PROTOCOL||req.executionId!==input.executionId||
          req.origin!==origin||input.signal.aborted||Date.now()-started>15_000||
          active>=1||used>=maxRequests)return reject();
        // A compromised worker may send an arbitrary string. Validate before
        // parsing URL components: malformed input must never crash the broker.
        let authorizedUrl:URL;
        try{authorizedUrl=requireExactWebUrl(req.url,origin);}
        catch{return reject();}
        if(apiProfiles.has(input.profile)){
          if(!["/v1/health","/v1/accounts/owner"].includes(authorizedUrl.pathname))
            return reject();
        }else if(req.identity!=="anonymous")return reject();
        active++;used++;
        const ac=new AbortController();aborters.add(ac);
        const abort=()=>ac.abort();
        input.signal.addEventListener("abort",abort,{once:true});
        const identity=req.identity;
        // Public transport NEVER carries auth headers. Synthetic API auth for
        // controlled fixture is implemented in the test-only request factory.
        const selected:HttpsRequestFactory=(options,callback)=>
          factory({...options,headers:{...options.headers,
            ...(identity==="anonymous"?{}:{
              authorization:"Bearer "+secretSynthetic[identity],
            })}},callback);
        const local=new PublicPinnedWebTransport(
          async()=>[{address:"8.8.8.8",family:4}],selected);
        void (identity==="anonymous"?transport:local).read(origin,req.url,{
          signal:ac.signal,maxBytes:Math.min(60_000,240_000-bytes),
        }).then(response=>{
          bytes+=response.bodyBytes.byteLength;
          const result=brokerReplySchema.parse({
            status:response.status,headers:response.headers,
            body:Buffer.from(response.bodyBytes).toString("base64"),
            sha256:createHash("sha256").update(response.bodyBytes).digest("hex"),
          });
          if(!socket.destroyed&&!input.signal.aborted)
            socket.end(bounds(result,90_000)+"\n");
        }).catch(()=>reject()).finally(()=>{
          active--;aborters.delete(ac);
          input.signal.removeEventListener("abort",abort);
          input.onStatistics?.({requests:used,bytes,failures:failure,active,
            externalRequests:0,profile:input.profile});
        });
      });
      socket.on("close",()=>sockets.delete(socket));
      socket.on("error",()=>undefined);
    });
    await new Promise<void>((ok,bad)=>{
      unix!.once("error",bad);unix!.listen(socketPath,()=>{unix!.off("error",bad);ok();});
    });
    await chmod(socketPath,input.socketDirectory?0o600:0o666);
    if(!input.socketDirectory)await chmod(socketDirectory,0o755);
    return {
      socketDirectory,
      stats:()=>Object.freeze({requests:used,bytes,failures:failure,active,
        externalRequests:0,profile:input.profile}),
      async close(){
        failClosed();
        for(const socket of sockets)socket.destroy();
        await Promise.all([
          new Promise<void>(ok=>unix?.close(()=>ok())),
          new Promise<void>(ok=>tls?.close(()=>ok())),
        ]);
        input.signal.removeEventListener("abort",failClosed);
        await rm(directory,{recursive:true,force:true});
      },
    };
  }catch{
    failClosed();for(const socket of sockets)socket.destroy();tls?.closeAllConnections();
    await rm(directory,{recursive:true,force:true});
    input.signal.removeEventListener("abort",failClosed);
    throw Error("BROKER_CONTROLLED_FIXTURE_SETUP_REJECTED");
  }
}
