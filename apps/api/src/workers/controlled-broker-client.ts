/* Credential-free runtime adapter in disposable --network none worker.
 * The worker has no TCP route, tokens, keys, or DNS resolver access.
 * Only the per-execution Unix socket can request an exact-scope GET.
 */
import { connect } from "node:net";
import { createHash } from "node:crypto";
import { z } from "zod";
import type { AuthorizedReadResponse } from "@lumicsec/web-security-engine";
import { requireExactWebUrl, WEB_READ_LIMITS } from "../lib/web-pinned-transport.js";

const PROTOCOL="CONTROLLED_RUNTIME_BROKER_V1";
const replySchema=z.strictObject({
  status:z.number().int().min(100).max(599),
  headers:z.record(z.string(),z.string()),
  body:z.string().max(80_000),
  sha256:z.string().regex(/^[0-9a-f]{64}$/),
});
export type RuntimeIdentity="anonymous"|"owner"|"other";
export class ControlledBrokerClient {
  private used=0;
  private totalBytes=0;
  constructor(private readonly input:Readonly<{
    executionId:string;origin:string;socketPath:string;signal:AbortSignal;
  }>) {}

  async read(_origin:string,url:string,opts:Readonly<{
    signal:AbortSignal;maxBytes:number;method?:"GET"|"HEAD";
  }>,identity:RuntimeIdentity="anonymous"):Promise<AuthorizedReadResponse> {
    if(_origin!==this.input.origin||opts.method&&opts.method!=="GET"||
      this.input.signal.aborted||opts.signal.aborted||
      this.used>=WEB_READ_LIMITS.maxRequests||
      this.totalBytes>=WEB_READ_LIMITS.maxTotalBytes)
      throw Error("BROKER_CLIENT_SCOPE_OR_BUDGET");
    requireExactWebUrl(url,this.input.origin);
    this.used++;
    const raw=JSON.stringify({protocol:PROTOCOL,executionId:this.input.executionId,
      origin:this.input.origin,url,identity,method:"GET"})+"\n";
    if(Buffer.byteLength(raw)>1_500)throw Error("BROKER_CLIENT_REQUEST_BOUNDS");
    return new Promise((resolve,reject)=>{
      let ended=false,text="";
      const socket=connect({path:this.input.socketPath});
      const fail=()=>{if(ended)return;ended=true;cleanup();socket.destroy();
        reject(Error("BROKER_CLIENT_DENIED"));};
      const abort=()=>fail();
      const cleanup=()=>{
        clearTimeout(timer);
        this.input.signal.removeEventListener("abort",abort);
        opts.signal.removeEventListener("abort",abort);
      };
      const timer=setTimeout(fail,Math.min(WEB_READ_LIMITS.maxRequestMs+1_000,4_000));
      this.input.signal.addEventListener("abort",abort,{once:true});
      opts.signal.addEventListener("abort",abort,{once:true});
      socket.on("connect",()=>socket.write(raw));
      socket.on("data",buf=>{
        text+=buf.toString("utf8");
        if(Buffer.byteLength(text)>90_000)fail();
      });
      socket.on("end",()=>{
        if(ended)return;
        if(!text.endsWith("\n")||text.indexOf("\n")!==text.length-1)return fail();
        try{
          const response=replySchema.parse(JSON.parse(text.slice(0,-1)));
          const bytes=Buffer.from(response.body,"base64");
          if(bytes.length>Math.min(opts.maxBytes,WEB_READ_LIMITS.maxResponseBytes,
            WEB_READ_LIMITS.maxTotalBytes-this.totalBytes)||
            createHash("sha256").update(bytes).digest("hex")!==response.sha256)
            return fail();
          this.totalBytes+=bytes.length;
          ended=true;cleanup();
          resolve({status:response.status,headers:response.headers,
            bodyBytes:new Uint8Array(bytes),headersComplete:true});
        }catch{fail();}
      });
      socket.on("error",fail);
      socket.on("close",()=>{if(!ended)fail();});
    });
  }
  get metrics(){return {requests:this.used,bytes:this.totalBytes};}
}
