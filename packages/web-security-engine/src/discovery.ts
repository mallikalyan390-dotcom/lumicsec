/* Reused from kalyankumarmalli480-sys/lumicsec-security-platform at audit/preintegration-forensic-completion-20261117 (10704777f758737927d70aed9c95c0f4f9d98e1c). See THIRD_PARTY_NOTICES.md. */
/**
 * Phase 08 — bounded, passive Web Assessment discovery.
 * No native fetch, DNS or sockets exist in this module. Every requested URL
 * must be sent by a separately authorized Phase06/07 worker adapter.
 */
import {createHash} from "node:crypto";
import {capturePassiveResponse} from "./response-capture.js";

export type DiscoveryKind="PAGE"|"SCRIPT"|"STYLESHEET"|"FORM"|"ENDPOINT"|"ROUTE"|"RESOURCE"|"TECHNOLOGY";
export type DiscoveryState="OBSERVED"|"DISCOVERED_UNFETCHED"|"BLOCKED"|"EXTERNAL"|"FAILED"|"TEMPLATE";
export type DiscoveryNode=Readonly<{
 id:string;kind:DiscoveryKind;state:DiscoveryState;path:string;method:string|null;
 sourceId:string|null;sourceFingerprint:string;observedAt:string;
 confidence:"OBSERVED"|"INFERRED";metadata:Readonly<Record<string,string|number|boolean>>;
}>;
export type DiscoveryEdge=Readonly<{id:string;from:string;to:string;relation:string;sourceFingerprint:string}>;
export type DiscoveryCoverage=Readonly<{
 state:"COMPLETE_WITHIN_LIMITS"|"PARTIAL"|"INCONCLUSIVE"|"CANCELLED";
 requested:number;fetched:number;failed:number;skipped:number;bytes:number;
 queued:number;limitations:readonly string[];
}>;
export type DiscoveryResult=Readonly<{
 origin:string;scopeHash:string;nodes:readonly DiscoveryNode[];edges:readonly DiscoveryEdge[];
 coverage:DiscoveryCoverage;parserVersion:"web-assessment-discovery-v1";
}>;
export type DiscoveryLimits=Readonly<{
 maxRequests:number;maxBytes:number;maxDepth:number;maxNodes:number;maxEdges:number;
 maxParserBytes:number;deadlineMs:number;maxResponseBytes:number;
 allowedPathPrefixes:readonly string[];excludedPathPrefixes:readonly string[];
}>;
export type AuthorizedReadResponse=Readonly<{
 status:number;headers:Readonly<Record<string,string>>;bodyBytes:Uint8Array;headersComplete?:boolean;
}>;
export type AuthorizedRead=(url:string,options:Readonly<{signal?:AbortSignal;maxBytes:number}>)=>Promise<AuthorizedReadResponse>;
export const DISCOVERY_DEFAULTS:DiscoveryLimits=Object.freeze({
 maxRequests:12,maxBytes:500000,maxDepth:2,maxNodes:350,maxEdges:700,
 maxParserBytes:100000,deadlineMs:60000,maxResponseBytes:100000,
 allowedPathPrefixes:Object.freeze(["/"]),excludedPathPrefixes:Object.freeze([]),
});
const fingerprint=(v:string)=>createHash("sha256").update(v).digest("hex");
const id=(prefix:string,key:string)=>prefix+"_"+fingerprint(key).slice(0,24);
const isUnsafePath=(path:string)=>/(?:^|\/)(?:logout|log-out|signout|sign-out|delete|remove|destroy|reset|checkout|payment|payments|purchase|buy|transfer|unsubscribe|deactivate|withdraw|terminate|confirm|admin)(?:\/|$|[-_])/i.test(path);
const dangerousEncoding=/%(?:2e|2f|5c|25|00|0[ad])/i;
const htmlDecode=(v:string)=>v.replace(/&(?:amp|quot|apos|lt|gt|#39);/gi,x=>({
 "&amp;":"&","&quot;":'"',"&apos;":"'","&lt;":"<","&gt;":">","&#39;":"'"} as Record<string,string>)[x.toLowerCase()]||"");
const attr=(source:string,name:string)=>{
 const m=new RegExp("(?:^|\\s)"+name+"\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))","i").exec(source);
 return m?(m[1]??m[2]??m[3]??""):null;
};
function prefixAllows(path:string,prefix:string){return path===prefix||path.startsWith(prefix.endsWith("/")?prefix:prefix+"/");}
function safeLimit(n:number,min:number,max:number){return Number.isSafeInteger(n)&&n>=min&&n<=max;}
export function validateDiscoveryLimits(l:DiscoveryLimits){
 if(!safeLimit(l.maxRequests,1,12)||!safeLimit(l.maxBytes,1,500000)||
 !safeLimit(l.maxDepth,0,5)||!safeLimit(l.maxNodes,1,600)||!safeLimit(l.maxEdges,1,1200)||
 !safeLimit(l.maxParserBytes,100,200000)||!safeLimit(l.deadlineMs,100,60000)||
 !safeLimit(l.maxResponseBytes,1,500000)||l.maxResponseBytes>l.maxBytes||
 !l.allowedPathPrefixes.length||l.allowedPathPrefixes.length>16||
 l.excludedPathPrefixes.length>32||
 [...l.allowedPathPrefixes,...l.excludedPathPrefixes].some(p=>!p.startsWith("/")||p.includes("..")||p.includes("?")||p.includes("#")||p.includes("\\")||p.length>250))
 throw new Error("P08_INVALID_DISCOVERY_LIMITS");
}
export type SafeReference=Readonly<{
 state:"PERMITTED"|"BLOCKED"|"EXTERNAL"|"TEMPLATE";
 requestUrl:string|null;safePath:string;parameterNames:readonly string[];
 reason:string|null;
}>;
/**
 * Execute only canonical same-origin HTTPS requests with no query values.
 * Merely discovering a URL does not grant permission to fetch it.
 */
export function classifyDiscoveryReference(raw:string,base:string,origin:string,limits:DiscoveryLimits=DISCOVERY_DEFAULTS):SafeReference{
 const excluded=(reason:string,state:"BLOCKED"|"EXTERNAL"|"TEMPLATE"="BLOCKED"):SafeReference=>({
  state,requestUrl:null,safePath:"",parameterNames:[],reason
 });
 if(typeof raw!=="string"||raw.length>2048||raw.includes("\\")||
 /[\u0000-\u001f\u007f]/.test(raw))return excluded("INVALID_REFERENCE");
 if(/[{}<>]/.test(raw)||/\/:[A-Za-z_]/.test(raw))return excluded("ROUTE_TEMPLATE","TEMPLATE");
 if(dangerousEncoding.test(raw))return excluded("AMBIGUOUS_ENCODING");
 if(raw.startsWith("//"))return excluded("SCHEME_RELATIVE_REFERENCE");
 let url:URL;
 try{url=new URL(htmlDecode(raw.trim()),base);}catch{return excluded("INVALID_REFERENCE");}
 if(url.protocol!=="https:")return excluded("UNSUPPORTED_SCHEME");
 if(url.username||url.password)return excluded("URL_CREDENTIALS");
 if(url.origin!==origin)return excluded("OUTSIDE_EXACT_ORIGIN","EXTERNAL");
 if(dangerousEncoding.test(url.pathname)||isUnsafePath(url.pathname))return excluded("UNSAFE_PATH");
 const path=url.pathname;
 if(!limits.allowedPathPrefixes.some(x=>prefixAllows(path,x))||
 limits.excludedPathPrefixes.some(x=>prefixAllows(path,x)))
 return excluded("DISALLOWED_PATH");
 const parameterNames=[...new Set([...url.searchParams.keys()].filter(k=>/^[a-zA-Z0-9_.-]{1,80}$/.test(k)))].sort().slice(0,32);
 // Never send query strings containing unknown/sensitive values.
 url.search="";url.hash="";
 return {state:"PERMITTED",requestUrl:url.toString(),safePath:path,parameterNames,reason:null};
}
function asText(bytes:Uint8Array,max:number){return new TextDecoder("utf-8",{fatal:false}).decode(bytes.slice(0,max));}
const safeDetail=(v:string)=>v.replace(/[\u0000-\u001f\u007f]/g,"").slice(0,160);
function safeTech(headers:Readonly<Record<string,string>>,html:string){
 const output:Array<Readonly<{name:string;value:string;kind:"OBSERVED"|"INFERRED"}>>=[];
 for(const [key,val] of Object.entries(headers)){
  const h=key.toLowerCase();
  if(["server","content-type","x-powered-by","via"].includes(h))
   output.push({name:h,value:safeDetail(val),kind:"OBSERVED"});
  if(h==="set-cookie"){
   // No names or values from cookies; record only attributes.
   for(const flag of ["Secure","HttpOnly","SameSite"]){
    if(new RegExp("(?:^|;)\\s*"+flag+"(?:\\s*[=;]|$)","i").test(val))
    output.push({name:"cookie-flag",value:flag,kind:"OBSERVED"});
   }
  }
 }
 const meta=/<meta\b[^>]*name\s*=\s*["']generator["'][^>]*>/i.exec(html)?.[0];
 if(meta){const value=attr(meta,"content");if(value)output.push({name:"html-generator",value:safeDetail(value),kind:"OBSERVED"});}
 return output.slice(0,20);
}
type Hint=Readonly<{raw:string;kind:DiscoveryKind;method:string|null;relation:string;metadata:Record<string,string|number|boolean>}>;
function passiveHints(text:string,contentType:string,sourceUrl:string):Hint[]{
 const result:Hint[]=[];
 const add=(raw:string,kind:DiscoveryKind,method:string|null,relation:string,metadata:Record<string,string|number|boolean>={})=>{
  if(result.length<400&&raw.length<=2048)result.push({raw,kind,method,relation,metadata});
 };
 if(contentType.includes("html")){
  for(const m of text.matchAll(/<a\b[^>]*>/gi)){
   const href=attr(m[0],"href");if(href)add(href,"PAGE","GET","LINKS_TO");
  }
  for(const m of text.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form\s*>/gi)){
   const rawAction=attr(m[0].slice(0,m[0].indexOf(">")+1),"action")||sourceUrl;
   const method=(attr(m[0],"method")||"GET").toUpperCase();
   const inputs=[...m[1].matchAll(/<input\b[^>]*>/gi)].map(x=>attr(x[0],"name")).filter((x):x is string=>!!x&&/^[\w.-]{1,80}$/.test(x)).slice(0,32);
   add(rawAction,"FORM",method,"HAS_FORM",{fieldNames:inputs.join(","),submitted:false});
  }
  for(const m of text.matchAll(/<(?:script|link|iframe)\b[^>]*>/gi)){
   const tag=m[0].slice(1).split(/[\s>]/)[0].toLowerCase();
   const href=attr(m[0],tag==="script"||tag==="iframe"?"src":"href");
   if(href)add(href,tag==="script"?"SCRIPT":tag==="iframe"?"RESOURCE":"STYLESHEET","GET","REFERENCES");
  }
  const canonical=/<link\b[^>]*rel\s*=\s*["']canonical["'][^>]*>/i.exec(text)?.[0];
  if(canonical){const href=attr(canonical,"href");if(href)add(href,"RESOURCE","GET","CANONICAL_HINT");}
 }
 if(contentType.includes("javascript")||contentType.includes("ecmascript")||contentType.includes("html")){
  const patterns:[RegExp,string,DiscoveryKind,string][]=[
   [/\bfetch\s*\(\s*["']([^"'\\]{1,500})["']/g,"GET","ENDPOINT","FETCH_HINT"],
   [/\baxios\.(get|head|post|put|patch|delete)\s*\(\s*["']([^"'\\]{1,500})["']/gi,"","ENDPOINT","AXIOS_HINT"],
   [/\bopen\s*\(\s*["'](GET|HEAD|POST|PUT|PATCH|DELETE)["']\s*,\s*["']([^"'\\]{1,500})["']/gi,"","ENDPOINT","XHR_HINT"],
   [/\b(?:path|route|endpoint|baseURL)\s*[:=]\s*["']([^"'\\]{1,500})["']/gi,"GET","ROUTE","CLIENT_ROUTE_HINT"],
  ];
  for(const [regex,defaultMethod,kind,relation] of patterns)for(const m of text.matchAll(regex)){
   const raw=m.length===3?m[2]:m[1],method=m.length===3?m[1].toUpperCase():defaultMethod;
   if(raw)add(raw,kind,method,relation,{passive:true});
  }
 }
 return result;
}
export async function crawlWebAssessment(input:Readonly<{
 origin:string;scopeHash:string;read:AuthorizedRead;limits?:DiscoveryLimits;
 signal?:AbortSignal;now?:()=>number;assertAuthorized?:(url:string)=>Promise<void>;
 onSnapshot?:(result:DiscoveryResult)=>Promise<void>;
}>):Promise<DiscoveryResult>{
 const l=input.limits||DISCOVERY_DEFAULTS;validateDiscoveryLimits(l);
 const origin=new URL(input.origin);
 if(origin.protocol!=="https:"||origin.origin!==input.origin||origin.username||origin.password||
 !/^[0-9a-f]{64}$/.test(input.scopeHash))throw new Error("P08_INVALID_SCOPE");
 const now=input.now||Date.now;const start=now();
 const nodes=new Map<string,DiscoveryNode>(),edges=new Map<string,DiscoveryEdge>();
 const frontier:Array<{url:string;depth:number}>=[{url:new URL("/",origin).toString(),depth:0}];
 const queued=new Set(frontier.map(x=>x.url));const visited=new Set<string>();
 const limitations=new Set<string>();
 let bytes=0,requested=0,fetched=0,failed=0,skipped=0,cancelled=false;
 const sourceFingerprint=(url:string)=>fingerprint(url.split("?")[0]);
 const addNode=(kind:DiscoveryKind,state:DiscoveryState,path:string,method:string|null,source:string|null,confidence:"OBSERVED"|"INFERRED",metadata:Record<string,string|number|boolean>={})=>{
  const key=[kind,path,method||""].join("|");const nodeId=id("wdn",key);
  if(!nodes.has(nodeId)){
   if(nodes.size>=l.maxNodes){limitations.add("GRAPH_NODE_LIMIT");return null;}
   nodes.set(nodeId,{id:nodeId,kind,state,path,method,sourceId:source,
    sourceFingerprint:sourceFingerprint(source||origin.toString()),observedAt:new Date(now()).toISOString(),confidence,metadata});
  }else if(state==="OBSERVED"){
   const old=nodes.get(nodeId)!;nodes.set(nodeId,{...old,state,confidence:"OBSERVED",observedAt:new Date(now()).toISOString(),
     // Root/queued pages start as DISCOVERED_UNFETCHED; the subsequent
     // authorized GET must upgrade them with captured privacy-safe metadata.
     metadata:{...old.metadata,...metadata},sourceId:source||old.sourceId,
     sourceFingerprint:sourceFingerprint(source||origin.toString())});
  }
  return nodeId;
 };
 const addEdge=(from:string,to:string,relation:string,src:string)=>{
  const edgeId=id("wde",[from,to,relation].join("|"));
  if(!edges.has(edgeId)){
   if(edges.size>=l.maxEdges){limitations.add("GRAPH_EDGE_LIMIT");return;}
   edges.set(edgeId,{id:edgeId,from,to,relation,sourceFingerprint:sourceFingerprint(src)});
  }
 };
 const root=addNode("PAGE","DISCOVERED_UNFETCHED","/","GET",null,"INFERRED")!;
 const snapshot=(state:DiscoveryCoverage["state"]):DiscoveryResult=>({
  origin:origin.origin,scopeHash:input.scopeHash,
  nodes:[...nodes.values()].sort((a,b)=>a.id.localeCompare(b.id)),
  edges:[...edges.values()].sort((a,b)=>a.id.localeCompare(b.id)),
  coverage:{state,requested,fetched,failed,skipped,bytes,
   queued:frontier.length,limitations:[...limitations].sort()},
  parserVersion:"web-assessment-discovery-v1"
 });
 const checkpoint=async()=>{if(input.onSnapshot)await input.onSnapshot(snapshot("PARTIAL"));};
 while(frontier.length){
  if(input.signal?.aborted){cancelled=true;limitations.add("CANCELLED");break;}
  if(now()-start>=l.deadlineMs){limitations.add("DEADLINE_REACHED");break;}
  if(requested>=l.maxRequests){limitations.add("REQUEST_BUDGET");break;}
  if(bytes>=l.maxBytes){limitations.add("BYTE_BUDGET");break;}
  const next=frontier.shift()!;
  if(visited.has(next.url))continue;
  visited.add(next.url);
  const parsed=classifyDiscoveryReference(next.url,next.url,origin.origin,l);
  if(parsed.state!=="PERMITTED"||!parsed.requestUrl){skipped++;await checkpoint();continue;}
  let response:AuthorizedReadResponse;
  try{
   if(input.assertAuthorized)await input.assertAuthorized(parsed.requestUrl);
   if(input.signal?.aborted){cancelled=true;limitations.add("CANCELLED");break;}
   requested++;
   response=await input.read(parsed.requestUrl,{signal:input.signal,maxBytes:Math.min(l.maxResponseBytes,l.maxBytes-bytes)});
   if(!Number.isInteger(response.status)||response.status<100||response.status>599||
    response.bodyBytes.byteLength>l.maxResponseBytes||response.bodyBytes.byteLength>l.maxBytes-bytes)
    throw new Error("P08_RESPONSE_BUDGET_OR_STATUS_INVALID");
  }catch{
   failed++;limitations.add("FETCH_FAILURE_OR_POLICY_DENIAL");
   addNode(next.url.endsWith(".js")?"SCRIPT":"PAGE","FAILED",parsed.safePath,"GET",next.url,"INFERRED");
   await checkpoint();continue;
  }
  fetched++;bytes+=response.bodyBytes.byteLength;
  const headers=Object.fromEntries(Object.entries(response.headers).map(([k,v])=>[k.toLowerCase(),v]));
  const contentType=(headers["content-type"]||"").toLowerCase().slice(0,200);
  const script=/(?:javascript|ecmascript)/.test(contentType)||/\.m?js$/.test(parsed.safePath);
  const kind:DiscoveryKind=script?"SCRIPT":"PAGE";
  const page=addNode(kind,"OBSERVED",parsed.safePath,"GET",next.url,"OBSERVED",{
    httpStatus:response.status,contentType:contentType.split(";")[0],responseBytes:response.bodyBytes.byteLength,
    passiveResponseV1:JSON.stringify(capturePassiveResponse(response.headers,origin.origin,response.headersComplete===true))
  })||root;
  if([301,302,303,307,308].includes(response.status)){
   const location=headers["location"];
   if(location){
    const ref=classifyDiscoveryReference(location,next.url,origin.origin,l);
    if(ref.state==="PERMITTED"&&ref.requestUrl&&next.depth<l.maxDepth&&!queued.has(ref.requestUrl)){
     queued.add(ref.requestUrl);frontier.push({url:ref.requestUrl,depth:next.depth+1});
    }else limitations.add("REDIRECT_NOT_TRAVERSED");
   }
   await checkpoint();continue;
  }
  if(!contentType.includes("html")&&!script&&!contentType.includes("json")){
   await checkpoint();continue;
  }
  const text=asText(response.bodyBytes,l.maxParserBytes);
  if(response.bodyBytes.byteLength>l.maxParserBytes)limitations.add("PARSER_INPUT_TRUNCATED");
  for(const observation of safeTech(headers,contentType.includes("html")?text:"")){
   const key=observation.name+"="+observation.value;
   const tech=addNode("TECHNOLOGY","OBSERVED",key,null,next.url,observation.kind,{"detector":"P08_PASSIVE_V1"});
   if(tech)addEdge(page,tech,"OBSERVED_HEADER_OR_META",next.url);
  }
  const hints=passiveHints(text,contentType,next.url);
  if(contentType.includes("json")&&/(?:openapi|swagger|routes|api-docs)/i.test(parsed.safePath)){
   try{
    const document=JSON.parse(text) as Record<string,unknown>;
    if(document&&typeof document==="object"&&document.paths&&typeof document.paths==="object"){
     for(const [path,definition] of Object.entries(document.paths as Record<string,unknown>).slice(0,100)){
      if(!definition||typeof definition!=="object")continue;
      for(const method of Object.keys(definition).filter(x=>/^(get|head|post|put|patch|delete)$/i.test(x)).slice(0,6)){
       hints.push({raw:path,kind:"ENDPOINT",method:method.toUpperCase(),relation:"SPECIFIES",
        metadata:{passive:true,sourceFormat:"OPENAPI_OR_SWAGGER"}});
      }
     }
    }
   }catch{limitations.add("API_SPEC_PARSE_FAILED");}
  }
  for(const hint of hints.slice(0,400)){
   const ref=classifyDiscoveryReference(hint.raw,next.url,origin.origin,l);
   // Never persist raw query values, HTTP credentials, third-party URL paths, secrets or source text.
   const safePath=ref.state==="PERMITTED"?ref.safePath:
     ref.state==="TEMPLATE"?"/<route-template>":"/<excluded>";
   const node=addNode(hint.kind,ref.state==="PERMITTED"?"DISCOVERED_UNFETCHED":
    ref.state==="EXTERNAL"?"EXTERNAL":ref.state==="TEMPLATE"?"TEMPLATE":"BLOCKED",
    safePath,hint.method,next.url,"INFERRED",{
     ...hint.metadata,reason:ref.reason||"",parameterNames:ref.parameterNames.join(",")
    });
   if(node)addEdge(page,node,hint.relation,next.url);
   // Only explicitly selected passive links/scripts can enter the GET crawl frontier.
   if(ref.state==="PERMITTED"&&ref.requestUrl&&
     (hint.kind==="PAGE"||hint.kind==="SCRIPT")&&hint.method==="GET"&&
     next.depth<l.maxDepth&&!queued.has(ref.requestUrl)){
    queued.add(ref.requestUrl);frontier.push({url:ref.requestUrl,depth:next.depth+1});
   }
  }
  await checkpoint();
 }
 if(frontier.length)limitations.add("UNVISITED_FRONTIER");
 if(fetched===0&&!cancelled)limitations.add("NO_SUCCESSFUL_FETCH");
 const terminal=cancelled?"CANCELLED":
   fetched===0?"INCONCLUSIVE":limitations.size?"PARTIAL":"COMPLETE_WITHIN_LIMITS";
 return snapshot(terminal);
}
