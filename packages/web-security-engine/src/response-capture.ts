/* Reused from kalyankumarmalli480-sys/lumicsec-security-platform at audit/preintegration-forensic-completion-20261117 (10704777f758737927d70aed9c95c0f4f9d98e1c). See THIRD_PARTY_NOTICES.md. */
/**
 * Phase09 privacy-preserving, allowlisted response observation. This runs only
 * inside an already permitted Phase08 GET; no network calls and no raw secrets.
 */
export type PassiveResponseCapture = Readonly<{
 version:"P09_RESPONSE_METADATA_V1"; headersComplete:boolean;
 hsts:"ABSENT"|"VALID"|"MALFORMED"|"UNKNOWN";hstsMaxAge:number|null;
 csp:"ABSENT"|"ENFORCED"|"REPORT_ONLY"|"BOTH"|"UNKNOWN";
 cspDirectives:string;cspUnsafeInline:boolean;cspUnsafeEval:boolean;
 cspWildcardScript:boolean;cspHasNonceOrHash:boolean;cspDuplicate:boolean;
 cspFrameAncestors:boolean;cspFrameAncestorsNone:boolean;
 cspObjectNone:boolean;cspBaseUri:boolean;cspFormAction:boolean;
 cspUpgradeInsecure:boolean;
 xContentTypeOptions:"NOSNIFF"|"OTHER"|"ABSENT"|"UNKNOWN";
 xFrameOptions:"DENY"|"SAMEORIGIN"|"OTHER"|"ABSENT"|"UNKNOWN";
 referrerPolicy:"STRICT"|"WEAK"|"OTHER"|"ABSENT"|"UNKNOWN";
 permissionsPolicy:"PRESENT"|"ABSENT"|"UNKNOWN";
 cacheControl:"PRIVATE"|"NO_STORE"|"PUBLIC"|"OTHER"|"ABSENT"|"UNKNOWN";
 corsOrigin:"WILDCARD"|"SAME_ORIGIN"|"OTHER_HTTPS"|"OTHER"|"ABSENT"|"UNKNOWN";
 corsCredentials:"TRUE"|"FALSE"|"ABSENT"|"UNKNOWN";
 corsVaryOrigin:"YES"|"NO"|"UNKNOWN";
 setCookieCount:number|null;secureFlagCount:number|null;
 httpOnlyFlagCount:number|null;sameSiteNoneCount:number|null;
}>;
const lower=(v:string)=>v.trim().toLowerCase();
const allowed=(s:string)=>s.length<=1000&&!/[\u0000-\u001f\u007f]/.test(s);
function cspParse(value:string){
 const out=new Map<string,string>();
 let duplicate=false;
 if(!allowed(value))return {out,duplicate:true};
 for(const raw of value.split(";").slice(0,64)){
  const parts=raw.trim().split(/\s+/).filter(Boolean);
  if(!parts.length)continue;
  const key=parts.shift()!.toLowerCase();
  if(!/^[a-z][a-z0-9-]{1,50}$/.test(key)){duplicate=true;continue;}
  if(out.has(key)){duplicate=true;continue;}
  out.set(key,parts.join(" ").toLowerCase());
 }
 return {out,duplicate};
}
function cookieFlags(raw:string){
 if(raw.length>1600)return null;
 // A comma in Expires is NOT a cookie separator.
 const parts=raw.split(/,(?=\s*[^;,= ]{1,100}=)/);
 if(parts.length>10)return null;
 let secure=0,httpOnly=0,sameSiteNone=0;
 for(const part of parts){
  if(!/^[^;=\r\n]{1,150}=/.test(part.trim()))return null;
  const attrs=part.split(";").slice(1).map(x=>lower(x));
  if(attrs.some(x=>x==="secure"))secure++;
  if(attrs.some(x=>x==="httponly"))httpOnly++;
  if(attrs.some(x=>/^samesite\s*=\s*none$/.test(x)))sameSiteNone++;
 }
 return {count:parts.length,secure,httpOnly,sameSiteNone};
}
export function capturePassiveResponse(headers:Readonly<Record<string,string>>,origin:string,complete=false):PassiveResponseCapture{
 const map=new Map<string,string[]>();
 for(const [name,value] of Object.entries(headers)){
  const n=name.toLowerCase();
  if(!/^[a-z0-9-]{2,65}$/.test(n)||typeof value!=="string")continue;
  const list=map.get(n)||[];list.push(value);map.set(n,list);
 }
 const present=(name:string)=>map.has(name);
 const field=(name:string)=>map.get(name)?.join(", ")??"";
 const flag=(name:string)=>present(name)?"PRESENT":complete?"ABSENT":"UNKNOWN";
 const h=field("strict-transport-security");
 const match=/^\s*max-age\s*=\s*(\d{1,12})(?:\s*;|$)/i.exec(h);
 const age=match?Number(match[1]):null;
 const hsts=present("strict-transport-security")?
  age!==null&&Number.isSafeInteger(age)?"VALID":"MALFORMED":complete?"ABSENT":"UNKNOWN";
 const csp=present("content-security-policy");
 const cspReport=present("content-security-policy-report-only");
 const policy=cspParse(field("content-security-policy"));
 const directives=policy.out;
 const scripts=directives.get("script-src")??directives.get("default-src")??"";
 const fa=directives.get("frame-ancestors");
 const frame=field("x-frame-options").toLowerCase().trim();
 const xcto=field("x-content-type-options").toLowerCase().trim();
 const refer=field("referrer-policy").toLowerCase().trim();
 const cors=field("access-control-allow-origin").trim();
 const credentials=field("access-control-allow-credentials").trim().toLowerCase();
 const cache=field("cache-control").toLowerCase();
 const vary=field("vary").toLowerCase();
 const cookies=present("set-cookie")?cookieFlags(field("set-cookie")):null;
 return {
  version:"P09_RESPONSE_METADATA_V1",headersComplete:complete,
  hsts,hstsMaxAge:age,
  csp:csp&&cspReport?"BOTH":csp?"ENFORCED":cspReport?"REPORT_ONLY":complete?"ABSENT":"UNKNOWN",
  cspDirectives:[...directives.keys()].sort().slice(0,32).join(","),
  cspUnsafeInline:/(?:^|\s)'unsafe-inline'(?:\s|$)/.test(scripts),
  cspUnsafeEval:/(?:^|\s)'unsafe-eval'(?:\s|$)/.test(scripts),
  cspWildcardScript:/(?:^|\s)\*(?:\s|$)/.test(scripts),
  cspHasNonceOrHash:/'nonce-|'sha(?:256|384|512)-'/.test(scripts),
  cspDuplicate:policy.duplicate,
  cspFrameAncestors:fa!==undefined,cspFrameAncestorsNone:fa?.trim()==="'none'",
  cspObjectNone:directives.get("object-src")?.trim()==="'none'",
  cspBaseUri:directives.has("base-uri"),cspFormAction:directives.has("form-action"),
  cspUpgradeInsecure:directives.has("upgrade-insecure-requests"),
  xContentTypeOptions:present("x-content-type-options")?xcto==="nosniff"?"NOSNIFF":"OTHER":complete?"ABSENT":"UNKNOWN",
  xFrameOptions:present("x-frame-options")?frame==="deny"?"DENY":frame==="sameorigin"?"SAMEORIGIN":"OTHER":complete?"ABSENT":"UNKNOWN",
  referrerPolicy:present("referrer-policy")?/(^|,)\s*(strict-origin-when-cross-origin|no-referrer|same-origin|strict-origin)(\s*,|$)/.test(refer)?"STRICT":refer==="unsafe-url"?"WEAK":"OTHER":complete?"ABSENT":"UNKNOWN",
  permissionsPolicy:flag("permissions-policy"),
  cacheControl:present("cache-control")?cache.includes("no-store")?"NO_STORE":cache.includes("private")?"PRIVATE":cache.includes("public")?"PUBLIC":"OTHER":complete?"ABSENT":"UNKNOWN",
  corsOrigin:present("access-control-allow-origin")?cors==="*"?"WILDCARD":cors===origin?"SAME_ORIGIN":/^https:\/\/[a-z0-9.-]{3,240}$/i.test(cors)?"OTHER_HTTPS":"OTHER":complete?"ABSENT":"UNKNOWN",
  corsCredentials:present("access-control-allow-credentials")?credentials==="true"?"TRUE":"FALSE":complete?"ABSENT":"UNKNOWN",
  corsVaryOrigin:present("vary")?/(?:^|,)\s*origin\s*(?:,|$)/.test(vary)?"YES":"NO":"UNKNOWN",
  setCookieCount:present("set-cookie")?cookies?.count??null:complete?0:null,
  secureFlagCount:cookies?.secure??null,
  httpOnlyFlagCount:cookies?.httpOnly??null,
  sameSiteNoneCount:cookies?.sameSiteNone??null
 };
}
