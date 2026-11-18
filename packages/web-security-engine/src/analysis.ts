/* Reused from kalyankumarmalli480-sys/lumicsec-security-platform at audit/preintegration-forensic-completion-20261117 (10704777f758737927d70aed9c95c0f4f9d98e1c). See THIRD_PARTY_NOTICES.md. */
/**
 * Phase09 deterministic OFFLINE security assessment. NO fetch, DNS, browser,
 * AI, execution grant, canonical finding or retest authority is imported.
 * All evidence must arrive through the fenced database source RPC.
 */
import {createHash} from "node:crypto";
import type {PassiveResponseCapture} from "./response-capture.js";

export const ANALYZER_VERSION="web-assessment-analysis-v1" as const;
export const RULE_PACK_VERSION="WEB_ASSESSMENT_DETERMINISTIC_V1" as const;
export const CANDIDATE_AUTHORITY="WEB_ASSESSMENT_DETERMINISTIC_ANALYSIS_V1" as const;
export const RULE_CATEGORIES=["HEADERS","CSP","COOKIES","CORS","FORMS","CLIENT","API","TECHNOLOGY"] as const;
export type RuleCategory=typeof RULE_CATEGORIES[number];
export type RuleOutcome="OBSERVED"|"RISK_SIGNAL"|"REVIEW_REQUIRED"|"INCONCLUSIVE"|"NOT_EVALUABLE"|"NOT_APPLICABLE";
export type EvidenceStrength="INSUFFICIENT"|"PASSIVE_OBSERVATION"|"DETERMINISTIC_CONFIGURATION_SIGNAL"|"REQUIRES_ACTIVE_VALIDATION";
export type AnalysisNode=Readonly<{id:string;kind:string;state:string;path:string;method:string|null;
 sourceFingerprint:string;observedAt:string;confidence:string;metadata:Readonly<Record<string,unknown>>}>;
export type AnalysisEdge=Readonly<{id:string;from:string;to:string;relation:string;sourceFingerprint:string}>;
export type AnalysisSnapshot=Readonly<{
 analysisId:string;jobId:string;organizationId:string;websiteId:string;actorId:string;
 origin:string;scopeHash:string;snapshotFingerprint:string;
 coverageState:string;coverage:Readonly<Record<string,unknown>>;
 nodes:readonly AnalysisNode[];edges:readonly AnalysisEdge[];
}>;
export type SecurityObservation=Readonly<{
 id:string;ruleId:string;ruleVersion:"1";category:RuleCategory;
 outcome:RuleOutcome;title:string;explanation:string;remediation:string;
 validation:string;sourceNodeIds:readonly string[];sourceFingerprints:readonly string[];
 evidenceStrength:EvidenceStrength;confidence:"LOW"|"MEDIUM"|"HIGH";severity:"INFO"|"LOW"|"MEDIUM";
 limitation:string;fingerprint:string;
}>;
export type ReviewCandidate=Readonly<{
 id:string;observationId:string;fingerprint:string;ruleId:string;
 title:string;category:RuleCategory;severityEstimate:"LOW"|"MEDIUM";
 confidence:"LOW"|"MEDIUM";evidenceStrength:EvidenceStrength;status:"REVIEW_REQUIRED";
 evidenceNodeIds:readonly string[];sourceFingerprints:readonly string[];
 summary:string;remediation:string;validation:string;authority:typeof CANDIDATE_AUTHORITY;
}>;
export type AnalysisProjection=Readonly<{
 analyzerVersion:typeof ANALYZER_VERSION;rulePackVersion:typeof RULE_PACK_VERSION;
 analysisId:string;jobId:string;organizationId:string;websiteId:string;
 origin:string;scopeHash:string;snapshotFingerprint:string;
 coverageState:"BOUNDED"|"PARTIAL"|"INSUFFICIENT_EVIDENCE";
 coverage:Readonly<Record<string,unknown>>;
 observations:readonly SecurityObservation[];candidates:readonly ReviewCandidate[];
 counts:Readonly<{observedPages:number;inferredNodes:number;failedNodes:number;
 notEvaluable:number;reviewRequired:number;analyzedNodes:number}>;
 limitations:readonly string[];
}>;
const hash=(x:string)=>createHash("sha256").update(x).digest("hex");
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const hex=/^[a-f0-9]{64}$/;
const nodeId=/^wdn_[a-f0-9]{24}$/;
const edgeId=/^wde_[a-f0-9]{24}$/;
const safeText=(v:unknown,max=280)=>typeof v==="string"&&!/[\u0000-\u001f\u007f]/.test(v)?v.slice(0,max):"";
function validateSnapshot(s:AnalysisSnapshot){
 if(!s||[s.analysisId,s.jobId,s.organizationId,s.websiteId,s.actorId].some(x=>!uuid.test(x))||
  !hex.test(s.scopeHash)||!hex.test(s.snapshotFingerprint)||
  !/^https:\/\/[a-z0-9.-]+$/i.test(s.origin)||
  !Array.isArray(s.nodes)||!Array.isArray(s.edges)||s.nodes.length>600||
  s.edges.length>1200||!s.coverage||typeof s.coverage!=="object")
  throw Error("P09_UNTRUSTED_SOURCE_SNAPSHOT");
 const ids=new Set<string>();
 for(const n of s.nodes){
  if(!n||!nodeId.test(n.id)||ids.has(n.id)||!hex.test(n.sourceFingerprint)||
   !/^[A-Z_]{3,30}$/.test(n.kind)||!safeText(n.path,301)||n.path.length>300||
   n.path.includes("?")||n.path.includes("#")||
   !Number.isFinite(Date.parse(n.observedAt))||
   Date.parse(n.observedAt)>Date.now()+120000||
   !n.metadata||typeof n.metadata!=="object"||Array.isArray(n.metadata)||
   JSON.stringify(n.metadata).length>3000)throw Error("P09_INVALID_EVIDENCE_NODE");
  ids.add(n.id);
 }
 const edges=new Set<string>();
 for(const e of s.edges){
  if(!e||!edgeId.test(e.id)||edges.has(e.id)||!ids.has(e.from)||!ids.has(e.to)||
   !hex.test(e.sourceFingerprint)||!/^([A-Z_]){3,80}$/.test(e.relation))
   throw Error("P09_INVALID_EVIDENCE_GRAPH");
  edges.add(e.id);
 }
}
function responseMeta(n:AnalysisNode):PassiveResponseCapture|null{
 if(n.state!=="OBSERVED"||!["PAGE","SCRIPT"].includes(n.kind))return null;
 const raw=n.metadata.passiveResponseV1;
 if(typeof raw!=="string"||raw.length>2800)return null;
 try{
  const meta=JSON.parse(raw) as PassiveResponseCapture;
  if(meta&&meta.version==="P09_RESPONSE_METADATA_V1"&&typeof meta.headersComplete==="boolean"&&
   ["ABSENT","VALID","MALFORMED","UNKNOWN"].includes(meta.hsts)&&
   ["UNKNOWN","ABSENT","ENFORCED","REPORT_ONLY","BOTH"].includes(meta.csp))return meta;
 }catch{}
 return null;
}
export function analyzeWebAssessmentSnapshot(s:AnalysisSnapshot):AnalysisProjection{
 validateSnapshot(s);
 const obs:SecurityObservation[]=[];
 const candidates:ReviewCandidate[]=[];
 const emitted=new Set<string>();
 const limitationSet=new Set<string>();
 const captureKinds=new Set<RuleCategory>();
 const sorted=[...s.nodes].sort((a,b)=>a.id.localeCompare(b.id));
 const pages=sorted.filter(n=>n.kind==="PAGE"&&n.state==="OBSERVED");
 function add(ruleId:string,category:RuleCategory,outcome:RuleOutcome,title:string,
   explanation:string,remediation:string,validation:string,
   nodes:readonly AnalysisNode[],opts?:Readonly<{strength?:EvidenceStrength;confidence?:"LOW"|"MEDIUM"|"HIGH";
   severity?:"INFO"|"LOW"|"MEDIUM";candidate?:boolean;limitation?:string}>){
  const refs=[...new Set(nodes.map(n=>n.id))].sort();
  const fps=[...new Set(nodes.map(n=>n.sourceFingerprint))].sort();
  const fp=hash([s.jobId,s.scopeHash,ruleId,...refs].join("|"));
  if(emitted.has(fp))return;
  emitted.add(fp);
  const strength=opts?.strength??"PASSIVE_OBSERVATION";
  const item:SecurityObservation={
   id:"w09o_"+fp.slice(0,24),ruleId,ruleVersion:"1",category,outcome,title,
   explanation:safeText(explanation,1200),remediation:safeText(remediation,1200),
   validation:safeText(validation,900),sourceNodeIds:refs,sourceFingerprints:fps,
   evidenceStrength:strength,confidence:opts?.confidence??"LOW",severity:opts?.severity??"INFO",
   limitation:opts?.limitation??"Passive evidence only; exploitability and whole-site coverage unverified.",
   fingerprint:fp
  };
  obs.push(item);captureKinds.add(category);
  if(opts?.candidate===true&&outcome==="REVIEW_REQUIRED"&&refs.length&&
     strength!=="INSUFFICIENT"){
   candidates.push({
    id:"w09c_"+fp.slice(0,24),observationId:item.id,fingerprint:fp,
    ruleId,title,category,severityEstimate:opts.severity==="MEDIUM"?"MEDIUM":"LOW",
    confidence:opts.confidence==="HIGH"?"MEDIUM":opts.confidence??"LOW",
    evidenceStrength:strength,status:"REVIEW_REQUIRED",
    evidenceNodeIds:refs,sourceFingerprints:fps,summary:item.explanation,
    remediation:item.remediation,validation:item.validation,authority:CANDIDATE_AUTHORITY
   });
  }
 }
 const explainHardening="Review representative affected responses and application compatibility before changing server configuration.";
 for(const n of pages){
  const meta=responseMeta(n);
  if(!meta){limitationSet.add("HTTP_HEADER_METADATA_NOT_CAPTURED");continue;}
  const html=typeof n.metadata.contentType==="string"&&n.metadata.contentType.includes("html");
  if(meta.hsts==="ABSENT")add("P09.HSTS.ABSENT","HEADERS","RISK_SIGNAL","HSTS header absent on observed HTTPS response",
   "A complete captured response header set did not include HSTS; this is a hardening signal, not proof of downgrade exploitation.",
   "Evaluate enabling Strict-Transport-Security with a tested max-age on HTTPS.",explainHardening,[n],
   {strength:"DETERMINISTIC_CONFIGURATION_SIGNAL",severity:"LOW",confidence:"MEDIUM"});
  else if(meta.hsts==="MALFORMED"||meta.hsts==="VALID"&&meta.hstsMaxAge===0)
   add("P09.HSTS.INVALID","HEADERS","RISK_SIGNAL","HSTS policy is ineffective or malformed",
    "Captured HSTS does not provide a positive valid max-age.",
    "Review max-age syntax and HTTPS deployment prerequisites.",explainHardening,[n],
    {strength:"DETERMINISTIC_CONFIGURATION_SIGNAL",severity:"LOW",confidence:"MEDIUM"});
  if(meta.xContentTypeOptions==="ABSENT"||meta.xContentTypeOptions==="OTHER")
   add("P09.XCTO.CONFIG","HEADERS","RISK_SIGNAL","MIME sniffing defense needs review",
    "The observed response did not include an effective X-Content-Type-Options: nosniff value.",
    "Consider X-Content-Type-Options: nosniff with correct Content-Type.",explainHardening,[n],
    {strength:"DETERMINISTIC_CONFIGURATION_SIGNAL",severity:"LOW",confidence:"MEDIUM"});
  if(html){
   if(meta.csp==="ABSENT")
    add("P09.CSP.ABSENT","CSP","RISK_SIGNAL","No enforced Content Security Policy on observed HTML response",
     "The fully captured response lacks an enforced CSP; this does not prove XSS.",
     "Introduce and validate a restrictive policy incrementally, using report-only during rollout.",
     explainHardening,[n],{strength:"DETERMINISTIC_CONFIGURATION_SIGNAL",confidence:"MEDIUM"});
   else if(meta.csp==="REPORT_ONLY")
    add("P09.CSP.REPORT_ONLY","CSP","OBSERVED","CSP is report-only",
     "The observed policy is not enforced by browsers.","Evaluate an enforced policy after reviewing reports.",
     explainHardening,[n],{confidence:"MEDIUM"});
   else if(meta.csp==="ENFORCED"||meta.csp==="BOTH"){
    if(meta.cspUnsafeInline||meta.cspUnsafeEval||meta.cspWildcardScript)
     add("P09.CSP.BROAD_SCRIPT","CSP","REVIEW_REQUIRED","Permissive script policy requires review",
      "An enforced CSP contains unsafe-inline, unsafe-eval or wildcard script source permissions.",
      "Review script sources and adopt nonce/hash-based or narrow allowlisting where suitable.",
      "Human review of effective policy and runtime compatibility is necessary; script injection was not tested.",[n],
      {strength:"DETERMINISTIC_CONFIGURATION_SIGNAL",confidence:"MEDIUM",severity:"LOW",candidate:true});
    if(meta.cspDuplicate)
     add("P09.CSP.DUPLICATE","CSP","RISK_SIGNAL","Duplicate CSP directives observed",
      "Duplicate directives can make effective policy behavior differ from expectations.",
      "Remove duplicate directives after determining browser-effective first-directive behavior.",
      explainHardening,[n],{strength:"DETERMINISTIC_CONFIGURATION_SIGNAL"});
   }
   if(meta.xFrameOptions==="ABSENT"&&!meta.cspFrameAncestors)
    add("P09.FRAME.NO_POLICY","HEADERS","REVIEW_REQUIRED","Observed HTML response has no framing policy",
     "Neither X-Frame-Options nor enforced CSP frame-ancestors was captured; this is not clickjacking proof.",
     "Consider frame-ancestors in enforced CSP or X-Frame-Options according to compatibility.",
     "Evaluate framing behavior and sensitive interaction flows separately.",[n],
     {strength:"DETERMINISTIC_CONFIGURATION_SIGNAL",severity:"LOW",confidence:"MEDIUM",candidate:true});
   if(meta.referrerPolicy==="WEAK")
    add("P09.REFERRER.WEAK","HEADERS","RISK_SIGNAL","Weak referrer policy observed",
     "The observed unsafe-url policy may expose URL path/query information to external destinations.",
     "Prefer strict-origin-when-cross-origin or no-referrer where compatible.",explainHardening,[n],
     {strength:"DETERMINISTIC_CONFIGURATION_SIGNAL"});
  }
  if(meta.corsOrigin==="WILDCARD"||meta.corsOrigin==="OTHER_HTTPS"){
   add("P09.CORS.CONFIG","CORS",meta.corsCredentials==="TRUE"?"REVIEW_REQUIRED":"OBSERVED",
    "CORS allow-origin configuration observed",
    "CORS response metadata allows a broad or external origin. Credentialed response access and attacker-origin reflection were not established.",
    "Review intended allowed origins, credentials behavior and Vary: Origin where dynamically selected.",
    "Validate actual request Origin context and browser behavior; a wildcard does not by itself prove an exploit.",[n],
    {strength:"PASSIVE_OBSERVATION",confidence:"LOW",severity:"LOW",
      candidate:meta.corsCredentials==="TRUE"});
  }
  if(meta.setCookieCount!==null&&meta.setCookieCount>0){
   if(meta.secureFlagCount!==null&&meta.secureFlagCount<meta.setCookieCount)
    add("P09.COOKIE.SECURE_AGG","COOKIES","REVIEW_REQUIRED","Observed cookie attributes need Secure review",
     "At least one observed Set-Cookie entry lacks Secure in an aggregate; cookie purpose is unknown.",
     "Classify cookie purpose, and enforce Secure on cookies that must only travel over HTTPS.",
     "Validate the actual Set-Cookie semantics and whether the cookie is session-related.",[n],
     {strength:"PASSIVE_OBSERVATION",confidence:"LOW",severity:"LOW",candidate:true});
   if(meta.sameSiteNoneCount!==null&&meta.secureFlagCount!==null&&meta.sameSiteNoneCount>meta.secureFlagCount)
    add("P09.COOKIE.SAMESITE_AGG","COOKIES","REVIEW_REQUIRED","Cookie SameSite=None / Secure aggregate mismatch",
     "Aggregate flag counts suggest a potential SameSite=None without Secure, not a proven per-cookie relationship.",
     "Review each cookie's SameSite and Secure pairing.","Inspect sanitized cookie-attribute observations with owner approval.",[n],
     {strength:"PASSIVE_OBSERVATION",candidate:true});
   if(meta.httpOnlyFlagCount!==null&&meta.httpOnlyFlagCount<meta.setCookieCount)
    add("P09.COOKIE.HTTPONLY_AGG","COOKIES","OBSERVED","Some cookies do not carry HttpOnly",
     "An aggregate of response cookie attributes lacks HttpOnly on some entries; JavaScript-accessible cookies are not always sensitive.",
     "Use HttpOnly for cookies that must not be read by client JavaScript.",
     "Determine cookie function before classifying a session security concern.",[n]);
  }
 }
 for(const n of sorted){
  if(n.kind==="FORM"){
   add("P09.FORM.INVENTORY","FORMS","OBSERVED","HTML form discovered",
    "A form method and action were inferred from observed HTML; submission and CSRF defenses were not tested.",
    "Review sensitive form actions and anti-CSRF controls in authenticated assessment.",
    "Form submission and anti-CSRF validation are out of scope.",[n]);
   const names=typeof n.metadata.fieldNames==="string"?n.metadata.fieldNames:"";
   if(n.method==="GET"&&/(?:^|,)(?:password|passwd|secret|token|otp|creditcard|ssn)(?:,|$)/i.test(names))
    add("P09.FORM.SENSITIVE_GET","FORMS","REVIEW_REQUIRED","Sensitive-looking field name on GET form",
     "A form named a sensitive-looking input with GET method; actual values and submissions were not inspected.",
     "Review use of POST and protection of sensitive form data.",
     "Validate form semantics and actual submission routes with authorization.",[n],
     {strength:"PASSIVE_OBSERVATION",severity:"LOW",candidate:true});
  }
  if(n.kind==="ENDPOINT"||n.kind==="ROUTE"){
   add("P09.API.INVENTORY","API","OBSERVED","Passive web API or route reference",
    "The route was found in markup, JavaScript hints or a document; reachability and authorization are untested.",
    "Inventory and classify routes for a future authorized API Family assessment.",
    "No mutating methods were called; names do not prove privilege bypass.",[n]);
  }
  if(n.kind==="SCRIPT"){
   if(n.state==="OBSERVED")
    add("P09.CLIENT.SCRIPT","CLIENT","OBSERVED","Client-side script reference observed",
     "A script response was fetched by an authorized passive GET; it was not executed or retained in raw form.",
     "Review client-side data flows and trusted sinks in a separately authorized stage.",
     "Passive discovery route hints alone do not establish XSS or token theft.",[n]);
  }
  if(n.kind==="TECHNOLOGY"){
   add("P09.TECH.OBSERVATION","TECHNOLOGY","OBSERVED","Technology or configuration indicator observed",
    "A passive server header or meta tag provided a technology indicator; exact version and vulnerability status are not established.",
    "Maintain technology inventory and validate versions before vulnerability intelligence correlation.",
    "No CVE lookup or version-based vulnerability claim was made.",[n]);
  }
 }
 for(const c of RULE_CATEGORIES){
  if(!captureKinds.has(c)){
   add("P09."+c+".NOT_EVALUABLE",c,"NOT_EVALUABLE",c+" evidence not evaluable",
    "Required captured observations are unavailable or insufficient in this bounded discovery snapshot.",
    "Collect suitable metadata on a future explicitly authorized discovery.",
    "UNKNOWN is not SAFE; this is not a passing security check.",[],
    {strength:"INSUFFICIENT",confidence:"LOW",limitation:"No eligible source observations for this category."});
   limitationSet.add(c+"_EVIDENCE_NOT_EVALUABLE");
  }
 }
 const state=s.coverageState;
 const observedPages=pages.length;
 const coverageState=observedPages===0?"INSUFFICIENT_EVIDENCE":
  state==="COMPLETE_WITHIN_LIMITS"?"BOUNDED":"PARTIAL";
 if(coverageState!=="BOUNDED")limitationSet.add("SOURCE_COVERAGE_"+state);
 const unavailable=obs.filter(o=>o.outcome==="NOT_EVALUABLE").length;
 const ordered=obs.sort((a,b)=>a.id.localeCompare(b.id));
 const risks=candidates.sort((a,b)=>a.id.localeCompare(b.id));
 const coverage={...s.coverage,discoveryState:state,
  boundedWebsiteSampling:true,entireWebsiteCoverageProven:false,
  ruleCategoryCount:RULE_CATEGORIES.length,notEvaluableCategories:unavailable,
  rawCookieOrTokenValuesStored:false,activeExploitationPerformed:false};
 return Object.freeze({
  analyzerVersion:ANALYZER_VERSION,rulePackVersion:RULE_PACK_VERSION,
  analysisId:s.analysisId,jobId:s.jobId,organizationId:s.organizationId,
  websiteId:s.websiteId,origin:s.origin,scopeHash:s.scopeHash,
  snapshotFingerprint:s.snapshotFingerprint,coverageState,coverage,
  observations:ordered,candidates:risks,
  counts:{observedPages,inferredNodes:sorted.filter(n=>n.state!=="OBSERVED").length,
   failedNodes:sorted.filter(n=>n.state==="FAILED").length,
   notEvaluable:unavailable,reviewRequired:risks.length,analyzedNodes:sorted.length},
  limitations:[...limitationSet].sort()
 });
}
