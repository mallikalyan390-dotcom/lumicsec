/* Offline, never-dispatched public egress admission policy.
 * This is NOT a customer scanning transport. The actual confined broker has
 * no public route; even a successful admission cannot enable execution.
 * A future allowlisted network namespace must independently enforce this
 * decision at the socket layer and pass CTO review before activation.
 */
import {isIP} from "node:net";
import {isPublicWebAddress,requireExactWebUrl,
  type PinnedAddress,WEB_READ_LIMITS} from "./web-pinned-transport.js";

export type StoredRuntimePlan=Readonly<{
 organization_id:string;asset_id:string;asset_kind:"website"|"api";
 exact_origin:string;approved_paths:readonly string[];
 safe_profile:"web_readonly"|"api_readonly";
 plan_state:"active"|"revoked";scope_sha256:string;
 proof_verified_at:string;expires_at:string;
 max_requests:number;max_response_bytes:number;max_total_bytes:number;
 max_execution_ms:number;
}>;
export type RuntimeAssetProof=Readonly<{
 id:string;organization_id:string;asset_kind:"website"|"api";
 canonical_origin:string;verified_at:string|null;
 verification_status:"pending"|"verified"|"revoked";
 verification_expires_at:string|null;
}>;
export class PublicEgressAdmissionDenied extends Error{
 constructor(readonly code:string){super(code);}
}
const fail=(code:string):never=>{throw new PublicEgressAdmissionDenied(code);};
/**
 * All DNS responses must be explicit currently public, present in a separately
 * approved exact IP allowlist, and bound to the SAME strict HTTPS hostname.
 * IPv4 and IPv6 comparisons use their full canonical string for now.
 * DNS answer changes require a fresh grant; no silent address failover.
 */
export function validateFuturePublicEgressPolicy(input:Readonly<{
 plan:StoredRuntimePlan;asset:RuntimeAssetProof;
 url:string;method:"GET";resolved:readonly PinnedAddress[];
 allowedPublicIps:readonly string[];nowMs:number;
}>):Readonly<{pinned: PinnedAddress;scopeSha256:string;
 host:string;path:string;method:"GET";executionAllowed:false}>{
 const {plan,asset}=input;
 if(!Number.isFinite(input.nowMs)||input.method!=="GET"||
   plan.plan_state!=="active"||
   !Number.isFinite(Date.parse(plan.expires_at))||
   Date.parse(plan.expires_at)<=input.nowMs||
   asset.verification_status!=="verified"||
   !asset.verified_at||!asset.verification_expires_at||
   Date.parse(asset.verification_expires_at)<=input.nowMs||
   asset.verified_at!==plan.proof_verified_at||
   asset.asset_kind!==plan.asset_kind||
   asset.id!==plan.asset_id||asset.organization_id!==plan.organization_id||
   asset.canonical_origin!==plan.exact_origin)
   fail("EGRESS_PLAN_NOT_CURRENTLY_AUTHORIZED");
 if((plan.asset_kind==="website")!==(plan.safe_profile==="web_readonly")||
   !/^[a-f0-9]{64}$/.test(plan.scope_sha256)||
   plan.approved_paths.length<1||plan.approved_paths.length>6||
   plan.max_requests<1||plan.max_requests>WEB_READ_LIMITS.maxRequests||
   plan.max_response_bytes<1||plan.max_response_bytes>WEB_READ_LIMITS.maxResponseBytes||
   plan.max_total_bytes<plan.max_response_bytes||
   plan.max_total_bytes>WEB_READ_LIMITS.maxTotalBytes||
   plan.max_execution_ms<1000||plan.max_execution_ms>WEB_READ_LIMITS.maxRuntimeMs)
   fail("EGRESS_SCOPE_BUDGET_DENIED");
 const target=requireExactWebUrl(input.url,plan.exact_origin,"GET");
 if(!plan.approved_paths.includes(target.pathname)||
   plan.approved_paths.some(p=>!/^\/[a-zA-Z0-9._~/-]{0,119}$/.test(p)))
   fail("EGRESS_PATH_NOT_EXPLICITLY_APPROVED");
 if(input.resolved.length<1||input.resolved.length>12||
   input.allowedPublicIps.length<1||input.allowedPublicIps.length>12)
   fail("EGRESS_DNS_OR_ALLOWLIST_BOUNDS");
 const approved=new Set(input.allowedPublicIps);
 if(approved.size!==input.allowedPublicIps.length ||
   input.allowedPublicIps.some(ip=>!isPublicWebAddress(ip,isIP(ip))))
   fail("EGRESS_IP_ALLOWLIST_INVALID");
 for(const answer of input.resolved){
   if(!isPublicWebAddress(answer.address,answer.family))
     fail("EGRESS_PRIVATE_OR_METADATA_DNS_BLOCKED");
   if(!approved.has(answer.address))
     fail("EGRESS_DNS_REBINDING_OR_UNAPPROVED_IP");
 }
 return {pinned:input.resolved[0]!,scopeSha256:plan.scope_sha256,
   host:target.hostname,path:target.pathname,method:"GET",executionAllowed:false};
}
