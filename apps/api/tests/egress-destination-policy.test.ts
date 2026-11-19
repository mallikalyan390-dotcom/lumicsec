import {describe,expect,it} from "vitest";
import {validateFuturePublicEgressPolicy as admit,
  type StoredRuntimePlan,type RuntimeAssetProof,
  PublicEgressAdmissionDenied} from "../src/lib/egress-destination-policy.js";
const plan:StoredRuntimePlan={
 organization_id:"00000000-0000-4000-8000-000000000011",
 asset_id:"00000000-0000-4000-8000-000000000022",
 asset_kind:"website",exact_origin:"https://owned.example.net",
 approved_paths:["/","/health"],safe_profile:"web_readonly",
 plan_state:"active",scope_sha256:"a".repeat(64),
 proof_verified_at:"2026-11-19T00:00:00.000Z",
 expires_at:"2026-11-20T00:00:00.000Z",max_requests:3,
 max_response_bytes:60000,max_total_bytes:240000,max_execution_ms:15000,
};
const asset:RuntimeAssetProof={
 id:plan.asset_id,organization_id:plan.organization_id,asset_kind:"website",
 canonical_origin:plan.exact_origin,
 verification_status:"verified",verified_at:plan.proof_verified_at,
 verification_expires_at:"2026-11-25T00:00:00.000Z",
};
const input=()=>({
 plan,asset,url:"https://owned.example.net/health",method:"GET" as const,
 resolved:[{address:"8.8.8.8",family:4 as const}],
 allowedPublicIps:["8.8.8.8"],nowMs:Date.parse("2026-11-19T06:00:00.000Z"),
});
describe("offline future public IP admission; never connects or grants execution",()=>{
 it("returns exact public IPv4 pin and still hard-denies execution",()=>{
  const result=admit(input());
  expect(result).toEqual({pinned:{address:"8.8.8.8",family:4},
   host:"owned.example.net",path:"/health",method:"GET",
   scopeSha256:"a".repeat(64),executionAllowed:false});
 });
 it("binds a public IPv6 pin when separately allowed",()=>{
  const result=admit({...input(),
   resolved:[{address:"2606:4700:4700::1111",family:6}],
   allowedPublicIps:["2606:4700:4700::1111"]});
  expect(result.pinned.family).toBe(6);
  expect(result.executionAllowed).toBe(false);
 });
 it.each([
  {resolved:[{address:"169.254.169.254",family:4 as const}]},
  {resolved:[{address:"8.8.8.8",family:4 as const},
    {address:"127.0.0.1",family:4 as const}]},
  {resolved:[{address:"::1",family:6 as const}]},
  {resolved:[{address:"fd00::1",family:6 as const}]},
  {resolved:[{address:"::ffff:10.1.2.3",family:6 as const}]},
  {resolved:[{address:"2002::1",family:6 as const}]},
 ])("blocks private, metadata, mapped, reserved and mixed DNS answers %#",change=>{
  expect(()=>admit({...input(),...change})).toThrow(PublicEgressAdmissionDenied);
 });
 it("denies DNS rebinding to a different, still-public IP",()=>{
  expect(()=>admit({...input(),resolved:[{address:"1.1.1.1",family:4}]}))
   .toThrow("EGRESS_DNS_REBINDING_OR_UNAPPROVED_IP");
 });
 it("denies an allowlist containing private, metadata, malformed or duplicate IPs",()=>{
  for(const allowedPublicIps of [
   ["8.8.8.8","169.254.169.254"],["8.8.8.8","8.8.8.8"],
   ["localhost"],["8.8.8.8","fd00::1"]]){
   expect(()=>admit({...input(),allowedPublicIps}))
    .toThrow(PublicEgressAdmissionDenied);
  }
 });
 it.each([
  {url:"https://evil.example.net/health"},
  {url:"https://owned.example.net/other"},
  {url:"https://owned.example.net/health?token=value"},
  {url:"http://owned.example.net/health"},
  {url:"https://owned.example.net:444/health"},
  {url:"https://owned.example.net/%2e%2e/admin"},
 ])("denies scope and URL manipulation %#",change=>{
  expect(()=>admit({...input(),...change})).toThrow();
 });
 it("denies revoked/expired permission and proof rotation",()=>{
  expect(()=>admit({...input(),plan:{...plan,plan_state:"revoked"}}))
   .toThrow("EGRESS_PLAN_NOT_CURRENTLY_AUTHORIZED");
  expect(()=>admit({...input(),nowMs:Date.parse("2026-11-21T00:00:00Z")}))
   .toThrow("EGRESS_PLAN_NOT_CURRENTLY_AUTHORIZED");
  expect(()=>admit({...input(),asset:{...asset,verified_at:"2026-11-19T01:00:00Z"}}))
   .toThrow("EGRESS_PLAN_NOT_CURRENTLY_AUTHORIZED");
  expect(()=>admit({...input(),asset:{...asset,verification_status:"revoked"}}))
   .toThrow("EGRESS_PLAN_NOT_CURRENTLY_AUTHORIZED");
 });
 it("rejects wrong tenant, asset kind, excessive budgets and unsigned scope",()=>{
  expect(()=>admit({...input(),asset:{...asset,organization_id:"other"}})).toThrow();
  expect(()=>admit({...input(),plan:{...plan,max_requests:100}})).toThrow();
  expect(()=>admit({...input(),plan:{...plan,scope_sha256:"fake"}})).toThrow();
 });
});
