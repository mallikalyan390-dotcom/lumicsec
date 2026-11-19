import { useMutation,useQuery,useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { ClipboardCheck, Clock3, LockKeyhole, ShieldAlert } from "lucide-react";
import type { CustomerAsset } from "@lumicsec/shared";
import { Badge } from "../components/ui/Badge.js";
import { Button } from "../components/ui/Button.js";
import { Card,CardContent,CardHeader } from "../components/ui/Card.js";
import { getAssets,getAuthSession,getOrganizations,getJson,postJson } from "../lib/api.js";
import { useOrganizationSelection } from "../lib/organization-selection.js";

type Plan={
 id:string; organization_id:string;asset_id:string;created_by:string;
 exact_origin:string;asset_kind:"website"|"api";safe_profile:string;
 approved_paths:string[];http_method:"GET";max_requests:number;max_response_bytes:number;
 max_total_bytes:number;max_execution_ms:number;authorization_reference:string;
 scope_sha256:string;plan_state:"active"|"revoked";created_at:string;expires_at:string;
 proof_expires_at:string;revoked_at:string|null;
};
type PlanEvent={id:number;actor_id:string;event_type:string;details:{
 scopeSha256?:string;paths?:string[];expiresAt?:string;scanningEnabled?:boolean};created_at:string};
type SavedFixtureExecution={id:string;plan_id:string;asset_id:string;
 exact_origin:string;safe_profile:string;status:string;lease_generation:number;
 result_count:number;scope_hash:string;created_at:string;
 started_at:string|null;completed_at:string|null;error_code:string|null};
type Check={eligibility:string;authorizedForPlanning:boolean;publicScanningEnabled:false;
 executionAllowed:false;scopeSha256:string};
const inputClass="w-full rounded-xl border border-white/10 bg-slate-950/80 px-3 py-2.5 text-sm text-white";
function currentlyOwned(asset:CustomerAsset){
 return asset.verification_status==="verified" && !!asset.verification_expires_at &&
 !!asset.verified_at && Date.parse(asset.verification_expires_at)>Date.now();
}
function parsePaths(value:string){
 const paths=value.split("\n").map(x=>x.trim()).filter(Boolean);
 if(paths.length<1||paths.length>6||new Set(paths).size!==paths.length)return null;
 if(paths.some(x=>!/^\/[a-zA-Z0-9._~/-]{0,119}$/.test(x)||x.includes("//")||
  /(^|\/)\.{1,2}(\/|$)/.test(x)||
  /(^|\/)(logout|delete|destroy|transfer|purchase|checkout|reset|token|secret|admin|signout)(\/|$)/i.test(x)))
  return null;
 return paths;
}
export function AssessmentPlansPage(){
 const queryClient=useQueryClient();
 const [assetId,setAssetId]=useState("");
 const [pathsText,setPathsText]=useState("/");
 const [reference,setReference]=useState("");
 const [consent,setConsent]=useState(false);
 const [hours,setHours]=useState(1);
 const [budget,setBudget]=useState(3);
 const [selectedId,setSelectedId]=useState("");
 const [requestId,setRequestId]=useState(()=>crypto.randomUUID());
 const session=useQuery({queryKey:["auth-session"],queryFn:getAuthSession});
 const orgs=useQuery({queryKey:["organizations"],queryFn:getOrganizations});
 const organizations=orgs.data?.organizations??[];
 const {activeOrganizationId,selectOrganization}=useOrganizationSelection(organizations);
 const role=orgs.data?.memberships.find(x=>x.organization_id===activeOrganizationId)?.member_role;
 const canAuthorize=role==="owner"||role==="admin"||role==="analyst";
 const assets=useQuery({queryKey:["assets",activeOrganizationId],
  queryFn:()=>getAssets(activeOrganizationId),enabled:Boolean(activeOrganizationId)});
 const verified=(assets.data?.assets??[]).filter(currentlyOwned);
 const selected=verified.find(a=>a.id===assetId);
 const paths=parsePaths(pathsText);
 const plans=useQuery({queryKey:["assessment-plans",activeOrganizationId],
  queryFn:()=>getJson<{plans:Plan[];scanningEnabled:false;executionAllowed:false}>(
   "/v1/assessment-plans?organizationId="+encodeURIComponent(activeOrganizationId)),
  enabled:Boolean(activeOrganizationId)});
 const history=useQuery({queryKey:["assessment-plan-events",activeOrganizationId,selectedId],
  queryFn:()=>getJson<{events:PlanEvent[]}>(
   "/v1/assessment-plans/events?organizationId="+encodeURIComponent(activeOrganizationId)
   +"&planId="+encodeURIComponent(selectedId)),
  enabled:Boolean(selectedId&&activeOrganizationId)});
 const executionHistory=useQuery({
  queryKey:["assessment-plan-fixture-executions",activeOrganizationId,selectedId],
  queryFn:()=>getJson<{executions:SavedFixtureExecution[];scanningEnabled:false;
    executionAllowed:false}>(
   "/v1/assessment-plans/executions?organizationId="+encodeURIComponent(activeOrganizationId)
    +"&planId="+encodeURIComponent(selectedId)),
  enabled:Boolean(selectedId&&activeOrganizationId),
 });
 const eligibility=useQuery({queryKey:["assessment-plan-check",activeOrganizationId,selectedId],
  queryFn:()=>getJson<{result:Check}>(
    "/v1/assessment-plans/check?organizationId="+encodeURIComponent(activeOrganizationId)
    +"&planId="+encodeURIComponent(selectedId)),
  enabled:Boolean(selectedId&&activeOrganizationId)});
 const create=useMutation({
  mutationFn:()=>{
   if(!selected||!paths)throw Error("INVALID_SCOPED_ASSET");
   const expiry=new Date(Math.min(Date.now()+hours*3600000,
    Date.parse(selected.verification_expires_at??""))).toISOString();
   return postJson<{planId:string;scanningEnabled:false;executionAllowed:false}>(
    "/v1/assessment-plans",{
     organizationId:activeOrganizationId,assetId:selected.id,requestId,
     profile:selected.asset_kind==="website"?"web_readonly":"api_readonly",
     approvedPaths:paths,expiresAt:expiry,maxRequests:budget,
     maxResponseBytes:60000,maxTotalBytes:240000,maxExecutionMs:15000,
     authorizationReference:reference.trim(),
     authorization:"I_AM_AUTHORIZED_TO_PLAN_READONLY_ASSESSMENT_OF_THIS_OWNED_ASSET",
    },session.data?.csrfToken??"");
  },
  onSuccess:async result=>{
   setSelectedId(result.planId);setConsent(false);setReference("");
   setRequestId(crypto.randomUUID());
   await queryClient.invalidateQueries({queryKey:["assessment-plans",activeOrganizationId]});
  },
 });
 const revoke=useMutation({
  mutationFn:(planId:string)=>postJson<{revoked:true}>(
   "/v1/assessment-plans/revoke",
   {organizationId:activeOrganizationId,planId},session.data?.csrfToken??""),
  onSuccess:async()=>{
   await queryClient.invalidateQueries({queryKey:["assessment-plans",activeOrganizationId]});
   await queryClient.invalidateQueries({queryKey:["assessment-plan-events",activeOrganizationId]});
   await queryClient.invalidateQueries({queryKey:["assessment-plan-check",activeOrganizationId]});
  },
 });
 function submit(e:FormEvent<HTMLFormElement>){
  e.preventDefault();
  if(!consent||!canAuthorize||!session.data?.csrfToken||!paths||!selected)return;
  create.mutate();
 }
 return <div className="space-y-7">
  <section>
   <p className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-200">Authorized assessment planning</p>
   <h1 className="mt-2 text-3xl font-semibold text-white">Runtime assessment plans</h1>
   <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-400">
    Record exactly which owned HTTPS paths may be assessed, how much traffic is permitted,
    and when approval ends. Plans are independently authorized; ownership proof alone is not scan consent.
   </p>
  </section>
  <div role="status" className="rounded-xl border border-amber-300/30 bg-amber-300/5 p-4 text-sm text-amber-100">
   Public customer scanning remains <strong>disabled</strong>. Saving a plan records consent
   and audit history only; it never queues a worker, sends a request or verifies a vulnerability.
   Confined broker qualification is restricted to controlled local HTTPS fixtures.
  </div>
  <Card><CardHeader><h2 className="font-semibold text-white"><LockKeyhole size={16} className="mr-2 inline"/>Exact owned asset and consent</h2></CardHeader>
   <CardContent>
    <form onSubmit={submit} className="space-y-4">
     <div className="grid gap-4 md:grid-cols-2">
      <div><label htmlFor="plan-org" className="text-xs text-slate-300">Organization</label>
       <select id="plan-org" className={inputClass} value={activeOrganizationId}
        onChange={e=>{selectOrganization(e.target.value);setAssetId("");setSelectedId("");setConsent(false);}}>
        <option value="">Select organization</option>
        {organizations.map(o=><option value={o.id} key={o.id}>{o.display_name}</option>)}
       </select></div>
      <div><label htmlFor="plan-asset" className="text-xs text-slate-300">Currently verified Web/API asset</label>
       <select id="plan-asset" className={inputClass} value={selected?.id??""}
        disabled={!canAuthorize} onChange={e=>{setAssetId(e.target.value);setConsent(false);}}>
        <option value="">Choose verified asset</option>
        {verified.map(a=><option value={a.id} key={a.id}>{a.display_name} — {a.canonical_origin}</option>)}
       </select></div>
     </div>
     {!canAuthorize&&activeOrganizationId?<p className="text-xs text-amber-100">
      Your role can inspect saved plans but cannot authorize or revoke another person's scope.</p>:null}
     {canAuthorize&&verified.length===0&&activeOrganizationId?
      <p role="status" className="text-xs text-amber-100">No currently verified assets. Complete asset ownership first.</p>:null}
     {selected?<p className="rounded-lg border border-white/10 p-3 text-xs text-cyan-100">
      Exact approved origin: <strong>{selected.canonical_origin}</strong> · GET only · No redirects · No credentials
      · Proof expires {selected.verification_expires_at?new Date(selected.verification_expires_at).toLocaleString():"unknown"}.
     </p>:null}
     <div><label htmlFor="plan-paths" className="text-xs text-slate-300">Approved paths — one exact GET path per line, max 6</label>
      <textarea id="plan-paths" className={inputClass} rows={3} value={pathsText}
       onChange={e=>{setPathsText(e.target.value);setConsent(false);}}
       disabled={!selected||!canAuthorize} placeholder={"/\n/health"} />
      <p className="mt-1 text-xs text-slate-500">
       No URL, query, wildcard, traversal, administrative or state-changing paths. Discovery beyond approved paths is not authorized.
      </p>
      {pathsText&&!paths?<p role="alert" className="text-xs text-rose-300">Use 1–6 distinct, safe absolute paths only.</p>:null}
     </div>
     <div className="grid gap-4 md:grid-cols-2">
      <div><label htmlFor="plan-expiry" className="text-xs text-slate-300">Authorization expires after</label>
       <select id="plan-expiry" className={inputClass} value={hours} onChange={e=>setHours(Number(e.target.value))}>
        <option value={1}>1 hour</option><option value={6}>6 hours</option><option value={12}>12 hours</option>
       </select></div>
      <div><label htmlFor="plan-budget" className="text-xs text-slate-300">Maximum GET requests</label>
       <select id="plan-budget" className={inputClass} value={budget} onChange={e=>setBudget(Number(e.target.value))}>
        <option value={1}>1</option><option value={3}>3</option><option value={6}>6</option>
       </select></div>
     </div>
     <p className="text-xs text-slate-500">Hard caps: 60 KB per response · 240 KB total · 15 seconds execution · one GET method.</p>
     <div><label htmlFor="plan-reference" className="text-xs text-slate-300">Written permission / approval reference (12–140 characters)</label>
      <input id="plan-reference" className={inputClass} value={reference} onChange={e=>setReference(e.target.value)}
       required minLength={12} maxLength={140} disabled={!selected||!canAuthorize}
       placeholder="Authorized ticket or written agreement reference — no credentials" /></div>
     <label className="flex items-start gap-3 text-sm text-slate-300">
      <input type="checkbox" checked={consent} disabled={!selected||!paths||!canAuthorize}
       onChange={e=>setConsent(e.target.checked)} className="mt-1"/>
      <span>I have explicit written permission for this owned asset's exact GET paths and budgets,
      accept expiry/revocation, and understand **no scanning is activated** by saving this plan.</span>
     </label>
     <Button type="submit" disabled={!canAuthorize||!selected||!consent||!paths||
      reference.trim().length<12||create.isPending||!session.data?.csrfToken}>
      <ClipboardCheck size={16}/> {create.isPending?"Saving permission…":"Authorize assessment plan (no scan)"}
     </Button>
     {create.isSuccess?<p role="status" className="text-xs text-cyan-200">
      Authorization saved. No network assessment was executed.</p>:null}
     {create.isError?<p role="alert" className="text-xs text-rose-300">{create.error.message}</p>:null}
    </form>
   </CardContent>
  </Card>
  <Card><CardHeader><h2 className="font-semibold text-white"><Clock3 size={16} className="mr-2 inline"/>Saved authorization and revocation history</h2></CardHeader>
   <CardContent className="space-y-4">
    {plans.isLoading?<p className="text-sm text-slate-400">Loading tenant authorization plans…</p>:null}
    {plans.isError?<p role="alert" className="text-xs text-rose-300">{plans.error.message}</p>:null}
    {plans.data?.plans.length===0?<p className="text-sm text-slate-400">
     No assessment plans. Previously completed findings and reports remain available separately.</p>:null}
    {plans.data?.plans.map(plan=><article key={plan.id} className="rounded-xl border border-white/10 p-4">
     <div className="flex flex-wrap justify-between gap-2">
      <span className="text-sm font-semibold text-white">{plan.exact_origin}</span>
      <Badge>{plan.plan_state==="revoked"?"revoked":Date.parse(plan.expires_at)<=Date.now()?"expired":"active"}</Badge>
     </div>
     <p className="mt-2 text-xs text-slate-400">{plan.safe_profile} · {plan.http_method} · {plan.approved_paths.join(", ")}</p>
     <p className="mt-2 text-xs text-slate-400">{plan.max_requests} requests · {plan.max_total_bytes} total bytes ·
      {plan.max_execution_ms} ms · Ends {new Date(plan.expires_at).toLocaleString()}</p>
     <p className="mt-1 break-all text-xs text-slate-500">Scope SHA-256: {plan.scope_sha256}</p>
     <p className="mt-1 text-xs text-slate-400">Consent reference: {plan.authorization_reference}</p>
     <div className="mt-3 flex flex-wrap gap-3">
      <Button type="button" variant="secondary" size="sm" onClick={()=>setSelectedId(plan.id)}>Inspect audit and live eligibility</Button>
      {canAuthorize&&plan.plan_state==="active"&&<Button type="button" variant="secondary" size="sm"
       disabled={revoke.isPending||!session.data?.csrfToken||
        (role==="analyst"&&plan.created_by!==session.data?.user?.id)}
       onClick={()=>revoke.mutate(plan.id)}>Revoke permission</Button>}
     </div>
    </article>)}
    {revoke.isSuccess?<p role="status" className="text-xs text-cyan-200">Authorization revoked. Future use denied.</p>:null}
    {revoke.isError?<p role="alert" className="text-xs text-rose-300">{revoke.error.message}</p>:null}
    {selectedId?<div className="rounded-xl border border-cyan-300/20 p-4 text-xs text-slate-300">
     <p className="font-semibold text-white">Authorization evidence</p>
     {eligibility.data?<p className="mt-2">Current proof check: <Badge>{eligibility.data.result.eligibility}</Badge>
      {" "}· Network execution remains disabled</p>:null}
     {eligibility.isError?<p role="alert">{eligibility.error.message}</p>:null}
     {history.data?.events.map(event=><p key={event.id} className="mt-2">
      {new Date(event.created_at).toLocaleString()} · {event.event_type} · actor {event.actor_id}</p>)}
     {history.isError?<p role="alert">{history.error.message}</p>:null}
     <div className="mt-4 border-t border-white/10 pt-3">
      <p className="font-semibold text-white">Controlled-fixture execution history (read-only)</p>
      <p className="mt-1 text-slate-400">Only saved internal Docker fixture jobs may appear.
       Customer network scanning remains disabled; creating a plan never starts execution.</p>
      {executionHistory.isLoading?<p className="mt-2">Loading fixture job history…</p>:null}
      {executionHistory.isError?<p role="alert" className="mt-2 text-rose-300">
       {executionHistory.error.message}</p>:null}
      {executionHistory.data?.executions.length===0?
       <p className="mt-2 text-slate-400">No controlled fixture executions recorded for this plan.</p>:null}
      {executionHistory.data?.executions.map(job=><div key={job.id}
        className="mt-3 rounded-lg border border-white/10 p-3">
       <div className="flex flex-wrap items-center gap-2">
        <Badge>{job.status}</Badge><span>{job.safe_profile}</span>
        <span>{job.result_count} saved review observations</span>
       </div>
       <p className="mt-1">Created {new Date(job.created_at).toLocaleString()}
        {job.completed_at?" · Ended "+new Date(job.completed_at).toLocaleString():""}</p>
       <p className="mt-1 break-all text-slate-500">Saved scope SHA-256: {job.scope_hash}</p>
       {job.error_code?<p className="mt-1 text-amber-200">Failure code: {job.error_code}</p>:null}
      </div>)}
     </div>
    </div>:null}
    <p className="text-sm text-slate-300"><ShieldAlert size={16} className="mr-2 inline"/>
     This milestone creates and revokes plans, not scanner jobs. To see any existing qualified observations,
     remediation, retest comparisons or PDF/JSON exports, open <Link className="text-cyan-200 underline" to="/app/findings">Findings & reports</Link>.
    </p>
   </CardContent>
  </Card>
 </div>;
}
