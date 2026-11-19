import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ArrowDownToLine, ClipboardList, FileCheck2, History, ShieldAlert } from "lucide-react";
import { Badge } from "../components/ui/Badge.js";
import { Button } from "../components/ui/Button.js";
import { Card, CardContent, CardHeader } from "../components/ui/Card.js";
import { getAssets, getAuthSession, getJson, getOrganizationMembers,
  getOrganizations, postJson } from "../lib/api.js";
import { useOrganizationSelection } from "../lib/organization-selection.js";

type Finding = {
  id:string; organization_id:string; asset_id:string;assessment_kind:string;rule_id:string;
  title:string;summary:string;remediation:string|null;severity_estimate:string;
  source_classification:string;reviewer_conclusion:string;review_reason:string|null;
  reviewer_id:string|null;workflow_status:string;assigned_to:string|null;
  source_locator:string;first_seen_at:string;last_seen_at:string;
};
type EvidenceLink={id:string;job_id:string;observation_id:string;scope_hash:string|null;
  source_fingerprint:string|null;evidence_source:{fingerprints?:string[];paths?:string[]}|null;linked_at:string};
type Event={id:number;event_type:string;actor_id:string;occurred_at:string;details:{
  operation?:string;input?:{message?:string;note?:string;uri?:string;reason?:string};
  result?:string;verifiedResolved?:boolean}};
type Retest={id:string;requested_at:string;compared_at:string|null;comparison_job_id:string|null;
  comparison_state:string;details?:{note?:string}};
type Assessment={id:string;asset_id:string;assessment_kind:string;job_state:string;
  requested_at:string;completed_at:string|null;observation_count:number;scope_hash:string|null};
const selectStyle="h-10 w-full rounded-lg border border-white/15 bg-slate-950 px-3 text-sm text-slate-100";
const inputStyle="h-10 w-full rounded-lg border border-white/15 bg-slate-950 px-3 text-sm text-slate-100";
const labelStyle="mb-1 block text-xs font-semibold text-slate-400";
const emptyText="No findings have been imported from saved assessments. This is not evidence that your assets are secure.";
const conclusions=["configuration_review","needs_evidence","false_positive","accepted_risk"] as const;
const statuses=["open","in_progress","ready_for_retest","reopened"] as const;
const apiBase=import.meta.env.VITE_API_BASE_URL??"";

export function FindingsPage(){
  const cache=useQueryClient();
  const [assetFilter,setAssetFilter]=useState("");
  const [statusFilter,setStatusFilter]=useState("");
  const [severityFilter,setSeverityFilter]=useState("");
  const [sort,setSort]=useState("newest");
  const [page,setPage]=useState(0);
  const [selectedId,setSelectedId]=useState("");
  const [importJob,setImportJob]=useState("");
  const [decision,setDecision]=useState("configuration_review");
  const [reason,setReason]=useState("");
  const [workflow,setWorkflow]=useState("in_progress");
  const [assignee,setAssignee]=useState("");
  const [comment,setComment]=useState("");
  const [reference,setReference]=useState("");
  const [referenceNote,setReferenceNote]=useState("");
  const [retestJob,setRetestJob]=useState("");
  const [downloadError,setDownloadError]=useState("");
  const [pendingDownload,setPendingDownload]=useState(false);
  const session=useQuery({queryKey:["auth-session"],queryFn:getAuthSession});
  const organizationsQuery=useQuery({queryKey:["organizations"],queryFn:getOrganizations});
  const orgs=organizationsQuery.data?.organizations??[];
  const {activeOrganizationId,selectOrganization}=useOrganizationSelection(orgs);
  const role=organizationsQuery.data?.memberships.find(x=>x.organization_id===activeOrganizationId)?.member_role;
  const canReview=role==="owner"||role==="admin"||role==="analyst";
  const canManage=role==="owner"||role==="admin";
  const orgName=orgs.find(o=>o.id===activeOrganizationId)?.display_name??"";
  const assets=useQuery({queryKey:["assets",activeOrganizationId],queryFn:()=>getAssets(activeOrganizationId),
    enabled:!!activeOrganizationId});
  const members=useQuery({queryKey:["finding-members",activeOrganizationId],
    queryFn:()=>getOrganizationMembers(activeOrganizationId),enabled:!!activeOrganizationId&&canManage});
  const assessments=useQuery({queryKey:["finding-assessments",activeOrganizationId],
    queryFn:()=>getJson<{assessments:Assessment[];scanningEnabled:false}>(
      "/v1/findings/assessments?organizationId="+encodeURIComponent(activeOrganizationId)),
    enabled:!!activeOrganizationId});
  const params=new URLSearchParams({organizationId:activeOrganizationId,sort,page:String(page)});
  if(assetFilter)params.set("assetId",assetFilter);
  if(statusFilter)params.set("status",statusFilter);
  if(severityFilter)params.set("severity",severityFilter);
  const findings=useQuery({queryKey:["findings",activeOrganizationId,assetFilter,statusFilter,severityFilter,sort,page],
    queryFn:()=>getJson<{findings:Finding[];total:number;page:number;pageSize:number}>(
      "/v1/findings?"+params.toString()),enabled:!!activeOrganizationId});
  const detail=useQuery({queryKey:["finding-detail",activeOrganizationId,selectedId],
    queryFn:()=>getJson<{finding:Finding;links:EvidenceLink[];events:Event[];retests:Retest[]}>(
      "/v1/findings/detail?"+new URLSearchParams({organizationId:activeOrganizationId,findingId:selectedId})),
    enabled:!!activeOrganizationId&&!!selectedId});
  const importAction=useMutation({mutationFn:()=>postJson<{result:{newFindings:number;linkedObservations:number}}>(
    "/v1/findings/import",{organizationId:activeOrganizationId,jobId:importJob,
      requestId:crypto.randomUUID()},session.data?.csrfToken??""),
    onSuccess:async()=>{await cache.invalidateQueries({queryKey:["findings",activeOrganizationId]});}});
  const action=useMutation({
    mutationFn:(input:{action:string;payload:Record<string,unknown>})=>postJson<{result:unknown}>(
      "/v1/findings/action",{organizationId:activeOrganizationId,findingId:selectedId,
        action:input.action,payload:input.payload,requestId:crypto.randomUUID()},
      session.data?.csrfToken??""),
    onSuccess:async()=>{
      await Promise.all([
        cache.invalidateQueries({queryKey:["findings",activeOrganizationId]}),
        cache.invalidateQueries({queryKey:["finding-detail",activeOrganizationId,selectedId]}),
      ]);
    },
  });
  async function download(format:"pdf"|"json"){
    if(!activeOrganizationId)return;
    setPendingDownload(true);setDownloadError("");
    try{
      const query=new URLSearchParams({organizationId:activeOrganizationId,format});
      if(assetFilter)query.set("assetId",assetFilter);
      const response=await fetch(apiBase+"/v1/findings/report?"+query.toString(),{
        credentials:"include",cache:"no-store",headers:{accept:format==="pdf"?"application/pdf":"application/json"},
      });
      if(!response.ok)throw Error("Report authorization, size, or export validation denied");
      const contentType=response.headers.get("content-type")??"";
      if(!contentType.includes(format==="pdf"?"application/pdf":"application/json"))
        throw Error("Unexpected report format");
      const blob=await response.blob();
      if(blob.size<40||blob.size>1_500_000)throw Error("Report resource limit exceeded");
      const url=URL.createObjectURL(blob);
      const anchor=document.createElement("a");
      anchor.href=url;anchor.download="lumicsec-authorized-findings."+format;
      document.body.append(anchor);anchor.click();anchor.remove();
      setTimeout(()=>URL.revokeObjectURL(url),15_000);
    }catch(e){setDownloadError(e instanceof Error?e.message:"Report download failed");}
    finally{setPendingDownload(false);}
  }
  const current=detail.data?.finding;
  const assetList=assets.data?.assets??[];
  const selectedAsset=assetList.find(a=>a.id===current?.asset_id);
  const assetOwnedNow=selectedAsset?.verification_status==="verified" &&
    !!selectedAsset.verification_expires_at && Date.parse(selectedAsset.verification_expires_at)>Date.now();
  const availableRetests=(assessments.data?.assessments??[]).filter(a=>
    a.asset_id===current?.asset_id&&a.assessment_kind===current?.assessment_kind&&
    a.id!==detail.data?.links[0]?.job_id);
  return <div className="space-y-7">
    <section>
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-200">Customer security operations</p>
      <h1 className="mt-2 text-3xl font-semibold text-white">Findings, remediation and reports</h1>
      <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-400">
        Review retained Web/API assessment observations, document decisions, assign remediation,
        compare authorized saved evidence and export professional reports. All passive and specification
        signals require human review. No exploitable vulnerability is automatically confirmed.
      </p>
    </section>
    <div className="rounded-xl border border-amber-400/30 bg-amber-400/5 p-4 text-sm text-amber-100" role="status">
      Live customer Web scanning is disabled. Retest requests only await new authorized assessment
      evidence. Not-observed findings are never automatically marked verified resolved.
    </div>
    <Card><CardHeader><h2 className="font-semibold text-white">Organization & scope</h2></CardHeader>
      <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div><label htmlFor="finding-org" className={labelStyle}>Organization</label>
          <select id="finding-org" className={selectStyle} value={activeOrganizationId}
            onChange={e=>{selectOrganization(e.target.value);setAssetFilter("");setSelectedId("");setPage(0);}}>
            <option value="">Choose organization</option>{orgs.map(o=><option key={o.id} value={o.id}>{o.display_name}</option>)}
          </select></div>
        <div><label htmlFor="finding-asset" className={labelStyle}>Asset</label>
          <select id="finding-asset" className={selectStyle} value={assetFilter}
            onChange={e=>{setAssetFilter(e.target.value);setPage(0);setSelectedId("");}}>
            <option value="">All authorized assets</option>
            {assetList.map(a=><option value={a.id} key={a.id}>{a.display_name} ({a.asset_kind})</option>)}
          </select></div>
        <div><label htmlFor="finding-status" className={labelStyle}>Remediation status</label>
          <select id="finding-status" className={selectStyle} value={statusFilter}
            onChange={e=>{setStatusFilter(e.target.value);setPage(0);}}>
            <option value="">All statuses</option>{[...statuses,"verified_resolved"].map(s=>
              <option value={s} key={s}>{s.replaceAll("_"," ")}</option>)}
          </select></div>
        <div><label htmlFor="finding-severity" className={labelStyle}>Estimated severity</label>
          <select id="finding-severity" className={selectStyle} value={severityFilter}
            onChange={e=>{setSeverityFilter(e.target.value);setPage(0);}}>
            <option value="">All severities</option>{["high","medium","low","info"].map(s=>
              <option value={s} key={s}>{s}</option>)}
          </select></div>
      </CardContent>
    </Card>
    <div className="grid gap-4 sm:grid-cols-3">
      <Card><CardContent className="p-5"><p className="text-xs text-slate-400">Matching findings</p>
        <p className="mt-2 text-3xl font-bold text-cyan-200">{findings.data?.total??"—"}</p></CardContent></Card>
      <Card><CardContent className="p-5"><p className="text-xs text-slate-400">On this page: review required</p>
        <p className="mt-2 text-3xl font-bold text-amber-200">
          {findings.data?.findings.filter(f=>f.reviewer_conclusion==="unreviewed").length??"—"}
        </p></CardContent></Card>
      <Card><CardContent className="p-5"><p className="text-xs text-slate-400">On this page: remediation underway</p>
        <p className="mt-2 text-3xl font-bold text-cyan-200">
          {findings.data?.findings.filter(f=>f.workflow_status==="in_progress").length??"—"}
        </p></CardContent></Card>
    </div>
    <Card><CardHeader><h2 className="flex items-center gap-2 font-semibold text-white">
      <ClipboardList size={18}/> Import saved assessment evidence</h2>
      <p className="text-xs text-slate-400">Idempotent: repeated imports link source observations without creating duplicate findings. No scan is started.</p>
    </CardHeader><CardContent className="space-y-3">
      {canReview?<div className="flex flex-wrap gap-3">
        <select id="finding-import-job" className={selectStyle+" max-w-xl"} value={importJob}
          onChange={e=>setImportJob(e.target.value)}>
          <option value="">Select completed assessment with observations</option>
          {(assessments.data?.assessments??[]).map(job=>
            <option key={job.id} value={job.id}>{job.assessment_kind} | {job.observation_count} observations | {new Date(job.requested_at).toLocaleDateString()} | {job.id.slice(0,8)}</option>)}
        </select>
        <Button disabled={!importJob||importAction.isPending||!session.data?.csrfToken}
          onClick={()=>importAction.mutate()}>Import saved evidence</Button>
      </div>:<p className="text-xs text-slate-400">This role may read findings. Reviewer actions require owner, admin or analyst.</p>}
      {importAction.isSuccess?<p role="status" className="text-sm text-cyan-200">
        Imported {importAction.data.result.newFindings} new findings; linked {importAction.data.result.linkedObservations} observations.</p>:null}
      {importAction.isError?<p role="alert" className="text-sm text-rose-300">{importAction.error.message}</p>:null}
      {assessments.data?.assessments.length===0?<p className="text-xs text-slate-400">
        No completed saved assessments contain review observations. Offline API specification review can provide evidence without network traffic.</p>:null}
    </CardContent></Card>
    <Card><CardHeader><div className="flex flex-wrap items-center justify-between gap-3">
      <h2 className="font-semibold text-white">Findings register</h2>
      <div><label htmlFor="finding-sort" className={labelStyle}>Sort</label>
        <select id="finding-sort" className={selectStyle} value={sort} onChange={e=>{setSort(e.target.value);setPage(0);}}>
          <option value="newest">Recently updated</option>
          <option value="oldest">Oldest updated</option>
          <option value="severity">Severity estimate</option>
        </select></div></div></CardHeader>
    <CardContent className="space-y-3">
      {!activeOrganizationId?<p className="text-sm text-slate-400">Select an organization to view authorized findings.</p>:null}
      {findings.isLoading?<p className="text-sm text-slate-400">Loading tenant-isolated findings…</p>:null}
      {findings.isError?<p role="alert" className="text-sm text-rose-300">{findings.error.message}</p>:null}
      {findings.data?.findings.length===0?<p className="text-sm text-slate-400">{emptyText}</p>:null}
      {findings.data?.findings.map(f=><div key={f.id} className="rounded-xl border border-white/10 bg-slate-950/40 p-4">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <Badge>{f.severity_estimate} estimate</Badge><Badge>{f.workflow_status}</Badge>
          <Badge>{f.reviewer_conclusion}</Badge><Badge>{f.source_classification}</Badge>
        </div>
        <p className="mt-2 font-semibold text-white">{f.rule_id} — {f.title}</p>
        <p className="mt-1 text-sm text-slate-400">{f.summary}</p>
        <p className="mt-2 text-xs text-slate-500">
          {assetList.find(a=>a.id===f.asset_id)?.display_name??f.asset_id} ·
          {" "}{f.assessment_kind} · Last observed {new Date(f.last_seen_at).toLocaleString()}
        </p>
        <Button variant="secondary" size="sm" className="mt-3" onClick={()=>setSelectedId(f.id)}>
          <FileCheck2 size={14}/> Review finding
        </Button>
      </div>)}
      {findings.data&&findings.data.total>25?<div className="flex justify-between gap-3">
        <Button variant="secondary" size="sm" disabled={page===0} onClick={()=>setPage(p=>p-1)}>Previous</Button>
        <span className="text-xs text-slate-400">Page {page+1} / {Math.ceil(findings.data.total/25)}</span>
        <Button variant="secondary" size="sm" disabled={(page+1)*25>=findings.data.total}
          onClick={()=>setPage(p=>p+1)}>Next</Button>
      </div>:null}
    </CardContent></Card>
    {selectedId?<Card><CardHeader><h2 className="flex items-center gap-2 font-semibold text-white">
      <ShieldAlert size={18}/> Finding review and remediation</h2>
      <p className="text-xs text-slate-400">Evidence provenance, human decisions and history are retained; no automatic exploit confirmation.</p>
    </CardHeader><CardContent className="space-y-5">
      {detail.isError?<p role="alert" className="text-sm text-rose-300">{detail.error.message}</p>:null}
      {detail.isLoading?<p className="text-sm text-slate-400">Loading evidence, reviews and retests…</p>:null}
      {current?<>
        <div className="space-y-2 rounded-xl border border-cyan-300/20 bg-cyan-300/5 p-4 text-sm">
          <p className="font-semibold text-white">{current.title}</p>
          <p className="text-slate-300">{current.summary}</p>
          <p className="text-cyan-200">Remediation: {current.remediation??"Review the source configuration."}</p>
          <p className="text-slate-400">Observed at {current.source_locator} on {selectedAsset?.canonical_origin??"the selected asset"}.</p>
          <p className="text-xs text-amber-200">Estimated severity: {current.severity_estimate}. Reviewer conclusion: {current.reviewer_conclusion}. Not confirmed exploitable.</p>
          {current.review_reason?<p>Reviewer reason: {current.review_reason}</p>:null}
          <p className="text-xs">Assignee: {current.assigned_to??"not assigned"} | Status: {current.workflow_status}</p>
        </div>
        <section><h3 className="mb-2 font-semibold text-white">Immutable source evidence references</h3>
          {(detail.data?.links??[]).map(l=><div key={l.id} className="mb-2 rounded-lg border border-white/10 p-3 text-xs text-slate-300">
            <p>Assessment: <code>{l.job_id}</code> | Observation: <code>{l.observation_id}</code></p>
            <p className="mt-1 break-all">Captured fingerprints: {l.evidence_source?.fingerprints?.join(", ")||l.source_fingerprint||"not retained"}</p>
            <p>Paths: {l.evidence_source?.paths?.join(", ")||current.source_locator}</p>
            <p className="mt-1 break-all">Scope hash: {l.scope_hash??"not saved"}</p>
          </div>)}
        </section>
        {canReview?<section className="grid gap-4 border-t border-white/10 pt-4 lg:grid-cols-2">
          <div className="space-y-2"><h3 className="font-semibold">Human classification</h3>
            <select id="finding-decision" className={selectStyle} value={decision}
              onChange={e=>setDecision(e.target.value)}>
              {conclusions.filter(x=>x!=="accepted_risk"||canManage).map(x=><option key={x} value={x}>{x.replaceAll("_"," ")}</option>)}
            </select>
            <label htmlFor="finding-reason" className={labelStyle}>Reason (required for false positives and accepted risk)</label>
            <textarea id="finding-reason" className={inputStyle+" h-24 py-2"} maxLength={1500}
              value={reason} onChange={e=>setReason(e.target.value)}/>
            <Button size="sm" disabled={action.isPending}
              onClick={()=>action.mutate({action:"classify",payload:{conclusion:decision,reason}})}>
              Record reviewer decision</Button>
          </div>
          <div className="space-y-2"><h3 className="font-semibold">Remediation status</h3>
            <select id="finding-workflow" className={selectStyle} value={workflow}
              onChange={e=>setWorkflow(e.target.value)}>
              {statuses.map(x=><option value={x} key={x}>{x.replaceAll("_"," ")}</option>)}
            </select>
            <Button size="sm" disabled={action.isPending}
              onClick={()=>action.mutate({action:"status",payload:{status:workflow}})}>
              Save workflow status</Button>
            <p className="text-xs text-amber-200">Verified resolved cannot be selected without independently qualified evidence.</p>
          </div>
          {canManage?<div className="space-y-2"><h3 className="font-semibold">Assign authorized reviewer</h3>
            <select id="finding-assignee" className={selectStyle} value={assignee}
              onChange={e=>setAssignee(e.target.value)}>
              <option value="">Unassigned</option>
              {(members.data?.members??[]).filter(m=>m.member_status==="active"&&["owner","admin","analyst"].includes(m.member_role))
                .map(m=><option value={m.user_id} key={m.user_id}>{m.member_email} ({m.member_role})</option>)}
            </select>
            <Button size="sm" disabled={action.isPending}
              onClick={()=>action.mutate({action:"assign",payload:{userId:assignee||null}})}>
              Save assignment</Button>
          </div>:null}
          <div className="space-y-2"><h3 className="font-semibold">Review comment</h3>
            <textarea id="finding-comment" className={inputStyle+" h-24 py-2"} maxLength={1500}
              value={comment} onChange={e=>setComment(e.target.value)}/>
            <Button size="sm" disabled={action.isPending||comment.trim().length<3}
              onClick={()=>action.mutate({action:"comment",payload:{message:comment}})}>Add audit comment</Button>
          </div>
          <div className="space-y-2"><h3 className="font-semibold">Safe asset-origin evidence reference</h3>
            <input id="finding-reference" className={inputStyle} placeholder={selectedAsset?.canonical_origin+"/review-proof"}
              maxLength={500} value={reference} onChange={e=>setReference(e.target.value)}/>
            <input id="finding-reference-note" className={inputStyle} placeholder="Review note (no secrets)" maxLength={500}
              value={referenceNote} onChange={e=>setReferenceNote(e.target.value)}/>
            <Button size="sm" disabled={action.isPending||!reference||referenceNote.length<3}
              onClick={()=>action.mutate({action:"reference",payload:{uri:reference,note:referenceNote}})}>
              Attach safe reference</Button>
            <p className="text-xs text-slate-500">Only sanitized URLs on the same registered HTTPS asset; no file upload or fetching.</p>
          </div>
          <div className="space-y-2"><h3 className="font-semibold">Evidence-backed retest</h3>
            <Button size="sm" disabled={action.isPending||!assetOwnedNow||detail.data?.retests.some(r=>r.comparison_state==="awaiting_execution")}
              onClick={()=>action.mutate({action:"retest_request",payload:{}})}>
              Request retest (await evidence)</Button>
            <select id="finding-retest-assessment" className={selectStyle} value={retestJob}
              onChange={e=>setRetestJob(e.target.value)}>
              <option value="">Choose later completed saved assessment</option>
              {availableRetests.map(a=><option key={a.id} value={a.id}>
                {a.assessment_kind} — {new Date(a.requested_at).toLocaleString()} — {a.id.slice(0,8)}</option>)}
            </select>
            <Button size="sm" disabled={action.isPending||!retestJob||
              !detail.data?.retests.some(r=>r.comparison_state==="awaiting_execution")}
              onClick={()=>action.mutate({action:"retest_compare",payload:{jobId:retestJob}})}>
              Compare saved evidence</Button>
            <p className="text-xs text-amber-200">New retest requests require current asset verification; no scan is started. Absence in later passive/spec evidence does not establish verified resolution.</p>
          </div>
        </section>:<p className="text-sm text-slate-400">Read-only reviewer access. Modifications require an authorized organization role.</p>}
        {action.isSuccess?<p role="status" className="text-sm text-cyan-200">Finding history updated. No network test executed.</p>:null}
        {action.isError?<p role="alert" className="text-sm text-rose-300">{action.error.message}</p>:null}
        <section className="border-t border-white/10 pt-4">
          <h3 className="mb-3 flex items-center gap-2 font-semibold"><History size={16}/> Review and remediation audit trail</h3>
          {!detail.data?.events.length?<p className="text-xs text-slate-400">No reviewer changes yet.</p>:null}
          {detail.data?.events.map(event=><div key={event.id} className="border-b border-white/5 py-2 text-xs text-slate-300">
            <span className="font-medium text-cyan-100">{event.event_type}</span> · {new Date(event.occurred_at).toLocaleString()}
            <p>Actor: {event.actor_id}</p>
            {event.details.input?.message?<p>Comment: {event.details.input.message}</p>:null}
            {event.details.input?.reason?<p>Decision reason: {event.details.input.reason}</p>:null}
            {event.details.result?<p>Retest result: {event.details.result}. Not verified resolved.</p>:null}
          </div>)}
        </section>
        <section className="border-t border-white/10 pt-4">
          <h3 className="mb-2 font-semibold text-white">Retest history</h3>
          {!detail.data?.retests.length?<p className="text-xs text-slate-400">No retest requested.</p>:null}
          {detail.data?.retests.map(r=><p key={r.id} className="mb-2 text-xs text-slate-300">
            {new Date(r.requested_at).toLocaleString()} — {r.comparison_state.replaceAll("_"," ")}
            {r.comparison_job_id?" · Evidence job "+r.comparison_job_id:" · Awaiting authorized evidence"}
            . Never automatically verified resolved.
          </p>)}
        </section>
      </>:null}
    </CardContent></Card>:null}
    <Card><CardHeader><h2 className="flex items-center gap-2 font-semibold text-white">
      <ArrowDownToLine size={18}/> Professional security reporting</h2>
      <p className="text-xs text-slate-400">Current organization: {orgName||"none selected"}. Reports contain authorized saved evidence,
        assessment scope, reviewer decisions, remediation, retests and coverage limitations.</p></CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap gap-3">
          <Button disabled={!activeOrganizationId||pendingDownload} onClick={()=>void download("pdf")}>
            Download PDF report</Button>
          <Button variant="secondary" disabled={!activeOrganizationId||pendingDownload}
            onClick={()=>void download("json")}>Download structured JSON</Button>
        </div>
        {downloadError?<p role="alert" className="text-sm text-rose-300">{downloadError}</p>:null}
        <p className="text-xs text-slate-400">
          Tenant-scoped, no-store exports only. Evidence may be incomplete. No CVSS, CVE or proven exploitation is asserted.
        </p>
      </CardContent>
    </Card>
  </div>;
}
