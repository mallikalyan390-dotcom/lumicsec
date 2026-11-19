import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { requireGoogleAal2 } from "../lib/auth-guard.js";
import { createSupabaseForRequest } from "../lib/supabase.js";
import { generateSecurityReportPdf, safeReportProjection,
  type ReportAsset, type ReportFinding, type ReportEvidence,
  type ReportEvent, type ReportRetest, type ReportJob, type SecurityReport,
} from "../lib/findings-report.js";

const uuid = z.string().uuid();
const org = z.object({ organizationId: uuid }).strict();
const orgAsset = org.extend({assetId:uuid.optional()}).strict();
const listQuery = org.extend({
  assetId:uuid.optional(),
  status: z.enum(["open","in_progress","ready_for_retest","reopened","verified_resolved"]).optional(),
  conclusion: z.enum(["unreviewed","configuration_review","needs_evidence","false_positive","accepted_risk"]).optional(),
  severity: z.enum(["info","low","medium","high"]).optional(),
  sort: z.enum(["newest","oldest","severity"]).default("newest"),
  page: z.coerce.number().int().min(0).max(100).default(0),
}).strict();
const detailQuery = org.extend({findingId:uuid}).strict();
const importSchema = org.extend({jobId:uuid,requestId:uuid}).strict();
const actionSchema = detailQuery.extend({
  action:z.enum(["classify","assign","status","comment","reference","retest_request","retest_compare"]),
  payload:z.record(z.string(),z.unknown()),
  requestId:uuid,
}).strict();
const reportQuery = orgAsset.extend({format:z.enum(["pdf","json"])}).strict();
const MAX_PAGE=25;
const MAX_REPORT_FINDINGS=100;

function dbStatus(code?:string) {
  if(code==="42501"||code==="PGRST116")return 403;
  if(code==="22023"||code==="23514")return 400;
  if(code==="23505")return 409;
  return 503;
}
function noStore(reply:{header:(k:string,v:string)=>unknown}){
  reply.header("cache-control","private, no-store, max-age=0");
  reply.header("x-content-type-options","nosniff");
}
export async function commercialFindingsRoutes(app:FastifyInstance) {
  app.get("/v1/findings", {preHandler:requireGoogleAal2},async(request,reply)=>{
    noStore(reply);
    const input=listQuery.safeParse(request.query);
    if(!input.success)return reply.code(400).send({error:"INVALID_FINDINGS_FILTER"});
    const client=createSupabaseForRequest(request,reply);
    if(!client)return reply.code(503).send({error:"AUTH_NOT_CONFIGURED"});
    const {organizationId,assetId,status,conclusion,severity,sort,page}=input.data;
    let query=client.from("security_findings").select(
      "id,organization_id,asset_id,assessment_kind,rule_id,title,summary,remediation,severity_estimate,source_classification,reviewer_conclusion,review_reason,reviewer_id,reviewed_at,workflow_status,assigned_to,first_job_id,first_observation_id,first_seen_at,last_seen_at,source_locator,updated_at",
      {count:"exact"}).eq("organization_id",organizationId);
    if(assetId)query=query.eq("asset_id",assetId);
    if(status)query=query.eq("workflow_status",status);
    if(conclusion)query=query.eq("reviewer_conclusion",conclusion);
    if(severity)query=query.eq("severity_estimate",severity);
    if(sort==="severity")query=query.order("severity_rank",{ascending:false}).order("updated_at",{ascending:false});
    else query=query.order("updated_at",{ascending:sort==="oldest"});
    const {data,error,count}=await query.range(page*MAX_PAGE,(page+1)*MAX_PAGE-1);
    if(error)return reply.code(503).send({error:"FINDINGS_UNAVAILABLE"});
    return {findings:data??[],total:count??0,page,pageSize:MAX_PAGE};
  });

  app.get("/v1/findings/assessments",{preHandler:requireGoogleAal2},async(request,reply)=>{
    noStore(reply);
    const input=org.safeParse(request.query);
    if(!input.success)return reply.code(400).send({error:"INVALID_ORGANIZATION_ID"});
    const client=createSupabaseForRequest(request,reply);
    if(!client)return reply.code(503).send({error:"AUTH_NOT_CONFIGURED"});
    const {data,error}=await client.from("assessment_jobs")
      .select("id,organization_id,asset_id,assessment_kind,job_state,observation_count,requested_at,completed_at,scope_hash")
      .eq("organization_id",input.data.organizationId).eq("job_state","succeeded")
      .gt("observation_count",0).order("requested_at",{ascending:false}).limit(50);
    if(error)return reply.code(503).send({error:"ASSESSMENT_EVIDENCE_UNAVAILABLE"});
    return {assessments:data??[],scanningEnabled:false};
  });

  app.get("/v1/findings/detail",{preHandler:requireGoogleAal2},async(request,reply)=>{
    noStore(reply);
    const input=detailQuery.safeParse(request.query);
    if(!input.success)return reply.code(400).send({error:"INVALID_FINDING_ID"});
    const client=createSupabaseForRequest(request,reply);
    if(!client)return reply.code(503).send({error:"AUTH_NOT_CONFIGURED"});
    const {organizationId,findingId}=input.data;
    const {data:finding,error}=await client.from("security_findings").select("*")
      .eq("organization_id",organizationId).eq("id",findingId).single();
    if(error||!finding)return reply.code(403).send({error:"FINDING_ACCESS_DENIED"});
    const [links,events,retests]=await Promise.all([
      client.from("finding_evidence_links").select("*")
        .eq("organization_id",organizationId).eq("finding_id",findingId)
        .order("linked_at",{ascending:false}).limit(100),
      client.from("finding_events").select("*")
        .eq("organization_id",organizationId).eq("finding_id",findingId)
        .order("occurred_at",{ascending:false}).limit(100),
      client.from("finding_retests").select("*")
        .eq("organization_id",organizationId).eq("finding_id",findingId)
        .order("requested_at",{ascending:false}).limit(40),
    ]);
    if(links.error||events.error||retests.error)
      return reply.code(503).send({error:"FINDING_EVIDENCE_UNAVAILABLE"});
    return {finding,links:links.data??[],events:events.data??[],retests:retests.data??[]};
  });

  app.post("/v1/findings/import",{
    preHandler:requireGoogleAal2,config:{rateLimit:{max:10,timeWindow:"1 minute"}},
  },async(request,reply)=>{
    noStore(reply);
    const input=importSchema.safeParse(request.body);
    if(!input.success)return reply.code(400).send({error:"INVALID_FINDING_IMPORT"});
    const client=createSupabaseForRequest(request,reply);
    if(!client)return reply.code(503).send({error:"AUTH_NOT_CONFIGURED"});
    // The authenticated RPC itself checks membership, writer role, signed AAL2,
    // the succeeded job, tenant, source observation and dedupe identity.
    const {data,error}=await client.rpc("findings_import",{
      p_org:input.data.organizationId,p_job:input.data.jobId,p_request:input.data.requestId,
    });
    if(error)return reply.code(dbStatus(error.code)).send({error:"FINDINGS_IMPORT_DENIED"});
    return {result:data,source:"SAVED_ASSESSMENT_ONLY",networkRequests:0};
  });

  app.post("/v1/findings/action",{
    preHandler:requireGoogleAal2,config:{rateLimit:{max:20,timeWindow:"1 minute"}},
  },async(request,reply)=>{
    noStore(reply);
    const input=actionSchema.safeParse(request.body);
    if(!input.success||Buffer.byteLength(JSON.stringify(request.body??{}))>4_000)
      return reply.code(400).send({error:"INVALID_FINDING_ACTION"});
    const client=createSupabaseForRequest(request,reply);
    if(!client)return reply.code(503).send({error:"AUTH_NOT_CONFIGURED"});
    const {organizationId,findingId,action,payload,requestId}=input.data;
    const {data,error}=await client.rpc("finding_action",{
      p_org:organizationId,p_finding:findingId,p_action:action,
      p_payload:payload,p_request:requestId,
    });
    if(error)return reply.code(dbStatus(error.code)).send({error:"FINDING_ACTION_DENIED"});
    return {result:data,verifiedResolved:false,networkRequests:0};
  });

  app.get("/v1/findings/report",{preHandler:requireGoogleAal2,
    config:{rateLimit:{max:6,timeWindow:"1 minute"}}},async(request,reply)=>{
    noStore(reply);
    const input=reportQuery.safeParse(request.query);
    if(!input.success)return reply.code(400).send({error:"INVALID_REPORT_SCOPE"});
    const client=createSupabaseForRequest(request,reply);
    if(!client)return reply.code(503).send({error:"AUTH_NOT_CONFIGURED"});
    const {organizationId,assetId,format}=input.data;
    // First operation MUST be membership-scoped RLS, before any data aggregation.
    const {data:orgRow,error:orgError}=await client.from("organizations")
      .select("id,display_name").eq("id",organizationId).single();
    if(orgError||!orgRow)return reply.code(403).send({error:"REPORT_ORGANIZATION_ACCESS_DENIED"});
    let assetQuery=client.from("assets").select("id,display_name,canonical_origin,asset_kind")
      .eq("organization_id",organizationId);
    if(assetId)assetQuery=assetQuery.eq("id",assetId);
    const {data:assets,error:assetError}=await assetQuery.limit(31);
    if(assetError)return reply.code(503).send({error:"REPORT_ASSETS_UNAVAILABLE"});
    if(assetId&&!assets?.some(a=>a.id===assetId))
      return reply.code(403).send({error:"REPORT_ASSET_ACCESS_DENIED"});
    if((assets?.length??0)>30)return reply.code(413).send({error:"REPORT_ASSET_LIMIT"});
    let findingsQuery=client.from("security_findings").select(
      "id,asset_id,assessment_kind,rule_id,title,summary,remediation,source_classification,severity_estimate,reviewer_conclusion,review_reason,workflow_status,first_seen_at,last_seen_at,source_locator,assigned_to")
      .eq("organization_id",organizationId).order("last_seen_at",{ascending:false});
    if(assetId)findingsQuery=findingsQuery.eq("asset_id",assetId);
    const {data:findings,error:findingsError}=await findingsQuery.limit(MAX_REPORT_FINDINGS+1);
    if(findingsError)return reply.code(503).send({error:"REPORT_FINDINGS_UNAVAILABLE"});
    if((findings?.length??0)>MAX_REPORT_FINDINGS)
      return reply.code(413).send({error:"REPORT_FINDING_LIMIT"});
    const ids=(findings??[]).map(f=>f.id);
    const fetchLinked=async (table:"finding_evidence_links"|"finding_events"|"finding_retests",
      fields:string,limit:number)=>{
      if(ids.length===0)return {data:[],error:null};
      return client.from(table).select(fields)
        .eq("organization_id",organizationId).in("finding_id",ids).limit(limit+1);
    };
    const [links,events,retests]=await Promise.all([
      fetchLinked("finding_evidence_links",
        "finding_id,job_id,observation_id,scope_hash,source_fingerprint,evidence_source",300),
      fetchLinked("finding_events","finding_id,actor_id,event_type,details,occurred_at",400),
      fetchLinked("finding_retests","finding_id,requested_at,compared_at,comparison_state,comparison_job_id",200),
    ]);
    if(links.error||events.error||retests.error)
      return reply.code(503).send({error:"REPORT_HISTORY_UNAVAILABLE"});
    if((links.data?.length??0)>300||(events.data?.length??0)>400||
       (retests.data?.length??0)>200)
      return reply.code(413).send({error:"REPORT_HISTORY_LIMIT"});
    let jobsQuery=client.from("assessment_jobs").select(
      "id,asset_id,assessment_kind,job_state,requested_at,scope_hash,result_coverage,web_report")
      .eq("organization_id",organizationId)
      .order("requested_at",{ascending:false});
    if(assetId)jobsQuery=jobsQuery.eq("asset_id",assetId);
    const {data:jobs,error:jobsError}=await jobsQuery.limit(61);
    if(jobsError)return reply.code(503).send({error:"REPORT_ASSESSMENTS_UNAVAILABLE"});
    if((jobs?.length??0)>60)return reply.code(413).send({error:"REPORT_ASSESSMENT_LIMIT"});
    const counts:Record<string,number>={};
    for(const finding of findings??[]) {
      for(const key of [finding.workflow_status,finding.reviewer_conclusion,finding.severity_estimate])
        counts[key]=(counts[key]??0)+1;
    }
    const raw:SecurityReport={
      classification:"TENANT_AUTHORIZED_REVIEW_REPORT",
      generatedAt:new Date().toISOString(),
      organization:{id:orgRow.id,displayName:orgRow.display_name},
      scope:{assetId:assetId??null,scopeDescription:assetId
        ? "Asset "+(assets?.find(a=>a.id===assetId)?.display_name??"selected")
        : "All authorized organization assets"},
      disclaimer:"Passive Web and offline API-specification observations are NOT verified vulnerabilities. No CVE, CVSS score, exploit proof or confirmed business impact is asserted.",
      counts,
      assets:(assets??[]) as ReportAsset[],
      findings:(findings??[]) as ReportFinding[],
      evidence:(links.data??[]) as unknown as ReportEvidence[],
      history:(events.data??[]) as unknown as ReportEvent[],
      retests:(retests.data??[]) as unknown as ReportRetest[],
      assessments:(jobs??[]) as ReportJob[],
      limitations:[
        "Web customer network scanning remains disabled; no new requests are sent by export.",
        "Offline API specification observations do not confirm runtime exploitability.",
        "Some saved evidence may be partial, absent, or limited to configuration.",
        "Not observed during retesting is NOT independently verified remediation.",
        "No CVE/CVSS or confirmed customer business impact is inferred.",
        "This document records permitted tenant-scoped evidence and human decisions only.",
      ],
    };
    let report:SecurityReport;
    try{report=safeReportProjection(raw);}
    catch{return reply.code(413).send({error:"REPORT_RESOURCE_LIMIT_EXCEEDED"});}
    reply.header("content-disposition",'attachment; filename="lumicsec-security-review.'+format+'"');
    if(format==="json"){
      const json=JSON.stringify(report);
      if(Buffer.byteLength(json,"utf8")>1_500_000)
        return reply.code(413).send({error:"REPORT_RESOURCE_LIMIT_EXCEEDED"});
      reply.header("content-type","application/json; charset=utf-8");
      return reply.send(json);
    }
    try{
      const pdf=await generateSecurityReportPdf(report);
      reply.header("content-type","application/pdf");
      return reply.send(Buffer.from(pdf));
    }catch{return reply.code(413).send({error:"PDF_REPORT_BOUNDS_OR_ENCODING_REJECTED"});}
  });
}
