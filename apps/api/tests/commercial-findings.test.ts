import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Fastify from "fastify";
import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import { PDFDocument } from "pdf-lib";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { commercialFindingsRoutes } from "../src/routes/commercial-findings.js";
import { generateSecurityReportPdf, safeReportProjection,
  type SecurityReport } from "../src/lib/findings-report.js";

const mock=vi.hoisted(()=>({client:null as unknown}));
vi.mock("../src/lib/supabase.js",()=>({createSupabaseForRequest:()=>mock.client}));
const org="00000000-0000-4000-8000-000000000011";
const asset="00000000-0000-4000-8000-000000000022";
const job="00000000-0000-4000-8000-000000000044";
const findingId="00000000-0000-4000-8000-000000000055";
const actor="00000000-0000-4000-8000-000000000033";
const payloadFinding={
  id:findingId,asset_id:asset,assessment_kind:"web_passive",
  rule_id:"P09.HSTS.ABSENT",title:"Observed missing HSTS configuration",
  summary:"Synthetic TLS response was missing HSTS",
  remediation:"Configure Strict-Transport-Security max-age after verification",
  severity_estimate:"low",source_classification:"DETERMINISTIC_CONFIGURATION_SIGNAL",
  reviewer_conclusion:"accepted_risk",review_reason:"Synthetic managed exception approved for QA.",
  workflow_status:"ready_for_retest",assigned_to:actor,
  source_locator:"/",first_seen_at:"2026-11-19T01:00:00Z",
  last_seen_at:"2026-11-19T02:00:00Z",
};
const evidence={
  finding_id:findingId,job_id:job,
  observation_id:"00000000-0000-4000-8000-000000000066",
  scope_hash:"a".repeat(64),source_fingerprint:null,
  evidence_source:{fingerprints:["c".repeat(64)],paths:["/"]},
};
const event={
  finding_id:findingId,actor_id:actor,event_type:"commented",
  occurred_at:"2026-11-19T02:00:00Z",details:{input:{message:"Reviewed safe synthetic evidence"}},
};
const retest={finding_id:findingId,requested_at:"2026-11-19T02:30:00Z",
  compared_at:null,comparison_state:"awaiting_execution",comparison_job_id:null};
const report:SecurityReport={
  classification:"TENANT_AUTHORIZED_REVIEW_REPORT",generatedAt:"2026-11-19T03:00:00Z",
  organization:{id:org,displayName:"Synthetic organization"},
  scope:{assetId:asset,scopeDescription:"Asset Synthetic owned website"},
  disclaimer:"Passive observations are not confirmed exploitable vulnerabilities.",
  counts:{low:1,open:0,unreviewed:0,in_progress:0},
  assets:[{id:asset,display_name:"Synthetic owned website",
    canonical_origin:"https://synthetic.fixture-web.net",asset_kind:"website"}],
  findings:[payloadFinding],
  evidence:[evidence],
  history:[event],
  retests:[retest],
  assessments:[{id:job,asset_id:asset,assessment_kind:"web_passive",job_state:"succeeded",
    requested_at:"2026-11-19T01:00:00Z",scope_hash:"a".repeat(64),result_coverage:null,
    web_report:{limitations:["Synthetic fixture, no production internet"],classification:"PASSIVE_WEB_REVIEW"}}],
  limitations:["No customer scanning performed.","No confirmed exploit.","No independent verified resolution."],
};
function q(data:unknown) {
  const result={data,error:null,count:Array.isArray(data)?data.length:null};
  const builder={
    select:vi.fn(),eq:vi.fn(),gt:vi.fn(),in:vi.fn(),order:vi.fn(),
    limit:vi.fn().mockResolvedValue(result),range:vi.fn().mockResolvedValue(result),
    single:vi.fn().mockResolvedValue({data,error:data===null?{code:"PGRST116"}:null}),
  };
  for(const key of ["select","eq","gt","in","order"] as const)builder[key].mockReturnValue(builder);
  return builder;
}
function fakeClient(){
  const builders={
    organizations:q({id:org,display_name:"Synthetic organization"}),
    assets:q(report.assets),
    security_findings:q(report.findings),
    finding_evidence_links:q(report.evidence),
    finding_events:q(report.history),
    finding_retests:q(report.retests),
    assessment_jobs:q(report.assessments),
  };
  return {
    auth:{
      getUser:vi.fn().mockResolvedValue({data:{user:{id:actor,app_metadata:{provider:"google"}}},error:null}),
      getClaims:vi.fn().mockResolvedValue({data:{claims:{aal:"aal2",amr:[{method:"oauth"},{method:"totp"}]}},error:null}),
      mfa:{getAuthenticatorAssuranceLevel:vi.fn().mockResolvedValue({
        data:{currentLevel:"aal2",nextLevel:"aal2"},error:null})},
    },
    rpc:vi.fn().mockResolvedValue({data:{newFindings:1,linkedObservations:1},error:null}),
    from:vi.fn((table:string)=>builders[table as keyof typeof builders]),
    builders,
  };
}
type Client=ReturnType<typeof fakeClient>;
let client:Client;
const open:Array<ReturnType<typeof Fastify>>=[];
async function server(){
  const app=Fastify({logger:false});
  open.push(app);
  await app.register(cookie);
  await app.register(rateLimit);
  await app.register(commercialFindingsRoutes);
  return app;
}
beforeEach(()=>{client=fakeClient();mock.client=client;});
afterEach(async()=>{await Promise.all(open.splice(0).map(app=>app.close()));mock.client=null;});
describe("findings + remediation API security, saved evidence, professional reporting",()=>{
  it("imports saved observations only with an authenticated scoped RPC",async()=>{
    const app=await server();
    const response=await app.inject({method:"POST",url:"/v1/findings/import",payload:{
      organizationId:org,jobId:job,requestId:findingId,
    }});
    expect(response.statusCode).toBe(200);
    expect(response.json().networkRequests).toBe(0);
    expect(client.rpc).toHaveBeenCalledWith("findings_import",{p_org:org,p_job:job,p_request:findingId});
  });
  it("mutates through AAL2 reviewer RPC with client supplied idempotency key",async()=>{
    const app=await server();
    const response=await app.inject({method:"POST",url:"/v1/findings/action",payload:{
      organizationId:org,findingId,requestId:job,action:"classify",
      payload:{conclusion:"accepted_risk",reason:"Full explicit owner decision for fixture"},
    }});
    expect(response.statusCode).toBe(200);
    expect(response.json().verifiedResolved).toBe(false);
    expect(client.rpc).toHaveBeenCalledWith("finding_action",{
      p_org:org,p_finding:findingId,p_action:"classify",
      p_payload:{conclusion:"accepted_risk",reason:"Full explicit owner decision for fixture"},
      p_request:job,
    });
  });
  it("rejects invalid status or oversized mutation before database",async()=>{
    const app=await server();
    const response=await app.inject({method:"POST",url:"/v1/findings/action",payload:{
      organizationId:org,findingId,requestId:job,action:"verified_resolved",
      payload:{message:"x".repeat(4000)},
    }});
    expect(response.statusCode).toBe(400);
    expect(client.rpc).not.toHaveBeenCalled();
  });
  it("enforces Google TOTP AAL2 on reads, imports, actions and downloads",async()=>{
    client.auth.getClaims.mockResolvedValue({data:{claims:{aal:"aal1",amr:[{method:"oauth"}]}},error:null});
    const app=await server();
    const outcomes=await Promise.all([
      app.inject({method:"GET",url:"/v1/findings?organizationId="+org}),
      app.inject({method:"GET",url:"/v1/findings/report?organizationId="+org+"&format=pdf"}),
      app.inject({method:"POST",url:"/v1/findings/import",payload:{organizationId:org,jobId:job,requestId:job}}),
      app.inject({method:"POST",url:"/v1/findings/action",payload:{
        organizationId:org,findingId,requestId:job,action:"comment",payload:{message:"qa"}}}),
    ]);
    expect(outcomes.map(r=>r.statusCode)).toEqual([403,403,403,403]);
    expect(client.from).not.toHaveBeenCalled();
    expect(client.rpc).not.toHaveBeenCalled();
  });
  it("rejects non-Google AAL2 identity",async()=>{
    client.auth.getUser.mockResolvedValue({data:{
      user:{id:actor,app_metadata:{provider:"email"}}},error:null});
    const app=await server();
    const response=await app.inject({method:"GET",url:"/v1/findings?organizationId="+org});
    expect(response.statusCode).toBe(403);
  });
  it("rejects cross-tenant report before reading any findings or observations",async()=>{
    client.builders.organizations.single.mockResolvedValue({data:null,error:{code:"PGRST116"}});
    const app=await server();
    const response=await app.inject({method:"GET",url:"/v1/findings/report?organizationId="+org+"&format=pdf"});
    expect(response.statusCode).toBe(403);
    expect(client.from).toHaveBeenCalledTimes(1);
    expect(client.from).toHaveBeenCalledWith("organizations");
  });
  it("filters tenant-scoped finding pages, sorting, and bound pagination",async()=>{
    const app=await server();
    const response=await app.inject({method:"GET",
      url:"/v1/findings?organizationId="+org+"&page=2&assetId="+asset+
        "&status=in_progress&severity=medium&sort=oldest"});
    expect(response.statusCode).toBe(200);
    const builder=client.builders.security_findings;
    expect(builder.eq).toHaveBeenCalledWith("organization_id",org);
    expect(builder.eq).toHaveBeenCalledWith("asset_id",asset);
    expect(builder.eq).toHaveBeenCalledWith("workflow_status","in_progress");
    expect(builder.eq).toHaveBeenCalledWith("severity_estimate","medium");
    expect(builder.range).toHaveBeenCalledWith(50,74);
  });
  it("uses numeric High/Medium/Low/Info severity order instead of alphabetical order",async()=>{
    const app=await server();
    const response=await app.inject({method:"GET",
      url:"/v1/findings?organizationId="+org+"&sort=severity"});
    expect(response.statusCode).toBe(200);
    expect(client.builders.security_findings.order)
      .toHaveBeenCalledWith("severity_rank",{ascending:false});
  });
  it("tenant finding detail never fetches another organization without scoped query",async()=>{
    const app=await server();
    const response=await app.inject({method:"GET",url:"/v1/findings/detail?organizationId="+org+"&findingId="+findingId});
    expect(response.statusCode).toBe(200);
    expect(response.json().events).toHaveLength(1);
    expect(client.builders.security_findings.eq).toHaveBeenCalledWith("organization_id",org);
    expect(client.builders.finding_events.eq).toHaveBeenCalledWith("organization_id",org);
    expect(client.builders.finding_evidence_links.eq).toHaveBeenCalledWith("organization_id",org);
  });
  it("streams authorized PDF bytes with verified content type and no-store",async()=>{
    const app=await server();
    const response=await app.inject({method:"GET",
      url:"/v1/findings/report?organizationId="+org+"&assetId="+asset+"&format=pdf"});
    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("application/pdf");
    expect(response.headers["cache-control"]).toContain("no-store");
    expect(response.rawPayload.subarray(0,5).toString("ascii")).toBe("%PDF-");
    const loaded=await PDFDocument.load(response.rawPayload);
    expect(loaded.getPageCount()).toBeGreaterThan(0);
  });
  it("streams bounded structured JSON containing real saved findings, audits, retests and coverage",async()=>{
    const app=await server();
    const response=await app.inject({method:"GET",
      url:"/v1/findings/report?organizationId="+org+"&format=json"});
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      organization:{displayName:"Synthetic organization"},
      findings:[{rule_id:"P09.HSTS.ABSENT",reviewer_conclusion:"accepted_risk",
        severity_estimate:"low",source_classification:"DETERMINISTIC_CONFIGURATION_SIGNAL"}],
      evidence:[{observation_id:evidence.observation_id}],
      history:[{event_type:"commented"}],
      retests:[{comparison_state:"awaiting_execution"}],
    });
    expect(response.body).toContain("NOT verified vulnerabilities");
    expect(response.body).not.toContain("CVSS: 9.8");
  });
});

describe("real PDF rendering and no secret disclosure",()=>{
  it("extracts actual generated report text from completed PDF content where poppler is available",async()=>{
    const pdf=await generateSecurityReportPdf(report);
    expect(Buffer.from(pdf).subarray(0,5).toString("ascii")).toBe("%PDF-");
    const loaded=await PDFDocument.load(pdf);
    expect(loaded.getPageCount()).toBeGreaterThan(0);
    let tmp:string|undefined;
    try{
      tmp=mkdtempSync(join(tmpdir(),"lumicsec-report-"));
      const source=join(tmp,"review.pdf");
      writeFileSync(source,pdf);
      const text=execFileSync("pdftotext",["-layout",source,"-"],{
        encoding:"utf8",timeout:5_000,
      });
      for(const phrase of [
        "Synthetic organization","Observed missing HSTS configuration",
        "P09.HSTS.ABSENT","accepted_risk","Configure Strict-Transport-Security",
        "Observed locator: /","Retest","No customer scanning performed.",
        "No independent verified resolution.",
      ])expect(text).toContain(phrase);
      expect(text).not.toContain("CVSS: 9.8");
      expect(text).not.toContain("VERIFIED EXPLOITABLE VULNERABILITY");
    }catch(error){
      if((error as NodeJS.ErrnoException).code!=="ENOENT")throw error;
      // CI runners without Poppler still validate the parseable PDF structure.
    }finally{if(tmp)rmSync(tmp,{recursive:true,force:true});}
  });
  it("redacts suspect tokens and raw credentials from JSON and PDF projections",()=>{
    const mutated:SecurityReport={...report,findings:[{
      ...payloadFinding,summary:"Secret not to disclose: Bearer SYNTHETICTOKENVALUE999999999",
    }]};
    const projection=safeReportProjection(mutated);
    const data=JSON.stringify(projection);
    expect(data).not.toContain("SYNTHETICTOKENVALUE");
    expect(data).toContain("[REDACTED]");
  });
  it("refuses silent truncation beyond report evidence/resource bounds",()=>{
    expect(()=>safeReportProjection({...report,findings:Array.from({length:101},()=>payloadFinding)}))
      .toThrow("REPORT_RESOURCE_LIMIT_EXCEEDED");
  });
});
