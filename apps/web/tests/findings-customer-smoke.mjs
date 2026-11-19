// Browser-only synthetic customer API; no Supabase, network scan or real account.
import { createServer } from "node:http";
import { Buffer } from "node:buffer";
import process from "node:process";
import { readFile, stat } from "node:fs/promises";
import { dirname, extname, join, relative, resolve } from "node:path";
import { URL, fileURLToPath } from "node:url";

const dist=resolve(dirname(fileURLToPath(import.meta.url)),"../dist");
const port=5195;
const org="00000000-0000-4000-8000-000000000011";
const asset="00000000-0000-4000-8000-000000000022";
const actor="00000000-0000-4000-8000-000000000033";
const job="00000000-0000-4000-8000-000000000044";
const findingId="00000000-0000-4000-8000-000000000055";
const observation="00000000-0000-4000-8000-000000000066";
const fingerprint="c".repeat(64);
const runtimeCaptured=JSON.parse(await readFile(new URL(
  "./controlled-runtime-actual-results.json",import.meta.url),"utf8"));
const apiActual=runtimeCaptured.fixtures.api_insecure.result;
const apiObservation=apiActual.observations.find(x=>x.ruleId==="API.RUNTIME.AUTH.ANON_SUCCESS");
if(!apiObservation)throw Error("ACTUAL_API_RUNTIME_EVIDENCE_MISSING");

const stateByRole=new Map();
const actions=[];
let importCount=0,exportPdfCount=0,exportJsonCount=0,webScanCount=0;
const send=(res,status,body,contentType="application/json")=>{
  res.writeHead(status,{"content-type":contentType,"cache-control":"private, no-store"});
  res.end(typeof body==="string"||Buffer.isBuffer(body)?body:JSON.stringify(body));
};
function roleState(role){
  if(!stateByRole.has(role))stateByRole.set(role,{
    finding:{
      id:findingId,organization_id:org,asset_id:asset,assessment_kind:"web_passive",
      rule_id:"P09.HSTS.ABSENT",title:"Synthetic saved HSTS review",
      summary:"An observed synthetic HTTPS response lacked an HSTS policy.",
      remediation:"Configure a reviewed Strict-Transport-Security policy.",
      severity_estimate:"low",source_classification:"DETERMINISTIC_CONFIGURATION_SIGNAL",
      reviewer_conclusion:"unreviewed",review_reason:null,reviewer_id:null,
      workflow_status:"open",assigned_to:null,source_locator:"/",first_job_id:job,
      first_observation_id:observation,first_seen_at:"2026-11-19T01:00:00Z",
      last_seen_at:"2026-11-19T01:10:00Z",updated_at:"2026-11-19T01:10:00Z",
    },events:[{id:1,actor_id:actor,event_type:"imported",
      occurred_at:"2026-11-19T01:12:00Z",details:{observationId:observation}}],
    links:[{id:"00000000-0000-4000-8000-000000000077",
      job_id:job,observation_id:observation,scope_hash:"a".repeat(64),
      evidence_source:{fingerprints:[fingerprint],paths:["/"]},
      source_fingerprint:null,linked_at:"2026-11-19T01:12:00Z"}],
    retests:[],
  });
  return stateByRole.get(role);
}
const server=createServer(async(req,res)=>{
  try{
    const url=new URL(req.url??"/","http://127.0.0.1:"+port);
    const path=url.pathname;
    const cookies=String(req.headers.cookie??"");
    const role=cookies.includes("synthetic_role=viewer")?"viewer":
      cookies.includes("synthetic_role=analyst")?"analyst":"owner";
    const unverified=cookies.includes("synthetic_status=unverified");
    const apiMode=cookies.includes("synthetic_runtime=api");
    const state=roleState(role+(apiMode?"-runtime":""));
    if(apiMode){
      state.finding.assessment_kind="api_runtime_review";
      state.finding.rule_id=apiObservation.ruleId;
      state.finding.title=apiObservation.title;
      state.finding.summary=apiObservation.summary;
      state.finding.remediation=apiObservation.remediation;
      state.finding.source_classification=apiObservation.classification;
      state.finding.severity_estimate=apiObservation.severityEstimate;
      state.finding.source_locator="/v1/accounts/owner";
      state.finding.first_job_id=apiActual.jobId;
      state.links[0].job_id=apiActual.jobId;
      state.links[0].evidence_source=apiObservation.evidenceSource;
    }
    const assetRow={id:asset,organization_id:org,asset_kind:apiMode?"api":"website",
      display_name:apiMode?"Controlled API review asset":"Synthetic reviewed HTTPS asset",
      canonical_origin:apiMode?"https://controlled-api.fixture-api.net":"https://synthetic.fixture-web.net",
      verification_status:unverified?"pending":"verified",
      verification_expires_at:unverified?null:"2099-01-01T00:00:00Z"};
    if(path==="/auth/session")return send(res,200,{configured:true,state:"authenticated",
      csrfToken:"synthetic-csrf",user:{id:actor,email:"qa-synthetic@example.invalid"}});
    if(path==="/v1/organizations")return send(res,200,{
      organizations:[{id:org,display_name:"Synthetic security organization",created_by:actor,
        created_at:"2026-01-01T00:00:00Z"}],
      memberships:[{organization_id:org,member_role:role,member_status:"active"}],
    });
    if(path==="/v1/assets")return send(res,200,{assets:[assetRow]});
    if(path==="/v1/organizations/"+org+"/members")return send(res,200,{members:[{
      user_id:actor,member_email:"synthetic-owner@example.invalid",
      member_role:"owner",member_status:"active",joined_at:"2026-01-01T00:00:00Z",
    }]});
    if(path==="/v1/findings/assessments")return send(res,200,{scanningEnabled:false,
      assessments:[{id:job,organization_id:org,asset_id:asset,assessment_kind:"web_passive",
        job_state:"succeeded",observation_count:1,requested_at:"2026-11-19T01:00:00Z",
        completed_at:"2026-11-19T01:10:00Z",scope_hash:"a".repeat(64)}]});
    if(path==="/v1/findings"&&req.method==="GET")return send(res,200,{
      findings:[state.finding],total:1,page:0,pageSize:25,
    });
    if(path==="/v1/findings/detail")return send(res,200,state);
    if(path==="/v1/findings/import"&&req.method==="POST"){
      if(role==="viewer")return send(res,403,{error:"REVIEWER_ACCESS_DENIED"});
      importCount++;return send(res,200,{result:{newFindings:0,linkedObservations:0},networkRequests:0});
    }
    if(path==="/v1/findings/action"&&req.method==="POST"){
      let body="";for await(const part of req){body+=part.toString("utf8");if(body.length>4200)break;}
      if(role==="viewer")return send(res,403,{error:"REVIEWER_ACCESS_DENIED"});
      const action=JSON.parse(body);
      if(action.action==="classify"){
        if(action.payload.conclusion==="accepted_risk"&&role!=="owner")
          return send(res,403,{error:"OWNER_RISK_DECISION_REQUIRED"});
        state.finding.reviewer_conclusion=action.payload.conclusion;
        state.finding.review_reason=action.payload.reason;
      }
      if(action.action==="status")state.finding.workflow_status=action.payload.status;
      if(action.action==="retest_request"){
        if(unverified)return send(res,403,{error:"CURRENT_ASSET_OWNERSHIP_REQUIRED"});
        state.retests.push({id:job,requested_at:new Date().toISOString(),compared_at:null,
          comparison_state:"awaiting_execution",comparison_job_id:null});
        state.finding.workflow_status="ready_for_retest";
      }
      if(action.action==="comment"){
        state.events.push({id:state.events.length+1,actor_id:actor,event_type:"commented",
          occurred_at:new Date().toISOString(),details:{input:{message:action.payload.message}}});
      }
      actions.push({role,action:action.action,classification:action.payload.conclusion??null,unverified});
      return send(res,200,{result:{eventId:11,verifiedResolved:false},networkRequests:0});
    }
    if(path==="/v1/findings/report"&&req.method==="GET"){
      const format=url.searchParams.get("format");
      if(format==="pdf"){
        exportPdfCount++;
        return send(res,200,Buffer.from("%PDF-1.4\n"+"Synthetic saved report proof. ".repeat(5)+"\n%%EOF"),
          "application/pdf");
      }
      if(format==="json"){
        exportJsonCount++;
        return send(res,200,{organization:{displayName:"Synthetic security organization"},
          findings:[state.finding],evidence:state.links,retests:state.retests});
      }
      return send(res,400,{error:"FORMAT_REQUIRED"});
    }
    if(path==="/v1/assessments/web"&&req.method==="POST"){
      webScanCount++;return send(res,423,{error:"CUSTOMER_WEB_EXECUTION_NOT_APPROVED"});
    }
    if(path==="/__status")return send(res,200,{
      actions,importCount,exportPdfCount,exportJsonCount,webScanCount,
      state:[...stateByRole.entries()].map(([role,s])=>({role,
        conclusion:s.finding.reviewer_conclusion,retests:s.retests.length})),
    });
    if(path.startsWith("/v1/")||path.startsWith("/auth/"))return send(res,403,{error:"UNEXPECTED_TEST_ENDPOINT"});
    let file=resolve(dist,"."+path);
    if(relative(dist,file).startsWith(".."))return send(res,403,{error:"FORBIDDEN"});
    if(!(await stat(file).catch(()=>null))?.isFile())file=join(dist,"index.html");
    const data=await readFile(file);
    const mime={".html":"text/html; charset=utf-8",".js":"text/javascript",".css":"text/css"};
    const headers={"content-type":mime[extname(file)]??"application/octet-stream","cache-control":"no-store"};
    if(file.endsWith(".html") && (path==="/app/findings"||path==="/")){
      // Reset only this synthetic role fixture between independent browser runs.
      stateByRole.delete((url.searchParams.get("role")??"owner")+
        (url.searchParams.get("runtime")==="api"?"-runtime":""));
      headers["set-cookie"]=[
        "synthetic_role="+(url.searchParams.get("role")??"owner")+"; Path=/; SameSite=Lax",
        "synthetic_runtime="+(url.searchParams.get("runtime")==="api"?"api":"web")+
          "; Path=/; SameSite=Lax",
        "synthetic_status="+(url.searchParams.get("mode")==="unverified"?"unverified":"verified")
          +"; Path=/; SameSite=Lax",
      ];
    }
    res.writeHead(200,headers);res.end(data);
  }catch{
    return send(res,500,{error:"SYNTHETIC_FINDINGS_FIXTURE_ERROR"});
  }
});
server.listen(port,"127.0.0.1",()=>process.stdout.write("FINDINGS_FIXTURE_READY\n"));
