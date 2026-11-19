// Compiled React website-security workspace fixture, no live customer network.
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { dirname, extname, join, relative, resolve } from "node:path";
import { URL, fileURLToPath } from "node:url";
import { stdout } from "node:process";

const dist=resolve(dirname(fileURLToPath(import.meta.url)),"../dist");
const port=5193;
const org="00000000-0000-4000-8000-000000000011";
const asset="00000000-0000-4000-8000-000000000022";
const actor="00000000-0000-4000-8000-000000000033";
const insecureJob="00000000-0000-4000-8000-000000000044";
const secureJob="00000000-0000-4000-8000-000000000045";
const finger="c".repeat(64);
const reports=[];
let webQueueRequests=0;
let webCancelRequests=0;
const send=(res,status,body)=>{
  res.writeHead(status,{"content-type":"application/json","cache-control":"no-store"});
  res.end(JSON.stringify(body));
};
const script=`<script>
(async()=>{
 const wait=async checker=>{
  for(let n=0;n<160;n++){
   const result=checker();if(result)return result;
   await new Promise(resolve=>setTimeout(resolve,100));
  }throw Error("WEB_UI_TIMEOUT");
 };
 const text=()=>document.querySelector("#root")?.textContent??"";
 const member=location.search.includes("role=member");
 const unverified=location.search.includes("mode=unverified");
 const result={browser:navigator.userAgent.includes("Firefox")?"firefox":"chromium",member,unverified};
 try {
  await wait(()=>text().includes("Authorized passive Web assessments"));
  await wait(()=>text().includes("Assessment jobs and retained evidence"));
  const assetSelect=await wait(()=>document.querySelector("#web-assessment-asset"));
  result.heading=true;
  result.scanDisabled=text().includes("Customer network scanning is")&&text().includes("not activated");
  result.noActiveScan=![...document.querySelectorAll("button")].some(b=>
    b.textContent.includes("Start authorized Web assessment")&&!b.disabled);
  result.verifiedSelection=unverified ? assetSelect.options.length===1 : member ? assetSelect.disabled : assetSelect.options.length===2;
  result.memberReadOnly=member ? document.querySelectorAll("input[type=checkbox]").length === 0 : true;
  if(unverified&&!member)result.unverifiedNotice=text().includes("No currently verified website");
  const reviews=await wait(()=>[...document.querySelectorAll("button")].filter(b=>b.textContent.includes("Review evidence")).length===2
    ? [...document.querySelectorAll("button")].filter(b=>b.textContent.includes("Review evidence")):null);
  reviews[0].click();
  await wait(()=>text().includes("P09.HSTS.ABSENT"));
  result.insecureEvidence=text().includes("Missing HSTS passive signal") &&
    text().includes("Remediation: Configure HSTS")&&text().includes("Source fingerprints")&&
    text().includes("Observed HTTPS paths: /");
  reviews[1].click();
  await wait(()=>text().includes("No review observations recorded"));
  result.secureNoFalseSignal=true;
 }catch(e){result.problem=String(e?.message).slice(0,110)}
 await fetch("/__report",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(result)}).catch(()=>{});
})();
</script>`;
const server=createServer(async(req,res)=>{
 try{
  const url=new URL(req.url??"/","http://127.0.0.1:"+port);
  const path=url.pathname;
  const cookies=String(req.headers.cookie??"");
  const member=cookies.includes("synthetic_role=member");
  const unverified=cookies.includes("synthetic_status=unverified");
  if(path==="/auth/session")return send(res,200,{
    configured:true,state:"authenticated",csrfToken:"synthetic-only",
    user:{id:actor,email:"web-synthetic@example.invalid"},
  });
  if(path==="/v1/organizations"&&req.method==="GET")return send(res,200,{
    organizations:[{id:org,display_name:"Synthetic Web QA",created_by:actor,created_at:"2026-01-01T00:00:00Z"}],
    memberships:[{organization_id:org,member_role:member?"member":"owner",member_status:"active"}],
  });
  if(path==="/v1/assets"&&req.method==="GET")return send(res,200,{assets:[{
    id:asset,organization_id:org,asset_kind:"website",display_name:"Synthetic Web Target",
    canonical_origin:"https://insecure.fixture-web.net",
    verification_status:unverified?"pending":"verified",
    verification_expires_at:unverified?null:"2099-01-01T00:00:00Z",
    created_at:"2026-01-01T00:00:00Z",
  }]});
  if(path==="/v1/assessments/web"&&req.method==="GET")return send(res,200,{
    scanningEnabled:false,
    jobs:[
      {id:insecureJob,organization_id:org,asset_id:asset,job_state:"succeeded",
        scope_hash:"a".repeat(64),requested_at:"2026-11-19T00:00:00Z",
        started_at:"2026-11-19T00:00:01Z",completed_at:"2026-11-19T00:00:03Z",
        authorization_at:"2026-11-19T00:00:00Z",web_origin:"https://insecure.fixture-web.net",
        observation_count:4,web_report:{classification:"PASSIVE_WEB_REVIEW",requests:2,fetched:2,bytes:400,
          coverageState:"BOUNDED",limitations:["Not confirmed"]}},
      {id:secureJob,organization_id:org,asset_id:asset,job_state:"succeeded",
        scope_hash:"b".repeat(64),requested_at:"2026-11-18T00:00:00Z",
        authorization_at:"2026-11-18T00:00:00Z",web_origin:"https://secure.fixture-web.net",
        observation_count:0,web_report:{classification:"PASSIVE_WEB_REVIEW",requests:1,fetched:1,bytes:64,
          coverageState:"BOUNDED",limitations:["Not confirmed"]}},
    ],
  });
  if(path==="/v1/assessments/web/observations"&&req.method==="GET")
    return send(res,200,{observations:url.searchParams.get("jobId")===insecureJob?[{
      id:"00000000-0000-4000-8000-000000000055",rule_id:"P09.HSTS.ABSENT",
      title:"Missing HSTS passive signal",summary:"Observed HTTPS response without HSTS.",
      remediation:"Configure HSTS on the HTTPS site.",
      limitation:"Signal only. Not a confirmed exploitable vulnerability.",
      observation_classification:"DETERMINISTIC_CONFIGURATION_SIGNAL",
      evidence_source:{nodeIds:["wdn_0123456789abcdef01234567"],fingerprints:[finger],paths:["/"]},
      severity_estimate:"low",review_state:"review_required",
    }]:[]});
  if(path==="/v1/assessments/web"&&req.method==="POST") {
    webQueueRequests++;return send(res,423,{error:"CUSTOMER_WEB_EXECUTION_NOT_APPROVED"});
  }
  if(path==="/v1/assessments/web/cancel"&&req.method==="POST"){
    webCancelRequests++;return send(res,403,{error:"FIXTURE_NO_ACTIVE_JOB"});
  }
  if(path==="/__report"&&req.method==="POST"){
    let body="";for await(const p of req){body+=String(p);if(body.length>2000)break}
    const item=JSON.parse(body);reports.push(item);
    stdout.write("WEB_CUSTOMER_BROWSER_RESULT "+JSON.stringify(item)+"\n");
    return send(res,200,{received:true});
  }
  if(path==="/__status")return send(res,200,{reports,webQueueRequests,webCancelRequests});
  if(path.startsWith("/v1/")||path.startsWith("/auth/"))return send(res,403,{error:"UNEXPECTED_API_REQUEST"});
  let file=resolve(dist,"."+path);
  if(relative(dist,file).startsWith(".."))return send(res,403,{error:"FORBIDDEN"});
  if(!(await stat(file).catch(()=>null))?.isFile())file=join(dist,"index.html");
  const data=await readFile(file);
  const html=file.endsWith(".html");
  const headers=html&&(path.startsWith("/app/")||path==="/")?{
    "set-cookie":[
      "synthetic_role="+(url.searchParams.get("role")==="member"?"member":"owner")+"; Path=/; SameSite=Lax",
      "synthetic_status="+(url.searchParams.get("mode")==="unverified"?"unverified":"verified")+"; Path=/; SameSite=Lax",
    ],
  }:{};
  const mime={".html":"text/html; charset=utf-8",".js":"text/javascript",".css":"text/css"};
  res.writeHead(200,{"content-type":mime[extname(file)]??"application/octet-stream",
    "cache-control":"no-store",...headers});
  res.end(html?data.toString().replace("</body>",script+"</body>"):data);
 }catch{send(res,500,{error:"WEB_SYNTHETIC_UI_FIXTURE_ERROR"})}
});
server.listen(port,"127.0.0.1",()=>stdout.write("WEB_CUSTOMER_BROWSER_FIXTURE_READY\n"));
