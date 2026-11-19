// Browser fixture for the ACTUAL BUILT React API Security customer UI.
// All identities, endpoints, files and assessment results are synthetic; no Supabase or DNS.
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath, URL } from "node:url";
import { stdout } from "node:process";

const dist=resolve(dirname(fileURLToPath(import.meta.url)),"../dist");
const port=5191;
const org="00000000-0000-4000-8000-000000000011";
const asset="00000000-0000-4000-8000-000000000022";
const user="00000000-0000-4000-8000-000000000033";
const job="00000000-0000-4000-8000-000000000044";
const reports=[];
let submitted=0;
let lastSubmission=null;
const json=(res,status,payload)=>{
  res.writeHead(status,{"content-type":"application/json","cache-control":"no-store"});
  res.end(JSON.stringify(payload));
};
const script=`<script>
(async()=>{
 const waitFor=async check=>{
  for(let n=0;n<150;n++){
   const item=check();
   if(item)return item;
   await new Promise(resolve=>setTimeout(resolve,100));
  }
  throw Error("UI_TIMEOUT");
 };
 const text=()=>document.querySelector("#root")?.textContent??"";
 const asset="00000000-0000-4000-8000-000000000022";
 const member=location.search.includes("role=member");
 const pending=location.search.includes("mode=unverified");
 const result={browser:navigator.userAgent.includes("Firefox")?"firefox":"chromium",member,pending};
 try{
  await waitFor(()=>text().includes("Verified-asset assessment history"));
  await waitFor(()=>document.querySelector("#assessment-asset")?.options.length);
  const assetSelect=document.querySelector("#assessment-asset");
  result.heading=!!assetSelect;
  result.explicitScopeText=text().includes("I am authorized by the asset owner");
  result.noNetworkMessage=text().includes("No API requests are executed");
  result.defaultNoSubmit=!([...document.querySelectorAll("button")].find(b=>b.textContent.includes("Save authorized offline assessment"))?.disabled===false);
  if(member) {
   result.memberCannotSubmit=!([...document.querySelectorAll("button")].some(b=>b.textContent.includes("Save authorized offline assessment")));
  }else if(pending){
   await waitFor(()=>text().includes("No currently verified API asset"));
   result.unverifiedCannotSubmit=assetSelect.options.length===1;
  }else{
   await waitFor(()=>assetSelect.options.length===2);
   const setter=Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,"value").set;
   setter.call(assetSelect,asset);
   assetSelect.dispatchEvent(new Event("change",{bubbles:true}));
   await waitFor(()=>text().includes("Choose API specification for saved review"));
   const upload=document.querySelector('input[type="file"]');
   const fixture=new File([JSON.stringify({openapi:"3.1.0",info:{title:"Synthetic",version:"1"},paths:{}})],"synthetic.json",{type:"application/json"});
   const transfer=new DataTransfer();transfer.items.add(fixture);upload.files=transfer.files;
   upload.dispatchEvent(new Event("change",{bubbles:true}));
   const consent=await waitFor(()=>document.querySelector('input[type="checkbox"]'));
   consent.click();
   const button=await waitFor(()=>[...document.querySelectorAll("button")].find(b=>b.textContent.includes("Save authorized offline assessment")&&!b.disabled));
   button.click();
   await waitFor(()=>text().includes("Saved job"));
   result.savedResultVisible=true;
  }
  const review=await waitFor(()=>[...document.querySelectorAll("button")].find(b=>b.textContent.includes("Review evidence")));
  review.click();
  await waitFor(()=>text().includes("AUTH_UNDECLARED"));
  result.reviewEvidenceVisible=text().includes("Review synthetic documentation");
  result.noConfirmedVulnerability=text().includes("runtime security remain unverified");
 }catch(e){result.problem=String(e?.message).slice(0,120)}
 await fetch("/__report",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(result)}).catch(()=>{});
})();
</script>`;
const server=createServer(async(req,res)=>{
 try{
  const u=new URL(req.url??"/","http://127.0.0.1:"+port);
  const path=u.pathname;
  const cookies=String(req.headers.cookie??"");
  const member=cookies.includes("lumicsec_fixture_role=member");
  const pending=cookies.includes("lumicsec_fixture_mode=unverified");
  if(path==="/auth/session") return json(res,200,{
    configured:true,state:"authenticated",csrfToken:"synthetic-only",
    user:{id:user,email:"browser-test@example.invalid"},
  });
  if(path==="/v1/organizations" && req.method==="GET")return json(res,200,{
    organizations:[{id:org,display_name:"Synthetic Organization",created_by:user,created_at:"2026-01-01T00:00:00Z"}],
    memberships:[{organization_id:org,member_role:member?"member":"owner",member_status:"active"}],
  });
  if(path==="/v1/assets" && req.method==="GET") return json(res,200,{
    assets:[{id:asset,organization_id:org,asset_kind:"api",display_name:"Synthetic API",
      canonical_origin:"https://api.example.com",verification_status:pending?"pending":"verified",
      verified_at:pending?null:"2026-10-01T00:00:00Z",
      verification_expires_at:pending?null:"2099-01-01T00:00:00Z",created_at:"2026-10-01T00:00:00Z"}],
  });
  if(path==="/v1/assessments/api-spec" && req.method==="GET") return json(res,200,{
    jobs:[{id:job,organization_id:org,asset_id:asset,job_state:"succeeded",
      source_format:"OPENAPI_3_1",source_fingerprint:"a".repeat(64),authorization_at:"2026-10-01T00:00:00Z",
      requested_at:"2026-10-01T00:00:00Z",observation_count:1,
      result_coverage:{operationCount:1,truncated:false}}],
  });
  if(path==="/v1/assessments/api-spec/observations" && req.method==="GET") return json(res,200,{
    observations:[{id:"00000000-0000-4000-8000-000000000055",rule_id:"AUTH_UNDECLARED",
      title:"Specification security declaration",summary:"Review synthetic documentation",
      severity_estimate:"low",review_state:"review_required"}],
  });
  if(path==="/v1/assessments/api-spec" && req.method==="POST"){
    let body="";
    for await(const part of req) {
      body+=part.toString();
      if(body.length>1024*1024+2048) return json(res,413,{error:"FIXTURE_TOO_LARGE"});
    }
    const data=JSON.parse(body);
    lastSubmission={orgAuthorized:data.organizationId===org,
      assetAuthorized:data.assetId===asset,
      explicitConsent:data.authorization==="I_AM_AUTHORIZED_FOR_OFFLINE_SPEC_REVIEW",
      contentIsSynthetic:data.content.includes("Synthetic")};
    if(member||pending||!Object.values(lastSubmission).every(Boolean))return json(res,403,{error:"FIXTURE_DENIED"});
    submitted++;
    return json(res,201,{jobId:job,organizationId:org,assetId:asset,state:"succeeded",
      classification:"SPEC_ONLY",operationCount:1,totalObservations:1,savedObservations:1,
      networkRequestsSent:0,reviewRequired:true});
  }
  if(path==="/__report" && req.method==="POST"){
    let body="";for await(const part of req){body+=part.toString();if(body.length>3000)break;}
    const data=JSON.parse(body);
    reports.push(data);
    stdout.write("OFFLINE_API_BROWSER_RESULT "+JSON.stringify(data)+"\n");
    return json(res,200,{received:true});
  }
  if(path==="/__status")return json(res,200,{reports,submitted,lastSubmission});
  // Only compiled app files are served; any unknown API route is blocked.
  if(path.startsWith("/v1/")||path.startsWith("/auth/"))return json(res,403,{error:"UNEXPECTED_API_REQUEST"});
  let file=resolve(dist,"."+path);
  if(relative(dist,file).startsWith(".."))return json(res,403,{error:"FORBIDDEN"});
  if(!(await stat(file).catch(()=>null))?.isFile())file=join(dist,"index.html");
  const bytes=await readFile(file);
  const html=file.endsWith(".html");
  // Only initial SPA navigation may set synthetic persona; asset fallback requests must not reset it.
  const extra=html && (path.startsWith("/app/") || path==="/")?{
    "set-cookie":[
      "lumicsec_fixture_role="+(u.searchParams.get("role")==="member"?"member":"owner")+"; Path=/; SameSite=Lax",
      "lumicsec_fixture_mode="+(u.searchParams.get("mode")==="unverified"?"unverified":"verified")+"; Path=/; SameSite=Lax",
    ],
  }:{};
  const mime={".html":"text/html; charset=utf-8",".js":"text/javascript",".css":"text/css"};
  res.writeHead(200,{"content-type":mime[extname(file)]??"application/octet-stream",
    "cache-control":"no-store",...extra});
  res.end(html?bytes.toString().replace("</body>",script+"</body>"):bytes);
 }catch{json(res,500,{error:"OFFLINE_BROWSER_FIXTURE_FAILURE"})}
});
server.listen(port,"127.0.0.1",()=>stdout.write("OFFLINE_API_BROWSER_FIXTURE_READY\n"));
