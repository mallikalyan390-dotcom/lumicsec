// Standalone UI smoke server for the compiled React bundle.
// Every identity, organization, hostname and token here is synthetic.
// Do not connect to Supabase, customer DNS or customer websites.
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { dirname, extname, join, relative, resolve } from "node:path";
import { URL, fileURLToPath } from "node:url";
import { stdout } from "node:process";

const dist = resolve(dirname(fileURLToPath(import.meta.url)), "../dist");
const port = 5189;
const orgId = "00000000-0000-4000-8000-000000000011";
const assetId = "00000000-0000-4000-8000-000000000022";
const userId = "00000000-0000-4000-8000-000000000033";
const challengeId = "00000000-0000-4000-8000-000000000044";
let challengesIssued = 0;
let invitationsIssued = 0;
let proofRequests = 0;
const reports = [];
const json = (res, code, body) => {
  res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
};
const harness = `<script>
(async () => {
 const waitFor = async (predicate) => {
   for (let n=0;n<145;n++) {
     const result=predicate();
     if (result) return result;
     await new Promise(resolve=>setTimeout(resolve,100));
   }
   throw new Error("UI condition not reached");
 };
 const visibleText=()=>document.querySelector("#root")?.textContent??"";
 const isFirefox=navigator.userAgent.includes("Firefox");
 const isAssets=location.pathname.includes("/assets");
 const isMember=location.search.includes("member");
 const result={browser:isFirefox?"firefox":"chromium", page:isAssets?"assets":"team", role:isMember?"member":"owner"};
 try {
   if(isAssets){
     const heading=await waitFor(()=>visibleText().includes("Organizations & assets"));
     result.heading=!!heading;
     await waitFor(()=>visibleText().includes("Synthetic QA website"));
     result.pendingStatus=visibleText().includes("pending");
     result.noScanning=visibleText().includes("No automatic scan permission");
     const issue=isMember ? null : await waitFor(()=>[...document.querySelectorAll("button")].find(x=>x.textContent.includes("Create ownership challenge") && !x.disabled));
     result.canIssue=!!issue;
     if(!isMember){
       issue.click();
       await waitFor(()=>visibleText().includes("Exact TXT value / file content:"));
       result.challengeDisplayed=true;
       const check=await waitFor(()=>[...document.querySelectorAll("button")].find(x=>x.textContent.includes("Check published proof")&&!x.disabled));
       check.click();
       await waitFor(()=>visibleText().includes("TRUSTED_VERIFICATION_BACKEND_NOT_CONFIGURED"));
       result.serverUnconfiguredShown=true;
     } else {
       result.memberCannotIssue=!issue;
     }
   } else {
     result.heading=!!(await waitFor(()=>visibleText().includes("Team & access management")));
     await waitFor(()=>visibleText().includes("Accept an invitation"));
     result.acceptFormVisible=true;
     const invite=await (async()=> {
       if(isMember) return null;
       return await waitFor(()=>[...document.querySelectorAll("button")].find(x=>x.textContent.includes("Create invite")&&!x.disabled));
     })();
     if(!isMember){
       result.ownerControls=!!invite && visibleText().includes("Team memberships") && visibleText().includes("Audit history");
       const input=document.querySelector("#invite-email");
       const native=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value").set;
       native.call(input,"synthetic-invitee@example.invalid");
       input.dispatchEvent(new Event("input",{bubbles:true}));
       invite.click();
       await waitFor(()=>visibleText().includes("Single-use invite code"));
       result.oneTimeCodeVisible=true;
     } else {
       await waitFor(()=>visibleText().includes("Your role: member") || visibleText().includes("Your role: owner"));
       result.memberRoleVisible=visibleText().includes("Your role: member");
       result.hasInviteInput=!!document.querySelector("#invite-email");
       result.hasTeamMembershipHeading=visibleText().includes("Team memberships");
       result.memberCannotManage=result.memberRoleVisible && !result.hasInviteInput && !document.querySelector("#invite-role");
     }
   }
 } catch(e){result.problem=String(e.message).slice(0,90);}
 await fetch("/__report",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(result)}).catch(()=>{});
})();
</script>`;

const server=createServer(async (req,res)=>{
 try{
  const u=new URL(req.url??"/","http://127.0.0.1:"+port);
  const path=u.pathname;
  const member=String(req.headers.cookie??"").includes("synthetic_role=member")
    || String(req.headers.referer??"").includes("role=member");
  if(path==="/auth/session") return json(res,200,{
    state:"authenticated", configured:true,csrfToken:"synthetic-csrf-only",
    user:{id:userId,email:"synthetic@example.invalid"},
  });
  if(path==="/v1/organizations" && req.method==="GET") return json(res,200,{
    organizations:[{id:orgId,display_name:"Synthetic QA Organization",created_at:"2026-01-01T00:00:00Z",created_by:userId}],
    memberships:[{organization_id:orgId,member_role:member?"member":"owner",member_status:"active"}],
  });
  if(path.endsWith("/members") && req.method==="GET") return json(res,200,{members:[
    {user_id:userId,member_role:"owner",member_status:"active",member_email:"synthetic@example.invalid",joined_at:"2026-01-01T00:00:00Z"},
  ]});
  if(path.endsWith("/invitations") && req.method==="GET") return json(res,200,{invitations:[]});
  if(path.endsWith("/audit") && req.method==="GET") return json(res,200,{events:[]});
  if(path.endsWith("/invitations") && req.method==="POST"){
    invitationsIssued++;
    return json(res,201,{invitation:{invitation_id:challengeId,invite_token:"b".repeat(64),expires_at:"2026-12-01T00:00:00Z"}});
  }
  if(path==="/v1/assets" && req.method==="GET") return json(res,200,{assets:[{
    id:assetId,organization_id:orgId,asset_kind:"website",display_name:"Synthetic QA website",
    canonical_origin:"https://qa-synthetic.example.com",verification_status:"pending",
    verified_at:null,verification_expires_at:null,created_at:"2026-01-01T00:00:00Z",
  }]});
  if(path==="/v1/assets/verification/challenges" && req.method==="GET"){
    return json(res,200,{challenges:challengesIssued?[{
      id:challengeId,organization_id:orgId,asset_id:assetId,method:"dns_txt",
      created_at:"2026-01-01T00:00:00Z",expires_at:"2099-01-01T00:00:00Z",
      verified_at:null,revoked_at:null,
    }]:[]});
  }
  if(path==="/v1/assets/verification/challenges" && req.method==="POST"){
    challengesIssued++;
    return json(res,201,{challenge:{
      challenge_id:challengeId,verification_token:"a".repeat(64),verification_host:"qa-synthetic.example.com",
      verification_path:"_lumicsec-challenge.qa-synthetic.example.com",
      expires_at:"2099-01-01T00:00:00Z",
    },scanningEnabled:false});
  }
  if(path==="/v1/assets/verification/check" && req.method==="POST"){
    proofRequests++;
    return json(res,503,{error:"TRUSTED_VERIFICATION_BACKEND_NOT_CONFIGURED"});
  }
  if(path==="/__report" && req.method==="POST"){
    let body="";
    for await(const part of req){
      body+=part.toString();
      if(body.length>2200) break;
    }
    const item=JSON.parse(body);
    const safe={
      browser:item.browser==="firefox"?"firefox":"chromium",
      page:item.page==="assets"?"assets":"team",role:item.role==="member"?"member":"owner",
      heading:!!item.heading,acceptFormVisible:!!item.acceptFormVisible,
      pendingStatus:!!item.pendingStatus,noScanning:!!item.noScanning,
      canIssue:!!item.canIssue,challengeDisplayed:!!item.challengeDisplayed,
      serverUnconfiguredShown:!!item.serverUnconfiguredShown,
      memberCannotIssue:!!item.memberCannotIssue,memberCannotManage:!!item.memberCannotManage,
      ownerControls:!!item.ownerControls,oneTimeCodeVisible:!!item.oneTimeCodeVisible,
      memberRoleVisible:!!item.memberRoleVisible,hasInviteInput:!!item.hasInviteInput,
      hasTeamMembershipHeading:!!item.hasTeamMembershipHeading,
      problem:typeof item.problem==="string"?item.problem:""
    };
    reports.push(safe);
    stdout.write("QA_BROWSER_RESULT " + JSON.stringify(safe) + "\n");
    return json(res,200,{received:true});
  }
  if(path==="/__status")return json(res,200,{reports,proofRequests,challengesIssued,invitationsIssued});
  let file=resolve(dist,"."+path);
  if(relative(dist,file).startsWith(".."))return json(res,403,{error:"FORBIDDEN"});
  if(!(await stat(file).catch(()=>null))?.isFile()) file=join(dist,"index.html");
  const bytes=await readFile(file);
  const output=file.endsWith(".html")?bytes.toString().replace("</body>",harness+"</body>"):bytes;
  const mime={".html":"text/html; charset=utf-8",".js":"text/javascript",".css":"text/css"};
  res.writeHead(200,{"content-type":mime[extname(file)]??"application/octet-stream","cache-control":"no-store",
    ...(file.endsWith(".html")?{"set-cookie":"synthetic_role="+(u.searchParams.get("role")==="member"?"member":"owner")+"; Path=/; SameSite=Lax"}:{})});
  res.end(output);
 }catch{
  json(res,500,{error:"SYNTHETIC_FIXTURE_ERROR"});
 }
});
server.listen(port,"127.0.0.1", () => stdout.write("RBAC_OWNERSHIP_BROWSER_FIXTURE_READY\n"));
