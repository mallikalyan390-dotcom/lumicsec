// Real compiled React + Playwright Chromium/Firefox. No public network.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { setTimeout as pause } from "node:timers/promises";
import process from "node:process";
const fetch=globalThis.fetch;

const require=createRequire("/opt/lumicsec-phase14/package.json");
const playwright=require("playwright-core");
const base="http://127.0.0.1:5195";
const runtimeEvidence=JSON.parse(readFileSync(
  "/opt/fixture/tests/controlled-runtime-actual-results.json","utf8"));
const actualApi=runtimeEvidence.fixtures.api_insecure.result.observations.find(
  x=>x.ruleId==="API.RUNTIME.AUTH.ANON_SUCCESS");
if(!actualApi)throw Error("RUNTIME_BROWSER_EVIDENCE_MISSING");
const server=spawn("/usr/bin/node",["/opt/fixture/tests/findings-customer-smoke.mjs"],{
  env:{PATH:"/usr/bin:/bin",HOME:"/tmp"},stdio:["ignore","pipe","pipe"],
});
server.stderr.on("data",data=>process.stderr.write("FINDINGS_FIXTURE_ERROR:"+String(data).slice(0,350)+"\n"));
const status=async()=>(await (await fetch(base+"/__status")).json());
async function until(fn,timeout=24_000){
  const start=Date.now();
  while(Date.now()-start<timeout){
    try{const result=await fn();if(result)return result;}catch{/* Local fixture not yet ready. */}
    await pause(160);
  }
  throw Error("FINDINGS_BROWSER_TIMEOUT");
}
let completed=0,planCompleted=0;
try{
  await until(status);
  for(const browserName of ["chromium","firefox"]){
    const browser=await playwright[browserName].launch({headless:true,
      ...(browserName==="chromium"?{args:["--no-sandbox","--disable-dev-shm-usage"]}
        :{env:{...process.env,MOZ_DISABLE_CONTENT_SANDBOX:"1"}})});
    try{
      for(const scenario of ["owner","analyst","viewer","unverified"]){
        const query=scenario==="unverified"?"role=owner&mode=unverified":"role="+scenario;
        const context=await browser.newContext({acceptDownloads:true,viewport:{width:1280,height:900}});
        const page=await context.newPage();
        try{
          await page.goto(base+"/app/findings?"+query,{waitUntil:"domcontentloaded",timeout:20_000});
          await page.getByRole("heading",{name:"Findings, remediation and reports"}).waitFor({timeout:16_000});
          await page.getByText("Synthetic saved HSTS review").first().waitFor({timeout:16_000});
          if(!(await page.getByText("P09.HSTS.ABSENT").first().isVisible()))
            throw Error("ACTUAL_SAVED_RULE_MISSING");
          await page.getByRole("button",{name:"Review finding"}).click();
          await page.getByText("Immutable source evidence references").waitFor({timeout:12_000});
          await page.getByText("c".repeat(64),{exact:false}).first().waitFor({timeout:12_000});
          const review=page.getByRole("button",{name:"Record reviewer decision"});
          if(scenario==="viewer"){
            if(await review.count()!==0)throw Error("VIEWER_CAN_REVIEW");
            if(await page.getByRole("button",{name:"Request retest (await evidence)"}).count()!==0)
              throw Error("VIEWER_CAN_RETEST");
          }else{
            if(await review.count()!==1)throw Error("REVIEWER_CONTROLS_MISSING");
            if(scenario==="analyst"){
              if(await page.locator("#finding-decision option[value='accepted_risk']").count()!==0) {
                const identity=await page.evaluate(async()=> (await (await fetch("/v1/organizations")).json()).memberships[0].member_role);
                throw Error("ANALYST_CAN_ACCEPT_RISK role="+identity);
              }
              if(await page.locator("#finding-assignee").count()!==0)
                throw Error("ANALYST_CAN_ASSIGN");
            }else if(scenario==="unverified"){
              const request=page.getByRole("button",{name:"Request retest (await evidence)"});
              if(!await request.isDisabled())throw Error("UNVERIFIED_ASSET_RETEST_ENABLED");
            }else{
              await page.locator("#finding-decision").selectOption("false_positive");
              await page.locator("#finding-reason").fill(
                "Synthetic asset has an explicitly documented expected response.");
              await review.click();
              await until(async()=>((await status()).actions.some(a=>
                a.role==="owner"&&a.action==="classify"&&a.classification==="false_positive")));
              await page.getByText("Finding history updated. No network test executed.").waitFor();
              await page.locator("#finding-comment").fill("Remediation owner will review HSTS configuration.");
              await page.getByRole("button",{name:"Add audit comment"}).click();
              await until(async()=>((await status()).actions.some(a=>a.action==="comment")));
              await page.getByRole("button",{name:"Request retest (await evidence)"}).click();
              await until(async()=>((await status()).state.some(s=>s.role==="owner"&&s.retests>0)));
              await page.getByText("awaiting execution",{exact:false}).last().waitFor({timeout:12_000});
              const current=await status();
              const j=current.exportJsonCount,p=current.exportPdfCount;
              await page.getByRole("button",{name:"Download structured JSON"}).click();
              await until(async()=>((await status()).exportJsonCount>j));
              await page.getByRole("button",{name:"Download PDF report"}).click();
              await until(async()=>((await status()).exportPdfCount>p));
            }
          }
          const state=await status();
          if(state.webScanCount!==0)throw Error("UNAUTHORIZED_NETWORK_SCAN_TRIGGERED");
          process.stdout.write("FINDINGS_"+browserName.toUpperCase()+"_"+scenario.toUpperCase()+"_PASS\n");
          completed++;
        }finally{await context.close();}
      }
      // Separate API-runtime saved-evidence review, sourced from actual
      // network-none Docker + TLS output, not invented customer findings.
      const context=await browser.newContext({acceptDownloads:true,viewport:{width:1280,height:900}});
      try{
        const page=await context.newPage();
        await page.goto(base+"/app/findings?role=owner&runtime=api",
          {waitUntil:"domcontentloaded",timeout:20_000});
        await page.getByText("Anonymous protected-route response").first().waitFor({timeout:16_000});
        await page.getByText("API.RUNTIME.AUTH.ANON_SUCCESS").first().waitFor({timeout:16_000});
        await page.getByRole("button",{name:"Review finding"}).click();
        await page.getByText(actualApi.evidenceSource.fingerprints[0],{exact:false})
          .first().waitFor({timeout:12_000});
        await page.getByText("INCONCLUSIVE",{exact:false}).first().waitFor({timeout:12_000});
        const stats=await status();
        if(stats.webScanCount!==0)throw Error("RUNTIME_BROWSER_STARTED_PUBLIC_SCAN");
        process.stdout.write("FINDINGS_"+browserName.toUpperCase()+"_SAVED_API_RUNTIME_PASS\n");
        completed++;
      }finally{await context.close();}
      for(const scenario of ["owner","analyst","viewer","unverified"]){
        const query=scenario==="unverified"?"role=owner&mode=unverified":"role="+scenario;
        const planContext=await browser.newContext({acceptDownloads:false,
          viewport:{width:1280,height:900}});
        const page=await planContext.newPage();
        try{
          await page.goto(base+"/app/assessment-plans?"+query,
            {waitUntil:"domcontentloaded",timeout:20_000});
          await page.getByRole("heading",{name:"Runtime assessment plans"}).waitFor({timeout:16_000});
          await page.getByText("Synthetic seeded written authorization")
            .first().waitFor({timeout:16_000});
          await page.getByText("Public customer scanning remains").first()
            .waitFor({timeout:12_000});
          const save=page.getByRole("button",{name:"Authorize assessment plan (no scan)"});
          if(scenario==="viewer"){
            await page.getByRole("button",{name:"Inspect audit and live eligibility"}).first().click();
            await page.getByText("Controlled-fixture execution history (read-only)").waitFor();
            await page.getByText("5 saved review observations").waitFor();
            if(!(await save.isDisabled()))throw Error("VIEWER_CAN_AUTHORIZE_PLAN");
            if(await page.getByRole("button",{name:"Revoke permission"}).count()!==0)
              throw Error("VIEWER_CAN_REVOKE_PLAN");
          }else if(scenario==="unverified"){
            await page.getByText("No currently verified assets").waitFor();
            if(!(await save.isDisabled()))throw Error("UNVERIFIED_PLAN_CAN_AUTHORIZE");
          }else{
            const seedRevokes=page.getByRole("button",{name:"Revoke permission"});
            if(scenario==="analyst" && !(await seedRevokes.first().isDisabled()))
              throw Error("ANALYST_CAN_REVOKE_ANOTHER_ACTOR_PLAN");
            const asset="00000000-0000-4000-8000-000000000022";
            await page.locator("#plan-asset").selectOption(asset);
            await page.locator("#plan-paths").fill("/\n/health");
            await page.locator("#plan-reference").fill(
              "Written synthetic permission for exact scoped GET endpoints");
            await page.getByRole("checkbox").check();
            if(await save.isDisabled())throw Error("VERIFIED_PLAN_AUTHORIZE_DISABLED");
            const before=(await status()).planCreateCount;
            await save.click();
            await until(async()=>((await status()).planCreateCount>before));
            await page.getByText("Authorization saved. No network assessment was executed.").waitFor();
            await page.getByRole("button",{name:"Inspect audit and live eligibility"}).first().click();
            await page.getByText("Current proof check:").waitFor({timeout:12_000});
            await page.getByText("No controlled fixture executions recorded for this plan.").waitFor({timeout:12_000});
            await page.getByText("ELIGIBLE_FOR_FUTURE_REVIEW").first().waitFor({timeout:12_000});
            if(scenario==="owner"){
              const revokes=page.getByRole("button",{name:"Revoke permission"});
              const initial=(await status()).planRevokeCount;
              await revokes.first().click();
              await until(async()=>((await status()).planRevokeCount>initial));
              await page.getByText("Authorization revoked. Future use denied.").waitFor();
              await page.locator("#plan-asset")
                .selectOption("00000000-0000-4000-8000-000000000088");
              await page.locator("#plan-paths").fill("/v1/health");
              await page.locator("#plan-reference").fill(
                "Owner written permission for controlled API read-only review");
              await page.getByRole("checkbox").check();
              const current=(await status()).planCreateCount;
              await save.click();
              await until(async()=>((await status()).planCreateCount>current));
              await page.getByText("api_readonly", {exact:false}).first()
                .waitFor({timeout:12_000});
            }
          }
          const current=await status();
          if(current.webScanCount!==0||current.planNetworkCount!==0)
            throw Error("PLAN_SCREEN_STARTED_CUSTOMER_SCAN");
          process.stdout.write("ASSESSMENT_PLANS_"+browserName.toUpperCase()+
            "_"+scenario.toUpperCase()+"_PASS\n");
          planCompleted++;
        }finally{await planContext.close();}
      }
    }finally{await browser.close();}
  }
  const current=await status();
  if(completed!==10||planCompleted!==8||current.webScanCount!==0||
     current.planNetworkCount!==0||current.planCreateCount<6||
     current.planRevokeCount<2||current.exportPdfCount<1||
     current.exportJsonCount<1||!current.actions.some(x=>x.action==="retest_request"))
    throw Error("FINDINGS_BROWSER_WORKFLOW_INCOMPLETE");
  process.stdout.write("FINDINGS_CHROMIUM_FIREFOX_10_OF_10_PASS\n");
  process.stdout.write("ASSESSMENT_PLANS_CHROMIUM_FIREFOX_8_OF_8_PASS\n");
}catch(error){
  process.stderr.write("FINDINGS_BROWSER_NOT_QUALIFIED:"+String(error).slice(0,700)+"\n");
  process.exitCode=1;
}finally{server.kill("SIGTERM");}
