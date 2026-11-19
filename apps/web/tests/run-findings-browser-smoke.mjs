// Real compiled React + Playwright Chromium/Firefox. No public network.
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { setTimeout as pause } from "node:timers/promises";
import process from "node:process";
const fetch=globalThis.fetch;

const require=createRequire("/opt/lumicsec-phase14/package.json");
const playwright=require("playwright-core");
const base="http://127.0.0.1:5195";
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
let completed=0;
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
    }finally{await browser.close();}
  }
  const current=await status();
  if(completed!==8||current.webScanCount!==0||current.exportPdfCount<1||
     current.exportJsonCount<1||!current.actions.some(x=>x.action==="retest_request"))
    throw Error("FINDINGS_BROWSER_WORKFLOW_INCOMPLETE");
  process.stdout.write("FINDINGS_CHROMIUM_FIREFOX_8_OF_8_PASS\n");
}catch(error){
  process.stderr.write("FINDINGS_BROWSER_NOT_QUALIFIED:"+String(error).slice(0,700)+"\n");
  process.exitCode=1;
}finally{server.kill("SIGTERM");}
