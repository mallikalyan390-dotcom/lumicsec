// Run only inside the pinned local browser-validation Docker image with
// --network none. Tests the compiled React bundle against ACTUAL isolated
// worker evidence stored in web-sandbox-actual-result.json.
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { setTimeout as pause } from "node:timers/promises";
import process from "node:process";
const fetch = globalThis.fetch;

const require = createRequire("/opt/lumicsec-phase14/package.json");
const playwright = require("playwright-core");
const port = 5193;
const base = "http://127.0.0.1:" + port;
const website = "/app/web-security";
const server = spawn("/usr/bin/node", ["/opt/fixture/tests/web-assessment-customer-smoke.mjs"], {
  env: { PATH: "/usr/bin:/bin", HOME: "/tmp" }, stdio: ["ignore", "pipe", "pipe"],
});
server.stderr.on("data", data=>process.stderr.write("FIXTURE_SERVER_ERROR:"+String(data).slice(0,300)+"\n"));
const done = async () => (await (await fetch(base+"/__status")).json());
async function waitFor(check, limit=24_000) {
  const started = Date.now();
  while(Date.now()-started < limit) {
    try {
      const value = await check();
      if (value) return value;
    } catch { /* Local fixture may not have started yet. */ }
    await pause(150);
  }
  throw Error("ISOLATED_BROWSER_UI_RESPONSE_TIMEOUT");
}
let total = 0;
try {
  await waitFor(async () => (await done()).reports !== undefined);
  for (const name of ["chromium", "firefox"]) {
    const browser = await playwright[name].launch({ headless:true,
      ...(name==="chromium" ? {args:["--disable-dev-shm-usage", "--no-sandbox"]}
        : {env:{...process.env,MOZ_DISABLE_CONTENT_SANDBOX:"1"}}) });
    try {
      for (const [query,role] of [
        ["role=owner","owner"],
        ["role=member","member"],
        ["role=owner&mode=unverified","unverified"],
      ]) {
        const previous = (await done()).reports.length;
        const context=await browser.newContext({ viewport:{ width:1280,height:900 } });
        const page=await context.newPage();
        try {
          await page.goto(base + website + "?" + query, {waitUntil:"domcontentloaded",timeout:20_000});
          const item = await waitFor(async () => {
            const current=await done();
            return current.reports.length>previous?current.reports.at(-1):null;
          });
          if(item.problem || item.browser !== name ||
             !item.heading || !item.scanDisabled || !item.noActiveScan ||
             !item.verifiedSelection || !item.memberReadOnly ||
             !item.insecureEvidence || !item.secureNoFalseSignal ||
             (role==="unverified" && !item.unverifiedNotice))
            throw Error("WEB_CUSTOMER_"+name+"_"+role+"_ASSERTION_FAILED:"+JSON.stringify(item));
          process.stdout.write("REAL_BROWSER_"+name.toUpperCase()+"_"+role.toUpperCase()+"_PASS\n");
          total++;
        } finally {
          await context.close();
        }
      }
    } finally {
      await browser.close();
    }
  }
  const summary=await done();
  if(total !== 6 || summary.webQueueRequests!==0 || summary.webCancelRequests!==0)
    throw Error("WEB_BROWSER_CUSTOMER_SCANNING_WAS_ENABLED");
  process.stdout.write("REAL_BROWSER_CHROMIUM_FIREFOX_6_OF_6_PASS\n");
} catch (error) {
  process.stderr.write("ISOLATED_BROWSER_WORKFLOW_NOT_QUALIFIED:"+String(error).slice(0,450)+"\n");
  process.exitCode=1;
} finally {
  server.kill("SIGTERM");
}
