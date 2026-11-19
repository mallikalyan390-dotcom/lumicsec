/* Explicit development-only fixture capture (no customer targets or secrets).
 * Generates actual evidence from network-none Docker worker through TLS broker.
 * Output is safe, structured review-only data; no HTTP body is included.
 */
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { writeFile } from "node:fs/promises";
import process from "node:process";
import { Buffer } from "node:buffer";
const AbortController=globalThis.AbortController;
import { runControlledRuntimeFixture } from "../src/workers/controlled-runtime-runner.ts";
import { fixtureOrigin } from "../src/workers/controlled-runtime-broker.ts";

const bundle=resolve("dist/isolated/runtime-worker.mjs");
const fixtures={};
for(const profile of ["api_insecure","api_secure","web_insecure","web_secure"]){
  const mode=profile.startsWith("api")?"api":"web";
  const result=await runControlledRuntimeFixture({
    mode,profile,signal:new AbortController().signal,
    bundlePath:bundle,
    scope:{jobId:randomUUID(),organizationId:"00000000-0000-4000-8000-000000000011",
      assetId:"00000000-0000-4000-8000-000000000022",
      actorId:"00000000-0000-4000-8000-000000000033",
      origin:fixtureOrigin(profile),scopeHash:"a".repeat(64)},
  });
  if(result.requests<1||result.externalRequests!==0)
    throw Error("CONTROLLED_CAPTURE_NETWORK_BUDGET");
  fixtures[profile]={...result,classification:"CONTROLLED_SYNTHETIC_FIXTURE_ONLY"};
}
const encoded=JSON.stringify({
  disclosure:"Actual synthetic HTTPS results, not customer data or verified vulnerabilities.",
  generatedAt:new Date().toISOString(),fixtures,
},null,2)+"\n";
if(/SYNTHETIC_OWNER_FIXTURE_ONLY|SYNTHETIC_OTHER_FIXTURE_ONLY|\\"set-cookie\\"|\\"authorization\\"/i.test(encoded))
  throw Error("CONTROLLED_FIXTURE_SECRET_REDACTION_FAILED");
const target=resolve("tests/fixtures/controlled-runtime-actual-results.json");
await writeFile(target,encoded,{mode:0o644});
process.stdout.write(JSON.stringify({target,bytes:Buffer.byteLength(encoded),
  rules:Object.fromEntries(Object.entries(fixtures).map(([k,v])=>[
    k,v.result.observations.map(o=>o.ruleId)]))})+"\n");
