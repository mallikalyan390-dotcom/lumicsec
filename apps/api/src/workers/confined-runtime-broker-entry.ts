/* Test-only HTTPS broker inside an independent --network none Docker
 * namespace. TLS key stays in its own private /tmp; only AF_UNIX socket
 * directory is shared with the independently network-none worker.
 */
import {z} from "zod";
import {readFile,open} from "node:fs/promises";
import {verifyControlledBrokerScope,type BrokerSignedTicket}
 from "./broker-scope-ticket.js";
import { openControlledRuntimeBroker,fixtureOrigin,
  type ControlledProfile } from "./controlled-runtime-broker.js";
const profiles:readonly string[]=[
  "web_insecure","web_secure","web_redirect","web_oversize","web_slow",
  "api_insecure","api_secure","api_redirect","api_oversize","api_slow",
];
async function main(){
  const keys=Object.keys(process.env);
  if(keys.some(k=>/(?:SUPABASE|PASSWORD|JWT|API_KEY|DATABASE_URL|COOKIE)/i.test(k)))
    throw Error("BROKER_PRIVILEGED_ENV_DENIED");
  const profile=process.env["LUMICSEC_BROKER_PROFILE"];
  const executionId=process.env["LUMICSEC_BROKER_EXECUTION_ID"];
  if(!profile||!profiles.includes(profile)||!executionId||
    process.env["LUMICSEC_CONTROLLED_FIXTURE"]!=="yes")
    throw Error("BROKER_PROFILE_DENIED");
  const rawScope=process.env["LUMICSEC_BROKER_SCOPED"];
  if(rawScope&&Buffer.byteLength(rawScope)>1300)
    throw Error("BROKER_SCOPE_LIMIT_DENIED");
  const scopedSchema=z.strictObject({
    approvedPaths:z.array(z.string().regex(/^\/[a-zA-Z0-9._~/-]{0,119}$/)).min(1).max(6),
    maxRequests:z.number().int().min(1).max(6),
    maxResponseBytes:z.number().int().min(1024).max(60000),
    maxTotalBytes:z.number().int().min(1024).max(240000),
    maxExecutionMs:z.number().int().min(1000).max(15000),
  });
  const scoped=rawScope?scopedSchema.parse(JSON.parse(rawScope) as unknown):undefined;
  if(scoped&&scoped.maxTotalBytes<scoped.maxResponseBytes)
    throw Error("BROKER_SCOPE_BUDGET_DENIED");
  const origin=fixtureOrigin(profile as ControlledProfile);
  const signedEnv=process.env["LUMICSEC_BROKER_SIGNED_TICKET"];
  let signedScope=undefined as typeof scoped;
  if(rawScope&&!signedEnv)
    throw Error("BROKER_SIGNED_TICKET_REQUIRED");
  if(signedEnv){
    if(Buffer.byteLength(signedEnv)>3500)
      throw Error("BROKER_SIGNED_ENV_BOUNDS");
    const signed=JSON.parse(Buffer.from(signedEnv,"base64url")
      .toString("utf8")) as BrokerSignedTicket;
    const pem=await readFile("/opt/lumicsec-admission/public-key.pem","utf8");
    const claimed=process.env["LUMICSEC_BROKER_EXPECTED"];
    if(!claimed||Buffer.byteLength(claimed)>700)
      throw Error("BROKER_EXPECTED_CLAIM_MISSING");
    const expected=z.strictObject({
      jobId:z.string().uuid(),planId:z.string().uuid(),
      workerId:z.string().uuid(),generation:z.number().int().min(1).max(2),
      scopeHash:z.string().regex(/^[a-f0-9]{64}$/),
    }).parse(JSON.parse(Buffer.from(claimed,"base64url").toString("utf8")) as unknown);
    const checked=verifyControlledBrokerScope(signed,pem,{
      executionId,origin,profile,...expected,
    });
    signedScope=scopedSchema.parse({
      approvedPaths:checked.scope.approvedPaths,
      maxRequests:checked.scope.maxRequests,
      maxResponseBytes:checked.scope.maxResponseBytes,
      maxTotalBytes:checked.scope.maxTotalBytes,
      maxExecutionMs:checked.scope.maxExecutionMs,
    });
    if(scoped&&JSON.stringify(scoped)!==JSON.stringify(signedScope))
      throw Error("BROKER_UNSIGNED_SCOPE_MISMATCH");
    // O_CREAT | O_EXCL is atomic between simultaneous broker containers.
    // The ledger mount is private to TRUSTED broker(s), NEVER worker.
    // Persistence across local restarts depends on the caller supplying
    // the same secure job-scoped ledger directory.
    const fh=await open("/opt/lumicsec-ticket-ledger/"+checked.nonceHash,
      "wx",0o600);
    await fh.close();
  }else if(process.env["LUMICSEC_BROKER_REQUIRE_TICKET"]==="yes"){
    throw Error("BROKER_SIGNED_TICKET_REQUIRED");
  }
  const aborter=new AbortController();
  const broker=await openControlledRuntimeBroker({
    profile:profile as ControlledProfile,origin,executionId,
    signal:aborter.signal,socketDirectory:"/opt/lumicsec-broker",
    ...(signedScope??scoped),
    onStatistics:metric=>process.stdout.write("CONTROLLED_BROKER_METRICS "+
      JSON.stringify(metric)+"\n"),
  });
  process.stdout.write("CONTROLLED_BROKER_READY\n");
  await new Promise<void>(done=>{
    process.once("SIGTERM",done);
    process.once("SIGINT",done);
  });
  await broker.close();
  aborter.abort();
  process.stdout.write("CONTROLLED_BROKER_STOPPED\n");
}
main().catch(error=>{
  // Only fixed, non-sensitive development error labels. Never echo keys,
  // signed ticket bodies, file paths or raw request evidence.
  const message=error instanceof Error?error.message:"";
  const labels=["BROKER_SIGNED_TICKET_REQUIRED","BROKER_SIGNED_SIGNATURE_INVALID",
    "BROKER_SIGNED_SCOPE_EXPIRED_OR_INVALID","BROKER_SIGNED_EXPECTED_SCOPE_MISMATCH",
    "BROKER_UNSIGNED_SCOPE_MISMATCH","BROKER_CONTROLLED_FIXTURE_SETUP_REJECTED",
    "BROKER_REMOTE_FIXTURE_SIGNED_SCOPE_REQUIRED","BROKER_REMOTE_TLS_REQUIRES_SIGNED_FIXTURE_SCOPE"];
  const label=labels.find(code=>message.includes(code))??"BROKER_SETUP_OR_SCHEMA_DENIED";
  process.stderr.write("CONFINED_BROKER_REJECTED "+label+"\n");
  process.exitCode=1;
});
