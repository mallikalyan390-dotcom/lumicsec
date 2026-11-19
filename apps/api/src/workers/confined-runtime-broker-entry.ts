/* Test-only HTTPS broker inside an independent --network none Docker
 * namespace. TLS key stays in its own private /tmp; only AF_UNIX socket
 * directory is shared with the independently network-none worker.
 */
import {z} from "zod";
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
  const aborter=new AbortController();
  const broker=await openControlledRuntimeBroker({
    profile:profile as ControlledProfile,origin,executionId,
    signal:aborter.signal,socketDirectory:"/opt/lumicsec-broker",
    ...scoped,
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
main().catch(()=>{
  process.stderr.write("CONFINED_BROKER_REJECTED\n");
  process.exitCode=1;
});
