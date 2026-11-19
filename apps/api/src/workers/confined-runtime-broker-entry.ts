/* Test-only HTTPS broker inside an independent --network none Docker
 * namespace. TLS key stays in its own private /tmp; only AF_UNIX socket
 * directory is shared with the independently network-none worker.
 */
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
  const origin=fixtureOrigin(profile as ControlledProfile);
  const aborter=new AbortController();
  const broker=await openControlledRuntimeBroker({
    profile:profile as ControlledProfile,origin,executionId,
    signal:aborter.signal,socketDirectory:"/opt/lumicsec-broker",
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
