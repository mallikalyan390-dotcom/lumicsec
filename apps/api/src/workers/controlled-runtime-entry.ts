/* Controlled runtime worker: no TCP egress, auth credentials, backend DB
 * client, host sockets, or service-role keys. A single test-only AF_UNIX
 * broker socket is mounted by the trusted fixture controller.
 */
import { ControlledBrokerClient } from "./controlled-broker-client.js";
import { executeUnprivilegedWebRead } from "./web-passive-core.js";
import { executeControlledApiRuntime } from "./controlled-api-runtime.js";
import { CONTROLLED_RUNTIME_VERSION, controlledInputFromText,
  parseControlledResult } from "./controlled-runtime-contract.js";

async function oneCommand() {
  let text="";
  for await(const part of process.stdin) {
    text+=part.toString("utf8");
    if(Buffer.byteLength(text)>2049)throw Error("CONTROLLED_WORKER_INPUT_OVERSIZE");
  }
  if(!text.endsWith("\n")||text.indexOf("\n")!==text.length-1)
    throw Error("CONTROLLED_WORKER_MULTI_COMMAND");
  return controlledInputFromText(text.slice(0,-1));
}
async function main() {
  const secrets=Object.keys(process.env).filter(name=>
    /(?:SUPABASE|SECRET|TOKEN|AUTH|PASSWORD|COOKIE|JWT|API_KEY|DATABASE_URL)/i.test(name));
  if(secrets.length)throw Error("CONTROLLED_WORKER_SECRET_ENV_DENIED");
  if(process.env["LUMICSEC_CONTROLLED_FIXTURE"]!=="yes")
    throw Error("CONTROLLED_WORKER_DISABLED");
  const input=await oneCommand();
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),15_000);
  const broker=new ControlledBrokerClient({
    executionId:input.executionId,origin:input.scope.origin,
    socketPath:"/opt/lumicsec-broker/request.sock",signal:controller.signal,
  });
  try{
    const result=input.mode==="web"
      ? await executeUnprivilegedWebRead({
          scope:input.scope,transport:broker,signal:controller.signal})
      : await executeControlledApiRuntime({
          origin:input.scope.origin,scopeHash:input.scope.scopeHash,
          client:broker,signal:controller.signal});
    const api=result as Awaited<ReturnType<typeof executeControlledApiRuntime>>;
    const apiReport={classification:api.classification,scopeHash:api.scopeHash,
      coverageState:api.coverageState,requests:api.requests,bytes:api.bytes,
      limitations:api.limitations,statuses:api.statuses};
    const output={protocol:CONTROLLED_RUNTIME_VERSION,type:"RESULT",
      executionId:input.executionId,jobId:input.scope.jobId,
      scopeHash:input.scope.scopeHash,mode:input.mode,
      report:input.mode==="web" ? (result as Awaited<ReturnType<typeof executeUnprivilegedWebRead>>).report :apiReport,
      observations:result.observations};
    const encoded=JSON.stringify(parseControlledResult(JSON.stringify(output),input));
    if(Buffer.byteLength(encoded)>120_000)
      throw Error("CONTROLLED_RESULT_TOO_LARGE");
    process.stdout.write(encoded+"\n");
  }finally{clearTimeout(timer);controller.abort();}
}
main().catch(()=>{
  process.stderr.write("CONTROLLED_RUNTIME_REJECTED\n");
  process.exitCode=1;
});
