/* Bounded, non-destructive synthetic API runtime evidence.
 * Reuses saved specification naming semantics but DOES NOT use synthetic
 * SPEC_ONLY detections as validated runtime vulnerabilities.
 * The three GET requests never accept arbitrary URLs, payloads or credentials.
 */
import { createHash } from "node:crypto";
import { requireExactWebUrl } from "../lib/web-pinned-transport.js";
import type { ControlledBrokerClient } from "./controlled-broker-client.js";
import type { RuntimeIdentity } from "./controlled-broker-client.js";

export type ApiRuntimeEvidence=Readonly<{
  ruleId:string;title:string;summary:string;remediation:string;limitation:string;
  severityEstimate:"info"|"low"|"medium";
  classification:"DETERMINISTIC_CONFIGURATION_SIGNAL"|"INCONCLUSIVE";
  evidenceSource:{paths:string[];fingerprints:string[];nodeIds:string[]};
}>;
export type ApiRuntimeResult=Readonly<{
  classification:"RUNTIME_API_REVIEW";
  requests:number;bytes:number;scopeHash:string;coverageState:"BOUNDED";
  limitations:string[];
  observations:readonly ApiRuntimeEvidence[];
  statuses:{anonymous:number;owner:number;other:number};
}>;
type Response=Awaited<ReturnType<ControlledBrokerClient["read"]>>;
export async function executeControlledApiRuntime(input:Readonly<{
  origin:string;scopeHash:string;client:ControlledBrokerClient;signal:AbortSignal;
}>):Promise<ApiRuntimeResult>{
  const path="/v1/accounts/owner";
  requireExactWebUrl(input.origin+path,input.origin);
  if(input.signal.aborted||!/^[0-9a-f]{64}$/.test(input.scopeHash))
    throw Error("API_RUNTIME_SCOPE_DENIED");
  const read=async (identity:RuntimeIdentity):Promise<Response>=>{
    if(input.signal.aborted)throw Error("API_RUNTIME_CANCELLED");
    return input.client.read(input.origin,input.origin+path,
      {signal:input.signal,maxBytes:30_000},identity);
  };
  // Exact same public endpoint and path under anonymous, owner and other
  // synthetic identities. Never display bearer credentials to this process.
  const anonymous=await read("anonymous");
  const owner=await read("owner");
  const other=await read("other");
  const records=[
    {identity:"anonymous",value:anonymous},
    {identity:"owner",value:owner},
    {identity:"other",value:other},
  ];
  const evidence=records.map(({identity,value})=>createHash("sha256")
    .update(JSON.stringify([input.scopeHash,identity,path,value.status,
      Object.fromEntries(Object.entries(value.headers)
        .filter(([k])=>["content-type","strict-transport-security",
          "x-content-type-options","x-frame-options"].includes(k)).sort())]))
    .digest("hex"));
  const shared={paths:[path],fingerprints:evidence,nodeIds:[
    "wdn_"+createHash("sha256").update(input.scopeHash+path).digest("hex").slice(0,24)]};
  const observations:ApiRuntimeEvidence[]=[];
  const push=(ruleId:string,title:string,summary:string,remediation:string,
    level:"info"|"low"|"medium",classification:ApiRuntimeEvidence["classification"])=>{
    observations.push({ruleId,title,summary,remediation,limitation:
      "Synthetic read-only response comparison; no confirmed exploit or generalizable authorization verdict.",
      severityEstimate:level,classification,evidenceSource:shared});
  };
  if(anonymous.status>=200&&anonymous.status<300&&owner.status>=200&&owner.status<300)
    push("API.RUNTIME.AUTH.ANON_SUCCESS","Anonymous protected-route response",
      "Controlled protected resource responded successfully without synthetic identity.",
      "Require server-side authentication for every protected object.", "medium","INCONCLUSIVE");
  if(owner.status>=200&&owner.status<300 && other.status>=200&&other.status<300)
    push("API.RUNTIME.AUTHZ.OTHER_SUCCESS","Synthetic cross-identity response",
      "The same controlled owner object responded successfully for the other synthetic identity.",
      "Enforce object ownership checks on every protected resource.",
      "medium","INCONCLUSIVE");
  if(!owner.headers["strict-transport-security"])
    push("API.RUNTIME.HEADER.HSTS_ABSENT","Missing HSTS response policy",
      "Controlled HTTPS resource did not return a Strict-Transport-Security header.",
      "Review and configure an appropriate HSTS policy.","low",
      "DETERMINISTIC_CONFIGURATION_SIGNAL");
  if(owner.headers["x-content-type-options"]!=="nosniff")
    push("API.RUNTIME.HEADER.NOSNIFF_ABSENT","Missing nosniff protection",
      "Controlled API resource did not return X-Content-Type-Options: nosniff.",
      "Add the nosniff response header.","low",
      "DETERMINISTIC_CONFIGURATION_SIGNAL");
  if(input.signal.aborted)throw Error("API_RUNTIME_CANCELLED");
  return {
    classification:"RUNTIME_API_REVIEW",scopeHash:input.scopeHash,
    coverageState:"BOUNDED",requests:input.client.metrics.requests,
    bytes:input.client.metrics.bytes,observations,
    statuses:{anonymous:anonymous.status,owner:owner.status,other:other.status},
    limitations:["Three bounded GET requests to one controlled object only.",
      "All identities and account content synthetic; no customer credentials.",
      "Successful responses are review signals, not proven data exposure.",
      "Not observed never proves general API security.",
      "Authentication and authorization policy inferred from explicit controlled fixture expectation."],
  };
}
