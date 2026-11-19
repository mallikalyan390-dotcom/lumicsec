/* Strict versioned broker-worker IPC for controlled local fixtures ONLY. */
import {z} from "zod";
import { webIpcResultSchema, parseWebIpcResult, WEB_IPC_VERSION } from "./web-worker-ipc-contract.js";
const uuid=z.string().uuid();
const hex=z.string().regex(/^[a-f0-9]{64}$/);
export const CONTROLLED_RUNTIME_VERSION="CONTROLLED_RUNTIME_V1";
export const controlledStartSchema=z.strictObject({
  protocol:z.literal(CONTROLLED_RUNTIME_VERSION),type:z.literal("START"),
  executionId:uuid,mode:z.enum(["web","api"]),
  scope:z.strictObject({jobId:uuid,organizationId:uuid,assetId:uuid,
    actorId:uuid,origin:z.string().max(250).regex(/^https:\/\/[a-z0-9.-]+$/),
    scopeHash:hex}),
});
export type ControlledStart=z.infer<typeof controlledStartSchema>;
const evidenceSource=z.strictObject({
  paths:z.array(z.string().max(160).regex(/^\/(?!\/)[^?#]*$/)).min(1).max(3),
  fingerprints:z.array(hex).min(1).max(4),
  nodeIds:z.array(z.string().regex(/^wdn_[a-f0-9]{24}$/)).min(1).max(4),
});
const apiObservation=z.strictObject({
  ruleId:z.string().regex(/^API\.RUNTIME\.[A-Z0-9._-]{4,80}$/),
  title:z.string().min(1).max(240),summary:z.string().min(1).max(3000),
  remediation:z.string().min(1).max(2000),
  limitation:z.string().min(1).max(1000),
  classification:z.enum(["DETERMINISTIC_CONFIGURATION_SIGNAL","INCONCLUSIVE"]),
  severityEstimate:z.enum(["info","low","medium"]),
  evidenceSource,
});
const apiReport=z.strictObject({
  classification:z.literal("RUNTIME_API_REVIEW"),scopeHash:hex,
  coverageState:z.literal("BOUNDED"),
  requests:z.number().int().min(3).max(6),
  bytes:z.number().int().min(0).max(240_000),
  limitations:z.array(z.string().min(1).max(200)).min(1).max(8),
  statuses:z.strictObject({
    anonymous:z.number().int().min(100).max(599),
    owner:z.number().int().min(100).max(599),
    other:z.number().int().min(100).max(599),
  }),
});
export const controlledResultSchema=z.strictObject({
  protocol:z.literal(CONTROLLED_RUNTIME_VERSION),type:z.literal("RESULT"),
  executionId:uuid,jobId:uuid,scopeHash:hex,mode:z.enum(["web","api"]),
  report:z.union([webIpcResultSchema.shape.report,apiReport]),
  observations:z.array(z.union([webIpcResultSchema.shape.observations.element,apiObservation])).max(60),
});
export type ControlledResult=z.infer<typeof controlledResultSchema>;
export function controlledInputFromText(raw:string){
  if(Buffer.byteLength(raw)>2048)throw Error("CONTROLLED_INPUT_BOUNDS");
  return controlledStartSchema.parse(JSON.parse(raw) as unknown);
}
export function parseControlledResult(raw:string,start:ControlledStart):ControlledResult{
  if(Buffer.byteLength(raw)>120_000)throw Error("CONTROLLED_RESULT_BOUNDS");
  const result=controlledResultSchema.parse(JSON.parse(raw) as unknown);
  if(result.jobId!==start.scope.jobId||result.scopeHash!==start.scope.scopeHash||
    result.executionId!==start.executionId||result.mode!==start.mode||
    result.report.scopeHash!==start.scope.scopeHash)throw Error("CONTROLLED_RESULT_IDENTITY");
  if(start.mode==="web"){
    if(result.report.classification!=="PASSIVE_WEB_REVIEW")
      throw Error("CONTROLLED_WEB_CLASSIFICATION_DENIED");
    parseWebIpcResult(JSON.stringify({protocol:WEB_IPC_VERSION,type:"RESULT",
      executionId:start.executionId,jobId:start.scope.jobId,
      scopeHash:start.scope.scopeHash,
      report:result.report,observations:result.observations}),{
      protocol:WEB_IPC_VERSION,type:"START",executionId:start.executionId,
      scope:start.scope,fixture:"none",
    });
  }else{
    if(result.report.classification!=="RUNTIME_API_REVIEW"||
      result.report.requests!==3 || result.observations.some(o=>
        !o.ruleId.startsWith("API.RUNTIME.")||
        o.evidenceSource.fingerprints.length<1))
      throw Error("CONTROLLED_API_RESULT_DENIED");
  }
  return result;
}
