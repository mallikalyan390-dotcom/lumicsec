import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { requireGoogleAal2 } from "../lib/auth-guard.js";
import { createSupabaseForRequest } from "../lib/supabase.js";

const uuid=z.string().uuid();
const orgQuery=z.strictObject({organizationId:uuid});
const planQuery=orgQuery.extend({planId:uuid});
const safePath=z.string().min(1).max(120).regex(/^\/[a-zA-Z0-9._~/-]*$/);
const planCreate=z.strictObject({
  organizationId:uuid,assetId:uuid,requestId:uuid,
  profile:z.enum(["web_readonly","api_readonly"]),
  approvedPaths:z.array(safePath).min(1).max(6),
  expiresAt:z.iso.datetime({offset:true}),
  maxRequests:z.number().int().min(1).max(6),
  maxResponseBytes:z.number().int().min(1024).max(60000),
  maxTotalBytes:z.number().int().min(1024).max(240000),
  maxExecutionMs:z.number().int().min(1000).max(15000),
  authorizationReference:z.string().trim().min(12).max(140),
  authorization:z.literal("I_AM_AUTHORIZED_TO_PLAN_READONLY_ASSESSMENT_OF_THIS_OWNED_ASSET"),
}).strict().superRefine((value,ctx)=>{
  if(value.maxTotalBytes<value.maxResponseBytes)
    ctx.addIssue({code:"custom",message:"TOTAL_BYTES_LT_RESPONSE_BYTES"});
  if(new Set(value.approvedPaths).size!==value.approvedPaths.length)
    ctx.addIssue({code:"custom",message:"DUPLICATE_PATH"});
  if(value.approvedPaths.some(path=>
    path.includes("//")||/(^|\/)\.{1,2}(\/|$)/.test(path)||
    /(^|\/)(logout|delete|destroy|transfer|purchase|checkout|reset|token|secret|admin|signout)(\/|$)/i.test(path)))
    ctx.addIssue({code:"custom",message:"UNSAFE_APPROVED_PATH"});
  const until=Date.parse(value.expiresAt);
  if(!Number.isFinite(until)||until<=Date.now()+5*60*1000||until>Date.now()+24*60*60*1000)
    ctx.addIssue({code:"custom",message:"EXPIRY_MUST_BE_WITHIN_5_MINUTES_TO_24_HOURS"});
});
const revokeSchema=planQuery;
export const CUSTOMER_PUBLIC_RUNTIME_EXECUTION_ENABLED=false as const;
function statusForDatabase(code?:string){
  if(code==="42501"||code==="PGRST116")return 403;
  if(code==="22023"||code==="23514")return 400;
  if(code==="23505")return 409;
  return 503;
}

/** Database is canonical: RLS reads plus user-context signed AAL2 RPCs.
 * Plan creation does NOT enqueue, allocate, dispatch or execute a network job.
 */
export async function assessmentPlanRoutes(app:FastifyInstance){
  app.get("/v1/assessment-plans",{preHandler:requireGoogleAal2},async(req,reply)=>{
    reply.header("cache-control","private, no-store");
    const parsed=orgQuery.safeParse(req.query);
    if(!parsed.success)return reply.code(400).send({error:"INVALID_ORGANIZATION"});
    const client=createSupabaseForRequest(req,reply);
    if(!client)return reply.code(503).send({error:"AUTH_NOT_CONFIGURED"});
    const {data,error}=await client.from("assessment_plans")
      .select("id,organization_id,asset_id,created_by,revoked_by,asset_kind,exact_origin,approved_paths,http_method,safe_profile,max_requests,max_response_bytes,max_total_bytes,max_execution_ms,authorization_reference,proof_verified_at,proof_expires_at,scope_sha256,expires_at,plan_state,created_at,revoked_at")
      .eq("organization_id",parsed.data.organizationId)
      .order("created_at",{ascending:false}).limit(40);
    if(error)return reply.code(503).send({error:"PLANS_HISTORY_UNAVAILABLE"});
    return {plans:data??[],scanningEnabled:CUSTOMER_PUBLIC_RUNTIME_EXECUTION_ENABLED,
      executionAllowed:false,explanation:"Scope authorization is recorded, not an executable scanning grant."};
  });
  app.get("/v1/assessment-plans/events",{preHandler:requireGoogleAal2},async(req,reply)=>{
    reply.header("cache-control","private, no-store");
    const parsed=planQuery.safeParse(req.query);
    if(!parsed.success)return reply.code(400).send({error:"INVALID_PLAN"});
    const client=createSupabaseForRequest(req,reply);
    if(!client)return reply.code(503).send({error:"AUTH_NOT_CONFIGURED"});
    // Prove ownership of the requested plan before querying its separate history.
    const {data:plan,error:planError}=await client.from("assessment_plans")
      .select("id").eq("organization_id",parsed.data.organizationId)
      .eq("id",parsed.data.planId).single();
    if(planError||!plan)return reply.code(403).send({error:"PLAN_ACCESS_DENIED"});
    const {data,error}=await client.from("assessment_plan_events")
      .select("id,actor_id,event_type,details,created_at")
      .eq("organization_id",parsed.data.organizationId)
      .eq("plan_id",parsed.data.planId).order("created_at",{ascending:false}).limit(40);
    if(error)return reply.code(503).send({error:"PLAN_HISTORY_UNAVAILABLE"});
    return {events:data??[],scanningEnabled:false};
  });
  app.post("/v1/assessment-plans",{
    preHandler:requireGoogleAal2,config:{rateLimit:{max:5,timeWindow:"1 minute"}},
  },async(req,reply)=>{
    reply.header("cache-control","private, no-store");
    const parsed=planCreate.safeParse(req.body);
    if(!parsed.success)return reply.code(400).send({error:"INVALID_PLAN_SCOPE_OR_CONSENT"});
    const client=createSupabaseForRequest(req,reply);
    if(!client)return reply.code(503).send({error:"AUTH_NOT_CONFIGURED"});
    const {data:asset,error:assetError}=await client.from("assets")
      .select("id,organization_id,asset_kind,canonical_origin,verification_status,verified_at,verification_expires_at")
      .eq("organization_id",parsed.data.organizationId).eq("id",parsed.data.assetId).single();
    if(assetError||!asset)return reply.code(403).send({error:"ASSET_ACCESS_DENIED"});
    if(asset.asset_kind!==(parsed.data.profile==="web_readonly"?"website":"api")||
       asset.verification_status!=="verified"||!asset.verified_at||
       !asset.verification_expires_at||
       Date.parse(asset.verification_expires_at)<=Date.now()||
       Date.parse(parsed.data.expiresAt)>Date.parse(asset.verification_expires_at))
      return reply.code(409).send({error:"CURRENT_MATCHING_ASSET_PROOF_REQUIRED"});
    const {data,error}=await client.rpc("assessment_plan_create",{
      p_org:parsed.data.organizationId,p_asset:parsed.data.assetId,
      p_profile:parsed.data.profile,p_paths:parsed.data.approvedPaths,
      p_expires:parsed.data.expiresAt,p_requests:parsed.data.maxRequests,
      p_response_bytes:parsed.data.maxResponseBytes,p_total_bytes:parsed.data.maxTotalBytes,
      p_execution_ms:parsed.data.maxExecutionMs,p_reference:parsed.data.authorizationReference,
      p_request:parsed.data.requestId,
    });
    if(error||typeof data!=="string")
      return reply.code(statusForDatabase(error?.code)).send({error:"PLAN_AUTHORIZATION_DENIED"});
    return reply.code(201).send({planId:data,scanningEnabled:false,executionAllowed:false,
      explanation:"Saved scope and permission only. No scanning job was created."});
  });
  app.post("/v1/assessment-plans/revoke",{
    preHandler:requireGoogleAal2,config:{rateLimit:{max:10,timeWindow:"1 minute"}},
  },async(req,reply)=>{
    reply.header("cache-control","private, no-store");
    const parsed=revokeSchema.safeParse(req.body);
    if(!parsed.success)return reply.code(400).send({error:"INVALID_PLAN"});
    const client=createSupabaseForRequest(req,reply);
    if(!client)return reply.code(503).send({error:"AUTH_NOT_CONFIGURED"});
    const {data,error}=await client.rpc("assessment_plan_revoke",
      {p_org:parsed.data.organizationId,p_plan:parsed.data.planId});
    if(error||data!==true)return reply.code(statusForDatabase(error?.code))
      .send({error:"PLAN_REVOCATION_DENIED"});
    return {revoked:true,executionAllowed:false,scanningEnabled:false};
  });
  app.get("/v1/assessment-plans/check",{preHandler:requireGoogleAal2},async(req,reply)=>{
    reply.header("cache-control","private, no-store");
    const parsed=planQuery.safeParse(req.query);
    if(!parsed.success)return reply.code(400).send({error:"INVALID_PLAN"});
    const client=createSupabaseForRequest(req,reply);
    if(!client)return reply.code(503).send({error:"AUTH_NOT_CONFIGURED"});
    const {data,error}=await client.rpc("assessment_plan_check",
      {p_org:parsed.data.organizationId,p_plan:parsed.data.planId});
    if(error||!data)return reply.code(statusForDatabase(error?.code))
      .send({error:"PLAN_REVALIDATION_DENIED"});
    return {result:data};
  });
}
