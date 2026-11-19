import Fastify from "fastify";
import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import {afterEach,beforeEach,describe,expect,it,vi} from "vitest";
import {assessmentPlanRoutes} from "../src/routes/assessment-plans.js";

const mocks=vi.hoisted(()=>({client:null as unknown}));
vi.mock("../src/lib/supabase.js",()=>({
  createSupabaseForRequest:()=>mocks.client,
}));
const ORG="00000000-0000-4000-8000-000000000011";
const ASSET="00000000-0000-4000-8000-000000000022";
const USER="00000000-0000-4000-8000-000000000033";
const PLAN="00000000-0000-4000-8000-000000000044";
const now=()=>new Date(Date.now()+60*60*1000).toISOString();
const valid=()=>({
  organizationId:ORG,assetId:ASSET,requestId:crypto.randomUUID(),
  profile:"web_readonly",approvedPaths:["/","/health"],
  expiresAt:now(),maxRequests:3,maxResponseBytes:60000,
  maxTotalBytes:240000,maxExecutionMs:15000,
  authorizationReference:"TEST-ONLY-WRITTEN-APPROVAL-2026",
  authorization:"I_AM_AUTHORIZED_TO_PLAN_READONLY_ASSESSMENT_OF_THIS_OWNED_ASSET",
});
function client(){
  const asset={
    id:ASSET,organization_id:ORG,asset_kind:"website",
    canonical_origin:"https://owned.example.com",verification_status:"verified",
    verified_at:new Date(Date.now()-3600000).toISOString(),
    verification_expires_at:new Date(Date.now()+2*86400000).toISOString(),
  };
  const table=(name:string)=>{
    const query={
      select:vi.fn().mockReturnThis(),eq:vi.fn().mockReturnThis(),
      order:vi.fn().mockReturnThis(),
      limit:vi.fn().mockResolvedValue({data:[],error:null}),
      single:vi.fn().mockResolvedValue({data:name==="assets"?asset:
        {id:PLAN},error:null}),
    };
    return query;
  };
  return {
    asset, auth:{
      getUser:vi.fn().mockResolvedValue({data:{user:{
        id:USER,app_metadata:{provider:"google"}}},error:null}),
      getClaims:vi.fn().mockResolvedValue({data:{claims:{
        aal:"aal2",amr:[{method:"oauth"},{method:"totp"}]}},error:null}),
      mfa:{getAuthenticatorAssuranceLevel:vi.fn().mockResolvedValue({
        data:{currentLevel:"aal2",nextLevel:"aal2"},error:null})},
    },
    rpc:vi.fn().mockImplementation(async(name:string)=>({
      data:name==="assessment_plan_create"?PLAN:
        name==="assessment_plan_check"?
        {eligibility:"ELIGIBLE_FOR_FUTURE_REVIEW",executionAllowed:false,
          publicScanningEnabled:false}:true,error:null,
    })),
    from:vi.fn().mockImplementation(table),
  };
}
type Client=ReturnType<typeof client>;
let db:Client;
const servers:Array<ReturnType<typeof Fastify>>=[];
async function app(){
  const instance=Fastify({logger:false});
  servers.push(instance);
  await instance.register(cookie);
  await instance.register(rateLimit);
  await instance.register(assessmentPlanRoutes);
  return instance;
}
describe("AAL2-bound tenant runtime plan API with customer execution disabled",()=>{
  beforeEach(()=>{db=client();mocks.client=db;});
  afterEach(async()=>{
    await Promise.all(servers.splice(0).map(s=>s.close()));
    mocks.client=null;
  });
  it("rejects AAL1 for creating, listing and revoking plans before database",async()=>{
    db.auth.getClaims.mockResolvedValue({data:{claims:{aal:"aal1",
      amr:[{method:"oauth"}]}},error:null});
    const s=await app();
    const results=await Promise.all([
      s.inject({method:"POST",url:"/v1/assessment-plans",payload:valid()}),
      s.inject({method:"GET",url:"/v1/assessment-plans?organizationId="+ORG}),
      s.inject({method:"POST",url:"/v1/assessment-plans/revoke",
        payload:{organizationId:ORG,planId:PLAN}}),
    ]);
    expect(results.map(r=>r.statusCode)).toEqual([403,403,403]);
    expect(db.from).not.toHaveBeenCalled();
    expect(db.rpc).not.toHaveBeenCalled();
  });
  it("rejects AAL2 user without Google primary identity",async()=>{
    db.auth.getUser.mockResolvedValue({data:{user:{id:USER,
      app_metadata:{provider:"email",providers:["google"]}}},error:null});
    const s=await app();
    const result=await s.inject({method:"POST",url:"/v1/assessment-plans",payload:valid()});
    expect(result.statusCode).toBe(403);
    expect(db.rpc).not.toHaveBeenCalled();
  });
  it("creates exact bounded plan with signed user-context RPC and no scan",async()=>{
    const s=await app();const body=valid();
    const response=await s.inject({method:"POST",url:"/v1/assessment-plans",payload:body});
    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({planId:PLAN,scanningEnabled:false,
      executionAllowed:false,
      explanation:"Saved scope and permission only. No scanning job was created."});
    expect(db.rpc).toHaveBeenCalledWith("assessment_plan_create",{
      p_org:ORG,p_asset:ASSET,p_profile:"web_readonly",p_paths:body.approvedPaths,
      p_expires:body.expiresAt,p_requests:3,p_response_bytes:60000,
      p_total_bytes:240000,p_execution_ms:15000,
      p_reference:body.authorizationReference,p_request:body.requestId,
    });
    expect(response.headers["cache-control"]).toBe("private, no-store");
  });
  it.each([
    {approvedPaths:["/../../private"]},
    {approvedPaths:["/health?token=a"]},
    {approvedPaths:["//169.254.169.254"]},
    {approvedPaths:["/logout"]},
    {approvedPaths:["/api/logout"]},
    {approvedPaths:["/safe","/safe"]},
    {approvedPaths:Array(7).fill("/safe")},
    {maxRequests:7},
    {maxExecutionMs:16000},
    {maxTotalBytes:1000},
    {maxResponseBytes:90000},
    {authorization:"OWNERSHIP_ONLY"},
    {authorizationReference:"too short"},
    {expiresAt:new Date(Date.now()+2*86400000).toISOString()},
    {expiresAt:new Date(Date.now()-10000).toISOString()},
    {organizationId:"INJECTED"},
    {profile:"arbitrary"},
    {unexpected:"external_scan_enable"},
  ])("rejects malicious/invalid plan input at boundary %#",async mutation=>{
    const s=await app();
    const response=await s.inject({method:"POST",url:"/v1/assessment-plans",
      payload:{...valid(),...mutation}});
    expect(response.statusCode).toBe(400);
    expect(db.rpc).not.toHaveBeenCalled();
  });
  it("rejects unverified, revoked and expired proof before authorization",async()=>{
    const s=await app();
    for(const verification_status of ["pending","revoked","verified"]){
      db.asset.verification_status=verification_status;
      if(verification_status==="verified")
        db.asset.verification_expires_at=new Date(Date.now()-1000).toISOString();
      const response=await s.inject({method:"POST",url:"/v1/assessment-plans",
        payload:valid()});
      expect(response.statusCode).toBe(409);
    }
    expect(db.rpc).not.toHaveBeenCalled();
  });
  it("fails closed on asset kind mismatch and proof window narrower than consent",async()=>{
    const s=await app();
    db.asset.asset_kind="api";
    expect((await s.inject({method:"POST",url:"/v1/assessment-plans",
      payload:valid()})).statusCode).toBe(409);
    db.asset.asset_kind="website";
    db.asset.verification_expires_at=new Date(Date.now()+20*60*1000).toISOString();
    expect((await s.inject({method:"POST",url:"/v1/assessment-plans",
      payload:valid()})).statusCode).toBe(409);
  });
  it("denies invisible cross-tenant asset early",async()=>{
    const s=await app();
    db.from.mockImplementation(()=>({
      select:vi.fn().mockReturnThis(),eq:vi.fn().mockReturnThis(),
      single:vi.fn().mockResolvedValue({data:null,error:{code:"PGRST116"}}),
    }));
    const response=await s.inject({method:"POST",url:"/v1/assessment-plans",
      payload:valid()});
    expect(response.statusCode).toBe(403);expect(db.rpc).not.toHaveBeenCalled();
  });
  it("does not bypass database authorization when analyst or viewer attempts cross-tenant changes",async()=>{
    db.rpc.mockResolvedValue({data:null,error:{code:"42501"}});
    const s=await app();
    const create=await s.inject({method:"POST",url:"/v1/assessment-plans",payload:valid()});
    const revoke=await s.inject({method:"POST",url:"/v1/assessment-plans/revoke",
      payload:{organizationId:ORG,planId:PLAN}});
    expect(create.statusCode).toBe(403);expect(revoke.statusCode).toBe(403);
  });
  it("returns bounded read-only history with public scan permanently false",async()=>{
    const s=await app();
    const response=await s.inject({method:"GET",url:"/v1/assessment-plans?organizationId="+ORG});
    expect(response.statusCode).toBe(200);
    expect(response.json().executionAllowed).toBe(false);
    expect(response.json().scanningEnabled).toBe(false);
    expect(db.from).toHaveBeenCalledWith("assessment_plans");
  });
  it("checks current revocation/ownership in DB but does not authorize execution",async()=>{
    const s=await app();
    const r=await s.inject({method:"GET",url:"/v1/assessment-plans/check?organizationId="+ORG+"&planId="+PLAN});
    expect(r.statusCode).toBe(200);
    expect(r.json().result.executionAllowed).toBe(false);
    expect(db.rpc).toHaveBeenCalledWith("assessment_plan_check",
      {p_org:ORG,p_plan:PLAN});
  });
  it("revokes the exact tenant plan using signed database RPC; no network job",async()=>{
    const s=await app();
    const response=await s.inject({method:"POST",url:"/v1/assessment-plans/revoke",
      payload:{organizationId:ORG,planId:PLAN}});
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({revoked:true,executionAllowed:false});
    expect(db.rpc).toHaveBeenCalledWith("assessment_plan_revoke",
      {p_org:ORG,p_plan:PLAN});
  });
  it("plan audit is scoped by the plan visibility check",async()=>{
    const s=await app();
    const response=await s.inject({method:"GET",
      url:"/v1/assessment-plans/events?organizationId="+ORG+"&planId="+PLAN});
    expect(response.statusCode).toBe(200);
    expect(db.from).toHaveBeenCalledWith("assessment_plan_events");
  });
  it("plan audit denies invisible plan without reading audit rows",async()=>{
    db.from.mockImplementation((table:string)=>({
      select:vi.fn().mockReturnThis(),eq:vi.fn().mockReturnThis(),
      single:vi.fn().mockResolvedValue({data:table==="assessment_plans"?null:{id:PLAN},
        error:table==="assessment_plans"?{code:"PGRST116"}:null}),
    }));
    const s=await app();
    const response=await s.inject({method:"GET",
      url:"/v1/assessment-plans/events?organizationId="+ORG+"&planId="+PLAN});
    expect(response.statusCode).toBe(403);
    expect(db.from).not.toHaveBeenCalledWith("assessment_plan_events");
  });
  it("signed tenant plan history returns bounded public-safe fixture job fields only",async()=>{
    const s=await app();
    const response=await s.inject({method:"GET",
      url:"/v1/assessment-plans/executions?organizationId="+ORG+"&planId="+PLAN});
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({executions:[],scanningEnabled:false,
      executionAllowed:false});
    expect(db.from).toHaveBeenCalledWith("assessment_plan_executions");
    expect(response.headers["cache-control"]).toBe("private, no-store");
  });
  it("denies cross-tenant execution history before touching execution table",async()=>{
    db.from.mockImplementation((table:string)=>({
      select:vi.fn().mockReturnThis(),eq:vi.fn().mockReturnThis(),
      single:vi.fn().mockResolvedValue({data:table==="assessment_plans"?null:{id:PLAN},
        error:table==="assessment_plans"?{code:"PGRST116"}:null}),
    }));
    const s=await app();
    const response=await s.inject({method:"GET",
      url:"/v1/assessment-plans/executions?organizationId="+ORG+"&planId="+PLAN});
    expect(response.statusCode).toBe(403);
    expect(db.from).not.toHaveBeenCalledWith("assessment_plan_executions");
  });
  it("denies AAL1 plan execution history before database access",async()=>{
    db.auth.getClaims.mockResolvedValue({data:{claims:{aal:"aal1",
      amr:[{method:"oauth"}]}},error:null});
    const s=await app();
    const response=await s.inject({method:"GET",
      url:"/v1/assessment-plans/executions?organizationId="+ORG+"&planId="+PLAN});
    expect(response.statusCode).toBe(403);
    expect(db.from).not.toHaveBeenCalled();
  });
  it("no customer execute endpoint exists; preexisting public Web scan stays disabled",async()=>{
    const s=await app();
    expect((await s.inject({method:"POST",url:"/v1/assessment-plans/execute",
      payload:{organizationId:ORG,planId:PLAN}})).statusCode).toBe(404);
  });
});
