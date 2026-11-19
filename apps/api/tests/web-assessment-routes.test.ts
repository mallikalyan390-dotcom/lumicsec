import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { authorizedWebAssessmentRoutes, authorizedWebScope,
  PUBLIC_WEB_SCANNING_ENABLED } from "../src/routes/web-assessments.js";

const mocks = vi.hoisted(() => ({ user: null as unknown, trusted: null as unknown }));
vi.mock("../src/lib/supabase.js", () => ({ createSupabaseForRequest: () => mocks.user }));
vi.mock("../src/lib/trusted-supabase.js", () => ({ createTrustedSupabase: () => mocks.trusted }));
const ORG = "00000000-0000-4000-8000-000000000011";
const OTHER = "00000000-0000-4000-8000-000000000012";
const ASSET = "00000000-0000-4000-8000-000000000022";
const JOB = "00000000-0000-4000-8000-000000000044";
const USER = "00000000-0000-4000-8000-000000000033";
const consent = "I_HAVE_EXPLICIT_PERMISSION_TO_PASSIVELY_REVIEW_THIS_OWNED_WEBSITE";
const REQUEST = { organizationId: ORG, assetId: ASSET, requestId: JOB, authorization: consent };
function query(data: unknown, error: unknown = null) {
  const builder = {
    select: vi.fn(), eq: vi.fn(), order: vi.fn(), limit: vi.fn(), single: vi.fn(),
  };
  builder.select.mockReturnValue(builder);
  builder.eq.mockReturnValue(builder);
  builder.order.mockReturnValue(builder);
  builder.limit.mockResolvedValue({ data: Array.isArray(data) ? data : [], error });
  builder.single.mockResolvedValue({ data, error });
  return builder;
}
function userClient() {
  const jobs = query([{ id: JOB, job_state: "succeeded", organization_id: ORG }]);
  const observations = query([{ id: JOB, rule_id: "P09.HSTS.ABSENT", review_state: "review_required" }]);
  return {
    auth: {
      getUser: vi.fn().mockResolvedValue({ data: {
        user: { id: USER, app_metadata: { provider: "google" } } }, error: null }),
      getClaims: vi.fn().mockResolvedValue({ data: {
        claims: { aal: "aal2", amr: [{ method: "oauth" }, { method: "totp" }] } }, error: null }),
      mfa: { getAuthenticatorAssuranceLevel: vi.fn().mockResolvedValue({
        data: { currentLevel: "aal2", nextLevel: "aal2" }, error: null }) },
    },
    from: vi.fn((table: string) => table === "assessment_jobs" ? jobs : observations),
    jobs, observations,
  };
}
const running: Array<ReturnType<typeof Fastify>> = [];
async function server() {
  const app = Fastify({ logger: false });
  running.push(app);
  await app.register(cookie);
  await app.register(rateLimit);
  await app.register(authorizedWebAssessmentRoutes);
  return app;
}
let user: ReturnType<typeof userClient>;
let trusted: { rpc: ReturnType<typeof vi.fn> };
beforeEach(() => {
  user = userClient(); trusted = { rpc: vi.fn().mockResolvedValue({ data: true, error: null }) };
  mocks.user = user; mocks.trusted = trusted;
});
afterEach(async () => {
  await Promise.all(running.splice(0).map(app => app.close()));
  mocks.user = null; mocks.trusted = null;
});

describe("customer Web scanning is disabled, AAL2 and RLS remain enforced", () => {
  it("does not expose any public scanning enablement", () => {
    expect(PUBLIC_WEB_SCANNING_ENABLED).toBe(false);
  });
  it("refuses customer queue even with syntactically valid explicit consent", async () => {
    const app = await server();
    const result = await app.inject({ method: "POST", url: "/v1/assessments/web", payload: REQUEST });
    expect(result.statusCode).toBe(423);
    expect(result.json()).toMatchObject({ scanningEnabled: false,
      error: "CUSTOMER_WEB_EXECUTION_NOT_APPROVED" });
    expect(user.from).not.toHaveBeenCalled();
    expect(trusted.rpc).not.toHaveBeenCalled();
  });
  it("rejects absent consent before any privileged query", async () => {
    const app = await server();
    const result = await app.inject({ method: "POST", url: "/v1/assessments/web",
      payload: { ...REQUEST, authorization: null } });
    expect(result.statusCode).toBe(400);
    expect(trusted.rpc).not.toHaveBeenCalled();
  });
  it("requires AAL2 even for disabled endpoint and read-only history", async () => {
    user.auth.getClaims.mockResolvedValue({ data: { claims: { aal: "aal1",
      amr: [{ method: "oauth" }] } }, error: null });
    const app = await server();
    const results = await Promise.all([
      app.inject({ method: "POST", url: "/v1/assessments/web", payload: REQUEST }),
      app.inject({ method: "GET", url: "/v1/assessments/web?organizationId=" + ORG }),
      app.inject({ method: "GET", url: "/v1/assessments/web/observations?organizationId=" + ORG + "&jobId=" + JOB }),
    ]);
    expect(results.map(res => res.statusCode)).toEqual([403, 403, 403]);
    expect(user.from).not.toHaveBeenCalled();
  });
  it("non-Google AAL2 identity is denied", async () => {
    user.auth.getUser.mockResolvedValue({ data: {
      user: { id: USER, app_metadata: { provider: "email" } } }, error: null });
    const app = await server();
    const result = await app.inject({ method: "GET", url: "/v1/assessments/web?organizationId=" + ORG });
    expect(result.statusCode).toBe(403);
  });
  it("reads only tenant-filtered saved jobs under authenticated RLS", async () => {
    const app = await server();
    const result = await app.inject({ method: "GET", url: "/v1/assessments/web?organizationId=" + ORG });
    expect(result.statusCode).toBe(200);
    expect(result.json().jobs).toHaveLength(1);
    expect(result.json().scanningEnabled).toBe(false);
    expect(user.jobs.eq).toHaveBeenCalledWith("organization_id", ORG);
    expect(user.jobs.eq).toHaveBeenCalledWith("assessment_kind", "web_passive");
  });
  it("reads only organization and job-scoped evidence", async () => {
    const app = await server();
    const result = await app.inject({ method: "GET", url: "/v1/assessments/web/observations?organizationId="
      + ORG + "&jobId=" + JOB });
    expect(result.statusCode).toBe(200);
    expect(result.json().observations).toHaveLength(1);
    expect(user.observations.eq).toHaveBeenCalledWith("organization_id", ORG);
    expect(user.observations.eq).toHaveBeenCalledWith("job_id", JOB);
  });
  it("cross-tenant cancellation fails before trusted RPC", async () => {
    user.jobs.single.mockResolvedValue({ data: null, error: { code: "PGRST116" } });
    const app = await server();
    const result = await app.inject({ method: "POST", url: "/v1/assessments/web/cancel",
      payload: { organizationId: OTHER, jobId: JOB } });
    expect(result.statusCode).toBe(403);
    expect(trusted.rpc).not.toHaveBeenCalled();
  });
  it("cancel binds caller identity to AAL2 session and worker-token-less cancellation", async () => {
    const app = await server();
    const result = await app.inject({ method: "POST", url: "/v1/assessments/web/cancel",
      payload: { organizationId: ORG, jobId: JOB } });
    expect(result.statusCode).toBe(200);
    expect(trusted.rpc).toHaveBeenCalledWith("web_assessment_stop", {
      p_job: JOB, p_actor: USER, p_token: null, p_generation: null, p_failed: false,
    });
  });
  it("cannot cancel when trusted key is missing", async () => {
    mocks.trusted = null;
    const app = await server();
    const result = await app.inject({ method: "POST", url: "/v1/assessments/web/cancel",
      payload: { organizationId: ORG, jobId: JOB } });
    expect(result.statusCode).toBe(503);
  });
  it("server scope hash changes for any tenant, asset or origin change", () => {
    const origin = "https://fixture.example.net";
    const a = authorizedWebScope(ORG, ASSET, origin);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toBe(authorizedWebScope(OTHER, ASSET, origin));
    expect(a).not.toBe(authorizedWebScope(ORG, JOB, origin));
    expect(a).not.toBe(authorizedWebScope(ORG, ASSET, "https://another.example.net"));
  });
});
