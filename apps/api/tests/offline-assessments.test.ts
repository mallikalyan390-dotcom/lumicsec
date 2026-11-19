import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { boundedOfflineEvidence, deterministicOfflineScope, offlineAssessmentRoutes }
  from "../src/routes/offline-assessments.js";

const mocks = vi.hoisted(() => ({ user: null as unknown, trusted: null as unknown }));
vi.mock("../src/lib/supabase.js", () => ({ createSupabaseForRequest: () => mocks.user }));
vi.mock("../src/lib/trusted-supabase.js", () => ({ createTrustedSupabase: () => mocks.trusted }));
const ORG = "00000000-0000-4000-8000-000000000011";
const OTHER = "00000000-0000-4000-8000-000000000012";
const ASSET = "00000000-0000-4000-8000-000000000022";
const JOB = "00000000-0000-4000-8000-000000000044";
const ACTOR = "00000000-0000-4000-8000-000000000033";
const ORIGIN = "https://api.example.com";
const DOCUMENT = JSON.stringify({
  openapi: "3.1.0",
  info: { title: "Synthetic API fixture", version: "1.0" },
  paths: {
    "/pets": { get: { responses: { "200": { description: "OK" } } } },
    "/orders": { post: { responses: { "201": { description: "Created" } } } },
  },
});
const REQUEST = {
  organizationId: ORG, assetId: ASSET,
  content: DOCUMENT,
  filename: "synthetic-openapi.json",
  authorization: "I_AM_AUTHORIZED_FOR_OFFLINE_SPEC_REVIEW",
};

function builder(data: unknown, error: unknown = null) {
  const query = {
    select: vi.fn(), eq: vi.fn(), single: vi.fn(),
    order: vi.fn(), limit: vi.fn(),
  };
  query.select.mockReturnValue(query);
  query.eq.mockReturnValue(query);
  query.order.mockReturnValue(query);
  query.single.mockResolvedValue({ data, error });
  query.limit.mockResolvedValue({ data: Array.isArray(data) ? data : [], error });
  return query;
}
function client() {
  const assets = builder({
    id: ASSET, organization_id: ORG, asset_kind: "api", canonical_origin: ORIGIN,
    verification_status: "verified", verification_expires_at: "2099-01-01T00:00:00.000Z",
  });
  const jobs = builder([{ id: JOB, organization_id: ORG, job_state: "succeeded" }]);
  const observations = builder([{ id: JOB, rule_id: "AUTH_UNDECLARED", summary: "Spec only" }]);
  const queries = { assets, assessment_jobs: jobs, assessment_observations: observations };
  return {
    auth: {
      getUser: vi.fn().mockResolvedValue({
        data: { user: { id: ACTOR, app_metadata: { provider: "google" } } }, error: null,
      }),
      getClaims: vi.fn().mockResolvedValue({
        data: { claims: { aal: "aal2", amr: [{ method: "oauth" }, { method: "totp" }] } },
        error: null,
      }),
      mfa: { getAuthenticatorAssuranceLevel: vi.fn().mockResolvedValue({
        data: { currentLevel: "aal2", nextLevel: "aal2" }, error: null,
      }) },
    },
    from: vi.fn((table: keyof typeof queries) => queries[table]),
    queries,
  };
}
function trusted() {
  return {
    rpc: vi.fn(async (fn: string) => {
      if (fn === "assessment_api_offline_queue") return { data: JOB, error: null };
      if (fn === "assessment_api_offline_begin") return { data: true, error: null };
      if (fn === "assessment_api_offline_complete") return { data: true, error: null };
      if (fn === "assessment_api_offline_stop") return { data: true, error: null };
      return { data: null, error: { code: "PGRST202" } };
    }),
  };
}
const running: Array<ReturnType<typeof Fastify>> = [];
async function server() {
  const app = Fastify({ logger: false, bodyLimit: 1_200_000 });
  running.push(app);
  await app.register(cookie);
  await app.register(rateLimit);
  await app.register(offlineAssessmentRoutes);
  return app;
}
let userClient: ReturnType<typeof client>;
let service: ReturnType<typeof trusted>;
beforeEach(() => {
  userClient = client();
  service = trusted();
  mocks.user = userClient;
  mocks.trusted = service;
});
afterEach(async () => {
  await Promise.all(running.splice(0).map((instance) => instance.close()));
  vi.unstubAllGlobals();
  mocks.user = null;
  mocks.trusted = null;
});

describe("offline API assessment authorization and bounded job state", () => {
  it("requires explicit authorization even for an authenticated user", async () => {
    const app = await server();
    const result = await app.inject({
      method: "POST", url: "/v1/assessments/api-spec",
      payload: { ...REQUEST, authorization: false },
    });
    expect(result.statusCode).toBe(400);
    expect(userClient.from).not.toHaveBeenCalled();
    expect(service.rpc).not.toHaveBeenCalled();
  });

  it("rejects an AAL1 token before asset inspection and queueing", async () => {
    userClient.auth.getClaims.mockResolvedValue({
      data: { claims: { aal: "aal1", amr: [{ method: "oauth" }] } }, error: null,
    });
    const app = await server();
    const result = await app.inject({ method: "POST", url: "/v1/assessments/api-spec", payload: REQUEST });
    expect(result.statusCode).toBe(403);
    expect(userClient.from).not.toHaveBeenCalled();
    expect(service.rpc).not.toHaveBeenCalled();
  });

  it("fails closed when the backend-only service key is missing", async () => {
    mocks.trusted = null;
    const app = await server();
    const result = await app.inject({ method: "POST", url: "/v1/assessments/api-spec", payload: REQUEST });
    expect(result.statusCode).toBe(503);
    expect(result.json().error).toBe("TRUSTED_ASSESSMENT_BACKEND_NOT_CONFIGURED");
    expect(userClient.from).not.toHaveBeenCalled();
  });

  it("rejects RLS-denied cross-tenant access before the privileged RPC", async () => {
    userClient.queries.assets.single.mockResolvedValue({ data: null, error: { code: "PGRST116" } });
    const app = await server();
    const result = await app.inject({ method: "POST", url: "/v1/assessments/api-spec",
      payload: { ...REQUEST, organizationId: OTHER } });
    expect(result.statusCode).toBe(403);
    expect(service.rpc).not.toHaveBeenCalled();
  });

  it("rejects pending or expired ownership without calling an offline engine", async () => {
    userClient.queries.assets.single.mockResolvedValue({
      data: { asset_kind: "api", canonical_origin: ORIGIN, verification_status: "verified",
        verification_expires_at: "2020-01-01T00:00:00Z" }, error: null,
    });
    const app = await server();
    const result = await app.inject({ method: "POST", url: "/v1/assessments/api-spec", payload: REQUEST });
    expect(result.statusCode).toBe(409);
    expect(service.rpc).not.toHaveBeenCalled();
  });

  it("queues, re-authorizes execution and persists deterministic offline observations", async () => {
    const forbiddenNetwork = vi.fn(() => { throw Error("NETWORK_REQUEST_PROHIBITED"); });
    vi.stubGlobal("fetch", forbiddenNetwork);
    const app = await server();
    const result = await app.inject({ method: "POST", url: "/v1/assessments/api-spec", payload: REQUEST });
    expect(result.statusCode).toBe(201);
    expect(result.json()).toMatchObject({
      jobId: JOB, assetId: ASSET, organizationId: ORG,
      classification: "SPEC_ONLY", networkRequestsSent: 0, reviewRequired: true,
    });
    expect(result.json().operationCount).toBe(2);
    expect(service.rpc.mock.calls.map((call) => call[0])).toEqual([
      "assessment_api_offline_queue",
      "assessment_api_offline_begin",
      "assessment_api_offline_complete",
    ]);
    expect(service.rpc.mock.calls[0]?.[1]).toMatchObject({
      p_org: ORG, p_asset: ASSET, p_actor: ACTOR,
      p_scope: expect.stringMatching(/^[a-f0-9]{64}$/),
      p_fingerprint: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    expect(service.rpc.mock.calls[2]?.[1]).toMatchObject({
      p_job: JOB, p_actor: ACTOR,
      p_items: expect.any(Array),
      p_coverage: expect.objectContaining({ classification: "SPEC_ONLY", operationCount: 2 }),
    });
    expect(JSON.stringify(service.rpc.mock.calls)).not.toContain("Synthetic API fixture");
    expect(forbiddenNetwork).not.toHaveBeenCalled();
    expect(result.headers["cache-control"]).toBe("no-store");
  });

  it("a scheduling-time DB role denial is fail-closed", async () => {
    service.rpc.mockResolvedValueOnce({ data: null, error: { code: "42501" } });
    const app = await server();
    const response = await app.inject({ method: "POST", url: "/v1/assessments/api-spec", payload: REQUEST });
    expect(response.statusCode).toBe(403);
    expect(service.rpc).toHaveBeenCalledTimes(1);
  });

  it("an execution-time revocation prevents analysis results being committed", async () => {
    service.rpc.mockResolvedValueOnce({ data: JOB, error: null })
      .mockResolvedValueOnce({ data: false, error: null });
    const app = await server();
    const response = await app.inject({ method: "POST", url: "/v1/assessments/api-spec", payload: REQUEST });
    expect(response.statusCode).toBe(409);
    expect(service.rpc).toHaveBeenCalledTimes(2);
  });

  it("a result-time revocation blocks persistence", async () => {
    service.rpc.mockResolvedValueOnce({ data: JOB, error: null })
      .mockResolvedValueOnce({ data: true, error: null })
      .mockResolvedValueOnce({ data: false, error: null });
    const app = await server();
    const response = await app.inject({ method: "POST", url: "/v1/assessments/api-spec", payload: REQUEST });
    expect(response.statusCode).toBe(409);
    expect(response.json().error).toBe("ASSESSMENT_RESULT_COMMIT_REJECTED");
  });

  it("lists tenant history and observations only via RLS-filtered queries", async () => {
    const app = await server();
    const history = await app.inject({ method: "GET", url: "/v1/assessments/api-spec?organizationId=" + ORG });
    const findings = await app.inject({ method: "GET", url: "/v1/assessments/api-spec/observations?organizationId=" + ORG + "&jobId=" + JOB });
    expect(history.statusCode).toBe(200);
    expect(findings.statusCode).toBe(200);
    expect(history.json().jobs).toHaveLength(1);
    expect(findings.json().observations).toHaveLength(1);
    expect(userClient.queries.assessment_jobs.eq).toHaveBeenCalledWith("organization_id", ORG);
    expect(userClient.queries.assessment_observations.eq).toHaveBeenCalledWith("job_id", JOB);
  });

  it("cross-tenant cancellation is rejected before privileged stop", async () => {
    userClient.queries.assessment_jobs.single.mockResolvedValue({ data: null, error: { code: "PGRST116" } });
    const app = await server();
    const response = await app.inject({ method: "POST", url: "/v1/assessments/api-spec/cancel",
      payload: { organizationId: OTHER, jobId: JOB } });
    expect(response.statusCode).toBe(403);
    expect(service.rpc).not.toHaveBeenCalled();
  });

  it("cancellation always binds actor identity to the verified session", async () => {
    const app = await server();
    const response = await app.inject({ method: "POST", url: "/v1/assessments/api-spec/cancel",
      payload: { organizationId: ORG, jobId: JOB } });
    expect(response.statusCode).toBe(200);
    expect(service.rpc).toHaveBeenCalledWith("assessment_api_offline_stop", {
      p_job: JOB, p_actor: ACTOR, p_failed: false,
    });
  });
});

describe("offline evidence guardrails", () => {
  it("scope depends on exact tenant and canonical origin", () => {
    const a = deterministicOfflineScope(ORG, ASSET, ORIGIN, "a".repeat(64));
    expect(a).toMatch(/^[a-f0-9]{64}$/);
    expect(a).not.toBe(deterministicOfflineScope(OTHER, ASSET, ORIGIN, "a".repeat(64)));
    expect(a).not.toBe(deterministicOfflineScope(ORG, ASSET, "https://other.example.com", "a".repeat(64)));
  });

  it("caps persisted items and removes control bytes, keeping review metadata only", () => {
    const items = boundedOfflineEvidence(Array.from({ length: 105 }, (_, index) => ({
      ruleId: "TEST_" + index,
      explanation: "Review\nconfiguration",
      remediation: "Apply policy",
      impact: "HIGH",
    })));
    expect(items).toHaveLength(100);
    expect(items[0]).toMatchObject({
      severityEstimate: "high", summary: "Review configuration Suggested review: Apply policy",
    });
  });
});
