import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { assetVerificationRoutes } from "../src/routes/asset-verification.js";
import { organizationManagementRoutes } from "../src/routes/organization-management.js";

const mocks = vi.hoisted(() => ({ currentClient: null as unknown }));
vi.mock("../src/lib/supabase.js", () => ({
  createSupabaseForRequest: () => mocks.currentClient,
}));

const ORG = "00000000-0000-4000-8000-000000000011";
const ASSET = "00000000-0000-4000-8000-000000000022";
const USER = "00000000-0000-4000-8000-000000000033";
const CHALLENGE = "00000000-0000-4000-8000-000000000044";

function client() {
  const query = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockResolvedValue({ data: [], error: null }),
  };
  return {
    auth: {
      getUser: vi.fn().mockResolvedValue({
        data: { user: { id: USER, app_metadata: { provider: "google" } } }, error: null,
      }),
      getClaims: vi.fn().mockResolvedValue({
        data: { claims: { aal: "aal2", amr: [{ method: "oauth" }, { method: "totp" }] } },
        error: null,
      }),
      mfa: { getAuthenticatorAssuranceLevel: vi.fn().mockResolvedValue({
        data: { currentLevel: "aal2", nextLevel: "aal2" }, error: null,
      }) },
    },
    rpc: vi.fn().mockResolvedValue({ data: [], error: null }),
    from: vi.fn().mockReturnValue(query),
    query,
  };
}
let supabase: ReturnType<typeof client>;
const instances: Array<ReturnType<typeof Fastify>> = [];

async function server() {
  const app = Fastify({ logger: false });
  instances.push(app);
  await app.register(cookie);
  await app.register(rateLimit);
  await app.register(organizationManagementRoutes);
  await app.register(assetVerificationRoutes);
  return app;
}

describe("tenant RBAC and ownership routes require Google+TOTP AAL2", () => {
  beforeEach(() => {
    supabase = client();
    mocks.currentClient = supabase;
  });
  afterEach(async () => {
    await Promise.all(instances.splice(0).map((app) => app.close()));
    mocks.currentClient = null;
  });

  it("blocks AAL1 for org invitations, members and asset challenges before RPC", async () => {
    supabase.auth.getClaims.mockResolvedValue({
      data: { claims: { aal: "aal1", amr: [{ method: "oauth" }] } }, error: null,
    });
    const app = await server();
    const results = await Promise.all([
      app.inject({ method: "GET", url: "/v1/organizations/" + ORG + "/members" }),
      app.inject({ method: "POST", url: "/v1/organizations/" + ORG + "/invitations",
        payload: { email: "test@example.com", role: "member" } }),
      app.inject({ method: "POST", url: "/v1/assets/verification/challenges",
        payload: { organizationId: ORG, assetId: ASSET, method: "dns_txt" } }),
    ]);
    expect(results.map((r) => r.statusCode)).toEqual([403, 403, 403]);
    expect(supabase.rpc).not.toHaveBeenCalled();
  });

  it("denies non-Google identity despite AAL2", async () => {
    supabase.auth.getUser.mockResolvedValue({
      data: { user: { id: USER, app_metadata: { provider: "email", providers: ["google"] } } },
      error: null,
    });
    const app = await server();
    const response = await app.inject({ method: "GET", url: "/v1/organizations/" + ORG + "/members" });
    expect(response.statusCode).toBe(403);
    expect(supabase.rpc).not.toHaveBeenCalled();
  });

  it("returns manager's member list from the per-organization authorized RPC", async () => {
    supabase.rpc.mockResolvedValue({ data: [{
      user_id: USER, member_role: "owner", member_status: "active",
      member_email: "synthetic@example.invalid", joined_at: "2026-01-01T00:00:00Z",
    }], error: null });
    const app = await server();
    const response = await app.inject({ method: "GET", url: "/v1/organizations/" + ORG + "/members" });
    expect(response.statusCode).toBe(200);
    expect(response.json().members).toHaveLength(1);
    expect(supabase.rpc).toHaveBeenCalledWith("org_list_members", { p_org: ORG });
    expect(response.headers["cache-control"]).toBe("no-store");
  });

  it("fails closed on database-rejected cross-tenant member listing", async () => {
    supabase.rpc.mockResolvedValue({ data: null, error: { code: "42501" } });
    const app = await server();
    const response = await app.inject({ method: "GET", url: "/v1/organizations/" + ORG + "/members" });
    expect(response.statusCode).toBe(403);
  });

  it("returns a token only on an explicit, authorized invitation creation", async () => {
    const token = "b".repeat(64);
    supabase.rpc.mockResolvedValue({ data: [{
      invitation_id: CHALLENGE, invite_token: token, expires_at: "2026-12-01T00:00:00Z",
    }], error: null });
    const app = await server();
    const response = await app.inject({
      method: "POST", url: "/v1/organizations/" + ORG + "/invitations",
      payload: { email: "synthetic@example.invalid", role: "member" },
    });
    expect(response.statusCode).toBe(201);
    expect(response.json().invitation.invite_token).toBe(token);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(supabase.rpc).toHaveBeenCalledWith("org_issue_invite", {
      p_org: ORG, p_email: "synthetic@example.invalid", p_role: "member",
    });
  });

  it("rejects invalid invitations without invoking RPC", async () => {
    const app = await server();
    const response = await app.inject({
      method: "POST", url: "/v1/organizations/" + ORG + "/invitations",
      payload: { email: "not-an-email", role: "owner" },
    });
    expect(response.statusCode).toBe(400);
    expect(supabase.rpc).not.toHaveBeenCalled();
  });

  it("invitation acceptance requires a strict single-use-format token", async () => {
    const app = await server();
    const response = await app.inject({
      method: "POST", url: "/v1/organizations/invitations/accept",
      payload: { token: "a".repeat(63) },
    });
    expect(response.statusCode).toBe(400);
    expect(supabase.rpc).not.toHaveBeenCalled();
  });

  it("expires or email-rejects an invitation at the database boundary", async () => {
    supabase.rpc.mockResolvedValue({ data: null, error: { code: "42501" } });
    const app = await server();
    const response = await app.inject({
      method: "POST", url: "/v1/organizations/invitations/accept",
      payload: { token: "b".repeat(64) },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "INVITATION_INVALID_EXPIRED_OR_EMAIL_MISMATCH" });
  });

  it("issues a pending DNS challenge with scanning disabled", async () => {
    supabase.rpc.mockResolvedValue({ data: [{
      challenge_id: CHALLENGE, verification_token: "c".repeat(64),
      verification_host: "example.com", verification_path: "_lumicsec-challenge.example.com",
      expires_at: "2026-12-01T00:00:00Z",
    }], error: null });
    const app = await server();
    const response = await app.inject({
      method: "POST", url: "/v1/assets/verification/challenges",
      payload: { organizationId: ORG, assetId: ASSET, method: "dns_txt" },
    });
    expect(response.statusCode).toBe(201);
    expect(response.json().scanningEnabled).toBe(false);
    expect(supabase.rpc).toHaveBeenCalledWith("asset_issue_challenge", {
      p_org: ORG, p_asset: ASSET, p_method: "dns_txt",
    });
  });

  it("refuses an explicit proof-check attempt without trusted backend credentials", async () => {
    const app = await server();
    const response = await app.inject({
      method: "POST", url: "/v1/assets/verification/check",
      payload: { organizationId: ORG, assetId: ASSET, challengeId: CHALLENGE },
    });
    expect(response.statusCode).toBe(503);
    expect(response.json()).toEqual({ error: "TRUSTED_VERIFICATION_BACKEND_NOT_CONFIGURED" });
    expect(supabase.rpc).not.toHaveBeenCalled();
  });

  it("blocks a client-supplied proof override, even with a valid challenge ID", async () => {
    const app = await server();
    const response = await app.inject({
      method: "POST", url: "/v1/assets/verification/check",
      payload: { organizationId: ORG, assetId: ASSET, challengeId: CHALLENGE, token: "a".repeat(64) },
    });
    expect(response.statusCode).toBe(400);
    expect(supabase.rpc).not.toHaveBeenCalled();
  });

  it("revocation uses only the bound asset/org RPC and cannot start scanners", async () => {
    const app = await server();
    const response = await app.inject({
      method: "POST", url: "/v1/assets/verification/revoke",
      payload: { organizationId: ORG, assetId: ASSET },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ revoked: true, scanningEnabled: false });
    expect(supabase.rpc).toHaveBeenCalledWith("asset_revoke_ownership", {
      p_org: ORG, p_asset: ASSET,
    });
  });
});
