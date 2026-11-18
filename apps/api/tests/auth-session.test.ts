import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { env } from "../src/env.js";
import { authRoutes } from "../src/routes/auth.js";

const mocks = vi.hoisted(() => ({ currentClient: null as unknown }));
vi.mock("../src/lib/supabase.js", () => ({
  createSupabaseForRequest: () => mocks.currentClient,
  clearLumicSecCookie: (reply: { clearCookie: (name: string) => unknown }, name: string) => reply.clearCookie(name),
}));

const fixtureUser = {
  id: "synthetic-google-user",
  email: "synthetic@example.invalid",
  app_metadata: { provider: "google" },
};

function fakeClient() {
  return {
    auth: {
      getUser: vi.fn().mockResolvedValue({ data: { user: fixtureUser }, error: null }),
      getClaims: vi.fn().mockResolvedValue({
        data: { claims: { aal: "aal2", amr: [{ method: "oauth" }, { method: "totp" }] } }, error: null,
      }),
      mfa: {
        listFactors: vi.fn().mockResolvedValue({
          data: {
            all: [{ id: "verified-factor", factor_type: "totp", status: "verified" }],
            totp: [{ id: "verified-factor", factor_type: "totp", status: "verified" }],
          },
          error: null,
        }),
        getAuthenticatorAssuranceLevel: vi.fn().mockResolvedValue({
          data: { currentLevel: "aal2", nextLevel: "aal2" }, error: null,
        }),
      },
      signInWithOAuth: vi.fn().mockResolvedValue({
        data: { url: "https://accounts.google.com/o/oauth2/v2/auth?client_id=synthetic" }, error: null,
      }),
      exchangeCodeForSession: vi.fn().mockResolvedValue({ data: { user: fixtureUser }, error: null }),
      signOut: vi.fn().mockResolvedValue({ error: null }),
    },
  };
}

let provider: ReturnType<typeof fakeClient>;
const apps: Array<ReturnType<typeof Fastify>> = [];

async function app() {
  const instance = Fastify({ logger: false });
  apps.push(instance);
  await instance.register(cookie);
  await instance.register(rateLimit);
  await instance.register(authRoutes);
  return instance;
}

describe("Google OAuth callback and session regression (mock provider)", () => {
  beforeEach(() => {
    provider = fakeClient();
    mocks.currentClient = provider;
  });
  afterEach(async () => {
    await Promise.all(apps.splice(0).map((instance) => instance.close()));
    mocks.currentClient = null;
  });

  it("initiates only Google OAuth with its configured server callback URL", async () => {
    const instance = await app();
    const response = await instance.inject({ method: "GET", url: "/auth/google" });
    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toMatch(/^https:\/\/accounts\.google\.com\//);
    expect(provider.auth.signInWithOAuth).toHaveBeenCalledExactlyOnceWith({
      provider: "google",
      options: { redirectTo: new URL("/auth/callback", env.API_BASE_URL).toString() },
    });
  });

  it("exchanges a synthetic OAuth authorization code and redirects to the app", async () => {
    const instance = await app();
    const response = await instance.inject({
      method: "GET", url: "/auth/callback?code=synthetic-test-value",
    });
    expect(response.statusCode).toBe(302);
    expect(provider.auth.exchangeCodeForSession).toHaveBeenCalledExactlyOnceWith("synthetic-test-value");
    expect(response.headers.location).toBe(new URL("/app", env.APP_BASE_URL).toString());
  });

  it("rejects a failed OAuth callback without attempting code exchange", async () => {
    const instance = await app();
    const response = await instance.inject({
      method: "GET", url: "/auth/callback?error=access_denied",
    });
    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toContain("authError=oauth_callback_failed");
    expect(provider.auth.exchangeCodeForSession).not.toHaveBeenCalled();
  });

  it("does not open the workspace with a verified factor but an AAL1 session", async () => {
    provider.auth.getClaims.mockResolvedValue({
      data: { claims: { aal: "aal1", amr: [{ method: "oauth" }] } }, error: null,
    });
    provider.auth.mfa.getAuthenticatorAssuranceLevel.mockResolvedValue({
      data: { currentLevel: "aal1", nextLevel: "aal2" }, error: null,
    });
    const instance = await app();
    const response = await instance.inject({ method: "GET", url: "/auth/session" });
    expect(response.statusCode).toBe(200);
    expect(response.json().state).toBe("needs_challenge");
  });

  it("opens the workspace only with matching OAuth, TOTP and AAL2 claims", async () => {
    const instance = await app();
    const response = await instance.inject({ method: "GET", url: "/auth/session" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      configured: true, state: "authenticated", user: { id: fixtureUser.id },
    });
    expect(provider.auth.getClaims).toHaveBeenCalledOnce();
  });

  it("requires enrollment if no verified TOTP factor exists", async () => {
    provider.auth.mfa.listFactors.mockResolvedValue({ data: { all: [], totp: [] }, error: null });
    const instance = await app();
    const response = await instance.inject({ method: "GET", url: "/auth/session" });
    expect(response.json().state).toBe("needs_enrollment");
  });

  it("fails closed when assurance claims cannot be refreshed", async () => {
    provider.auth.getClaims.mockResolvedValue({ data: null, error: { code: "token_expired" } });
    const instance = await app();
    const response = await instance.inject({ method: "GET", url: "/auth/session" });
    expect(response.json().state).toBe("needs_challenge");
  });

  it("signs out a non-Google primary identity instead of authenticating it", async () => {
    provider.auth.getUser.mockResolvedValue({
      data: { user: { ...fixtureUser, app_metadata: { provider: "email" } } }, error: null,
    });
    const instance = await app();
    const response = await instance.inject({ method: "GET", url: "/auth/session" });
    expect(response.json().state).toBe("anonymous");
    expect(provider.auth.signOut).toHaveBeenCalledOnce();
  });

  it("logout revokes the Supabase session through the auth client", async () => {
    const instance = await app();
    const response = await instance.inject({
      method: "POST", url: "/auth/logout", headers: { cookie: "lumicsec_pending_totp=synthetic" },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ signedOut: true });
    expect(provider.auth.signOut).toHaveBeenCalledOnce();
    expect(String(response.headers["set-cookie"])).toContain("lumicsec_pending_totp=");
  });
});
