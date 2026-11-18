import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { authRoutes } from "../src/routes/auth.js";
import { customerWorkspaceRoutes } from "../src/routes/customer-workspace.js";

const mocks = vi.hoisted(() => ({ currentClient: null as unknown }));
vi.mock("../src/lib/supabase.js", () => ({
  createSupabaseForRequest: () => mocks.currentClient,
  clearLumicSecCookie: (reply: { clearCookie: (name: string) => unknown }, name: string) => reply.clearCookie(name),
}));

const qr = 'data:image/svg+xml;utf-8,<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>';
const pending = { id: "pending", status: "unverified", factor_type: "totp", friendly_name: "LumicSec Authenticator 1234" };
const verified = { id: "existing-verified", status: "verified", factor_type: "totp", friendly_name: "LumicSec Authenticator backup" };
const other = { id: "other", status: "unverified", factor_type: "totp", friendly_name: "Another service" };

function client() {
  return {
    from: vi.fn(),
    auth: {
      getClaims: vi.fn().mockResolvedValue({
        data: { claims: { aal: "aal2", amr: [{ method: "oauth" }, { method: "totp" }] } }, error: null,
      }),
      getUser: vi.fn().mockResolvedValue({
        data: { user: { id: "test-user", app_metadata: { provider: "google" } } },
        error: null,
      }),
      mfa: {
        listFactors: vi.fn().mockResolvedValue({ data: { all: [pending, other], totp: [] }, error: null }),
        getAuthenticatorAssuranceLevel: vi.fn().mockResolvedValue({
          data: { currentLevel: "aal2", nextLevel: "aal2" }, error: null,
        }),
        enroll: vi.fn().mockResolvedValue({
          data: { id: "new-pending", totp: { qr_code: qr, secret: "SYNTHETIC_TEST_ONLY_BASE32_KEY" } },
          error: null,
        }),
        unenroll: vi.fn().mockResolvedValue({ data: {}, error: null }),
        challenge: vi.fn().mockResolvedValue({ data: { id: "challenge" }, error: null }),
        verify: vi.fn().mockResolvedValue({ data: {}, error: null }),
      },
    },
  };
}

const apps: Array<ReturnType<typeof Fastify>> = [];
let supabase: ReturnType<typeof client>;

async function app() {
  const instance = Fastify({ logger: false });
  apps.push(instance);
  await instance.register(cookie);
  await instance.register(rateLimit);
  await instance.register(authRoutes);
  await instance.register(customerWorkspaceRoutes);
  return instance;
}

describe("Google TOTP MFA API regression", () => {
  beforeEach(() => {
    supabase = client();
    mocks.currentClient = supabase;
  });
  afterEach(async () => {
    await Promise.all(apps.splice(0).map((instance) => instance.close()));
    mocks.currentClient = null;
  });

  it("returns only verified factor labels to an AAL2 Google/TOTP session", async () => {
    supabase.auth.mfa.listFactors.mockResolvedValue({
      data: { all: [pending, verified, other], totp: [verified] }, error: null,
    });
    const instance = await app();
    const response = await instance.inject({ method: "GET", url: "/auth/mfa/factors" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ verifiedTotpFactors: [
      { id: "existing-verified", friendlyName: "LumicSec Authenticator backup" },
    ] });
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(supabase.auth.mfa.unenroll).not.toHaveBeenCalled();
  });

  it("denies AAL1 factor inventory and never calls listFactors", async () => {
    supabase.auth.getClaims.mockResolvedValue({
      data: { claims: { aal: "aal1", amr: [{ method: "oauth" }] } }, error: null,
    });
    const instance = await app();
    const response = await instance.inject({ method: "GET", url: "/auth/mfa/factors" });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "AAL2_REQUIRED" });
    expect(supabase.auth.mfa.listFactors).not.toHaveBeenCalled();
  });

  it("denies non-Google primary identity access to factor inventory", async () => {
    supabase.auth.getUser.mockResolvedValue({
      data: { user: { id: "test-user", app_metadata: { provider: "email", providers: ["google", "email"] } } },
      error: null,
    });
    const instance = await app();
    const response = await instance.inject({ method: "GET", url: "/auth/mfa/factors" });
    expect(response.statusCode).toBe(401);
    expect(supabase.auth.mfa.listFactors).not.toHaveBeenCalled();
  });

  it("fails closed when factor-inventory JWT verification fails", async () => {
    supabase.auth.getClaims.mockResolvedValue({ data: null, error: { code: "token_expired" } });
    const instance = await app();
    const response = await instance.inject({ method: "GET", url: "/auth/mfa/factors" });
    expect(response.statusCode).toBe(401);
    expect(supabase.auth.mfa.listFactors).not.toHaveBeenCalled();
  });

  it("does not enroll a backup with a forged AAL2 claim missing TOTP proof", async () => {
    supabase.auth.mfa.listFactors.mockResolvedValue({
      data: { all: [verified], totp: [verified] }, error: null,
    });
    supabase.auth.getClaims.mockResolvedValue({
      data: { claims: { aal: "aal2", amr: [{ method: "oauth" }] } }, error: null,
    });
    const instance = await app();
    const response = await instance.inject({ method: "POST", url: "/auth/mfa/enroll", payload: {} });
    expect(response.statusCode).toBe(403);
    expect(supabase.auth.mfa.enroll).not.toHaveBeenCalled();
    expect(supabase.auth.mfa.unenroll).not.toHaveBeenCalled();
  });

  it("rotates only own unverified factor before a fresh enrollment", async () => {
    const instance = await app();
    const result = await instance.inject({ method: "POST", url: "/auth/mfa/enroll", payload: {} });
    expect(result.statusCode).toBe(200);
    expect(result.json().qrCodeSvg).toMatch(/^data:image\/svg\+xml;charset=utf-8,/);
    expect(result.headers["cache-control"]).toBe("no-store");
    expect(String(result.headers["set-cookie"])).toContain("lumicsec_pending_totp=new-pending");
    expect(supabase.auth.mfa.unenroll).toHaveBeenCalledExactlyOnceWith({ factorId: "pending" });
  });

  it("blocks additional enrollment at AAL1 if a verified factor exists", async () => {
    supabase.auth.mfa.listFactors.mockResolvedValue({
      data: { all: [pending, verified], totp: [verified] }, error: null,
    });
    supabase.auth.mfa.getAuthenticatorAssuranceLevel.mockResolvedValue({
      data: { currentLevel: "aal1", nextLevel: "aal2" }, error: null,
    });
    const instance = await app();
    const result = await instance.inject({ method: "POST", url: "/auth/mfa/enroll", payload: {} });
    expect(result.statusCode).toBe(403);
    expect(supabase.auth.mfa.unenroll).not.toHaveBeenCalled();
    expect(supabase.auth.mfa.enroll).not.toHaveBeenCalled();
  });

  it("does not create a new factor if abandoned-factor cleanup fails", async () => {
    supabase.auth.mfa.unenroll.mockResolvedValue({ data: null, error: { code: "cleanup_failed" } });
    const instance = await app();
    const result = await instance.inject({ method: "POST", url: "/auth/mfa/enroll", payload: {} });
    expect(result.statusCode).toBe(503);
    expect(supabase.auth.mfa.enroll).not.toHaveBeenCalled();
  });

  it("renders a PNG from a synthetic TOTP secret even when provider SVG is rejected", async () => {
    supabase.auth.mfa.listFactors.mockResolvedValue({ data: { all: [], totp: [] }, error: null });
    supabase.auth.mfa.enroll.mockResolvedValue({
      data: { id: "new-pending", totp: { qr_code: "INVALID_SVG_FIXTURE", secret: "JBSWY3DPEHPK3PXP" } },
      error: null,
    });
    const instance = await app();
    const response = await instance.inject({ method: "POST", url: "/auth/mfa/enroll", payload: {} });
    expect(response.statusCode).toBe(200);
    expect(response.json().qrCodeSvg).toBeNull();
    expect(response.json().qrCodePng).toMatch(/^data:image\/png;base64,/);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(supabase.auth.mfa.unenroll).not.toHaveBeenCalled();
  });

  it("continues the same pending enrollment with manual key for an unsafe QR", async () => {
    supabase.auth.mfa.listFactors.mockResolvedValue({ data: { all: [], totp: [] }, error: null });
    supabase.auth.mfa.enroll.mockResolvedValue({
      data: { id: "new-pending", totp: { qr_code: "data:text/html,<svg></svg>", secret: "SYNTHETIC_TEST_ONLY_BASE32_KEY" } },
      error: null,
    });
    const instance = await app();
    const result = await instance.inject({ method: "POST", url: "/auth/mfa/enroll", payload: {} });
    expect(result.statusCode).toBe(200);
    expect(result.json()).toEqual({
      qrCodePng: null, qrCodeSvg: null, secret: "SYNTHETIC_TEST_ONLY_BASE32_KEY",
    });
    expect(result.headers["cache-control"]).toBe("no-store");
    expect(String(result.headers["set-cookie"])).toContain("lumicsec_pending_totp=new-pending");
    expect(supabase.auth.mfa.unenroll).not.toHaveBeenCalled();
  });

  it("accepts a multiline XML-prefixed SVG in the real enrollment route", async () => {
    const multiline = 'data:image/svg+xml;utf-8,<?xml version="1.0"?>\n'
      + '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 90 90">\n'
      + '<path d="M0 0 h20 v20 H0 z" fill="#000"/>\n</svg>';
    supabase.auth.mfa.listFactors.mockResolvedValue({ data: { all: [], totp: [] }, error: null });
    supabase.auth.mfa.enroll.mockResolvedValue({
      data: { id: "new-pending", totp: { qr_code: multiline, secret: "SYNTHETIC_TEST_ONLY_BASE32_KEY" } }, error: null,
    });
    const instance = await app();
    const result = await instance.inject({ method: "POST", url: "/auth/mfa/enroll", payload: {} });
    expect(result.statusCode).toBe(200);
    expect(result.json().qrCodeSvg?.startsWith("data:image/svg+xml;charset=utf-8,")).toBe(true);
    expect(supabase.auth.mfa.unenroll).not.toHaveBeenCalled();
  });

  it("continues enrollment with manual key when Supabase QR is missing", async () => {
    supabase.auth.mfa.listFactors.mockResolvedValue({ data: { all: [], totp: [] }, error: null });
    supabase.auth.mfa.enroll.mockResolvedValue({
      data: { id: "new-pending", totp: { qr_code: null, secret: "SYNTHETIC_TEST_ONLY_BASE32_KEY" } },
      error: null,
    });
    const instance = await app();
    const result = await instance.inject({ method: "POST", url: "/auth/mfa/enroll", payload: {} });
    expect(result.statusCode).toBe(200);
    expect(result.json().qrCodeSvg).toBeNull();
    expect(supabase.auth.mfa.unenroll).not.toHaveBeenCalled();
  });

  it("rejects unusable enrollment secrets without exposing a TOTP factor", async () => {
    supabase.auth.mfa.listFactors.mockResolvedValue({ data: { all: [], totp: [] }, error: null });
    supabase.auth.mfa.enroll.mockResolvedValue({
      data: { id: "new-pending", totp: { qr_code: qr, secret: "" } },
      error: null,
    });
    const instance = await app();
    const result = await instance.inject({ method: "POST", url: "/auth/mfa/enroll", payload: {} });
    expect(result.statusCode).toBe(400);
    expect(result.json()).toEqual({ error: "TOTP_ENROLLMENT_FAILED" });
    expect(String(result.headers["set-cookie"] ?? "")).not.toContain("new-pending");
  });

  it("completes manual fallback enrollment, challenge and AAL2 in one controlled flow", async () => {
    supabase.auth.mfa.listFactors
      .mockResolvedValueOnce({ data: { all: [], totp: [] }, error: null })
      .mockResolvedValueOnce({
        data: {
          all: [{
            id: "new-pending", status: "unverified", factor_type: "totp",
            friendly_name: "LumicSec Authenticator test-only",
          }],
          totp: [],
        },
        error: null,
      });
    supabase.auth.mfa.enroll.mockResolvedValue({
      data: {
        id: "new-pending",
        totp: { qr_code: "data:text/html,unsafe-qr", secret: "SYNTHETIC_TEST_ONLY_BASE32_KEY" },
      },
      error: null,
    });
    const instance = await app();
    const setup = await instance.inject({ method: "POST", url: "/auth/mfa/enroll", payload: {} });
    expect(setup.statusCode).toBe(200);
    expect(setup.json().qrCodeSvg).toBeNull();
    const verification = await instance.inject({
      method: "POST", url: "/auth/mfa/verify",
      headers: { cookie: "lumicsec_pending_totp=new-pending" }, payload: { code: "123456" },
    });
    expect(verification.statusCode).toBe(200);
    expect(verification.json()).toEqual({ verified: true, assuranceLevel: "aal2" });
    expect(supabase.auth.mfa.challenge).toHaveBeenCalledWith({ factorId: "new-pending" });
    expect(supabase.auth.mfa.verify).toHaveBeenCalledWith({
      factorId: "new-pending", challengeId: "challenge", code: "123456",
    });
    expect(supabase.auth.mfa.unenroll).not.toHaveBeenCalled();
  });

  it("preserves an existing verified factor even if a new backup QR is unusable", async () => {
    supabase.auth.mfa.listFactors.mockResolvedValue({
      data: { all: [verified], totp: [verified] }, error: null,
    });
    supabase.auth.mfa.enroll.mockResolvedValue({
      data: {
        id: "new-pending",
        totp: { qr_code: "data:text/html,unsupported", secret: "SYNTHETIC_TEST_ONLY_BASE32_KEY" },
      },
      error: null,
    });
    const instance = await app();
    const result = await instance.inject({ method: "POST", url: "/auth/mfa/enroll", payload: {} });
    expect(result.statusCode).toBe(200);
    expect(result.json().qrCodeSvg).toBeNull();
    expect(supabase.auth.mfa.unenroll).not.toHaveBeenCalled();
  });

  it("verifies first-time enrollment via all[] and confirms AAL2", async () => {
    const instance = await app();
    const result = await instance.inject({
      method: "POST", url: "/auth/mfa/verify",
      headers: { cookie: "lumicsec_pending_totp=pending" },
      payload: { code: "123456" },
    });
    expect(result.statusCode).toBe(200);
    expect(result.json()).toEqual({ verified: true, assuranceLevel: "aal2" });
    expect(supabase.auth.mfa.challenge).toHaveBeenCalledWith({ factorId: "pending" });
    expect(supabase.auth.mfa.verify).toHaveBeenCalledWith({
      factorId: "pending", challengeId: "challenge", code: "123456",
    });
  });

  it("rejects a stale enrollment cookie, never falling back to a verified factor", async () => {
    supabase.auth.mfa.listFactors.mockResolvedValue({ data: { all: [verified], totp: [verified] }, error: null });
    const instance = await app();
    const result = await instance.inject({
      method: "POST", url: "/auth/mfa/verify",
      headers: { cookie: "lumicsec_pending_totp=stale" }, payload: { code: "123456" },
    });
    expect(result.statusCode).toBe(409);
    expect(result.json()).toEqual({ error: "TOTP_ENROLLMENT_EXPIRED_REGENERATE" });
    expect(supabase.auth.mfa.challenge).not.toHaveBeenCalled();
  });

  it("rejects invalid and expired TOTP attempts", async () => {
    const instance = await app();
    const invalid = await instance.inject({ method: "POST", url: "/auth/mfa/verify", payload: { code: "123" } });
    expect(invalid.statusCode).toBe(400);
    expect(supabase.auth.mfa.challenge).not.toHaveBeenCalled();
    supabase.auth.mfa.verify.mockResolvedValue({ data: null, error: { code: "expired_otp" } });
    const expired = await instance.inject({
      method: "POST", url: "/auth/mfa/verify",
      headers: { cookie: "lumicsec_pending_totp=pending" }, payload: { code: "123456" },
    });
    expect(expired.statusCode).toBe(401);
    expect(expired.json()).toEqual({ error: "MFA_VERIFICATION_FAILED" });
  });

  it("fails closed if the session is still AAL1 after verification", async () => {
    supabase.auth.mfa.getAuthenticatorAssuranceLevel.mockResolvedValue({
      data: { currentLevel: "aal1", nextLevel: "aal2" }, error: null,
    });
    const instance = await app();
    const result = await instance.inject({
      method: "POST", url: "/auth/mfa/verify",
      headers: { cookie: "lumicsec_pending_totp=pending" }, payload: { code: "123456" },
    });
    expect(result.statusCode).toBe(403);
    expect(result.json()).toEqual({ error: "AAL2_NOT_CONFIRMED" });
  });

  it("blocks protected customer APIs at JWT AAL1, even with a stale AAL2 assurance response", async () => {
    supabase.auth.getClaims.mockResolvedValue({
      data: { claims: { aal: "aal1", amr: [{ method: "oauth" }] } }, error: null,
    });
    const instance = await app();
    const result = await instance.inject({ method: "GET", url: "/v1/organizations" });
    expect(result.statusCode).toBe(403);
    expect(result.json()).toEqual({ error: "AAL2_REQUIRED" });
    expect(supabase.from).not.toHaveBeenCalled();
  });

  it("blocks protected APIs if JWT says AAL2 but session assurance remains AAL1", async () => {
    supabase.auth.mfa.getAuthenticatorAssuranceLevel.mockResolvedValue({
      data: { currentLevel: "aal1", nextLevel: "aal2" }, error: null,
    });
    const instance = await app();
    const result = await instance.inject({ method: "GET", url: "/v1/organizations" });
    expect(result.statusCode).toBe(403);
    expect(supabase.from).not.toHaveBeenCalled();
  });

  it("allows the read-only customer route only with Google OAuth + TOTP AAL2 claims", async () => {
    const builder = {
      select: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      limit: vi.fn().mockResolvedValue({ data: [], error: null }),
    };
    supabase.from.mockReturnValue(builder);
    const instance = await app();
    const result = await instance.inject({ method: "GET", url: "/v1/organizations" });
    expect(result.statusCode).toBe(200);
    expect(result.json()).toEqual({ organizations: [], memberships: [] });
    expect(supabase.from).toHaveBeenCalledWith("organizations");
    expect(supabase.from).toHaveBeenCalledWith("organization_memberships");
  });

  it("does not enroll non-Google primary identities", async () => {
    supabase.auth.getUser.mockResolvedValue({
      data: { user: { id: "test-user", app_metadata: { provider: "email", providers: ["google", "email"] } } }, error: null,
    });
    const instance = await app();
    const result = await instance.inject({ method: "POST", url: "/auth/mfa/enroll", payload: {} });
    expect(result.statusCode).toBe(401);
    expect(supabase.auth.mfa.enroll).not.toHaveBeenCalled();
  });
});
