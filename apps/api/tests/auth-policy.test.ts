import { describe, expect, it } from "vitest";
import { isGoogleAal2, isGoogleIdentity } from "../src/lib/auth-policy.js";

describe("Google-only AAL2 policy", () => {
  it("accepts a server-controlled Google provider identity", () => {
    expect(isGoogleIdentity({
      app_metadata: { provider: "google", providers: ["google"] },
      user_metadata: { provider: "email" },
    })).toBe(true);
  });

  it("does not trust user-editable metadata for provider authorization", () => {
    expect(isGoogleIdentity({
      app_metadata: { provider: "email", providers: ["email"] },
      user_metadata: { provider: "google", providers: ["google"] },
    })).toBe(false);
  });

  it("does not confuse a linked Google identity with a Google-first-factor account", () => {
    expect(isGoogleIdentity({
      app_metadata: { provider: "email", providers: ["email", "google"] },
    })).toBe(false);
  });

  it("requires Google identity, AAL2 and OAuth plus TOTP methods", () => {
    const user = { app_metadata: { provider: "google", providers: ["google"] } };
    const claims = { aal: "aal2", amr: [{ method: "oauth" }, { method: "totp" }] };
    expect(isGoogleAal2(user, claims, { currentLevel: "aal2" })).toBe(true);
    expect(isGoogleAal2(user, { ...claims, aal: "aal1" }, { currentLevel: "aal1" })).toBe(false);
    expect(isGoogleAal2(user, { aal: "aal2", amr: [{ method: "password" }, { method: "totp" }] }, { currentLevel: "aal2" })).toBe(false);
  });
});
