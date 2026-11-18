import { describe, expect, it } from "vitest";
import { managedUnverifiedTotp, selectTotpChallengeFactor } from "../src/lib/mfa-factors.js";

const pending = { id: "pending", status: "unverified", factor_type: "totp", friendly_name: "LumicSec Authenticator 1234" };
const verified = { id: "verified", status: "verified", factor_type: "totp", friendly_name: "LumicSec Authenticator backup" };
const other = { id: "other", status: "unverified", factor_type: "totp", friendly_name: "Another application" };
const factors = { all: [pending, verified, other], totp: [verified] };

describe("MFA factor selection and safe cleanup", () => {
  it("uses .all to find a pending factor, not the verified-only .totp array", () => {
    expect(selectTotpChallengeFactor(factors, "pending")?.id).toBe("pending");
  });

  it("never falls back to a verified factor with an expired or unexpected pending cookie", () => {
    expect(selectTotpChallengeFactor(factors, "missing")).toBeNull();
    expect(selectTotpChallengeFactor(factors, "verified")).toBeNull();
    expect(selectTotpChallengeFactor(factors, "other")).toBeNull();
  });

  it("uses an already-verified factor for normal login challenge only", () => {
    expect(selectTotpChallengeFactor(factors)?.id).toBe("verified");
    expect(selectTotpChallengeFactor({ all: [pending], totp: [] })).toBeNull();
  });

  it("cleans only own abandoned, unverified TOTP factors", () => {
    expect(managedUnverifiedTotp(factors).map((factor) => factor.id)).toEqual(["pending"]);
  });
});
