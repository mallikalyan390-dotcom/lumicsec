import { describe, expect, it } from "vitest";
import { apiSpecAssessmentRequestSchema, mfaCodeSchema } from "../src/index.js";

describe("shared validation", () => {
  it("accepts a six-digit TOTP code", () => {
    expect(mfaCodeSchema.safeParse("123456").success).toBe(true);
  });

  it("rejects malformed TOTP input", () => {
    expect(mfaCodeSchema.safeParse("12x456").success).toBe(false);
    expect(mfaCodeSchema.safeParse("12345").success).toBe(false);
  });

  it("requires specification content", () => {
    expect(apiSpecAssessmentRequestSchema.safeParse({ content: "" }).success).toBe(false);
    expect(apiSpecAssessmentRequestSchema.safeParse({ content: "{}", filename: "api.json" }).success).toBe(true);
  });
});
