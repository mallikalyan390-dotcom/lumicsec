import { describe, expect, it } from "vitest";
import {
  analyzeWebAssessmentSnapshot,
  type AnalysisSnapshot,
} from "../src/analysis.js";
import { capturePassiveResponse } from "../src/response-capture.js";

describe("offline Web analysis", () => {
  it("emits reviewable passive configuration observations, not confirmed vulnerabilities", () => {
    const capture = capturePassiveResponse(
      { "content-type": "text/html" },
      "https://example.test",
      true,
    );
    const snapshot: AnalysisSnapshot = {
      analysisId: "00000000-0000-4000-8000-000000000001",
      jobId: "00000000-0000-4000-8000-000000000002",
      organizationId: "00000000-0000-4000-8000-000000000003",
      websiteId: "00000000-0000-4000-8000-000000000004",
      actorId: "00000000-0000-4000-8000-000000000005",
      origin: "https://example.test",
      scopeHash: "a".repeat(64),
      snapshotFingerprint: "b".repeat(64),
      coverageState: "COMPLETE_WITHIN_LIMITS",
      coverage: {},
      nodes: [{
        id: "wdn_" + "c".repeat(24),
        kind: "PAGE",
        state: "OBSERVED",
        path: "/",
        method: "GET",
        sourceFingerprint: "d".repeat(64),
        observedAt: new Date().toISOString(),
        confidence: "OBSERVED",
        metadata: {
          contentType: "text/html",
          passiveResponseV1: JSON.stringify(capture),
        },
      }],
      edges: [],
    };

    const result = analyzeWebAssessmentSnapshot(snapshot);
    expect(result.observations.some((item) => item.ruleId === "P09.HSTS.ABSENT")).toBe(true);
    expect(result.observations.every((item) => item.outcome !== "VALIDATED")).toBe(true);
    expect(result.candidates.every((item) => item.status === "REVIEW_REQUIRED")).toBe(true);
  });
});
