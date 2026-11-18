import { describe, expect, it } from "vitest";
import {
  classifyDiscoveryReference,
  crawlWebAssessment,
  DISCOVERY_DEFAULTS,
} from "../src/discovery.js";

describe("bounded passive Web discovery", () => {
  it("classifies external references without retaining query values", () => {
    const result = classifyDiscoveryReference(
      "https://outside.example.test/path?token=secret",
      "https://example.test/",
      "https://example.test",
      DISCOVERY_DEFAULTS,
    );

    expect(result.state).toBe("EXTERNAL");
    expect(result.requestUrl).toBeNull();
    expect(JSON.stringify(result)).not.toContain("secret");
  });

  it("uses only the injected read adapter and records external links as excluded", async () => {
    let readCount = 0;
    const result = await crawlWebAssessment({
      origin: "https://example.test",
      scopeHash: "a".repeat(64),
      limits: { ...DISCOVERY_DEFAULTS, maxRequests: 1 },
      read: async () => {
        readCount += 1;
        return {
          status: 200,
          headers: { "content-type": "text/html; charset=utf-8" },
          bodyBytes: new TextEncoder().encode(
            '<html><body><a href="https://outside.example.test/path?token=secret">external</a></body></html>',
          ),
          headersComplete: true,
        };
      },
    });

    expect(readCount).toBe(1);
    expect(result.coverage.fetched).toBe(1);
    expect(result.nodes.some((node) => node.state === "EXTERNAL")).toBe(true);
    expect(JSON.stringify(result)).not.toContain("token=secret");
  });
});
