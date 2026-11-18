import { describe, expect, it } from "vitest";
import { canonicalAssetOrigin } from "../src/lib/asset-origin.js";
import { buildApp } from "../src/app.js";

describe("asset-origin validation", () => {
  it("normalizes a real HTTPS origin without fetching it", () => {
    expect(canonicalAssetOrigin("https://EXAMPLE.COM:443/")).toBe("https://example.com");
    expect(canonicalAssetOrigin("https://api.example.com")).toBe("https://api.example.com");
  });

  it.each([
    "http://example.com",
    "https://example.com:8443",
    "https://example.com/admin",
    "https://example.com/?token=secret",
    "https://user:password@example.com",
    "https://127.0.0.1",
    "https://169.254.169.254",
    "https://localhost",
    "https://app.internal",
    "https://example.test",
  ])("rejects unqualified or unsafe origins: %s", (origin) => {
    expect(() => canonicalAssetOrigin(origin)).toThrow();
  });
});

describe("tenant endpoints default closed", () => {
  it("blocks organization and asset listing when Supabase Auth is unconfigured", async () => {
    const app = buildApp();
    try {
      const org = await app.inject({ method: "GET", url: "/v1/organizations" });
      const asset = await app.inject({
        method: "GET",
        url: "/v1/assets?organizationId=00000000-0000-4000-8000-000000000001",
      });
      expect(org.statusCode).toBe(503);
      expect(asset.statusCode).toBe(503);
    } finally {
      await app.close();
    }
  });

  it("rejects asset creation without origin-bound CSRF proof", async () => {
    const app = buildApp();
    try {
      const result = await app.inject({
        method: "POST",
        url: "/v1/assets",
        payload: {
          organizationId: "00000000-0000-4000-8000-000000000001",
          kind: "website",
          displayName: "Site",
          origin: "https://example.com",
        },
      });
      expect(result.statusCode).toBe(403);
      expect(result.json()).toMatchObject({ error: "CSRF_ORIGIN_CHECK_FAILED" });
    } finally {
      await app.close();
    }
  });
});
