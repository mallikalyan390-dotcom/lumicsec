import { describe, expect, it } from "vitest";
import { detectInventory, importOfflineDocument } from "../src/index.js";

const openApi = {
  openapi: "3.1.0",
  info: { title: "Example API", version: "1.0.0" },
  servers: [{ url: "https://api.example.test" }],
  components: {
    securitySchemes: {
      bearerAuth: { type: "http", scheme: "bearer" },
    },
  },
  paths: {
    "/users": {
      get: {
        responses: { "200": { description: "List users" } },
      },
      post: {
        security: [],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: { name: { type: "string" } },
                required: ["name"],
              },
            },
          },
        },
        responses: { "201": { description: "Created" } },
      },
    },
  },
};

describe("offline API specification engine", () => {
  it("imports OpenAPI and emits SPEC_ONLY observations", async () => {
    const inventory = await importOfflineDocument(JSON.stringify(openApi));
    expect(inventory.format).toBe("OPENAPI_3_1");
    expect(inventory.operations).toHaveLength(2);

    const result = detectInventory(inventory);
    expect(result.observations.length).toBeGreaterThan(0);
    expect(result.observations.every((item) => item.validationLevel === "SPEC_OBSERVATION")).toBe(true);
    expect(result.observations.every((item) => item.reviewRequired)).toBe(true);
    expect(result.limitations).toContain("SPEC_ONLY: maxRequests = 0; methods = []");
  });

  it("rejects external references without attempting network resolution", async () => {
    const invalid = {
      ...openApi,
      paths: {
        "/users": {
          get: {
            responses: { "200": { description: "OK", content: { "application/json": { schema: { $ref: "https://outside.example/schema.json" } } } } },
          },
        },
      },
    };

    await expect(importOfflineDocument(JSON.stringify(invalid))).rejects.toThrow("EXTERNAL_REF_PROHIBITED");
  });

  it("keeps valid empty API specs as an explicit zero-operation inventory", async () => {
    const inventory = await importOfflineDocument(JSON.stringify({
      openapi: "3.1.0",
      info: { title: "Empty", version: "1.0.0" },
      paths: {},
    }));
    expect(inventory.operations).toHaveLength(0);
    expect(inventory.metadata.warnings).toContain("DECLARED_SPEC_ONLY_NO_RUNTIME_CONFIRMATION");
  });
});
