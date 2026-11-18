import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";

describe("Fastify API", () => {
  const apps: Array<ReturnType<typeof buildApp>> = [];

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  it("exposes a non-sensitive health endpoint", async () => {
    const app = buildApp();
    apps.push(app);
    const response = await app.inject({ method: "GET", url: "/healthz" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      status: "ok",
      service: "lumicsec-api",
    });
  });

  it("blocks a CSRF-less POST before entering a protected assessment", async () => {
    const app = buildApp();
    apps.push(app);
    const response = await app.inject({
      method: "POST",
      url: "/v1/api-specs/assess",
      payload: { content: "{}" },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ error: "CSRF_ORIGIN_CHECK_FAILED" });
  });

  it("does not return product access when Supabase has not been configured", async () => {
    const app = buildApp();
    apps.push(app);
    const response = await app.inject({ method: "GET", url: "/auth/session" });
    expect(response.statusCode).toBe(200);
    expect(response.json().state).not.toBe("authenticated");
  });

});
