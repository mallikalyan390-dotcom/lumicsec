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
});
