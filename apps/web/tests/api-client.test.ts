import { afterEach, describe, expect, it, vi } from "vitest";
import { getAuthSession, postJson } from "../src/lib/api.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("browser API client", () => {
  it("checks the session without caching and sends cookies", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      state: "anonymous",
      configured: true,
      csrfToken: "test-token",
    }), { status: 200, headers: { "content-type": "application/json" } }));

    vi.stubGlobal("fetch", fetchMock);
    const session = await getAuthSession();

    expect(session.state).toBe("anonymous");
    expect(session.csrfToken).toBe("test-token");
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/auth/session");
    expect(options.credentials).toBe("include");
    expect(options.cache).toBe("no-store");
  });

  it("passes a CSRF token with JSON POST requests", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{"ok":true}', {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    const data = await postJson<{ ok: boolean }>("/v1/test", { name: "check" }, "csrf");
    expect(data.ok).toBe(true);
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/v1/test");
    expect(options.method).toBe("POST");
    expect(options.body).toBe('{"name":"check"}');
    expect(new Headers(options.headers).get("x-csrf-token")).toBe("csrf");
  });

  it("does not treat rejected protected calls as successful", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      '{"error":"AAL2_REQUIRED"}',
      { status: 403, headers: { "content-type": "application/json" } },
    )));
    await expect(postJson("/v1/api-specs/assess", {}, "csrf")).rejects.toThrow("AAL2_REQUIRED");
  });
});
