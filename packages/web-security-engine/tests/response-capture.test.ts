import { describe, expect, it } from "vitest";
import { capturePassiveResponse } from "../src/response-capture.js";

describe("passive response capture", () => {
  it("records security header state without storing cookie values", () => {
    const capture = capturePassiveResponse({
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
      "set-cookie": "session-secret=do-not-store; Secure; HttpOnly; SameSite=Lax",
    }, "https://example.test", true);

    expect(capture.hsts).toBe("VALID");
    expect(capture.csp).toBe("ENFORCED");
    expect(capture.setCookieCount).toBe(1);
    expect(JSON.stringify(capture)).not.toContain("do-not-store");
    expect(JSON.stringify(capture)).not.toContain("session-secret");
  });
});
