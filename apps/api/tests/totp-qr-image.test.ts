import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import jsQR from "jsqr";
import { PNG } from "pngjs";
import { isTrustedTotpPngDataUrl } from "@lumicsec/validation";
import { createTotpProvisioningUri, createTotpQrPngDataUrl } from "../src/lib/totp-qr-image.js";

// Public, deterministic fixture only. Never use a real enrollment secret here.
const SYNTHETIC_BASE32 = "JBSWY3DPEHPK3PXP";

describe("local TOTP QR PNG generation", () => {
  it("builds a standard time-based provisioning URI from the exact factor secret", () => {
    const uri = createTotpProvisioningUri(SYNTHETIC_BASE32, "synthetic@example.invalid");
    expect(uri).not.toBeNull();
    const parsed = new URL(uri!);
    expect(parsed.protocol).toBe("otpauth:");
    expect(parsed.hostname).toBe("totp");
    expect(decodeURIComponent(parsed.pathname)).toBe("/LumicSec:synthetic@example.invalid");
    expect(parsed.searchParams.get("secret")).toBe(SYNTHETIC_BASE32);
    expect(parsed.searchParams.get("issuer")).toBe("LumicSec");
    expect(parsed.searchParams.get("algorithm")).toBe("SHA1");
    expect(parsed.searchParams.get("digits")).toBe("6");
    expect(parsed.searchParams.get("period")).toBe("30");
  });

  it("renders a decodable 256x256 PNG locally without any HTTP requests", async () => {
    const image = await createTotpQrPngDataUrl(SYNTHETIC_BASE32, "synthetic@example.invalid");
    expect(isTrustedTotpPngDataUrl(image)).toBe(true);
    expect(image).toMatch(/^data:image\/png;base64,/);
    const buffer = Buffer.from(image!.slice("data:image/png;base64,".length), "base64");
    expect(buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))).toBe(true);
    expect(buffer.toString("ascii", 12, 16)).toBe("IHDR");
    expect(buffer.readUInt32BE(16)).toBe(256);
    expect(buffer.readUInt32BE(20)).toBe(256);
    expect(buffer.length).toBeLessThan(90_000);
    // Independent decoder validates the QR contains the EXACT synthetic
    // provisioning URI and uses the standard TOTP parameters.
    const decodedPng = PNG.sync.read(buffer);
    const decoded = jsQR(new Uint8ClampedArray(decodedPng.data), decodedPng.width, decodedPng.height);
    expect(decoded?.data).toBe(createTotpProvisioningUri(SYNTHETIC_BASE32, "synthetic@example.invalid"));
  });

  it("produces deterministic account metadata without embedding untrusted control sequences", async () => {
    const uri = createTotpProvisioningUri(SYNTHETIC_BASE32, "person\r\nInjected");
    expect(uri).not.toContain("Injected");
    expect(uri).not.toContain("\r");
    expect(uri).not.toContain("\n");
    expect(uri).toContain("Authenticator");
  });

  it.each([
    "",
    "TEST_ONLY_NOT_BASE32_SECRET",
    "javascript:alert(1)",
    "JBSWY3DPEHPK3PX8", // 8 is not base32
    "JBSWY3DPEHPK3PXP".repeat(50),
    null,
    undefined,
  ])("rejects invalid or oversized secrets before any QR encoding", async (secret) => {
    expect(createTotpProvisioningUri(secret)).toBeNull();
    expect(await createTotpQrPngDataUrl(secret)).toBeNull();
  });

  it("rejects forged PNG URLs and unsafe schemes in the shared frontend guard", () => {
    const bad = [
      "", "javascript:alert(1)", "https://unknown.invalid/image.png",
      "data:image/svg+xml,<svg></svg>",
      "data:image/png;base64,SGVsbG8=",
      "data:image/png;base64," + "A".repeat(120_001),
    ];
    expect(bad.every((value) => !isTrustedTotpPngDataUrl(value))).toBe(true);
  });
});
