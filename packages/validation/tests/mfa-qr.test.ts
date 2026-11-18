import { describe, expect, it } from "vitest";
import { isTrustedTotpQrImageDataUrl } from "../src/index.js";

describe("Supabase TOTP QR data URLs", () => {
  const svg = '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>';
  it("accepts the unmodified data URL produced by Supabase Auth JS", () => {
    expect(isTrustedTotpQrImageDataUrl("data:image/svg+xml;utf-8," + svg)).toBe(true);
    expect(isTrustedTotpQrImageDataUrl("data:image/svg+xml;utf-8," + encodeURIComponent(svg))).toBe(true);
    expect(isTrustedTotpQrImageDataUrl("data:image/svg+xml;base64," + btoa(svg))).toBe(true);
  });

  it.each([
    "",
    "https://untrusted.example/qr.svg",
    "javascript:alert(1)",
    "data:text/html,<svg onload=alert(1)>",
    "data:image/svg+xml;charset=utf-8,data:image/svg+xml;utf-8,<svg></svg>",
    "data:image/svg+xml;base64,<svg></svg>",
    "data:image/svg+xml;utf-8,invalid",
    "data:image/svg+xml;utf-8,<svg>\n</svg>",
  ])("rejects invalid QR sources (no TOTP secret used)", (value) => {
    expect(isTrustedTotpQrImageDataUrl(value)).toBe(false);
  });
});
