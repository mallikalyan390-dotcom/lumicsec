import { describe, expect, it } from "vitest";
import {
  isTrustedTotpQrImageDataUrl,
  normalizeTotpSvgQrDataUrl,
  totpQrFormatMetadata,
} from "../src/index.js";

const svg = [
  '<svg xmlns="http://www.w3.org/2000/svg" width="180" height="180" viewBox="0 0 180 180">',
  '<rect width="180" height="180" fill="#fff"/>',
  '<path fill="#000" d="M0 0 h10 v10 H0 z M20 20 l10 0 v10 z"/>',
  '</svg>',
].join("\n");

function dataUrl(body: string, prefix = "data:image/svg+xml;utf-8,") {
  return prefix + body;
}

describe("Supabase TOTP QR data URLs (synthetic SVG only)", () => {
  it.each([
    ["raw multiline SDK format", dataUrl(svg)],
    ["raw CRLF newlines", dataUrl(svg.replaceAll("\n", "\r\n"))],
    ["newline inside path data", dataUrl(svg.replace('d="M0 0 h10', 'd="M0 0\n h10'))],
    ["XML declaration with newlines", dataUrl('<?xml version="1.0" encoding="utf-8"?>\n\n' + svg)],
    ["XML declaration with whitespace before svg", dataUrl(' \n <?xml version="1.0"?>\n\n  ' + svg)],
    ["leading SVG whitespace", dataUrl("\n  \t " + svg)],
    ["UTF-8 BOM then XML declaration", dataUrl("\uFEFF\n<?xml version='1.0'?>\n" + svg)],
    ["URI encoded SVG", dataUrl(encodeURIComponent(svg))],
    ["URI encoded BOM and leading spaces", dataUrl(encodeURIComponent("\uFEFF\n  " + svg))],
    ["Base64 with MIME marker", dataUrl(btoa(svg), "data:image/svg+xml;base64,")],
    ["Base64 with charset", dataUrl(btoa(svg), "data:image/svg+xml;charset=utf-8;base64,")],
    ["Base64 with wrapped lines", dataUrl(btoa(svg).replace(/(.{64})/g, "$1\n"), "data:image/svg+xml;utf-8;base64,")],
    ["charset raw", dataUrl(svg, "data:image/svg+xml;charset=utf-8,")],
    ["no charset raw", dataUrl(svg, "data:image/svg+xml,")],
  ])("accepts safe %s", (_case, sample) => {
    expect(isTrustedTotpQrImageDataUrl(sample)).toBe(true);
    const normalized = normalizeTotpSvgQrDataUrl(sample);
    expect(normalized?.startsWith("data:image/svg+xml;charset=utf-8,")).toBe(true);
    expect(isTrustedTotpQrImageDataUrl(normalized)).toBe(true);
  });

  it.each([
    ["not an image", "https://example.invalid/svg"],
    ["javascript URL", "javascript:alert(1)"],
    ["HTML data URL", "data:text/html,<svg onload='alert(1)'></svg>"],
    ["script", dataUrl(svg.replace("</svg>", "<script>alert(1)</script></svg>"))],
    ["event handler", dataUrl(svg.replace('viewBox="0 0 180 180"', 'onload="alert(1)"'))],
    ["external reference", dataUrl(svg.replace("<path", '<path href="https://example.invalid/collect"'))],
    ["xlink reference", dataUrl(svg.replace("<path", '<path xlink:href="http://127.0.0.1/collect"'))],
    ["foreignObject", dataUrl(svg.replace("</svg>", '<foreignObject><body>bad</body></foreignObject></svg>'))],
    ["style element", dataUrl(svg.replace("</svg>", '<style>@import url(https://x.invalid)</style></svg>'))],
    ["inline CSS", dataUrl(svg.replace("<rect", '<rect style="background:url(https://x.invalid)"'))],
    ["DTD", dataUrl('<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]>' + svg)],
    ["XML entity", dataUrl(svg.replace("#000", "&x;"))],
    ["CDATA", dataUrl(svg.replace("</svg>", "<![CDATA[hi]]></svg>"))],
    ["XML processing instruction", dataUrl(svg.replace("</svg>", '<?xml-stylesheet href="evil.css"?></svg>'))],
    ["invalid Base64", "data:image/svg+xml;base64,<svg></svg>"],
    ["non SVG Base64", dataUrl(btoa("<html><script>bad</script></html>"), "data:image/svg+xml;base64,")],
    ["double-prefixed data URL", dataUrl(dataUrl(svg))],
    ["unsafe MIME", dataUrl(svg, "data:image/svg+xml;script,")],
    ["invalid nesting", dataUrl(svg.replace("</svg>", "</g></svg>"))],
    ["missing SVG namespace", dataUrl(svg.replace('xmlns="http://www.w3.org/2000/svg"', ""))],
    ["extra root", dataUrl(svg + svg)],
    ["unapproved gradient", dataUrl(svg.replace("</svg>", "<linearGradient id='x'/></svg>"))],
    ["oversized payload", dataUrl(svg + "x".repeat(100_001))],
    ["control character", dataUrl(svg.replace("#000", "#000\u0000"))],
    ["untrusted source", dataUrl('<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="url(http://evil.invalid)"/></svg>')],
    ["encoded script", dataUrl(encodeURIComponent(svg.replace("</svg>", "<script>bad</script></svg>")))],
    ["encoded external ref", dataUrl(encodeURIComponent(svg.replace("<rect", '<rect href="https://evil.invalid"')))],
  ])("rejects unsafe %s", (_case, sample) => {
    expect(isTrustedTotpQrImageDataUrl(sample)).toBe(false);
    expect(normalizeTotpSvgQrDataUrl(sample)).toBeNull();
  });

  it("returns only categorical QR metadata, never the image or a secret", () => {
    const meta = totpQrFormatMetadata(dataUrl(svg));
    expect(meta).toEqual({
      category: "svg-data-url", encoding: "text", multiline: true, size: "short",
    });
    expect(JSON.stringify(meta)).not.toContain("M0 0");
    expect(totpQrFormatMetadata(null).category).toBe("missing");
  });
});
