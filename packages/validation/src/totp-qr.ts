// Supabase Auth JS prefixes SVG QR markup with "data:image/svg+xml;utf-8,".
// Accept common wire encodings, then reduce the image to an intentionally
// restricted SVG drawing grammar before it reaches an <img> element.
// Unknown SVG is NOT rendered; the verified user's manual TOTP key remains usable.
const MAX_INPUT_CHARS = 100_000;
const MAX_SVG_CHARS = 90_000;
const MAX_SHAPES = 4_096;
const MAX_DEPTH = 12;
const SVG_NS = "http://www.w3.org/2000/svg";
const permittedElements = new Set(["svg", "g", "path", "rect", "circle", "polygon", "polyline", "line"]);
const permittedAttributes = new Set([
  "xmlns", "viewBox", "width", "height", "x", "y", "rx", "ry", "cx", "cy", "r",
  "x1", "y1", "x2", "y2", "d", "points", "fill", "stroke", "stroke-width",
  "opacity", "fill-opacity", "stroke-opacity", "shape-rendering",
  "fill-rule", "stroke-linecap", "stroke-linejoin", "transform",
  "version", "preserveAspectRatio",
]);

function containsUnsafeControlCharacters(input: string): boolean {
  for (const symbol of input) {
    const point = symbol.charCodeAt(0);
    if ((point < 32 && point !== 9 && point !== 10 && point !== 13) || point === 127) {
      return true;
    }
  }
  return false;
}

function svgInput(value: unknown): string | null {
  if (typeof value !== "string" || value.length < 40 || value.length > MAX_INPUT_CHARS) {
    return null;
  }

  const comma = value.indexOf(",");
  if (comma < 0 || comma > 90) return null;
  const metadata = value.slice(0, comma).toLowerCase().split(";");
  if (metadata.shift() !== "data:image/svg+xml") return null;
  let isBase64 = false;
  let hasCharset = false;
  for (const part of metadata) {
    if (part === "base64" && !isBase64) {
      isBase64 = true;
    } else if ((part === "utf-8" || part === "charset=utf-8") && !hasCharset) {
      hasCharset = true;
    } else {
      return null;
    }
  }

  const payload = value.slice(comma + 1);
  if (!payload) return null;
  let svg: string;
  try {
    if (isBase64) {
      const encoded = payload.replace(/[\t\r\n ]/g, "");
      if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
        return null;
      }
      const bytes = Uint8Array.from(atob(encoded), (symbol) => symbol.charCodeAt(0));
      svg = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } else if (/%[0-9a-f]{2}/i.test(payload)) {
      // Raw Supabase SVG can contain literal '%' in dimension attributes.
      // Only treat this as URI encoding when the payload is actually encoded.
      const normalized = payload.trimStart();
      svg = /^(?:%(?:20|09|0a|0d))*%(?:3c|ef)/i.test(normalized) ? decodeURIComponent(payload) : payload;
    } else {
      svg = payload;
    }
  } catch {
    return null;
  }

  if (svg.length > MAX_SVG_CHARS || containsUnsafeControlCharacters(svg)) return null;
  return svg;
}

function permittedAttribute(key: string, value: string, element: string): boolean {
  if (!permittedAttributes.has(key) || value.length > 25_000
    || containsUnsafeControlCharacters(value) || /[<>&"'\\]/.test(value)) {
    return false;
  }
  if (key === "xmlns") return element === "svg" && value === SVG_NS;
  if (key === "version") return element === "svg" && value === "1.1";
  if (key === "viewBox") return element === "svg" && /^\s*-?\d+(?:\.\d+)?(?:\s+-?\d+(?:\.\d+)?){3}\s*$/.test(value);
  if (key === "preserveAspectRatio") return element === "svg" && /^(none|x(?:Min|Mid|Max)Y(?:Min|Mid|Max)(?: (?:meet|slice))?)$/.test(value);
  if (key === "fill" || key === "stroke") {
    return /^(?:none|black|white|transparent|#[a-fA-F0-9]{3,8}|rgb\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*\))$/.test(value);
  }
  if (key === "shape-rendering") return /^(auto|crispEdges|geometricPrecision|optimizeSpeed)$/.test(value);
  if (key === "fill-rule") return /^(evenodd|nonzero)$/.test(value);
  if (key === "stroke-linecap") return /^(round|butt|square)$/.test(value);
  if (key === "stroke-linejoin") return /^(round|miter|bevel)$/.test(value);
  if (key === "d") return /^[0-9eE+.,\-\sMmLlHhVvCcQqSsTtAaZz]+$/.test(value);
  if (key === "points") return /^[0-9eE+.,\-\s]+$/.test(value);
  if (key === "transform") return /^(?:(?:translate|scale|rotate|matrix)\([0-9eE+.,\-\s]+\)\s*)+$/.test(value);
  // Dimensions and positions (including 100% width) are non-executable.
  return /^-?(?:\d+(?:\.\d*)?|\.\d+)(?:px|%)?$/.test(value);
}

function safeSvgMarkup(svg: string): boolean {
  let xml = svg.replace(/^\uFEFF/, "").trim();
  if (xml.startsWith("<?xml")) {
    const declaration = /^<\?xml\s+version=(["'])1\.0\1(?:\s+encoding=(["'])utf-8\2)?\s*\?>/i.exec(xml);
    if (!declaration) return false;
    xml = xml.slice(declaration[0].length).trimStart();
  }

  // No DTD, entities, extra processing instructions, XML comments or styles.
  if (/[&]/.test(xml) || xml.includes("<!") || xml.includes("<?")) return false;
  const tags = /<(\/?)\s*([A-Za-z][A-Za-z0-9-]*)([^<>]*)>/g;
  const stack: string[] = [];
  let offset = 0;
  let shapes = 0;
  let sawRoot = false;
  let sawShape = false;

  for (const match of xml.matchAll(tags)) {
    if (match.index === undefined || !/^\s*$/.test(xml.slice(offset, match.index))) return false;
    offset = match.index + match[0].length;
    const name = match[2];
    if (!name || !permittedElements.has(name)) return false;

    if (match[1]) {
      if (match[3]?.trim() || stack.pop() !== name) return false;
      continue;
    }
    if (!sawRoot) {
      if (name !== "svg") return false;
      sawRoot = true;
    } else if (stack.length === 0 || name === "svg") {
      return false;
    }

    shapes++;
    if (shapes > MAX_SHAPES || stack.length >= MAX_DEPTH) return false;
    if (name !== "svg" && name !== "g") sawShape = true;
    const rawAttributes = match[3] ?? "";
    const selfClosing = /\/\s*$/.test(rawAttributes);
    const attributes = selfClosing ? rawAttributes.replace(/\/\s*$/, "") : rawAttributes;
    const attr = /\s+([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*(["'])([\s\S]*?)\2/gy;
    const seen = new Set<string>();
    let position = 0;
    while (position < attributes.length) {
      attr.lastIndex = position;
      const item = attr.exec(attributes);
      if (!item || !item[1] || item[3] === undefined || seen.has(item[1]) || !permittedAttribute(item[1], item[3], name)) {
        return false;
      }
      seen.add(item[1]);
      position = attr.lastIndex;
    }
    if (name === "svg" && !seen.has("xmlns")) return false;
    if (!selfClosing) stack.push(name);
  }

  return sawRoot && sawShape && stack.length === 0 && /^\s*$/.test(xml.slice(offset));
}

/** Returns a canonical, percent-encoded Data URL only for a bounded safe SVG QR. */
export function normalizeTotpSvgQrDataUrl(value: unknown): string | null {
  const svg = svgInput(value);
  if (svg === null || !safeSvgMarkup(svg)) return null;
  return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg.replace(/^\uFEFF/, "").trim());
}

/** Frontend defense in depth: never hand an arbitrary SVG URL to the browser. */
export function isTrustedTotpQrImageDataUrl(value: unknown): value is string {
  return normalizeTotpSvgQrDataUrl(value) !== null;
}

/** No QR/secret values, lengths in bytes, tokens, URIs, or user identifiers. */
export function totpQrFormatMetadata(value: unknown): {
  category: "missing" | "svg-data-url" | "other-data-url" | "other";
  encoding: "base64" | "text" | "unknown";
  multiline: boolean;
  size: "short" | "medium" | "large";
} {
  if (typeof value !== "string") {
    return { category: "missing", encoding: "unknown", multiline: false, size: "short" };
  }
  const head = value.slice(0, 95).toLowerCase();
  return {
    category: head.startsWith("data:image/svg+xml") ? "svg-data-url"
      : head.startsWith("data:") ? "other-data-url" : "other",
    encoding: /^data:[^,;]+(?:;[^,]*)?;base64,/.test(head) ? "base64"
      : head.startsWith("data:") ? "text" : "unknown",
    multiline: /[\r\n]/.test(value),
    size: value.length < 2_000 ? "short" : value.length < 40_000 ? "medium" : "large",
  };
}


/** Bounded browser-side check for PNGs generated by the local server encoder.
 * This validates the data URL, PNG signature and IHDR, not full PNG decoding.
 * PNG is never inserted as HTML, only as an <img> source.
 */
export function isTrustedTotpPngDataUrl(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1_000 || value.length > 120_000
    || !/^data:image\/png;base64,[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  try {
    const prefix = "data:image/png;base64,";
    const header = atob(value.slice(prefix.length, prefix.length + 48));
    if (header.length < 26 || !header.startsWith("\x89PNG\r\n\x1a\n")
      || header.slice(12, 16) !== "IHDR") return false;
    const number = (offset: number) =>
      ((header.charCodeAt(offset) * 16_777_216)
      + (header.charCodeAt(offset + 1) * 65_536)
      + (header.charCodeAt(offset + 2) * 256)
      + header.charCodeAt(offset + 3));
    const width = number(16), height = number(20);
    return number(8) === 13 && width >= 128 && width <= 512
      && height >= 128 && height <= 512 && header.charCodeAt(24) === 8
      && (header.charCodeAt(25) === 2 || header.charCodeAt(25) === 6);
  } catch {
    return false;
  }
}
