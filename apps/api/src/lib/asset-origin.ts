import { isIP } from "node:net";

const reservedSuffixes = new Set([
  "localhost", "local", "internal", "lan", "home", "invalid", "test", "example", "onion",
]);

/**
 * Validate a declared customer origin without performing a network request.
 * This does NOT prove DNS ownership and never grants permission to scan.
 */
export function canonicalAssetOrigin(input: string): string {
  if (input.length > 253 || input.trim() !== input) {
    throw new Error("INVALID_ORIGIN");
  }
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new Error("INVALID_ORIGIN");
  }

  if (
    url.protocol !== "https:"
    || url.username !== ""
    || url.password !== ""
    || url.port !== ""
    || url.pathname !== "/"
    || url.search !== ""
    || url.hash !== ""
    || isIP(url.hostname) !== 0
  ) {
    throw new Error("PUBLIC_HTTPS_ORIGIN_REQUIRED");
  }

  const hostname = url.hostname.toLowerCase();
  const labels = hostname.split(".");
  if (
    hostname.length > 240
    || labels.length < 2
    || labels.some((label) =>
      label.length < 1
      || label.length > 63
      || !/^[a-z0-9-]+$/.test(label)
      || label.startsWith("-")
      || label.endsWith("-")
    )
    || !/[a-z]/.test(labels[labels.length - 1] ?? "")
    || reservedSuffixes.has(labels[labels.length - 1] ?? "")
  ) {
    throw new Error("PUBLIC_DNS_HOSTNAME_REQUIRED");
  }
  return url.origin;
}
