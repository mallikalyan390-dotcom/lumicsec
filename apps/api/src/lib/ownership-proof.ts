import { promises as dns } from "node:dns";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import ipaddr from "ipaddr.js";
import { canonicalAssetOrigin } from "./asset-origin.js";

const MAX_DNS_ANSWERS = 16;
const MAX_TXT_ANSWERS = 64;
const MAX_HTTPS_RESPONSE_BYTES = 512;
export const OWNERSHIP_TXT_PREFIX = "lumicsec-verification=";
export const OWNERSHIP_HTTPS_PATH = "/.well-known/lumicsec-verification.txt";

export type OwnershipMethod = "dns_txt" | "https_file";
export type Resolver = Pick<typeof dns, "resolve4" | "resolve6" | "resolveTxt">;

/** Total DNS lookup deadline, not just a per-socket inactivity timeout.
 * A timed-out OS resolver may finish later, but no result is ever trusted.
 */
async function withDnsDeadline<T>(operation: Promise<T>, ms = 4_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("DNS_LOOKUP_TIMEOUT")), Math.min(Math.max(ms, 1), 4_000));
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}


export function isPublicAddress(address: string): boolean {
  if (!isIP(address)) return false;
  try {
    const parsed = ipaddr.parse(address);
    if (parsed.kind() === "ipv4") return parsed.range() === "unicast";
    // Only direct globally routable IPv6; reject mapped IPv4, ULA, link-local,
    // 6to4, Teredo, documentation, unspecified and multicast addresses.
    return parsed.range() === "unicast"
      && parsed.match(ipaddr.parse("2000::"), 3);
  } catch {
    return false;
  }
}

function allowedNoDataError(error: unknown): boolean {
  const code = error !== null && typeof error === "object" && "code" in error
    ? String(error.code) : "";
  return code === "ENODATA" || code === "ENOTFOUND";
}

export async function resolvePublicAddresses(hostname: string, resolver: Resolver = dns, timeoutMs = 4_000):
  Promise<Array<{ address: string; family: 4 | 6 }>> {
  if (isIP(hostname)) throw new Error("IP_LITERAL_BLOCKED");
  const origin = canonicalAssetOrigin("https://" + hostname);
  if (new URL(origin).hostname !== hostname) throw new Error("HOSTNAME_MISMATCH");

  const answers = await withDnsDeadline(Promise.allSettled([
    resolver.resolve4(hostname),
    resolver.resolve6(hostname),
  ]), timeoutMs);
  const result: Array<{ address: string; family: 4 | 6 }> = [];
  for (let index = 0; index < answers.length; index++) {
    const item = answers[index]!;
    if (item.status === "rejected") {
      if (!allowedNoDataError(item.reason)) throw new Error("DNS_RESOLUTION_FAILED");
      continue;
    }
    if (!Array.isArray(item.value)) throw new Error("DNS_RESOLUTION_FAILED");
    for (const address of item.value) {
      if (typeof address !== "string" || !isPublicAddress(address)) {
        throw new Error("PRIVATE_ADDRESS_BLOCKED");
      }
      result.push({ address, family: index === 0 ? 4 : 6 });
    }
  }
  if (result.length === 0 || result.length > MAX_DNS_ANSWERS) {
    throw new Error("DNS_RESOLUTION_UNSAFE");
  }
  return result;
}

function candidateToken(value: string): string | null {
  if (!value.startsWith(OWNERSHIP_TXT_PREFIX)) return null;
  const token = value.slice(OWNERSHIP_TXT_PREFIX.length);
  return /^[0-9a-f]{64}$/.test(token) ? token : null;
}

/** A DNS read is a proof lookup only; never a vulnerability scan. */
export async function getDnsOwnershipProof(
  hostname: string, resolver: Resolver = dns,
): Promise<string | null> {
  // Block DNS names resolving to private/reserved targets even for TXT proofs.
  await resolvePublicAddresses(hostname, resolver);
  const records = await withDnsDeadline(resolver.resolveTxt("_lumicsec-challenge." + hostname));
  if (records.length > MAX_TXT_ANSWERS) throw new Error("TXT_RECORD_LIMIT");
  for (const fragments of records) {
    if (!Array.isArray(fragments) || fragments.length > 16) continue;
    const record = fragments.join("");
    if (record.length > 150) continue;
    const token = candidateToken(record);
    if (token) return token;
  }
  return null;
}

/**
 * No fetch(), redirects, proxy, cookies, user credentials or TLS bypass.
 * Request connects to an already validated/pinned IP with original TLS SNI.
 * A rebinding answer after preflight cannot change the socket destination.
 */
export async function getHttpsOwnershipProof(
  hostname: string,
  resolver: Resolver = dns,
): Promise<string | null> {
  const addresses = await resolvePublicAddresses(hostname, resolver);
  const pinned = addresses[0]!;
  return new Promise<string | null>((resolve, reject) => {
    let absoluteDeadline: ReturnType<typeof setTimeout> | undefined;
    const settle = (fn: () => void) => {
      if (absoluteDeadline) clearTimeout(absoluteDeadline);
      absoluteDeadline = undefined;
      fn();
    };
    let size = 0;
    const chunks: Buffer[] = [];
    const req = httpsRequest({
      hostname,
      port: 443,
      method: "GET",
      path: OWNERSHIP_HTTPS_PATH,
      servername: hostname,
      rejectUnauthorized: true,
      agent: false,
      timeout: 4_000,
      maxHeaderSize: 8_192,
      headers: { accept: "text/plain", "user-agent": "LumicSec-Ownership-Verify/1" },
      lookup: (requested, _options, callback) => {
        if (requested !== hostname || !isPublicAddress(pinned.address)) {
          callback(new Error("UNTRUSTED_SOCKET_DESTINATION"), "", 4);
          return;
        }
        // Passing the same preflight-checked IP to the actual socket precludes
        // a second hostname resolution, including DNS rebinding to loopback.
        callback(null, pinned.address, pinned.family);
      },
    }, (response) => {
      if (response.statusCode !== 200
        || (response.headers["content-encoding"] && response.headers["content-encoding"] !== "identity")) {
        response.resume();
        settle(() => resolve(null));
        return;
      }
      response.on("data", (piece: Buffer) => {
        size += piece.length;
        if (size > MAX_HTTPS_RESPONSE_BYTES) {
          req.destroy(new Error("RESPONSE_TOO_LARGE"));
          return;
        }
        chunks.push(piece);
      });
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8").trimEnd();
        settle(() => resolve(candidateToken(text)));
      });
      response.on("error", (error: Error) => settle(() => reject(error)));
    });
    // Set a hard wall-clock cap: a malicious server cannot trickle 1 byte
    // every 3 seconds forever and evade the 4-second idle socket deadline.
    absoluteDeadline = setTimeout(() => {
      req.destroy(new Error("HTTPS_TOTAL_TIMEOUT"));
      settle(() => reject(new Error("HTTPS_TOTAL_TIMEOUT")));
    }, 5_000);
    absoluteDeadline.unref();
    req.setTimeout(4_000, () => req.destroy(new Error("HTTPS_IDLE_TIMEOUT")));
    req.on("error", (error: Error) => settle(() => reject(error)));
    req.end();
  });
}

/** Only a bounded, exact-domain proof lookup. No crawler or scanner. */
export async function discoverAssetOwnershipProof(
  canonicalOrigin: string, method: OwnershipMethod, resolver: Resolver = dns,
): Promise<string | null> {
  const url = new URL(canonicalAssetOrigin(canonicalOrigin));
  if (method === "dns_txt") return getDnsOwnershipProof(url.hostname, resolver);
  if (method === "https_file") return getHttpsOwnershipProof(url.hostname, resolver);
  throw new Error("UNSUPPORTED_VERIFICATION_METHOD");
}
