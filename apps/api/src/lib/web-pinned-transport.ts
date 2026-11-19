/* Adapted from founder-controlled Web source at audited
 * 10704777f758737927d70aed9c95c0f4f9d98e1c and Phase20
 * edfe0bb663c6be6c157176231e88bc35bd8b5331:
 * src/lib/pentest/network-safety.ts and node-read-only-transport.ts.
 * No source auth/grants, Next.js, external scanner or legacy DB imported.
 */
import { promises as dns } from "node:dns";
import { request as httpsRequest, type RequestOptions } from "node:https";
import { BlockList, isIP } from "node:net";
import type { ClientRequest, IncomingMessage } from "node:http";
import type { AuthorizedReadResponse } from "@lumicsec/web-security-engine";

export const WEB_READ_LIMITS = Object.freeze({
  maxRequests: 6, maxTotalBytes: 240_000, maxResponseBytes: 60_000,
  maxRequestMs: 2_000, maxDnsMs: 1_500, maxRuntimeMs: 15_000,
  maxConcurrency: 1, maxRedirects: 0, maxHeadersBytes: 8_192,
});
export type PinnedAddress = Readonly<{ address: string; family: 4 | 6 }>;
export type AddressResolver = (hostname: string, signal: AbortSignal) => Promise<readonly PinnedAddress[]>;
export type HttpsRequestFactory =
  (options: RequestOptions, onResponse: (response: IncomingMessage) => void) => ClientRequest;

const deny4 = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0",8],["10.0.0.0",8],["100.64.0.0",10],["127.0.0.0",8],
  ["169.254.0.0",16],["172.16.0.0",12],["192.0.0.0",24],
  ["192.0.2.0",24],["192.31.196.0",24],["192.52.193.0",24],
  ["192.88.99.0",24],["192.168.0.0",16],["192.175.48.0",24],
  ["198.18.0.0",15],["198.51.100.0",24],["203.0.113.0",24],
  ["224.0.0.0",4],["240.0.0.0",4],
] as const) deny4.addSubnet(address, prefix, "ipv4");
const deny6 = new BlockList();
for (const [address, prefix] of [
  ["2001::",23],["2001:db8::",32],["2002::",16],["3fff::",20],
] as const) deny6.addSubnet(address, prefix, "ipv6");

export class WebTransportDenied extends Error {
  constructor(readonly code: string) { super(code); }
}
const fail = (code: string): never => { throw new WebTransportDenied(code); };

export function isPublicWebAddress(address: string, family: number): boolean {
  if (isIP(address) !== family) return false;
  if (family === 4) return !deny4.check(address, "ipv4");
  if (family === 6) {
    if (address.includes("%") || address.includes(".")) return false;
    const first = Number.parseInt(address.split(":")[0] ?? "", 16);
    return Number.isInteger(first) && first >= 0x2000 && first < 0x4000
      && !deny6.check(address, "ipv6");
  }
  return false;
}

export function requireExactWebUrl(candidate: string, origin: string, method: "GET" | "HEAD" = "GET") {
  if (candidate.length > 2048 || candidate.includes("\\") ||
    [...candidate].some(ch => ch.charCodeAt(0) < 32 || ch.charCodeAt(0) === 127)) fail("WEB_URL_UNSAFE");
  let url: URL; let scope: URL;
  try { url = new URL(candidate); scope = new URL(origin); }
  catch { return fail("WEB_URL_INVALID"); }
  if (scope.protocol !== "https:" || scope.origin !== origin || scope.port ||
    isIP(scope.hostname) || !/^[a-z0-9.-]+$/.test(scope.hostname) ||
    /\.(?:local|localhost|internal|lan|home|corp|invalid|test|example|onion|arpa)$/.test(scope.hostname))
    fail("WEB_ORIGIN_UNSAFE");
  if (url.protocol !== "https:" || url.origin !== origin || url.port ||
    url.username || url.password || url.hash || url.search || method !== "GET" && method !== "HEAD")
    fail("WEB_EXACT_SCOPE_DENIED");
  if (/%(?:2e|2f|5c|25|00|0[ad])/i.test(url.pathname) ||
    /(?:^|\/)(?:logout|log-out|signout|sign-out|delete|remove|destroy|reset|checkout|payment|purchase|buy|transfer|unsubscribe|deactivate|withdraw|terminate|confirm|admin)(?:\/|$|[-_])/i.test(url.pathname))
    fail("WEB_PATH_BLOCKED");
  return url;
}

async function withinDeadline<T>(operation: Promise<T>, signal: AbortSignal, ms: number): Promise<T> {
  if (signal.aborted) return fail("WEB_CANCELLED");
  let timer: ReturnType<typeof setTimeout> | undefined;
  let listener: (() => void) | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new WebTransportDenied("WEB_DNS_TIMEOUT")), ms);
        listener = () => reject(new WebTransportDenied("WEB_CANCELLED"));
        signal.addEventListener("abort", listener, { once: true });
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
    if (listener) signal.removeEventListener("abort", listener);
  }
}

export async function resolveWebPublicAddresses(hostname: string, signal: AbortSignal): Promise<readonly PinnedAddress[]> {
  if (isIP(hostname) || !/^[a-z0-9.-]+$/.test(hostname)) fail("WEB_HOSTNAME_BLOCKED");
  const lookup = await withinDeadline(Promise.allSettled([
    dns.resolve4(hostname), dns.resolve6(hostname),
  ]), signal, WEB_READ_LIMITS.maxDnsMs);
  const answers: PinnedAddress[] = [];
  for (let familyIndex = 0; familyIndex < lookup.length; familyIndex++) {
    const result = lookup[familyIndex]!;
    if (result.status === "rejected") {
      const code = (result.reason as { code?: string } | null)?.code;
      if (code !== "ENODATA" && code !== "ENOTFOUND") fail("WEB_DNS_FAILED");
      continue;
    }
    for (const address of result.value) {
      const family = familyIndex === 0 ? 4 : 6;
      if (!isPublicWebAddress(address, family)) fail("WEB_PRIVATE_ADDRESS_BLOCKED");
      answers.push({ address, family });
      if (answers.length > 12) fail("WEB_DNS_ANSWER_LIMIT");
    }
  }
  if (!answers.length) fail("WEB_DNS_EMPTY");
  return answers;
}

function filteredHeaders(response: IncomingMessage) {
  const allow = [
    "content-type", "strict-transport-security", "content-security-policy",
    "content-security-policy-report-only", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy", "cache-control",
    "access-control-allow-origin", "access-control-allow-credentials",
    "vary", "set-cookie", "location", "content-encoding", "content-length",
  ];
  const headers: Record<string, string> = {};
  for (const name of allow) {
    const value = response.headers[name];
    if (typeof value === "string") headers[name] = value.slice(0, 1800);
    else if (Array.isArray(value)) headers[name] = value.slice(0, 10).join(", ").slice(0, 1800);
  }
  return headers;
}

/**
 * Socket is IP pinned via request.lookup, TLS uses original hostname and
 * default CA validation. No redirects are followed and no credentials sent.
 * Only the explicit test harness injects a requestFactory, never an API route.
 */
export class PublicPinnedWebTransport {
  constructor(
    private readonly resolver: AddressResolver = resolveWebPublicAddresses,
    private readonly requestFactory: HttpsRequestFactory = httpsRequest,
  ) {}

  async read(origin: string, candidate: string, input: Readonly<{
    signal: AbortSignal; method?: "GET" | "HEAD"; maxBytes: number;
  }>): Promise<AuthorizedReadResponse> {
    const method = input.method ?? "GET";
    const url = requireExactWebUrl(candidate, origin, method);
    if (input.signal.aborted) fail("WEB_CANCELLED");
    const addresses = await withinDeadline(
      this.resolver(url.hostname, input.signal), input.signal, WEB_READ_LIMITS.maxDnsMs,
    );
    if (!Array.isArray(addresses) || addresses.length === 0 || addresses.length > 12 ||
      addresses.some(a => !isPublicWebAddress(a.address, a.family))) fail("WEB_PRIVATE_ADDRESS_BLOCKED");
    const pinned = addresses[0]!;
    const maximum = Math.min(input.maxBytes, WEB_READ_LIMITS.maxResponseBytes);
    if (!Number.isSafeInteger(maximum) || maximum < 1) fail("WEB_RESPONSE_BUDGET");
    return new Promise((resolve, reject) => {
      let settled = false;
      let size = 0;
      const buffers: Buffer[] = [];
      const cleanup = () => { clearTimeout(timer); input.signal.removeEventListener("abort", cancelled); };
      const error = (reason: unknown) => {
        if (settled) return;
        settled = true; cleanup();
        reject(reason instanceof WebTransportDenied ? reason : new WebTransportDenied("WEB_NETWORK_FAILED"));
      };
      const cancelled = () => req.destroy(new WebTransportDenied("WEB_CANCELLED"));
      const done = (result: AuthorizedReadResponse) => {
        if (settled) return;
        settled = true; cleanup(); resolve(result);
      };
      const options: RequestOptions = {
        protocol: "https:", hostname: url.hostname, port: 443, path: url.pathname,
        method, servername: url.hostname, rejectUnauthorized: true, agent: false,
        maxHeaderSize: WEB_READ_LIMITS.maxHeadersBytes,
        headers: { host: url.host, accept: "text/html,application/xhtml+xml,text/plain,*/*;q=0.1",
          "accept-encoding": "identity", "user-agent": "LumicSec-Authorized-Passive/0.1" },
        lookup: (requested, _options, callback) => {
          if (requested !== url.hostname || !isPublicWebAddress(pinned.address, pinned.family)) {
            callback(new WebTransportDenied("WEB_PIN_DENIED"), "", 4); return;
          }
          if (_options.all) {
            const answerAll = callback as (error: Error | null,
              answers: Array<{ address: string; family: number }>) => void;
            answerAll(null, [{ address: pinned.address, family: pinned.family }]);
          } else callback(null, pinned.address, pinned.family);
        },
      };
      const req = this.requestFactory(options, (res) => {
        const headerBytes = res.rawHeaders.reduce((sum, s) => sum + Buffer.byteLength(s), 0);
        if (headerBytes > WEB_READ_LIMITS.maxHeadersBytes || res.rawHeaders.length > 80) {
          error(new WebTransportDenied("WEB_HEADERS_EXCEEDED")); res.destroy(); return;
        }
        const headers = filteredHeaders(res);
        if (headers["content-encoding"] && headers["content-encoding"] !== "identity") {
          error(new WebTransportDenied("WEB_COMPRESSED_RESPONSE_DENIED")); res.destroy(); return;
        }
        if (res.statusCode !== undefined && res.statusCode >= 300 && res.statusCode < 400) {
          // Redirects are denied, not followed. Prevents any scope expansion.
          error(new WebTransportDenied("WEB_REDIRECT_DENIED")); res.destroy(); return;
        }
        const length = Number(headers["content-length"] ?? "0");
        if (Number.isFinite(length) && length > maximum) {
          error(new WebTransportDenied("WEB_RESPONSE_BUDGET")); res.destroy(); return;
        }
        if (method === "HEAD") {
          res.destroy(); done({ status: res.statusCode ?? 502, headers, bodyBytes: new Uint8Array(), headersComplete: true });
          return;
        }
        res.on("data", (part: Buffer) => {
          size += part.length;
          if (size > maximum) {
            error(new WebTransportDenied("WEB_RESPONSE_BUDGET")); res.destroy(); return;
          }
          buffers.push(part);
        });
        res.on("end", () => done({ status: res.statusCode ?? 502, headers,
          bodyBytes: new Uint8Array(Buffer.concat(buffers, size)), headersComplete: true }));
        res.on("aborted", () => error(new WebTransportDenied("WEB_RESPONSE_ABORTED")));
        res.on("error", error);
      });
      const timer = setTimeout(() => req.destroy(new WebTransportDenied("WEB_REQUEST_TIMEOUT")),
        WEB_READ_LIMITS.maxRequestMs);
      req.setTimeout(WEB_READ_LIMITS.maxRequestMs, () =>
        req.destroy(new WebTransportDenied("WEB_REQUEST_TIMEOUT")));
      input.signal.addEventListener("abort", cancelled, { once: true });
      req.on("error", error);
      if (input.signal.aborted) cancelled(); else req.end();
    });
  }
}
