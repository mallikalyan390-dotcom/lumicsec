import { EventEmitter } from "node:events";
import { request as httpsRequest } from "node:https";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  discoverAssetOwnershipProof, getDnsOwnershipProof, getHttpsOwnershipProof,
  isPublicAddress, resolvePublicAddresses,
} from "../src/lib/ownership-proof.js";

vi.mock("node:https", () => ({ request: vi.fn() }));
const syntheticToken = "a".repeat(64);
const fakeDns = (ipv4: string[], ipv6: string[] = [], txt: string[][] = []) => ({
  resolve4: vi.fn().mockResolvedValue(ipv4),
  resolve6: vi.fn().mockResolvedValue(ipv6),
  resolveTxt: vi.fn().mockResolvedValue(txt),
});

describe("SSRF-safe asset ownership proofs, synthetic resolution only", () => {
  beforeEach(() => vi.clearAllMocks());
  it.each([
    "127.0.0.1", "0.0.0.0", "10.0.0.1", "172.16.0.1", "192.168.1.1",
    "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.51.100.4",
    "203.0.113.7", "224.0.0.1", "240.0.0.1", "255.255.255.255",
    "::1", "::", "fc00::1", "fd00::1", "fe80::1", "ff02::1",
    "2001:db8::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8",
    "2002:0a00:0001::", "2001:0000::1",
  ])("rejects non-public IP: %s", (ip) => {
    expect(isPublicAddress(ip)).toBe(false);
  });

  it.each(["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])(
    "accepts routable IP: %s", (ip) => {
      expect(isPublicAddress(ip)).toBe(true);
    });

  it("rejects a mixed DNS answer containing any private address", async () => {
    const resolver = fakeDns(["93.184.216.34", "127.0.0.1"]);
    await expect(resolvePublicAddresses("example.com", resolver)).rejects
      .toThrow("PRIVATE_ADDRESS_BLOCKED");
    expect(resolver.resolveTxt).not.toHaveBeenCalled();
  });

  it("rejects DNS rebinding bait with a private IPv6 answer", async () => {
    await expect(resolvePublicAddresses("example.com",
      fakeDns(["93.184.216.34"], ["::ffff:127.0.0.1"]))).rejects
      .toThrow("PRIVATE_ADDRESS_BLOCKED");
  });

  it("fails closed when an A/AAAA DNS resolver stalls beyond the total deadline", async () => {
    const never = new Promise<string[]>(() => {});
    const resolver = fakeDns([]);
    resolver.resolve4.mockImplementation(() => never);
    resolver.resolve6.mockImplementation(() => never);
    await expect(resolvePublicAddresses("example.com", resolver, 10))
      .rejects.toThrow("DNS_LOOKUP_TIMEOUT");
    expect(resolver.resolveTxt).not.toHaveBeenCalled();
  });

  it("rejects DNS names without A or AAAA records", async () => {
    await expect(resolvePublicAddresses("example.com", fakeDns([]))).rejects
      .toThrow("DNS_RESOLUTION_UNSAFE");
  });

  it.each(["localhost", "127.0.0.1", "metadata.google.internal", "api.example.test"])(
    "rejects private or special hostnames before any verification request: %s", async (hostname) => {
      await expect(resolvePublicAddresses(hostname, fakeDns(["8.8.8.8"]))).rejects.toThrow();
    });

  it("requests TXT only for the exact asset host and parses full multi-string DNS TXT", async () => {
    const resolver = fakeDns(["93.184.216.34"], [], [
      ["unrelated=token"],
      ["lumicsec-verifica", "tion=" + syntheticToken],
    ]);
    const found = await getDnsOwnershipProof("example.com", resolver);
    expect(found).toBe(syntheticToken);
    expect(resolver.resolveTxt).toHaveBeenCalledExactlyOnceWith("_lumicsec-challenge.example.com");
  });

  it("does not accept a valid-looking token published on another domain", async () => {
    const resolver = fakeDns(["93.184.216.34"], [], [["domain=other"], ["wrong=" + syntheticToken]]);
    expect(await discoverAssetOwnershipProof("https://example.com", "dns_txt", resolver)).toBeNull();
    expect(resolver.resolveTxt).toHaveBeenCalledExactlyOnceWith("_lumicsec-challenge.example.com");
  });

  it("blocks redirect response and never follows it", async () => {
    const request = vi.mocked(httpsRequest);
    request.mockImplementationOnce(((_options: unknown, responseCallback: (response: unknown) => void) => {
      const req = new EventEmitter() as EventEmitter & {
        setTimeout: ReturnType<typeof vi.fn>; end: () => void; destroy: () => void;
      };
      req.setTimeout = vi.fn();
      req.destroy = vi.fn();
      req.end = () => {
        const res = new EventEmitter() as EventEmitter & {
          statusCode: number; headers: Record<string, string>; resume: ReturnType<typeof vi.fn>;
        };
        res.statusCode = 302;
        res.headers = { location: "http://127.0.0.1/internal" };
        res.resume = vi.fn();
        responseCallback(res);
      };
      return req;
    }) as typeof httpsRequest);
    const proof = await getHttpsOwnershipProof("example.com", fakeDns(["93.184.216.34"]));
    expect(proof).toBeNull();
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("pins the actual HTTPS socket to the validated public IP with TLS enabled", async () => {
    const request = vi.mocked(httpsRequest);
    let pinned = "";
    request.mockImplementationOnce(((options: {
      hostname: string; path: string; rejectUnauthorized: boolean;
      servername: string; agent: boolean;
      lookup: (hostname: string, options: object, callback: (error: Error | null, address: string, family: number) => void) => void;
    }, responseCallback: (response: unknown) => void) => {
      expect(options.hostname).toBe("example.com");
      expect(options.path).toBe("/.well-known/lumicsec-verification.txt");
      expect(options.rejectUnauthorized).toBe(true);
      expect(options.servername).toBe("example.com");
      expect(options.agent).toBe(false);
      options.lookup("example.com", {}, (_error: unknown, address: string) => { pinned = address; });
      const req = new EventEmitter() as EventEmitter & {
        setTimeout: ReturnType<typeof vi.fn>; end: () => void; destroy: () => void;
      };
      req.setTimeout = vi.fn();
      req.destroy = vi.fn();
      req.end = () => {
        const res = new EventEmitter() as EventEmitter & {
          statusCode: number; headers: Record<string, string>;
        };
        res.statusCode = 200;
        res.headers = { "content-type": "text/plain" };
        responseCallback(res);
        queueMicrotask(() => {
          res.emit("data", Buffer.from("lumicsec-verification=" + syntheticToken + "\n"));
          res.emit("end");
        });
      };
      return req;
    }) as unknown as typeof httpsRequest);
    const resolver = fakeDns(["93.184.216.34"]);
    const result = await getHttpsOwnershipProof("example.com", resolver);
    expect(result).toBe(syntheticToken);
    expect(pinned).toBe("93.184.216.34");
    expect(resolver.resolve4).toHaveBeenCalledTimes(1);
    expect(request).toHaveBeenCalledTimes(1);
  });
});
