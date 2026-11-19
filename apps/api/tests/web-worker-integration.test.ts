import { createServer, type Server as HttpsServer } from "node:https";
import { request as httpsRequest } from "node:https";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { WEB_READ_LIMITS, PublicPinnedWebTransport, isPublicWebAddress,
  requireExactWebUrl,
  type HttpsRequestFactory } from "../src/lib/web-pinned-transport.js";
import { executeClaimedWebAssessment, type WebWorkerClaim,
  type WebAssessmentEvidence, type WebWorkerStore,
  type WebAssessmentReport } from "../src/workers/web-assessment-worker.js";

const execFileAsync = promisify(execFile);
const ORG = "00000000-0000-4000-8000-000000000011";
const ASSET = "00000000-0000-4000-8000-000000000022";
const ACTOR = "00000000-0000-4000-8000-000000000033";
const JOB = "00000000-0000-4000-8000-000000000044";
const SCOPE = "a".repeat(64);
const TOKEN = "b".repeat(64);
const INSECURE = "https://insecure.fixture-web.net";
const SECURE = "https://secure.fixture-web.net";
const REDIRECT = "https://redirect.fixture-web.net";
const TOO_BIG = "https://big.fixture-web.net";
const SLOW = "https://slow.fixture-web.net";
const MANY = "https://many.fixture-web.net";
const ALL_DOMAINS = [
  "insecure.fixture-web.net","secure.fixture-web.net",
  "redirect.fixture-web.net","big.fixture-web.net",
  "slow.fixture-web.net","many.fixture-web.net",
];
let dir: string;
let cert: Buffer;
let server: HttpsServer;
let port: number;
const paths: string[] = [];
const seenHosts: string[] = [];
const insecureHTML = `<!doctype html><html><body><a href="/next">next</a></body></html>`;
const secureHeaders = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "permissions-policy": "geolocation=()",
  "set-cookie": "session=synthetic; Secure; HttpOnly; SameSite=Lax; Path=/",
};

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "lumicsec-web-tls-"));
  const keyPath = join(dir, "fixture.key");
  const certPath = join(dir, "fixture.crt");
  // Ephemeral self-signed fixture CA never committed or logged.
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", keyPath, "-out", certPath, "-days", "1",
    "-subj", "/CN=insecure.fixture-web.net",
    "-addext", "subjectAltName=" + ALL_DOMAINS.map(d => "DNS:" + d).join(",")],
  { stdio: "ignore" });
  cert = await readFile(certPath);
  server = createServer({ key: await readFile(keyPath), cert }, (req, res) => {
    const host = (req.headers.host ?? "").toLowerCase();
    const path = req.url ?? "/";
    seenHosts.push(host);
    paths.push(host + path);
    if (host.startsWith("redirect.")) {
      res.writeHead(302, { location: "https://169.254.169.254/latest/meta-data/" });
      res.end(); return;
    }
    if (host.startsWith("big.")) {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("x".repeat(80_000)); return;
    }
    if (host.startsWith("slow.")) {
      setTimeout(() => {
        if (!res.writableEnded) res.end("<html>slow</html>");
      }, 4_000);
      return;
    }
    if (host.startsWith("secure.")) {
      res.writeHead(200, { "content-type": "text/html", ...secureHeaders });
      res.end("<html><body>Safe comparator</body></html>"); return;
    }
    if (host.startsWith("many.")) {
      res.writeHead(200, { "content-type": "text/html", ...secureHeaders });
      res.end(path === "/"
        ? "<html><body>" + Array.from({ length: 18 }, (_, i) => `<a href="/p${i}">Page ${i}</a>`).join("") + "</body></html>"
        : "<html><body>bounded page</body></html>");
      return;
    }
    res.writeHead(200, { "content-type": "text/html",
      "set-cookie": "session=opaque; Path=/" });
    res.end(insecureHTML);
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw Error("FIXTURE_BIND_FAILED");
  port = address.port;
}, 15_000);
afterAll(async () => {
  await new Promise<void>(resolve => server.close(() => resolve()));
  await rm(dir, { recursive: true, force: true });
});

const syntheticPublicResolver = vi.fn(async () => [{ address: "8.8.8.8", family: 4 as const }]);
/** Test-only socket redirection into local TLS fixture, never used by customer routes.
 * The transport still performs URL, DNS pin validation and TLS hostname checking.
 */
function actualFixtureTransport() {
  const factory: HttpsRequestFactory = (options, callback) => {
    const request = httpsRequest({
      ...options, port, ca: cert,
      lookup: (_hostname, opts, respond) => {
        if (opts.all) {
          const answerAll = respond as (error: Error | null,
            answers: Array<{ address: string; family: number }>) => void;
          answerAll(null, [{ address: "127.0.0.1", family: 4 }]);
        } else respond(null, "127.0.0.1", 4);
      },
    }, callback);
    return request;
  };
  return new PublicPinnedWebTransport(syntheticPublicResolver, factory);
}
function mockStore(origin: string, opts: { heartbeat?: () => boolean; complete?: () => boolean } = {}) {
  const claim: WebWorkerClaim = {
    jobId: JOB, organizationId: ORG, assetId: ASSET, actorId: ACTOR,
    origin, scopeHash: SCOPE, token: TOKEN, generation: 1,
  };
  let observations: readonly WebAssessmentEvidence[] = [];
  let report: WebAssessmentReport | null = null;
  const store: WebWorkerStore = {
    claim: vi.fn(async () => claim),
    heartbeat: vi.fn(async () => opts.heartbeat?.() ?? true),
    complete: vi.fn(async (_claim, items, metadata) => {
      if (opts.complete && !opts.complete()) return false;
      observations = items; report = metadata;
      return true;
    }),
    stop: vi.fn(async () => true),
  };
  return { store, get observations() { return observations; },
    get report() { return report; } };
}

describe("real local TLS fixture + production worker logic", () => {
  it("detects actual missing passive security controls on insecure fixture", async () => {
    const state = mockStore(INSECURE);
    const result = await executeClaimedWebAssessment({
      jobId: JOB, scopeHash: SCOPE, store: state.store, transport: actualFixtureTransport(),
    });
    expect(result.state).toBe("succeeded");
    expect(result.report.fetched).toBeGreaterThan(0);
    expect(result.report.requests).toBeLessThanOrEqual(WEB_READ_LIMITS.maxRequests);
    expect(result.report.bytes).toBeLessThanOrEqual(WEB_READ_LIMITS.maxTotalBytes);
    const rules = result.observations.map(item => item.ruleId);
    expect(rules).toContain("P09.HSTS.ABSENT");
    expect(rules).toContain("P09.CSP.ABSENT");
    expect(rules).toContain("P09.FRAME.NO_POLICY");
    expect(rules).toContain("P09.COOKIE.SECURE_AGG");
    expect(result.observations.every(item => item.evidenceSource.nodeIds.length > 0
      && item.evidenceSource.fingerprints.length > 0
      && item.evidenceSource.paths.some(path => path.startsWith("/")))).toBe(true);
    expect(state.observations).toEqual(result.observations);
    expect(JSON.stringify(state.observations)).not.toContain("session=opaque");
    expect(JSON.stringify(state.observations)).not.toContain(insecureHTML);
    expect(paths.some(path => path === "insecure.fixture-web.net/")).toBe(true);
  });

  it("does not flag the same four rules on securely configured comparison fixture", async () => {
    const state = mockStore(SECURE);
    const result = await executeClaimedWebAssessment({
      jobId: JOB, scopeHash: SCOPE, store: state.store, transport: actualFixtureTransport(),
    });
    const rules = result.observations.map(item => item.ruleId);
    for (const rule of ["P09.HSTS.ABSENT","P09.CSP.ABSENT",
      "P09.FRAME.NO_POLICY","P09.COOKIE.SECURE_AGG"]) {
      expect(rules).not.toContain(rule);
    }
    expect(result.report.fetched).toBe(1);
    expect(state.store.complete).toHaveBeenCalledOnce();
  });

  it("rejects redirect to metadata endpoint without a second request", async () => {
    const before = paths.length;
    const state = mockStore(REDIRECT);
    await expect(executeClaimedWebAssessment({
      jobId: JOB, scopeHash: SCOPE, store: state.store, transport: actualFixtureTransport(),
    })).rejects.toThrow("WEB_REDIRECT_DENIED");
    expect(paths.length).toBe(before + 1);
    expect(state.store.complete).not.toHaveBeenCalled();
    expect(state.store.stop).toHaveBeenCalledOnce();
  });

  it("limits actual HTTPS response bytes and fails rather than saving partial evidence", async () => {
    const state = mockStore(TOO_BIG);
    await expect(executeClaimedWebAssessment({
      jobId: JOB, scopeHash: SCOPE, store: state.store, transport: actualFixtureTransport(),
    })).rejects.toThrow("WEB_RESPONSE_BUDGET");
    expect(state.store.complete).not.toHaveBeenCalled();
  });

  it("blocks slow real fixture by an absolute timeout", async () => {
    const state = mockStore(SLOW);
    await expect(executeClaimedWebAssessment({
      jobId: JOB, scopeHash: SCOPE, store: state.store, transport: actualFixtureTransport(),
    })).rejects.toThrow("WEB_REQUEST_TIMEOUT");
    expect(state.store.complete).not.toHaveBeenCalled();
  }, 9_000);

  it("never makes more than six real GET requests across a large discovery graph", async () => {
    const state = mockStore(MANY);
    const result = await executeClaimedWebAssessment({
      jobId: JOB, scopeHash: SCOPE, store: state.store, transport: actualFixtureTransport(),
    });
    expect(result.report.requests).toBe(WEB_READ_LIMITS.maxRequests);
    expect(result.report.fetched).toBe(WEB_READ_LIMITS.maxRequests);
  });

  it("aborts an in-flight socket on explicit cancellation and stores nothing", async () => {
    const controller = new AbortController();
    const state = mockStore(SLOW);
    setTimeout(() => controller.abort(), 60);
    await expect(executeClaimedWebAssessment({
      jobId: JOB, scopeHash: SCOPE, store: state.store, signal: controller.signal,
      transport: actualFixtureTransport(),
    })).rejects.toThrow();
    expect(state.store.complete).not.toHaveBeenCalled();
    expect(state.store.stop).toHaveBeenCalledOnce();
  });

  it("revoked claim during execution aborts and prevents result commit", async () => {
    let calls = 0;
    const state = mockStore(INSECURE, { heartbeat: () => ++calls <= 2 });
    await expect(executeClaimedWebAssessment({
      jobId: JOB, scopeHash: SCOPE, store: state.store, transport: actualFixtureTransport(),
    })).rejects.toThrow();
    expect(state.store.complete).not.toHaveBeenCalled();
  });

  it("atomic result-time revocation denies completion after a real fixture read", async () => {
    const state = mockStore(INSECURE, { complete: () => false });
    await expect(executeClaimedWebAssessment({
      jobId: JOB, scopeHash: SCOPE, store: state.store, transport: actualFixtureTransport(),
    })).rejects.toThrow("WEB_RESULT_COMMIT_DENIED");
    expect(state.store.stop).toHaveBeenCalledOnce();
  });

  it("a duplicate/stale claim cannot start another scan", async () => {
    const state = mockStore(INSECURE);
    state.store.claim = vi.fn(async () => null);
    await expect(executeClaimedWebAssessment({ jobId: JOB, scopeHash: SCOPE,
      store: state.store, transport: actualFixtureTransport() }))
      .rejects.toThrow("WEB_WORKER_ADMISSION_DENIED");
  });
});

describe("separately spawned OS worker on real controlled TLS fixture", () => {
  it("executes the bounded worker in a distinct Node process without any backend secrets", async () => {
    const { stdout, stderr } = await execFileAsync(process.execPath,
      ["--import", "tsx", "tests/fixtures/web-worker-process.ts",
        String(port), join(dir, "fixture.crt")],
      { cwd: process.cwd(), timeout: 12_000, maxBuffer: 100_000 });
    expect(stderr).toBe("");
    const result = JSON.parse(stdout.trim()) as {
      isolatedProcess: boolean; committed: boolean; requests: number; observations: string[];
    };
    expect(result.isolatedProcess).toBe(true);
    expect(result.committed).toBe(true);
    expect(result.requests).toBeGreaterThan(0);
    expect(result.requests).toBeLessThanOrEqual(6);
    expect(result.observations).toContain("P09.HSTS.ABSENT");
    expect(result.observations).toContain("P09.CSP.ABSENT");
  }, 16_000);
});

describe("network safety negative contract", () => {
  it.each(["127.0.0.1","10.1.2.3","169.254.169.254","100.100.100.200",
    "192.168.1.3","198.51.100.20","203.0.113.4","0.0.0.0"])(
    "rejects private, metadata or documentation IPv4 %s", address => {
      expect(isPublicWebAddress(address, 4)).toBe(false);
    });
  it.each(["::1","fc00::1","fe80::1","2001:db8::3","2002::1","::ffff:127.0.0.1"])(
    "rejects IPv6 private, documentation or tunnels %s", address => {
      expect(isPublicWebAddress(address, 6)).toBe(false);
    });
  it("allows strictly public addresses only", () => {
    expect(isPublicWebAddress("8.8.8.8", 4)).toBe(true);
    expect(isPublicWebAddress("2606:4700:4700::1111", 6)).toBe(true);
  });
  it.each(["https://127.0.0.1", "http://insecure.fixture-web.net",
    "https://insecure.fixture-web.net:8443", "https://insecure.fixture-web.net/delete",
    "https://insecure.fixture-web.net/?password=value",
    "https://evil.example.org/path","https://insecure.fixture-web.net/%2e%2e/admin"])(
    "fails exact origin, method, path, and query controls for %s", candidate => {
      expect(() => requireExactWebUrl(candidate, INSECURE)).toThrow();
    });
  it("rejects POST method", () => {
    expect(() => requireExactWebUrl(INSECURE + "/", INSECURE, "POST" as "GET")).toThrow();
  });
  it("revalidates DNS on every request and blocks a rebound to metadata", async () => {
    let n = 0;
    const resolver = vi.fn(async () =>
      ++n === 1 ? [{ address: "8.8.8.8", family: 4 as const }]
        : [{ address: "169.254.169.254", family: 4 as const }]);
    const transport = new PublicPinnedWebTransport(resolver, (_opts, _cb) => {
      throw Error("NETWORK_FACTORY_NEVER_EXPECTED");
    });
    const signal = new AbortController().signal;
    await expect(transport.read(INSECURE, INSECURE + "/",
      { signal, maxBytes: 1024 })).rejects.toThrow("NETWORK_FACTORY_NEVER_EXPECTED");
    await expect(transport.read(INSECURE, INSECURE + "/",
      { signal, maxBytes: 1024 })).rejects.toThrow("WEB_PRIVATE_ADDRESS_BLOCKED");
    expect(n).toBe(2);
  });
  it("rejects resolver returning any mixed public/private address", async () => {
    const resolver = vi.fn(async () => [{ address: "8.8.8.8", family: 4 as const },
      { address: "10.0.0.1", family: 4 as const }]);
    const transport = new PublicPinnedWebTransport(resolver);
    await expect(transport.read(INSECURE, INSECURE + "/", {
      signal: new AbortController().signal, maxBytes: 1000,
    })).rejects.toThrow("WEB_PRIVATE_ADDRESS_BLOCKED");
  });
  it("rejects stalled resolver before a socket is created", async () => {
    const transport = new PublicPinnedWebTransport(
      async () => new Promise(() => {}), (_opts, _cb) => { throw Error("NO_SOCKET_ALLOWED"); });
    await expect(transport.read(INSECURE, INSECURE + "/", {
      signal: new AbortController().signal, maxBytes: 100,
    })).rejects.toThrow("WEB_DNS_TIMEOUT");
  }, 5_000);
});
