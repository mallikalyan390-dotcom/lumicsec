/* SINGLE ENTRY for the credential-free Docker worker bundle.
 * No database clients, HTTP session headers, lease tokens, host path access,
 * customer cookies, or arbitrary command execution are imported here.
 */
import { createServer, request as httpsRequest, type Server as HttpsServer } from "node:https";
import { execFileSync } from "node:child_process";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PublicPinnedWebTransport, type HttpsRequestFactory } from "../lib/web-pinned-transport.js";
import { executeUnprivilegedWebRead } from "./web-passive-core.js";
import { WEB_IPC_VERSION, parseWebIpcStart, webIpcResultSchema,
  MAX_WEB_IPC_INPUT, MAX_WEB_IPC_OUTPUT } from "./web-worker-ipc-contract.js";

type Fixture = "insecure" | "secure" | "slow" | "oversize" | "redirect";
const safeHeaders = Object.freeze({
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
  "x-frame-options": "DENY", "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer", "permissions-policy": "geolocation=()",
  "set-cookie": "session=synthetic; Path=/; Secure; HttpOnly; SameSite=Lax",
});

async function openIsolatedTlsFixture(fixture: Fixture, origin: string) {
  const directory = await mkdtemp(join(tmpdir(), "lumicsec-ephemeral-tls-"));
  const keyPath = join(directory, "tls.key");
  const certPath = join(directory, "tls.crt");
  try {
    const hostname = new URL(origin).hostname;
    // Ephemeral temporary TLS material exists solely INSIDE read-only/no-egress
    // container's 16MB private tmpfs. Never passed to host or persisted.
    execFileSync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048",
      "-nodes", "-keyout", keyPath, "-out", certPath, "-days", "1",
      "-subj", "/CN=" + hostname, "-addext", "subjectAltName=DNS:" + hostname],
    { stdio: "ignore", timeout: 3_000 });
    const cert = await readFile(certPath);
    const server: HttpsServer = createServer({
      key: await readFile(keyPath), cert,
    }, (request, response) => {
      if (request.headers.host !== hostname || request.method !== "GET") {
        response.writeHead(403).end(); return;
      }
      if (fixture === "redirect") {
        response.writeHead(302, { location: "https://169.254.169.254/latest/meta-data/" });
        response.end(); return;
      }
      if (fixture === "oversize") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end("x".repeat(80_000)); return;
      }
      if (fixture === "slow") {
        const timer = setTimeout(() => {
          if (!response.writableEnded) response.end("<html>synthetic slow</html>");
        }, 4_000);
        timer.unref(); return;
      }
      if (fixture === "secure") {
        response.writeHead(200, { "content-type": "text/html", ...safeHeaders });
        response.end("<html><body>synthetic secure comparison</body></html>");
        return;
      }
      response.writeHead(200, {
        "content-type": "text/html", "set-cookie": "session=opaque; Path=/",
      });
      response.end("<html><body>synthetic insecure page</body></html>");
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.removeListener("error", reject); resolve();
      });
    });
    const address = server.address();
    if (!address || typeof address === "string") throw Error("WEB_FIXTURE_BIND_FAILED");
    const factory: HttpsRequestFactory = (options, callback) => httpsRequest({
      ...options, port: address.port, ca: cert,
      lookup: (_hostname, settings, answer) => {
        if (settings.all) {
          const all = answer as (error: Error | null,
            addresses: { address: string; family: number }[]) => void;
          all(null, [{ address: "127.0.0.1", family: 4 }]);
        } else answer(null, "127.0.0.1", 4);
      },
    }, callback);
    const transport = new PublicPinnedWebTransport(
      async () => [{ address: "8.8.8.8", family: 4 as const }], factory,
    );
    return {
      transport,
      async close() {
        server.closeAllConnections();
        await new Promise<void>(resolve => server.close(() => resolve()));
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch {
    await rm(directory, { recursive: true, force: true });
    throw Error("WEB_EPHEMERAL_FIXTURE_SETUP_FAILED");
  }
}

async function readOneInput() {
  let bytes = 0;
  let text = "";
  for await (const data of process.stdin) {
    const part = Buffer.isBuffer(data) ? data : Buffer.from(data);
    bytes += part.byteLength;
    if (bytes > MAX_WEB_IPC_INPUT) throw Error("WEB_IPC_INPUT_OVERSIZE");
    text += part.toString("utf8");
  }
  if (!text.endsWith("\n") || text.indexOf("\n") !== text.length - 1)
    throw Error("WEB_IPC_EXACTLY_ONE_REQUEST");
  return parseWebIpcStart(text.slice(0, -1));
}

async function main() {
  // Refuse to start if credentials are accidentally propagated into this
  // process. Docker image's benign base environment is not a credential.
  const forbidden = Object.keys(process.env).filter(name =>
    /(?:SUPABASE|SECRET|TOKEN|AUTH|PASSWORD|COOKIE|JWT|API_KEY|DATABASE_URL)/i.test(name));
  if (forbidden.length) throw Error("WEB_ISOLATED_SECRET_ENV_DENIED");
  const command = await readOneInput();
  if (command.fixture !== "none" && process.env["LUMICSEC_ISOLATED_FIXTURE"] !== "yes")
    throw Error("WEB_ISOLATED_FIXTURE_MODE_DENIED");
  if (command.fixture === "crash") {
    // Explicit controlled crash regression. This branch cannot be selected by
    // customer-facing API; no partial evidence or privileged token exists here.
    process.kill(process.pid, "SIGKILL");
    return;
  }
  const abort = new AbortController();
  const timeout = setTimeout(() => abort.abort(), 15_000);
  const fixture = command.fixture === "none" ? null :
    await openIsolatedTlsFixture(command.fixture, command.scope.origin);
  try {
    const result = await executeUnprivilegedWebRead({
      scope: command.scope, signal: abort.signal,
      ...(fixture ? { transport: fixture.transport } : {}),
    });
    const output = webIpcResultSchema.parse({
      protocol: WEB_IPC_VERSION, type: "RESULT", executionId: command.executionId,
      jobId: command.scope.jobId, scopeHash: command.scope.scopeHash,
      report: result.report, observations: result.observations,
    });
    const serialized = JSON.stringify(output);
    if (Buffer.byteLength(serialized) > MAX_WEB_IPC_OUTPUT)
      throw Error("WEB_IPC_OUTPUT_OVERSIZE");
    process.stdout.write(serialized + "\n");
  } finally {
    clearTimeout(timeout); abort.abort();
    await fixture?.close();
  }
}
main().catch(() => {
  // No stack traces, URLs, response bodies, or secrets on stdout/stderr.
  process.stderr.write("WEB_ISOLATED_EXECUTION_REJECTED\n");
  process.exitCode = 1;
});
