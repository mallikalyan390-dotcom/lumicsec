// Invoked only by the isolated TLS integration test in a separate Node process.
// Fixed synthetic host / identity. No service role, Supabase, public DNS or browser.
import { request as httpsRequest } from "node:https";
import { readFile } from "node:fs/promises";
import { PublicPinnedWebTransport, type HttpsRequestFactory } from "../../src/lib/web-pinned-transport.js";
import { executeClaimedWebAssessment, type WebWorkerStore,
  type WebWorkerClaim } from "../../src/workers/web-assessment-worker.js";

async function run() {
  const port = Number(process.argv[2]);
  const certPath = process.argv[3];
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535 || !certPath)
    throw Error("INVALID_SYNTHETIC_WORKER_FIXTURE");
  const cert = await readFile(certPath);
  const origin = "https://insecure.fixture-web.net";
  const scopeHash = "a".repeat(64);
  const jobId = "00000000-0000-4000-8000-000000000044";
  const claim: WebWorkerClaim = {
    jobId, organizationId: "00000000-0000-4000-8000-000000000011",
    assetId: "00000000-0000-4000-8000-000000000022",
    actorId: "00000000-0000-4000-8000-000000000033",
    origin, scopeHash, token: "b".repeat(64), generation: 1,
  };
  let committed = false;
  const store: WebWorkerStore = {
    claim: async () => claim,
    heartbeat: async () => true,
    complete: async (_claim, observations) => {
      committed = observations.length > 0;
      return committed;
    },
    stop: async () => true,
  };
  const fixtureFactory: HttpsRequestFactory = (opts, onResponse) => httpsRequest({
    ...opts, port, ca: cert,
    lookup: (_host, options, callback) => {
      if (options.all) {
        const cb = callback as (error: Error | null,
          addresses: Array<{ address: string; family: number }>) => void;
        cb(null, [{ address: "127.0.0.1", family: 4 }]);
      } else callback(null, "127.0.0.1", 4);
    },
  }, onResponse);
  const transport = new PublicPinnedWebTransport(
    async () => [{ address: "8.8.8.8", family: 4 as const }], fixtureFactory,
  );
  const result = await executeClaimedWebAssessment({ jobId, scopeHash, store, transport });
  const evidence = result.observations.map(item => item.ruleId).sort();
  process.stdout.write(JSON.stringify({
    isolatedProcess: true, committed, requests: result.report.requests,
    observations: evidence, scope: "synthetic-owned-local-TLS-only",
  }) + "\n");
}
run().catch(() => { process.stderr.write("ISOLATED_WEB_FIXTURE_FAILED\n"); process.exitCode = 1; });
