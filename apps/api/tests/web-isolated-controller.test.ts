import { describe, expect, it, vi } from "vitest";
import { executeWebSandboxController } from "../src/workers/web-isolated-controller.js";
import { parseWebIpcResult, WEB_IPC_VERSION,
  type WebIpcStart, type WebIpcResult } from "../src/workers/web-worker-ipc-contract.js";
import type { WebWorkerClaim, WebWorkerStore } from "../src/workers/web-assessment-worker.js";
const JOB = "00000000-0000-4000-8000-000000000044";
const ORG = "00000000-0000-4000-8000-000000000011";
const ASSET = "00000000-0000-4000-8000-000000000022";
const ACTOR = "00000000-0000-4000-8000-000000000033";
const SCOPE = "a".repeat(64);
const claim: WebWorkerClaim = {
  jobId: JOB, organizationId: ORG, assetId: ASSET, actorId: ACTOR,
  origin: "https://insecure.fixture-web.net", scopeHash: SCOPE,
  token: "b".repeat(64), generation: 1,
};
const fingerprint = "c".repeat(64);
const nodeId = "wdn_" + "d".repeat(24);
function makeResult(start: WebIpcStart): WebIpcResult {
  return {
    protocol: WEB_IPC_VERSION, type: "RESULT",
    executionId: start.executionId, jobId: start.scope.jobId,
    scopeHash: start.scope.scopeHash,
    report: {
      classification: "PASSIVE_WEB_REVIEW", analysisVersion: "web-assessment-analysis-v1",
      scopeHash: start.scope.scopeHash, snapshotFingerprint: fingerprint,
      requests: 1, fetched: 1, bytes: 69, failed: 0, coverageState: "BOUNDED",
      candidateCount: 1, observationCount: 1,
      limitations: ["Passive signal only"],
    },
    observations: [{
      ruleId: "P09.HSTS.ABSENT", title: "Synthetic header observation",
      summary: "Insecure fixture response lacked HSTS.",
      remediation: "Review the HSTS policy.", limitation: "Not proven exploitable.",
      severityEstimate: "low", classification: "DETERMINISTIC_CONFIGURATION_SIGNAL",
      evidenceSource: { nodeIds: [nodeId], fingerprints: [fingerprint], paths: ["/"] },
    }],
  };
}
function makeStore() {
  const store: WebWorkerStore = {
    claim: vi.fn(async () => claim),
    heartbeat: vi.fn(async () => true),
    complete: vi.fn(async () => true),
    stop: vi.fn(async () => true),
  };
  return store;
}
const defaultInput = { jobId: JOB, scopeHash: SCOPE,
  bundlePath: "/tmp/synthetic-placeholder.mjs" };

describe("trusted controller and zero-credential IPC", () => {
  it("persists only validated observations and withholds the DB lease token", async () => {
    const store = makeStore();
    const runner = vi.fn(async ({ request }: { request: WebIpcStart }) => {
      const bytes = JSON.stringify(request);
      expect(bytes).not.toContain(claim.token);
      expect(bytes).not.toContain("SUPABASE");
      expect(request.scope.organizationId).toBe(ORG);
      expect(request.scope.actorId).toBe(ACTOR);
      expect(request.fixture).toBe("none");
      return makeResult(request);
    });
    const result = await executeWebSandboxController({ ...defaultInput, store, runner });
    expect(result.observations.map(o => o.ruleId)).toEqual(["P09.HSTS.ABSENT"]);
    expect(store.claim).toHaveBeenCalledOnce();
    expect(store.complete).toHaveBeenCalledOnce();
    expect(store.stop).not.toHaveBeenCalled();
    expect(runner).toHaveBeenCalledOnce();
  });
  it("rejects tampered scope in worker output before DB persistence", async () => {
    const store = makeStore();
    await expect(executeWebSandboxController({ ...defaultInput, store,
      runner: async ({ request }) => ({ ...makeResult(request), jobId: ORG }),
    })).rejects.toThrow("WEB_IPC_SCOPE_OR_COUNT_MISMATCH");
    expect(store.complete).not.toHaveBeenCalled();
    expect(store.stop).toHaveBeenCalledOnce();
  });
  it("rejects unbounded or malformed evidence", async () => {
    const store = makeStore();
    await expect(executeWebSandboxController({ ...defaultInput, store,
      runner: async ({ request }) => ({
        ...makeResult(request),
        observations: [{ ...makeResult(request).observations[0]!, summary: "x".repeat(3_100) }],
      }),
    })).rejects.toThrow();
    expect(store.complete).not.toHaveBeenCalled();
  });
  it("denies observations with no captured source", () => {
    const start: WebIpcStart = {
      protocol: WEB_IPC_VERSION, type: "START", executionId: JOB,
      scope: { jobId: JOB, organizationId: ORG, assetId: ASSET,
        actorId: ACTOR, origin: claim.origin, scopeHash: SCOPE }, fixture: "none",
    };
    const result = makeResult(start);
    result.observations[0]!.evidenceSource.nodeIds.splice(0); // contract test
    expect(() => parseWebIpcResult(JSON.stringify(result), start))
      .toThrow("WEB_IPC_MISSING_EVIDENCE");
  });
  it("refuses duplicate simultaneous controller admission", async () => {
    const store = makeStore();
    const controller = new AbortController();
    const first = executeWebSandboxController({ ...defaultInput, store,
      signal: controller.signal,
      runner: ({ signal }) => new Promise((_resolve, reject) =>
        signal.addEventListener("abort", () => reject(Error("WEB_SANDBOX_CANCELLED")), { once: true })),
    });
    // controller has entered activeJobs synchronously.
    await expect(executeWebSandboxController({ ...defaultInput, store,
      runner: async ({ request }) => makeResult(request),
    })).rejects.toThrow("WEB_CONTROLLER_CAPACITY_OR_DUPLICATE");
    controller.abort();
    await expect(first).rejects.toThrow();
  });
  it("controller cancellation kills I/O and never persists", async () => {
    const store = makeStore();
    const controller = new AbortController();
    const first = executeWebSandboxController({ ...defaultInput, store,
      signal: controller.signal,
      runner: ({ signal }) => new Promise((_resolve, reject) =>
        signal.addEventListener("abort", () => reject(Error("WEB_SANDBOX_CANCELLED")), { once: true })),
    });
    setTimeout(() => controller.abort(), 20);
    await expect(first).rejects.toThrow("WEB_SANDBOX_CANCELLED");
    expect(store.complete).not.toHaveBeenCalled();
    expect(store.stop).toHaveBeenCalledOnce();
  });
  it("ownership revocation during processing aborts IPC", async () => {
    const store = makeStore();
    let n = 0;
    store.heartbeat = vi.fn(async () => ++n < 2);
    await expect(executeWebSandboxController({ ...defaultInput, store,
      runner: ({ signal }) => new Promise((_resolve, reject) =>
        signal.addEventListener("abort", () => reject(Error("WEB_SANDBOX_CANCELLED")), { once: true })),
    })).rejects.toThrow("WEB_SANDBOX_CANCELLED");
    expect(store.complete).not.toHaveBeenCalled();
  }, 4_000);
  it("a crashed disposable container retains its fenced lease for DB expiry/reclaim", async () => {
    const store = makeStore();
    await expect(executeWebSandboxController({ ...defaultInput, store,
      runner: async () => { throw Error("WEB_SANDBOX_PROCESS_CRASH"); },
    })).rejects.toThrow("WEB_SANDBOX_PROCESS_CRASH");
    expect(store.stop).not.toHaveBeenCalled();
    expect(store.complete).not.toHaveBeenCalled();
  });
  it("ordinary worker failure releases claim and records failed status", async () => {
    const store = makeStore();
    await expect(executeWebSandboxController({ ...defaultInput, store,
      runner: async () => { throw Error("WEB_SANDBOX_EXECUTION_FAILED"); },
    })).rejects.toThrow();
    expect(store.stop).toHaveBeenCalledWith(claim, true);
  });
  it("failed fenced result commit does not mark a job succeeded", async () => {
    const store = makeStore();
    store.complete = vi.fn(async () => false);
    await expect(executeWebSandboxController({ ...defaultInput, store,
      runner: async ({ request }) => makeResult(request),
    })).rejects.toThrow("WEB_CONTROLLER_RESULT_REVOKED");
    expect(store.stop).toHaveBeenCalled();
  });
  it("cannot claim when backend authorization is revoked", async () => {
    const store = makeStore();
    store.claim = vi.fn(async () => null);
    await expect(executeWebSandboxController({ ...defaultInput, store,
      runner: async ({ request }) => makeResult(request),
    })).rejects.toThrow("WEB_CONTROLLER_CLAIM_DENIED");
    expect(store.complete).not.toHaveBeenCalled();
  });
});
