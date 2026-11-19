/** Explicit opt-in REAL Docker sandbox tests.
 * CI without this preloaded pinned image SKIPS the suite, not a passed gate.
 * Run: pnpm --filter @lumicsec/api build:isolated-web
 *      pnpm --filter @lumicsec/api test:sandbox
 * All containers are --rm --network none, never touch host firewall/DNS.
 */
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { executeWebSandboxController, type IsolationFixture } from "../src/workers/web-isolated-controller.js";
import type { WebWorkerClaim, WebWorkerStore, WebAssessmentEvidence } from "../src/workers/web-assessment-worker.js";

const IMAGE = "sha256:35e7c432242067a653e10bd96d9de5913ad35e60b884f2245ec7e43a41dc38f2";
const JOB = "00000000-0000-4000-8000-000000000044";
const SCOPE = "a".repeat(64);
const ACTOR = "00000000-0000-4000-8000-000000000033";
const ORG = "00000000-0000-4000-8000-000000000011";
const ASSET = "00000000-0000-4000-8000-000000000022";
const bundlePath = resolve(process.cwd(), "dist/isolated/web-worker.mjs");
const enabled = process.env["LUMICSEC_RUN_DOCKER_SANDBOX"] === "1";
function storeFor(fixture: IsolationFixture) {
  const claim: WebWorkerClaim = {
    jobId: JOB, actorId: ACTOR, organizationId: ORG, assetId: ASSET,
    origin: "https://" + (fixture === "secure" ? "secure" : fixture === "redirect"
      ? "redirect" : fixture === "slow" ? "slow" : fixture === "oversize"
        ? "oversize" : "insecure") + ".fixture-web.net",
    scopeHash: SCOPE, generation: 1, token: "b".repeat(64),
  };
  let persisted: readonly WebAssessmentEvidence[] = [];
  const store: WebWorkerStore = {
    claim: vi.fn(async () => claim),
    heartbeat: vi.fn(async () => true),
    complete: vi.fn(async (_claim, evidence) => { persisted = evidence; return true; }),
    stop: vi.fn(async () => true),
  };
  return { store, get persisted() { return persisted; } };
}
const checkRules = ["P09.HSTS.ABSENT", "P09.CSP.ABSENT",
  "P09.FRAME.NO_POLICY", "P09.COOKIE.SECURE_AGG"];
function dockerProbe(source: string) {
  const args = [
    "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--pids-limit", "24", "--memory", "128m", "--memory-swap", "128m",
    "--cpus", "0.5", "--user", "65534:65534",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
    "--entrypoint", "/usr/bin/node", IMAGE, "-e", source,
  ];
  return execFileSync("docker", args, { encoding: "utf8", timeout: 14_000,
    env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: "/tmp" } });
}
const testSuite = enabled ? describe : describe.skip;
testSuite("REAL no-egress Docker isolation and controller IPC", () => {
  it("uses an actual kernel network namespace with no external/metadata egress", () => {
    const raw = dockerProbe(`const net=require('node:net');
      Promise.all(['1.1.1.1','169.254.169.254','127.0.0.1'].map(host=>
      new Promise(resolve=>{
        const s=net.connect({host,port:443,timeout:800});
        s.on('connect',()=>{s.destroy();resolve({host,blocked:false})});
        s.on('error',e=>resolve({host,blocked:true,code:e.code}));
        s.on('timeout',()=>{s.destroy();resolve({host,blocked:true,code:'TIMEOUT'})});
      }))).then(data=>console.log(JSON.stringify(data)));`);
    const addresses = JSON.parse(raw) as Array<{host:string;blocked:boolean;code:string}>;
    expect(addresses).toHaveLength(3);
    expect(addresses[0]).toMatchObject({host:"1.1.1.1",blocked:true,code:"ENETUNREACH"});
    expect(addresses[1]).toMatchObject({host:"169.254.169.254",blocked:true,code:"ENETUNREACH"});
    expect(addresses[2]).toMatchObject({host:"127.0.0.1",blocked:true,code:"ECONNREFUSED"});
  }, 16_000);

  it("enforces non-root, read-only rootfs, no host env/secrets/socket and resource cgroups", () => {
    // This deliberately contains a canary secret in the HOST TEST process.
    // Docker's allowlisted CLI environment must NOT forward it to the worker.
    process.env["SUPABASE_SECRET_KEY"] = "SYNTHETIC_CANARY_NOT_REAL_SECRET";
    try {
      const raw = dockerProbe(`const fs=require('node:fs');
        let readonly=false;try{fs.writeFileSync('/etc/no-write-test','x')}catch(e){readonly=true}
        const exists=p=>fs.existsSync(p);
        const read=p=>{try{return fs.readFileSync(p,'utf8').trim()}catch{return 'UNKNOWN'}};
        console.log(JSON.stringify({
          uid:process.getuid(),rootReadonly:readonly,
          hostEnv:process.env.SUPABASE_SECRET_KEY||null,
          dockerSock:exists('/var/run/docker.sock'),
          founderHome:exists('/home/kalyan/lumicsec'),
          memory:read('/sys/fs/cgroup/memory.max'),
          pids:read('/sys/fs/cgroup/pids.max'),
          cpu:read('/sys/fs/cgroup/cpu.max'),
        }));`);
      const observed = JSON.parse(raw) as {
        uid:number;rootReadonly:boolean;hostEnv:string|null;dockerSock:boolean;
        founderHome:boolean;memory:string;pids:string;cpu:string;
      };
      expect(observed.uid).toBe(65534);
      expect(observed.rootReadonly).toBe(true);
      expect(observed.hostEnv).toBeNull();
      expect(observed.dockerSock).toBe(false);
      expect(observed.founderHome).toBe(false);
      expect(Number(observed.memory)).toBeLessThanOrEqual(134217728);
      expect(Number(observed.pids)).toBeLessThanOrEqual(24);
      expect(observed.cpu).toMatch(/^50000 100000$/);
    } finally {
      delete process.env["SUPABASE_SECRET_KEY"];
    }
  }, 16_000);

  it("controlled insecure TLS fixture: expected four configuration signals persisted via IPC", async () => {
    const state = storeFor("insecure");
    const result = await executeWebSandboxController({ jobId: JOB, scopeHash: SCOPE,
      store: state.store, bundlePath, fixture: "insecure" });
    const actual = result.observations.map(i => i.ruleId);
    for (const rule of checkRules) expect(actual).toContain(rule);
    expect(result.report.requests).toBeGreaterThan(0);
    expect(result.report.bytes).toBeLessThan(240_000);
    expect(result.observations.every(o => o.evidenceSource.paths.includes("/"))).toBe(true);
    expect(state.persisted).toEqual(result.observations);
    expect(state.store.complete).toHaveBeenCalledOnce();
    expect(JSON.stringify(result)).not.toContain("session=opaque");
    expect(JSON.stringify(result)).not.toContain("bbbbbbbb");
  }, 16_000);

  it("controlled secure TLS fixture: same four rules produce no false alerts", async () => {
    const state = storeFor("secure");
    const result = await executeWebSandboxController({ jobId: JOB, scopeHash: SCOPE,
      store: state.store, bundlePath, fixture: "secure" });
    const actual = result.observations.map(o => o.ruleId);
    for (const rule of checkRules) expect(actual).not.toContain(rule);
    expect(result.report.fetched).toBe(1);
    expect(state.store.complete).toHaveBeenCalledOnce();
  }, 16_000);

  it.each(["oversize", "redirect", "slow"] as const)(
    "real isolated %s fixture fails closed without persisting partial evidence", async fixture => {
      const state = storeFor(fixture);
      await expect(executeWebSandboxController({ jobId: JOB, scopeHash: SCOPE,
        store: state.store, bundlePath, fixture })).rejects.toThrow("WEB_SANDBOX_EXECUTION_FAILED");
      expect(state.store.complete).not.toHaveBeenCalled();
      expect(state.store.stop).toHaveBeenCalledOnce();
    }, 16_000);

  it("kills a real in-progress Docker worker after controller cancellation", async () => {
    const state = storeFor("slow");
    const aborter = new AbortController();
    const started = Date.now();
    const running = executeWebSandboxController({ jobId: JOB, scopeHash: SCOPE,
      store: state.store, bundlePath, fixture: "slow", signal: aborter.signal });
    setTimeout(() => aborter.abort(), 900);
    await expect(running).rejects.toThrow("WEB_SANDBOX_CANCELLED");
    expect(Date.now()-started).toBeLessThan(4_000);
    expect(state.store.complete).not.toHaveBeenCalled();
    expect(state.store.stop).toHaveBeenCalledWith(expect.anything(), false);
  }, 12_000);

  it("a real worker SIGKILL cannot forge result or persist evidence", async () => {
    const state = storeFor("crash");
    await expect(executeWebSandboxController({ jobId: JOB, scopeHash: SCOPE,
      store: state.store, bundlePath, fixture: "crash" }))
      .rejects.toThrow("WEB_SANDBOX_PROCESS_CRASH");
    expect(state.store.complete).not.toHaveBeenCalled();
    expect(state.store.stop).not.toHaveBeenCalled();
    // DB generation-1 lease remains until expiry, as qualified by the
    // real PostgreSQL web-worker-lifecycle.sql recovery regression.
  }, 16_000);
});
