/* Trusted controller only. Owns service-role DB store / lease token.
 * The disposable container sees ONLY an allowlisted scope over stdin and
 * returns validated bounded evidence over stdout. No credential env, args,
 * mounts or Docker socket are supplied to the network-facing process.
 */
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import { extname } from "node:path";
import type { WebWorkerClaim, WebWorkerStore, WebAssessmentEvidence,
  WebAssessmentReport } from "./web-assessment-worker.js";
import { parseWebIpcResult, webIpcStartSchema, WEB_IPC_VERSION,
  MAX_WEB_IPC_OUTPUT, type WebIpcStart, type WebIpcResult } from "./web-worker-ipc-contract.js";
import { WEB_READ_LIMITS, requireExactWebUrl } from "../lib/web-pinned-transport.js";

const IMMUTABLE_LOCAL_IMAGE =
  "sha256:35e7c432242067a653e10bd96d9de5913ad35e60b884f2245ec7e43a41dc38f2";
const MAX_SIMULTANEOUS_SANDBOXES = 2;
const activeJobs = new Set<string>();
export type IsolationFixture = "none" | "insecure" | "secure" | "slow" | "oversize" | "redirect" | "crash";
export type IsolatedContainerInput = Readonly<{
  request: WebIpcStart; bundlePath: string; signal: AbortSignal;
}>;
export type IsolatedContainerRunner = (input: IsolatedContainerInput) => Promise<WebIpcResult>;

/** Container refuses ALL outbound network, including metadata endpoints.
 * A synthetic in-container loopback TLS fixture exists only in test mode.
 * Intentionally not a production public Internet scanning execution profile.
 */
export async function runNoEgressDockerSandbox(input: IsolatedContainerInput) {
  if (input.signal.aborted) throw Error("WEB_SANDBOX_CANCELLED");
  const file = await realpath(input.bundlePath);
  if (extname(file) !== ".mjs" || !(await stat(file)).isFile())
    throw Error("WEB_SANDBOX_BUNDLE_INVALID");
  const serialized = JSON.stringify(input.request) + "\n";
  const containerName = "lumicsec-passive-" + randomUUID();
  const args = [
    "run", "--rm", "--interactive", "--pull", "never",
    "--name", containerName,
    "--network", "none", "--read-only",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--pids-limit", "24", "--memory", "128m", "--memory-swap", "128m",
    "--cpus", "0.5", "--user", "65534:65534",
    "--ulimit", "nofile=64:64", "--ulimit", "nproc=24:24",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
    "--workdir", "/tmp", "--hostname", "lumicsec-isolated",
    "--mount", "type=bind,src=" + file + ",dst=/opt/lumicsec-isolated/worker.mjs,readonly",
    ...(input.request.fixture === "none" ? [] : ["--env", "LUMICSEC_ISOLATED_FIXTURE=yes"]),
    "--entrypoint", "/usr/bin/node",
    IMMUTABLE_LOCAL_IMAGE, "/opt/lumicsec-isolated/worker.mjs",
  ];
  return new Promise<WebIpcResult>((resolve, reject) => {
    let output = "";
    let errors = 0;
    let stderrIndicator = "";
    let finished = false;
    let cancellation = input.signal.aborted;
    // The host docker CLI also gets a minimal environment, never the host
    // SUPABASE_SECRET_KEY, shell profiles or OAuth session variables.
    const cleanEnvironment = { PATH: process.env['PATH'] ?? "/usr/bin:/bin", HOME: "/tmp" };
    const child = spawn("docker", args, { env: cleanEnvironment, stdio: ["pipe", "pipe", "pipe"] });
    const killContainer = () => {
      cancellation = true;
      // Docker kill targets ONLY this unique disposable container. No host
      // firewall/network mutation or unrelated running containers touched.
      const killer = spawn("docker", ["kill", "--signal", "KILL", containerName],
        { env: cleanEnvironment, stdio: "ignore" });
      killer.on("error", () => undefined);
      // Guard docker CLI itself if daemon hangs after abort.
      setTimeout(() => { if (!finished) child.kill("SIGKILL"); }, 1_500).unref();
    };
    input.signal.addEventListener("abort", killContainer, { once: true });
    const timeout = setTimeout(killContainer, WEB_READ_LIMITS.maxRuntimeMs + 2_000);
    child.stdout.on("data", (data: Buffer) => {
      output += data.toString("utf8");
      if (Buffer.byteLength(output) > MAX_WEB_IPC_OUTPUT + 1) killContainer();
    });
    child.stderr.on("data", (data: Buffer) => {
      errors += data.byteLength;
      if (errors <= 1_024) stderrIndicator += data.toString("utf8");
      if (errors > 1_024) killContainer();
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(serialized);
    child.on("error", () => { cancellation = true; });
    child.on("close", (code, signal) => {
      finished = true; clearTimeout(timeout);
      input.signal.removeEventListener("abort", killContainer);
      if (cancellation || input.signal.aborted)
        return reject(Error("WEB_SANDBOX_CANCELLED"));
      if (code !== 0 || signal || output.length === 0)
        return reject(Error(stderrIndicator.includes("WEB_ISOLATED_EXECUTION_REJECTED")
          ? "WEB_SANDBOX_EXECUTION_FAILED" : "WEB_SANDBOX_PROCESS_CRASH"));
      try {
        if (!output.endsWith("\n") || output.indexOf("\n") !== output.length - 1)
          throw Error("WEB_IPC_EXTRA_OUTPUT_DENIED");
        resolve(parseWebIpcResult(output.slice(0,-1), input.request));
      } catch { reject(Error("WEB_IPC_RESULT_VALIDATION_DENIED")); }
    });
  });
}

export async function executeWebSandboxController(input: Readonly<{
  store: WebWorkerStore; jobId: string; scopeHash: string;
  bundlePath: string; signal?: AbortSignal;
  fixture?: IsolationFixture;
  runner?: IsolatedContainerRunner;
}>): Promise<Readonly<{ report: WebAssessmentReport; observations: readonly WebAssessmentEvidence[] }>> {
  if (activeJobs.has(input.jobId) || activeJobs.size >= MAX_SIMULTANEOUS_SANDBOXES)
    throw Error("WEB_CONTROLLER_CAPACITY_OR_DUPLICATE");
  activeJobs.add(input.jobId);
  let claim: WebWorkerClaim | null = null;
  let committed = false;
  let processCrash = false;
  const controller = new AbortController();
  const abort = () => controller.abort();
  input.signal?.addEventListener("abort", abort, { once: true });
  let timer: ReturnType<typeof setInterval> | undefined;
  let deadline: ReturnType<typeof setTimeout> | undefined;
  let inFlight: Promise<void> | null = null;
  let lostLease = false;
  try {
    claim = await input.store.claim({
      jobId: input.jobId, scopeHash: input.scopeHash, workerId: randomUUID(),
    });
    if (!claim) throw Error("WEB_CONTROLLER_CLAIM_DENIED");
    if (claim.jobId !== input.jobId || claim.scopeHash !== input.scopeHash ||
      !/^[a-f0-9]{64}$/.test(claim.token) || claim.generation < 1 || claim.generation > 2)
      throw Error("WEB_CONTROLLER_UNTRUSTED_CLAIM");
    requireExactWebUrl(claim.origin + "/", claim.origin);
    // The claim token is never serialized to the worker.
    const command = webIpcStartSchema.parse({
      protocol: WEB_IPC_VERSION, type: "START", executionId: randomUUID(),
      scope: { jobId: claim.jobId, organizationId: claim.organizationId,
        assetId: claim.assetId, actorId: claim.actorId, origin: claim.origin,
        scopeHash: claim.scopeHash },
      fixture: input.fixture ?? "none",
    });
    const fencedClaim = claim;
    const heartbeat = async () => {
      if (controller.signal.aborted) return;
      if (inFlight) return inFlight;
      const ongoing = (async () => {
        try {
          if (!await input.store.heartbeat(fencedClaim)) {
            lostLease = true; abort();
          }
        } catch { lostLease = true; abort(); }
      })();
      inFlight = ongoing;
      try { await ongoing; } finally { inFlight = null; }
    };
    await heartbeat();
    if (lostLease || controller.signal.aborted) throw Error("WEB_CONTROLLER_LEASE_LOST");
    timer = setInterval(() => { void heartbeat(); }, 500);
    deadline = setTimeout(abort, WEB_READ_LIMITS.maxRuntimeMs + 2_000);
    if (input.signal?.aborted) abort();
    const response = await (input.runner ?? runNoEgressDockerSandbox)({
      request: command, bundlePath: input.bundlePath, signal: controller.signal,
    }).catch((error: unknown) => {
      if (error instanceof Error && error.message === "WEB_SANDBOX_PROCESS_CRASH") processCrash = true;
      throw error;
    });
    // Even a test-injected runner must pass the exact same IPC validation.
    const verified = parseWebIpcResult(JSON.stringify(response), command);
    await heartbeat();
    if (lostLease || controller.signal.aborted) throw Error("WEB_CONTROLLER_LEASE_LOST");
    if (!await input.store.complete(fencedClaim, verified.observations, verified.report))
      throw Error("WEB_CONTROLLER_RESULT_REVOKED");
    committed = true;
    return { report: verified.report, observations: verified.observations };
  } catch (error) {
    if (claim && !committed && !processCrash) {
      // Stale token cannot end a reclaimed lease. A real OS crash leaves
      // the fenced claim to expire and permits at most one re-claim.
      await input.store.stop(claim, !input.signal?.aborted).catch(() => false);
    }
    throw error;
  } finally {
    if (timer) clearInterval(timer);
    if (deadline) clearTimeout(deadline);
    input.signal?.removeEventListener("abort", abort);
    abort(); activeJobs.delete(input.jobId);
  }
}
