/* Explicit opt-in browser acceptance in an existing pinned local image.
 * Separate from the Web worker: no network, no host system configuration
 * changes, no production endpoints, only compiled React + synthetic evidence.
 */
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { setTimeout, clearTimeout } from "node:timers";
import { realpath, stat } from "node:fs/promises";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const tests = dirname(fileURLToPath(import.meta.url));
const root = resolve(tests, "..");
const image = "sha256:35e7c432242067a653e10bd96d9de5913ad35e60b884f2245ec7e43a41dc38f2";
const targets = [
  [join(root,"dist"),"/opt/fixture/dist"],
  [join(tests,"findings-customer-smoke.mjs"),"/opt/fixture/tests/findings-customer-smoke.mjs"],
  [join(tests,"run-findings-browser-smoke.mjs"),"/opt/fixture/tests/run-findings-browser-smoke.mjs"],
  [resolve(root,"../api/tests/fixtures/controlled-runtime-actual-results.json"),"/opt/fixture/tests/controlled-runtime-actual-results.json"],
];
const name="lumicsec-ui-"+randomUUID();
const args = [
  "run","--rm","--pull","never","--name",name,"--network","none","--read-only",
  "--cap-drop","ALL","--security-opt","no-new-privileges",
  "--pids-limit","256","--memory","2g","--cpus","2",
  "--user","1001:1001","--shm-size","384m",
  "--tmpfs","/tmp:rw,nosuid,nodev,size=384m","--env","HOME=/tmp",
];
for (const [source,target] of targets) {
  const file = await realpath(source);
  if (!(await stat(file)).isFile() && !(await stat(file)).isDirectory())
    throw Error("FINDINGS_BROWSER_MOUNT_INVALID");
  args.push("--mount", "type=bind,src="+file+",dst="+target+",readonly");
}
args.push("--entrypoint","/usr/bin/node",image,
  "/opt/fixture/tests/run-findings-browser-smoke.mjs");
const env={PATH:process.env["PATH"]??"/usr/bin:/bin",HOME:"/tmp"};
const child=spawn("docker",args,{env,stdio:"inherit"});
const timer=setTimeout(()=>{
  const kill=spawn("docker",["kill","--signal","KILL",name],{env,stdio:"ignore"});
  kill.on("error",()=>undefined);
  setTimeout(()=>child.kill("SIGKILL"),1500).unref();
},120_000);
child.on("error",()=>{process.exitCode=1;});
child.on("close",code=>{clearTimeout(timer);process.exitCode=code??1;});
