import { build } from "esbuild";
import process from "node:process";
import { Buffer } from "node:buffer";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const target = resolve(project, "dist/isolated/web-worker.mjs");
const result = await build({
  entryPoints: [resolve(project, "src/workers/web-isolated-entry.ts")],
  outfile: target, bundle: true, platform: "node", format: "esm",
  target: ["node22"], packages: "bundle", treeShaking: true,
  sourcemap: false, legalComments: "none", minify: false,
  metafile: true, logLevel: "warning",
});
const files = Object.keys(result.metafile.inputs);
const forbidden = files.filter(path =>
  /(?:supabase|auth-guard|trusted-supabase|customer-workspace|offline-assessment|web-supabase-store|web-isolated-controller)/i.test(path));
if (forbidden.length) throw Error("WEB_ISOLATED_BUNDLE_CONTAINS_PRIVILEGED_MODULE");
const text = await readFile(target, "utf8");
if (/(?:@supabase\/supabase-js|web_assessment_claim|SUPABASE_SECRET_KEY\s*=)/i.test(text))
  throw Error("WEB_ISOLATED_BUNDLE_CONTAINS_BACKEND_SECRET_CODE");
process.stdout.write(JSON.stringify({
  bundle: "dist/isolated/web-worker.mjs", bytes: Buffer.byteLength(text),
  modules: files.length, excludedPrivilegedImports: true,
}) + "\n");
