import { build } from "esbuild";
import { Buffer } from "node:buffer";
import { readFile } from "node:fs/promises";
import { resolve,dirname } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const api=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const target=resolve(api,"dist/isolated/runtime-worker.mjs");
const output=await build({
  entryPoints:[resolve(api,"src/workers/controlled-runtime-entry.ts")],
  outfile:target,bundle:true,platform:"node",format:"esm",
  target:["node22"],packages:"bundle",treeShaking:true,
  sourcemap:false,legalComments:"none",minify:false,
  metafile:true,logLevel:"warning",
});
const files=Object.keys(output.metafile.inputs);
const forbidden=files.filter(name=>/(?:supabase|auth-guard|trusted-supabase|web-supabase-store|web-isolated-controller|controlled-runtime-broker|controlled-runtime-runner|customer-workspace)/i.test(name));
if(forbidden.length)throw Error("CONTROLLED_BUNDLE_PRIVILEGED_IMPORT_DENIED");
const text=await readFile(target,"utf8");
if(/(?:@supabase\/supabase-js|web_assessment_claim|SYNTHETIC_OWNER_FIXTURE_ONLY|SYNTHETIC_OTHER_FIXTURE_ONLY)/.test(text))
  throw Error("CONTROLLED_WORKER_PRIVILEGED_CODE_DENIED");
process.stdout.write(JSON.stringify({bundle:"dist/isolated/runtime-worker.mjs",
  modules:files.length,bytes:Buffer.byteLength(text),
  privilegedImports:0,syntheticCredentialsEmbedded:false})+"\n");
