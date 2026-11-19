import {build} from "esbuild";
import {Buffer} from "node:buffer";
import process from "node:process";
import {readFile} from "node:fs/promises";
import {resolve,dirname} from "node:path";
import {fileURLToPath} from "node:url";
const root=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const target=resolve(root,"dist/isolated/confined-broker.mjs");
const result=await build({
 entryPoints:[resolve(root,"src/workers/confined-runtime-broker-entry.ts")],
 outfile:target,bundle:true,platform:"node",format:"esm",target:["node22"],
 packages:"bundle",sourcemap:false,legalComments:"none",metafile:true,logLevel:"warning",
});
const imports=Object.keys(result.metafile.inputs);
const forbidden=imports.filter(p=>/(?:trusted-supabase|auth-guard|supabase-store|commercial-findings|web-isolated-controller|controlled-runtime-runner|\.env)/i.test(p));
if(forbidden.length)throw Error("CONFINED_BROKER_PRIVILEGED_IMPORT");
const data=await readFile(target);
if(data.includes(Buffer.from("SUPABASE_SECRET_KEY"))||data.includes(Buffer.from("SERVICE_ROLE_KEY")))
 throw Error("CONFINED_BROKER_SECRET_BUNDLE");
process.stdout.write(JSON.stringify({bundle:"dist/isolated/confined-broker.mjs",
 modules:imports.length,bytes:data.length,privilegedImports:0,network:"none"})+"\n");
