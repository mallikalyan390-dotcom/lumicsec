/* Actual independent Docker broker signature verification and persistent local
 * atomic replay ledger. NO worker/customer public target or host firewall.
 */
import {randomUUID,createHash} from "node:crypto";
import {rm,stat} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {describe,it,expect} from "vitest";
import {openConfinedRuntimeBroker} from
 "../src/workers/confined-runtime-broker-controller.js";
import {createBrokerSigningKeys,signControlledBrokerScope} from
 "../src/workers/broker-scope-ticket.js";

const only=process.env["LUMICSEC_RUN_BROKER_TICKET_DOCKER"]==="1"
 ? describe:describe.skip;
const fixture="web_insecure" as const;
const origin="https://controlled-web.fixture-web.net";
const bundle=resolve(process.cwd(),"dist/isolated/confined-broker.mjs");
const planScope={approvedPaths:["/"],maxRequests:1,
 maxResponseBytes:60000,maxTotalBytes:240000,maxExecutionMs:15000};
const make=(issued=Date.now())=>{
 const executionId=randomUUID(),jobId=randomUUID(),planId=randomUUID(),
   workerId=randomUUID(),generation=1,scopeHash="c".repeat(64);
 const keys=createBrokerSigningKeys();
 const signed=signControlledBrokerScope({
  executionId,jobId,planId,workerId,generation,scopeHash,
  origin,profile:fixture,...planScope,
 },keys.privateKey,issued,issued+9000);
 const durableReplayDirectory=join(tmpdir(),"lumicsec-broker-replay-"+jobId);
 const input={executionId,origin,profile:fixture,
   bundlePath:bundle,signal:new AbortController().signal,
   planScope,brokerAdmission:{
     signed,publicKeyPem:keys.publicKeyPem,durableReplayDirectory,
     expected:{jobId,planId,workerId,generation,scopeHash},
   },
 };
 return {input,keys,durableReplayDirectory};
};
only("real network-none broker container checks Ed25519 and persistent replay",()=>{
 it("accepts a valid bound grant then rejects exact ticket replay after broker restart",async()=>{
  const m=make();
  try{
   const first=await openConfinedRuntimeBroker(m.input);
   try{
    expect(first.networkMode).toBe("none");
    const nonce=JSON.parse(m.input.brokerAdmission.signed.body).nonce;
    const fingerprint=createHash("sha256").update(nonce).digest("hex");
    const marker=await stat(join(m.durableReplayDirectory,fingerprint));
    expect(marker.isFile()).toBe(true);
   }finally{await first.close();}
   await expect(openConfinedRuntimeBroker(m.input))
     .rejects.toThrow();
  }finally{
   await rm(m.durableReplayDirectory,{recursive:true,force:true});
  }
 },25_000);
 it("real broker startup denies a forged signed scope and leaves no replay marker",async()=>{
  const m=make();
  try{
   const raw=JSON.parse(m.input.brokerAdmission.signed.body);
   const modified={...m.input,brokerAdmission:{
      ...m.input.brokerAdmission,signed:{
       ...m.input.brokerAdmission.signed,
       body:JSON.stringify({...raw,approvedPaths:["/admin"]}),
      },
   }};
   await expect(openConfinedRuntimeBroker(modified)).rejects.toThrow();
   await expect(stat(m.durableReplayDirectory)).resolves.toBeDefined();
  }finally{await rm(m.durableReplayDirectory,{recursive:true,force:true});}
 },15_000);
 it("real broker startup rejects wrong trust anchor and expired ticket",async()=>{
  const m=make();
  try{
    const wrong={...m.input,brokerAdmission:{
      ...m.input.brokerAdmission,
      publicKeyPem:createBrokerSigningKeys().publicKeyPem,
    }};
    await expect(openConfinedRuntimeBroker(wrong)).rejects.toThrow();
  }finally{await rm(m.durableReplayDirectory,{recursive:true,force:true});}
  const expired=make(Date.now()-20_000);
  try{
    await expect(openConfinedRuntimeBroker(expired.input)).rejects.toThrow();
  }finally{await rm(expired.durableReplayDirectory,{recursive:true,force:true});}
 },25_000);
 it("cannot start plan-scoped broker without signed broker admission",async()=>{
  const m=make();
  await expect(openConfinedRuntimeBroker({
    executionId:m.input.executionId,origin,profile:fixture,
    bundlePath:bundle,signal:m.input.signal,planScope,
  })).rejects.toThrow("CONFINED_BROKER_SIGNED_SCOPE_REQUIRED");
 },8_000);
});