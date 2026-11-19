import {randomUUID} from "node:crypto";
import {describe,expect,it} from "vitest";
import {createBrokerSigningKeys,signControlledBrokerScope,
 verifyControlledBrokerScope,type BrokerUnsignedScope}
 from "../src/workers/broker-scope-ticket.js";
const claims=():BrokerUnsignedScope=>({
 executionId:randomUUID(),jobId:randomUUID(),planId:randomUUID(),
 workerId:randomUUID(),generation:1,scopeHash:"a".repeat(64),
 origin:"https://controlled-web.fixture-web.net",
 profile:"web_insecure",approvedPaths:["/"],maxRequests:1,
 maxResponseBytes:60000,maxTotalBytes:240000,maxExecutionMs:15000,
});
const expected=(scope:BrokerUnsignedScope)=>({
 executionId:scope.executionId,jobId:scope.jobId,planId:scope.planId,
 workerId:scope.workerId,generation:scope.generation,
 scopeHash:scope.scopeHash,origin:scope.origin,profile:scope.profile,
});
describe("signed broker-side admission: Ed25519 detached signature and generation",()=>{
 it("verifies exact lease, actor-approved paths, budgets and 9-second TTL",()=>{
  const c=claims(),key=createBrokerSigningKeys(),now=Date.now();
  const envelope=signControlledBrokerScope(c,key.privateKey,now,now+4000);
  const read=verifyControlledBrokerScope(envelope,key.publicKeyPem,
    expected(c),now+20);
  expect(read.scope).toMatchObject({...c,
    issuedAt:now,expiresAt:now+4000});
  expect(read.nonceHash).toMatch(/^[a-f0-9]{64}$/);
  expect(envelope.body).not.toContain("privateKey");
  expect(envelope.body).not.toContain("leaseToken");
 });
 it("broker rejects unsigned path/limit/expiry mutation",()=>{
  const c=claims(),key=createBrokerSigningKeys(),now=Date.now();
  const envelope=signControlledBrokerScope(c,key.privateKey,now);
  for(const field of [
    {approvedPaths:["/admin"]},{maxRequests:6},{expiresAt:now+120_000},
    {jobId:randomUUID()},{generation:2},{scopeHash:"b".repeat(64)},
  ]){
   const body=JSON.stringify({...JSON.parse(envelope.body),...field});
   expect(()=>verifyControlledBrokerScope({...envelope,body},key.publicKeyPem,
     expected(c),now)).toThrow("BROKER_SIGNED_SIGNATURE_INVALID");
  }
 });
 it("broker rejects incorrect key and altered signature",()=>{
  const c=claims(),key=createBrokerSigningKeys();
  const envelope=signControlledBrokerScope(c,key.privateKey);
  expect(()=>verifyControlledBrokerScope(envelope,
    createBrokerSigningKeys().publicKeyPem,expected(c))).toThrow();
  const signature=envelope.signature.replace(/^./,
    envelope.signature.startsWith("A")?"B":"A");
  expect(()=>verifyControlledBrokerScope({...envelope,signature},
    key.publicKeyPem,expected(c))).toThrow();
 });
 it("broker refuses mismatched execution, job, worker, lease generation, tenant scope",()=>{
  const c=claims(),key=createBrokerSigningKeys();
  const envelope=signControlledBrokerScope(c,key.privateKey);
  for(const change of [
    {executionId:randomUUID()},{jobId:randomUUID()},
    {workerId:randomUUID()},{generation:2},
    {scopeHash:"b".repeat(64)},{origin:"https://controlled-api.fixture-api.net"},
  ]){
    expect(()=>verifyControlledBrokerScope(envelope,key.publicKeyPem,
      {...expected(c),...change})).toThrow("BROKER_SIGNED_EXPECTED_SCOPE_MISMATCH");
  }
 });
 it("broker refuses expiration, clock skew and future issuance",()=>{
  const c=claims(),key=createBrokerSigningKeys(),now=Date.now();
  const envelope=signControlledBrokerScope(c,key.privateKey,now);
  expect(()=>verifyControlledBrokerScope(envelope,
    key.publicKeyPem,expected(c),now+9001)).toThrow();
  expect(()=>verifyControlledBrokerScope(envelope,
    key.publicKeyPem,expected(c),now-1000)).toThrow();
  expect(()=>signControlledBrokerScope(c,key.privateKey,
    now,now-1)).toThrow();
 });
 it("cannot sign public domain, unsafe scope, duplicate, overbudget or malformed key",()=>{
  const key=createBrokerSigningKeys(),now=Date.now();
  for(const change of [
    {origin:"https://unapproved.example.net"},
    {approvedPaths:["/","/"]},{approvedPaths:["/../private"]},
    {maxRequests:7},{maxTotalBytes:10000,maxResponseBytes:60000},
  ]){
    expect(()=>signControlledBrokerScope({...claims(),...change},
      key.privateKey,now)).toThrow();
  }
 });
 it("session nonce changes each signing of identical claims, never a replay token",()=>{
  const c=claims(),key=createBrokerSigningKeys(),now=Date.now();
  const a=signControlledBrokerScope(c,key.privateKey,now);
  const b=signControlledBrokerScope(c,key.privateKey,now);
  expect(a.body).not.toBe(b.body);
  expect(a.signature).not.toBe(b.signature);
 });
});