/* Trusted-controller -> broker signed admission for CONTROLLED LOCAL fixtures.
 * The Ed25519 private key exists ONLY in the trusted launcher process.
 * Public key and scope ticket may enter the broker, never the worker.
 * The broker validates independently before opening any Unix request socket.
 * A filesystem atomic nonce marker handles replay within one durable local
 * broker ledger. Cross-host distributed replay still needs a DB witness.
 */
import {createHash,generateKeyPairSync,sign,verify,
  createPublicKey,type KeyObject} from "node:crypto";
import {isIP} from "node:net";
import {z} from "zod";
const uuid=z.string().uuid(),hex=z.string().regex(/^[a-f0-9]{64}$/);
const path=z.string().regex(/^\/[a-zA-Z0-9._~/-]{0,119}$/);
export const brokerSignedScopeSchema=z.strictObject({
  version:z.literal("LUMICSEC_SIGNED_BROKER_SCOPE_V1"),
  executionId:uuid,jobId:uuid,planId:uuid,workerId:uuid,
  generation:z.number().int().min(1).max(2),scopeHash:hex,
  origin:z.string().regex(/^https:\/\/[a-z0-9.-]{4,240}$/),
  profile:z.enum(["web_insecure","web_secure","web_redirect","web_oversize",
    "web_slow","api_insecure","api_secure","api_redirect","api_oversize","api_slow"]),
  approvedPaths:z.array(path).min(1).max(6),
  maxRequests:z.number().int().min(1).max(6),
  maxResponseBytes:z.number().int().min(1024).max(60000),
  maxTotalBytes:z.number().int().min(1024).max(240000),
  maxExecutionMs:z.number().int().min(1000).max(15000),
  // Optional signed binding exclusively for a synthetic --internal bridge.
  // The broker refuses a remote CA or destination not signed here.
  controlledFixtureDestination:z.strictObject({
    ipv4:z.string().max(45),caSha256:hex,
  }).optional(),
  issuedAt:z.number().int(),expiresAt:z.number().int(),
  nonce:hex,
});
export type BrokerSignedScope=z.infer<typeof brokerSignedScopeSchema>;
export type BrokerSignedTicket=Readonly<{body:string;signature:string}>;
export type BrokerUnsignedScope=Omit<BrokerSignedScope,
 "version"|"issuedAt"|"expiresAt"|"nonce">;
const deny=(code:string):never=>{throw Error(code);};
export function createBrokerSigningKeys(){
 const keys=generateKeyPairSync("ed25519");
 return {privateKey:keys.privateKey,
   publicKeyPem:keys.publicKey.export({format:"pem",type:"spki"}).toString()};
}
export function signControlledBrokerScope(
 claims:BrokerUnsignedScope,privateKey:KeyObject,nowMs=Date.now(),
 maxExpiryMs=nowMs+9000,
):BrokerSignedTicket{
 const source=brokerSignedScopeSchema.parse({
  ...claims,version:"LUMICSEC_SIGNED_BROKER_SCOPE_V1",
  issuedAt:nowMs,expiresAt:Math.min(nowMs+9000,maxExpiryMs),
  nonce:createHash("sha256").update(
    Buffer.from(globalThis.crypto.randomUUID()+":"+globalThis.crypto.randomUUID()))
   .digest("hex"),
 });
 validateScope(source,nowMs);
 const body=JSON.stringify(source);
 if(Buffer.byteLength(body)>2000)deny("BROKER_SIGNED_SCOPE_TOO_LARGE");
 return {body,signature:sign(null,Buffer.from(body),privateKey)
   .toString("base64url")};
}
function validateScope(scope:BrokerSignedScope,nowMs:number){
 const fixture=scope.controlledFixtureDestination;
 if(fixture&&(
   scope.profile!=="web_insecure"||
   scope.approvedPaths.length!==1||scope.approvedPaths[0]!=="/"||
   isIP(fixture.ipv4)!==4||
   !/^(?:172\.(?:1[6-9]|2\d|3[01])\.|10\.|192\.168\.)/.test(
     fixture.ipv4)))
   deny("BROKER_SIGNED_REMOTE_DESTINATION_INVALID");
 if(!Number.isFinite(nowMs)||scope.issuedAt>nowMs+500||
   scope.expiresAt<=nowMs||scope.expiresAt-scope.issuedAt>9000||
   scope.expiresAt<=scope.issuedAt||
   scope.maxResponseBytes>scope.maxTotalBytes||
   new Set(scope.approvedPaths).size!==scope.approvedPaths.length||
   scope.approvedPaths.some(p=>p.includes("//")||
     /(^|\/)\.{1,2}(\/|$)/.test(p))||
   scope.origin!==(scope.profile.startsWith("web_")?
     "https://controlled-web.fixture-web.net":
     "https://controlled-api.fixture-api.net"))
   deny("BROKER_SIGNED_SCOPE_EXPIRED_OR_INVALID");
}
export function verifyControlledBrokerScope(
 envelope:BrokerSignedTicket,publicKeyPem:string,
 expected:Readonly<{executionId:string;origin:string;profile:string;
   jobId:string;planId:string;workerId:string;generation:number;
   scopeHash:string}>,
 nowMs=Date.now(),
):Readonly<{scope:BrokerSignedScope;nonceHash:string}>{
 if(Buffer.byteLength(envelope.body)>2000||
   Buffer.byteLength(publicKeyPem)>2000||
   !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature))
   deny("BROKER_SIGNED_ENVELOPE_BOUNDS");
 let key:KeyObject;let valid=false;
 try{
   key=createPublicKey(publicKeyPem);
   if(key.asymmetricKeyType!=="ed25519")deny("BROKER_SIGNED_KEY_TYPE_DENIED");
   valid=verify(null,Buffer.from(envelope.body),key,
     Buffer.from(envelope.signature,"base64url"));
 }catch{deny("BROKER_SIGNED_SIGNATURE_INVALID");}
 if(!valid)deny("BROKER_SIGNED_SIGNATURE_INVALID");
 const scope=brokerSignedScopeSchema.parse(JSON.parse(envelope.body) as unknown);
 validateScope(scope,nowMs);
 if(scope.executionId!==expected.executionId||
   scope.origin!==expected.origin||scope.profile!==expected.profile||
   scope.jobId!==expected.jobId||scope.planId!==expected.planId||
   scope.workerId!==expected.workerId||
   scope.generation!==expected.generation||
   scope.scopeHash!==expected.scopeHash)
   deny("BROKER_SIGNED_EXPECTED_SCOPE_MISMATCH");
 return {scope,nonceHash:createHash("sha256").update(scope.nonce).digest("hex")};
}