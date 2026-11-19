/* Immutable Linux nftables output-chain policy for a dedicated broker
 * network namespace. Never install this in the host namespace. Never permit
 * DNS, proxy, loopback, metadata, or arbitrary ports in the broker namespace.
 * The controlled fixture exception accepts private Docker bridge addresses
 * ONLY when explicit controlled_fixture_only=true; it cannot be selected
 * by customer assessments or the public egress policy.
 */
import {isIP} from "node:net";
import {createHash} from "node:crypto";
import {isPublicWebAddress} from "../lib/web-pinned-transport.js";

export type EgressNftGrant=Readonly<{
  address:string;family:4|6;port:443;
}>;
export type EgressNftPolicy=Readonly<{
  nftSource:string;sha256:string;allowed:readonly EgressNftGrant[];
  controlledFixtureOnly:boolean;executionAllowed:false;
}>;
const forbidden=(code:string):never=>{throw Error(code);};
const escape=(input:EgressNftGrant)=>{
 if(input.port!==443||isIP(input.address)!==input.family||
   input.address.includes("%")||
   (input.family===6&&input.address.includes(".")))
   forbidden("EGRESS_KERNEL_ADDRESS_OR_PORT_DENIED");
 return input.address;
};
export function compileNamespaceEgressPolicy(
 input:Readonly<{grants:readonly EgressNftGrant[];
  controlledFixtureOnly?:boolean}>,
):EgressNftPolicy {
 const fixture=input.controlledFixtureOnly===true;
 if(input.grants.length<1||input.grants.length>12)
   forbidden("EGRESS_KERNEL_ALLOWLIST_BOUNDS");
 const unique=new Set<string>();
 for(const grant of input.grants){
   const ip=escape(grant);
   if(!fixture&&!isPublicWebAddress(ip,grant.family))
     forbidden("EGRESS_KERNEL_PRIVATE_OR_RESERVED_IP_DENIED");
   if(fixture&&grant.family===4&&!/^(?:172\.(?:1[6-9]|2\d|3[01])|10\.|192\.168\.)/.test(ip))
     forbidden("EGRESS_KERNEL_FIXTURE_MUST_BE_RFC1918");
   if(fixture&&grant.family!==4)forbidden("EGRESS_KERNEL_FIXTURE_IPV6_DISABLED");
   const fingerprint=grant.family+":"+ip+":"+grant.port;
   if(unique.has(fingerprint))forbidden("EGRESS_KERNEL_DUPLICATE_IP");
   unique.add(fingerprint);
 }
 // Output hook is scoped to a new container network namespace, NOT the host.
 // Drop all traffic unless exact destination address AND TCP/443. Ingress is
 // not exposed by this firewall. No DNS, ICMP, HTTP, UDP, loopback, IPv6
 // fallback, transparent proxy or default gateway bypass is permitted.
 const lines=[
  "table inet lumicsec_guard {",
  " chain output {",
  "  type filter hook output priority -100; policy drop;",
  ...input.grants.map(g=>g.family===4
   ?`  ip daddr ${g.address} tcp dport 443 counter accept;`
   :`  ip6 daddr ${g.address} tcp dport 443 counter accept;`),
  " }",
  "}",
 ];
 const nftSource=lines.join("\n")+"\n";
 return Object.freeze({nftSource,sha256:createHash("sha256")
   .update(nftSource).digest("hex"),allowed:input.grants,
   controlledFixtureOnly:fixture,executionAllowed:false});
}
