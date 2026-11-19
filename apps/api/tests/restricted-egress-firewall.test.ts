import {describe,expect,it} from "vitest";
import {compileNamespaceEgressPolicy as compile} from
 "../src/workers/restricted-egress-firewall.js";
const grant=(address:string,family:4|6=4,port:443=443)=>({address,family,port});
describe("kernel namespace nftables rule compiler (no network execution)",()=>{
 it("compiles exact public IPv4+IPv6 TCP/443 output-only deny-by-default",()=>{
  const p=compile({grants:[grant("8.8.8.8"),
   grant("2606:4700:4700::1111",6)]});
  expect(p.nftSource).toContain("policy drop");
  expect(p.nftSource).toContain("ip daddr 8.8.8.8 tcp dport 443");
  expect(p.nftSource).toContain("ip6 daddr 2606:4700:4700::1111 tcp dport 443");
  expect(p.nftSource).not.toContain("udp");
  expect(p.executionAllowed).toBe(false);
  expect(p.controlledFixtureOnly).toBe(false);
  expect(p.sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(p.sha256).toBe(compile({grants:[grant("8.8.8.8"),
   grant("2606:4700:4700::1111",6)]}).sha256);
 });
 it.each([
  "127.0.0.1","169.254.169.254","10.0.0.1","192.168.1.1",
  "172.16.0.1","100.64.0.1","0.0.0.0","198.51.100.17",
  "224.0.0.1","255.255.255.255","1.2.3.999",
 ])("rejects unsafe public output destination %s",address=>{
  expect(()=>compile({grants:[grant(address)]})).toThrow();
 });
 it.each(["::1","fe80::1","fd00::2","::ffff:10.0.0.1",
  "2001:db8::1","2002::1","::","ff02::1"])(
  "rejects unsafe public IPv6 %s",address=>{
    expect(()=>compile({grants:[grant(address,6)]})).toThrow();
  });
 it("rejects wrong port, malformed family, CIDR ranges and duplicate output",()=>{
  expect(()=>compile({grants:[{address:"8.8.8.8",family:4,
    port:8443 as never}]})).toThrow();
  expect(()=>compile({grants:[grant("8.8.8.8",6)]})).toThrow();
  expect(()=>compile({grants:[grant("8.8.8.0/24")]})).toThrow();
  expect(()=>compile({grants:[grant("8.8.8.8"),grant("8.8.8.8")]})).toThrow();
 });
 it("denies empty and too-large allowlists",()=>{
  expect(()=>compile({grants:[]})).toThrow();
  expect(()=>compile({grants:Array.from({length:13},(_,i)=>
    grant("8.8.8."+(i+1)))})).toThrow();
 });
 it("isolated private test fixture exception is gated and cannot include public",()=>{
  const p=compile({controlledFixtureOnly:true,
    grants:[grant("172.23.0.2")]});
  expect(p.controlledFixtureOnly).toBe(true);
  expect(p.executionAllowed).toBe(false);
  expect(()=>compile({controlledFixtureOnly:true,
    grants:[grant("8.8.8.8")]})).toThrow();
  expect(()=>compile({controlledFixtureOnly:true,
    grants:[grant("2606:4700:4700::1111",6)]})).toThrow();
 });
});