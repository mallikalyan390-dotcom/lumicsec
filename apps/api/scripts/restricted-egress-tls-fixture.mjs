/* Synthetic SAN HTTPS target used ONLY on an ephemeral --internal Docker
 * network for kernel egress acceptance. Key stays in this fixture container.
 * No real domains, tokens, cookies, customer API or external services.
 */
import {createServer} from "node:https";
import {readFileSync} from "node:fs";
import process from "node:process";
import {setTimeout} from "node:timers";
const key=readFileSync("/opt/fixture/private.key");
const cert=readFileSync("/opt/fixture/certificate.crt");
const expectedHost="controlled-web.fixture-web.net";
const server=createServer({key,cert},(request,response)=>{
 if(request.method!=="GET"||request.headers.host!==expectedHost||
   request.url?.includes("?")||request.url?.includes("#")){
   response.writeHead(403).end("denied");return;
 }
 if(request.url==="/redirect"){
   response.writeHead(302,{location:"https://169.254.169.254/latest/meta-data/"})
     .end();return;
 }
 if(request.url==="/oversize"){
   response.writeHead(200,{"content-type":"text/plain"})
     .end("x".repeat(70000));return;
 }
 if(request.url==="/slow"){setTimeout(()=>response.end("slow"),5000);return;}
 if(request.url!=="/"){response.writeHead(404).end();return;}
 response.writeHead(200,{"content-type":"text/html","x-content-type-options":"nosniff",
  "strict-transport-security":"max-age=31536000"})
  .end("<html><body>controlled HTTPS allowlist fixture only</body></html>");
});
server.listen(443,"0.0.0.0",()=>{
 process.stdout.write("RESTRICTED_EGRESS_TEST_TLS_READY\n");
});