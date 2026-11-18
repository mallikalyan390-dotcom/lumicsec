// Optional local-only browser smoke test. No real Supabase calls, users, or factors.
// Build apps/web first; serve the real production React bundle with synthetic responses.
// Run with: node apps/web/tests/mfa-manual-fallback-smoke.mjs
import console from "node:console";
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath, URL } from "node:url";

const dist = resolve(dirname(fileURLToPath(import.meta.url)), "../dist");
const port = 5187;
const results = [];
let submissions = 0;
const qrBroken = 'data:image/svg+xml;utf-8,<svg xmlns="http://www.w3.org/2000/svg"><path';
const qrWorking = 'data:image/svg+xml;utf-8,<svg xmlns="http://www.w3.org/2000/svg" width="180" height="180"><rect width="180" height="180" fill="white"/></svg>';

const browserHarness = `<script>
(async function browserSmoke() {
  const waitFor = async (predicate) => {
    for (let attempt = 0; attempt < 110; attempt++) {
      const value = predicate();
      if (value) return value;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error("Fixture UI condition not reached");
  };
  const report = { browser: navigator.userAgent.includes("Firefox") ? "firefox" : "chromium", fixture: location.search.includes("valid") ? "valid" : "broken" };
  try {
    const create = await waitFor(() => [...document.querySelectorAll("button")].find((button) => button.textContent.includes("Create authenticator")));
    create.click();
    const input = await waitFor(() => document.querySelector("#totp-code"));
    const qrAlert = report.fixture === "broken"
      ? !!(await waitFor(() => document.body.textContent.includes("QR image unavailable")))
      : false;
    report.qrImageLoaded = report.fixture === "valid"
      ? !!(await waitFor(() => {
          const image = document.querySelector('img[alt="Authenticator enrollment QR code"]');
          return image && image.complete && image.naturalWidth > 0;
        }))
      : false;
    report.formVisible = !!input && input.getBoundingClientRect().height > 0;
    report.manualKeyVisible = document.body.textContent.includes("Manual setup key");
    report.manualInstructionsVisible = document.body.textContent.includes("manual entry in your authenticator");
    report.qrErrorShown = qrAlert;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(input, "123456");
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.closest("form").requestSubmit();
    report.failedCodeMessageVisible = !!(await waitFor(() =>
      document.body.textContent.includes("MFA_VERIFICATION_FAILED")));
  } catch (error) {
    report.problem = error.message;
  }
  document.body.dataset.fixtureResult = report.problem ? "FAIL" : "DONE";
  await fetch("/__report", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(report),
  }).catch(() => {});
})();
</script>`;

function sendJson(res, statusCode, value) {
  res.writeHead(statusCode, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(value));
}
const mime = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
};
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", "http://127.0.0.1:" + port);
    if (url.pathname === "/auth/session") {
      return sendJson(res, 200, {
        state: "needs_enrollment", configured: true, csrfToken: "synthetic-csrf-only",
        user: { id: "synthetic-user", email: "synthetic@example.invalid" },
      });
    }
    if (url.pathname === "/auth/mfa/enroll" && req.method === "POST") {
      return sendJson(res, 200, {
        qrCodeSvg: String(req.headers.referer ?? "").includes("?valid") ? qrWorking : qrBroken,
        secret: "SYNTHETIC_NOT_A_VALID_TOTP_SECRET",
      });
    }
    if (url.pathname === "/auth/mfa/verify" && req.method === "POST") {
      submissions++;
      return sendJson(res, 401, { error: "MFA_VERIFICATION_FAILED" });
    }
    if (url.pathname === "/__report" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) {
        body += chunk.toString();
        if (body.length > 2048) break;
      }
      const item = JSON.parse(body);
      // Avoid leaking any user-provided or QR data in the test output.
      const safe = {
        browser: item.browser === "firefox" ? "firefox" : "chromium",
        fixture: item.fixture === "valid" ? "valid" : "broken",
        formVisible: !!item.formVisible,
        manualKeyVisible: !!item.manualKeyVisible,
        manualInstructionsVisible: !!item.manualInstructionsVisible,
        qrErrorShown: !!item.qrErrorShown,
        qrImageLoaded: !!item.qrImageLoaded,
        failedCodeMessageVisible: !!item.failedCodeMessageVisible,
        problem: typeof item.problem === "string" ? item.problem.slice(0, 100) : null,
      };
      results.push(safe);
      console.log("MFA_BROWSER_FIXTURE_RESULT " + JSON.stringify(safe));
      return sendJson(res, 200, { received: true });
    }
    if (url.pathname === "/__status") {
      return sendJson(res, 200, { results, submissions });
    }
    let filename = resolve(dist, "." + url.pathname);
    if (relative(dist, filename).startsWith("..")) return sendJson(res, 403, { error: "FORBIDDEN" });
    const item = await stat(filename).catch(() => null);
    if (!item?.isFile()) filename = join(dist, "index.html");
    const data = await readFile(filename);
    const body = filename.endsWith(".html")
      ? data.toString().replace("</body>", browserHarness + "</body>")
      : data;
    res.writeHead(200, { "content-type": mime[extname(filename)] ?? "application/octet-stream", "cache-control": "no-store" });
    res.end(body);
  } catch {
    sendJson(res, 500, { error: "FIXTURE_INTERNAL_ERROR" });
  }
});
server.listen(port, "127.0.0.1", () => {
  console.log("MFA_SYNTHETIC_BROWSER_FIXTURE_READY http://127.0.0.1:" + port);
});
