# Web Worker Container Isolation — independent development qualification

Date: **2026-11-19**. Existing `main` baseline:
`6b6e737e00cc10eb22bf5e9da5ec785c1af5a543`
(exact baseline GitHub CI `44446244900` success, lockfile `44446244847` success).
**Disposition: Controlled local no-egress isolated worker QUALIFIED for synthetic
TLS fixtures; public customer execution NOT QUALIFIED and remains hard disabled.**

## Scope and source conservation

The accepted implementation and database migration
`20261119021508_isolated_authorized_web_assessments` remain unchanged.
No new migrations or production configuration changes were needed.
The existing Web Security engine captures passive response metadata, bounded
discovery, and offline deterministic observations unchanged. Source was previously
audited at `kalyankumarmalli480-sys/lumicsec-security-platform` SHAs
`10704777f758737927d70aed9c95c0f4f9d98e1c` and
`edfe0bb663c6be6c157176231e88bc35bd8b5331`.
No Web/API runtime exploit engine is claimed.

## Privilege separation — new actual code

- `apps/api/src/workers/web-isolated-controller.ts`:
  trusted host process owns the service-role store, DB claim/lease token,
  heartbeat (every 500ms), current scope, commit authorization and stop/recovery.
  Limits controller to two simultaneous jobs. It does **not** pass a
  backend key, Google session, customer cookies, original lease token
  or privileged DB operation to Docker. It rechecks lease before and after run.
- `apps/api/src/workers/web-worker-ipc-contract.ts`:
  strict schema-versioned single JSON-line request (max **2,048 bytes**),
  JSON-line result (max **120,000 bytes**). Scope, execution UUID, job UUID,
  SHA-256 scope hash, observation counts, source node IDs, fingerprints,
  explanation, remediation, severity and limitations all validated.
  Scope/counter mismatches and malformed evidence fail before DB commit.
- `apps/api/src/workers/web-passive-core.ts`:
  network-facing unprivileged engine invokes existing Phase8 discovery and
  Phase9 analysis with real bounded GETs. No DB, Auth or service-role imports.
- `apps/api/src/workers/web-isolated-entry.ts`:
  receives exactly one strict IPC command on STDIN, returns only
  bounded structured evidence on STDOUT. Explicitly denies suspicious
  credential-bearing environment variable names. On failure emits only
  generic redacted error. Test-only ephemeral TLS fixture mode is
  separately gated by a fixed sandbox environment setting.
- `apps/api/scripts/build-isolated-web-worker.mjs`:
  esbuild bundles the unprivileged entry into
  `apps/api/dist/isolated/web-worker.mjs` (**821,182 bytes; 104 modules**);
  static import inventory blocks Supabase, auth guard, privileged store and
  controller dependencies. Built artifact is gitignored and **not committed**.
  `esbuild@0.28.2` is a pinned dev/build dependency already present in pnpm
  dependency graph; lockfile updated and frozen verified.

### Actual disposable Docker execution boundary

Uses the *already cached founder-local* image with verified immutable ID
`sha256:35e7c432242067a653e10bd96d9de5913ad35e60b884f2245ec7e43a41dc38f2`,
never pulling an external image. This is a **test image**, not an independently
qualified minimal production security image.

`docker run --rm -i --pull never --network none --read-only
--cap-drop ALL --security-opt no-new-privileges --pids-limit 24
--memory 128m --memory-swap 128m --cpus 0.5 --user 65534:65534
--ulimit nofile=64:64 --ulimit nproc=24:24
--tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m`

Only the bundled worker executable is bind mounted **read-only**; no host
repo root, `.env`, Docker socket, service credentials, source tokens,
customer databases or unrestricted files are mounted. Root filesystem is
read-only, non-root UID, all Linux capabilities dropped, no-new-privileges,
namespaced networking and tight cgroup budgets confirmed by actual Docker
kernel probes. Worker stdout/stderr bounded; controller uses a random unique
container name, `docker kill --signal KILL` on revocation/cancellation,
and a 1.5-second CLI fallback. Docker is invoked with a minimal allowlisted
host environment, not the controller environment.

**Actual egress proof:** Real network sockets to `1.1.1.1:443` and
`169.254.169.254:443` returned `ENETUNREACH`; loopback without
fixture returned `ECONNREFUSED`. This is kernel-enforced **deny all external**,
not merely an in-process SSRF check. No founder host firewall, DNS, routes,
container networks or system settings were modified.

**Critical qualification limitation:** This profile cannot fetch ANY external
authorized production website. The controlled insecure/secure HTTPS websites
run on loopback **inside that same isolated container namespace**. Only this
test-only mode uses a synthetic public resolver and a test-only request factory
pointing to local fixture port, while still using actual TLS hostname/CA
verification and the real Web transport/discovery/analysis. This is NOT proof
of enforcement for a future network-enabled allowlist, DNS pin under real
public routing, or independently sandboxed production scanner. Actual
public HTTP execution **remains disabled**, not silently relaxed.

## Real execution, transport, evidence and persistence

`pnpm test:isolated-web` first builds the unprivileged executable, then
executes 9 **actual Docker** tests under
`apps/api/tests/web-isolated-container.test.ts`:

1. External/metadata socket **ENETUNREACH**, isolated loopback.
2. Real cgroups/rootfs/UID/no Docker socket/no inherited fake service key.
3. Insecure synthetic HTTPS fixture: actual TLS GET, parser, analysis and
   IPC result committed by a mock trusted store; no cookies or token in
   response.
4. Secure TLS comparator: four targeted rules absent.
5. Oversized response denied without a result.
6. Redirect toward metadata denied.
7. Stalled response triggers bounded HTTP timeout.
8. Live cancellation kills running Docker worker; no result commit.
9. Worker process SIGKILL; empty response never accepted and fenced DB
   claim remains for expiry/reclaim rather than forging a success.

**9/9 real isolation tests PASS.** The full default CI test runner SKIPS
these nine platform-specific tests unless explicitly opt-in; do not count
a CI skip as a completed Docker gate.

`apps/api/tests/web-isolated-controller.test.ts` adds **11 pure controller
contract tests**, including no lease token over IPC, malformed output,
duplicate admission, AAL/ownership store loss, cancellation, atomic commit
rejection, worker crash, and failure/recovery behavior.

### Detection accuracy (controlled fixture only)

| Passive rule | Expected insecure | Actual insecure | Expected secure | Actual secure |
|---|---|---|---|---|
| `P09.HSTS.ABSENT` | positive | detected | absent | absent |
| `P09.CSP.ABSENT` | positive | detected | absent | absent |
| `P09.FRAME.NO_POLICY` | positive | detected | absent | absent |
| `P09.COOKIE.SECURE_AGG` | positive | detected | absent | absent |

The insecure worker actually emitted **5** review observations: those four
plus `P09.XCTO.CONFIG`. Four selected rules: **4/4 true synthetic positives,
0/4 false positives in secure fixture, 0 targeted misses, 0 targeted
inconclusive**. This is not statistical real-customer accuracy, a proven
exploit, a generalized application scan, or complete coverage. XSS, SQLi,
authz abuse, SSRF of the assessed application, CSRF exploitability,
business-logic flaws, APIs, identity/role auth and exploit paths remain
untested by this passive worker.

### Actual Docker evidence → real development PostgreSQL / RLS

The literal validated five-observation IPC payload from the actual restricted
worker was used in **`supabase/tests/web-isolated-real-tls-evidence.sql`**.
Executed against the actual founder **development** Supabase project, it
created temporary synthetic Google AAL2 owner/organization/verified website,
queued + claimed the job via existing backend-only RPCs, atomically saved
the five **real container observations** including actual source fingerprints
and explanations, rejected duplicate result submission, verified four
expected rules persisted, verified AAL2 owner visibility, AAL1 denial and
cross-tenant isolation, and **ROLLBACK**ed all synthetic records.

Actual result marker:
`ROLLBACK_ONLY_ACTUAL_CONTAINER_TLS_EVIDENCE_PASS`.

This verifies real worker output compatibility with real durable DB
transactional persistence. The test uses trusted SQL tooling for the
transaction because a local server-side Supabase service-role secret is
not provisioned. **The live Docker controller and hosted Supabase were
not joined via a production credential in one continuous process**;
no false claim of that full hosted path. Previous rollback-only
`tenant-isolation`, `rbac-ownership`, `offline-api-assessments`, and
`web-worker-lifecycle` regressions remain required.

### Real customer browser checks

`apps/web/tests/web-sandbox-actual-result.json` retains only public-synthetic
review evidence actually generated by the Docker worker (no host secret).
The compiled customer React fixture uses those exact five observations
rather than invented rule bodies. `pnpm test:web-browsers` launches a
separately limited **no-egress** browser-test Docker container with cached
Playwright Chromium + Firefox; it runs owner, member and unverified-asset
cases, viewing real captured evidence paths, fingerprints, remediation,
and secure-comparator no-findings state.

**Chromium 3/3 PASS, Firefox 3/3 PASS — 6/6 total; customer queue and
cancel requests = 0.** This remains a synthetic UI data-adapter test,
not end-user hosted OAuth or actual logged-in RLS browser acceptance.

## Negative and resource gates

Frozen pnpm installation, lint, TypeScript, full unit/API suite,
bounded worker bundle, actual Docker tests, real development DB SQL,
production build, dependency audit and explicit source/credential pattern
scan are required release evidence. Existing browser and security code
paths preserved unchanged. Vite >500KB chunk warning remains.

## Important open risks — NOT READY FOR CUSTOMER SCANNING

1. **No production network-allowlist sandbox**: a real external HTTPS
   allowlisted profile would need independently evaluated per-destination
   network namespace egress enforcement / proxy, DNS pinning under rebinding,
   all-answers validation at packet layer, source-controlled secure image,
   credential isolation review, and owner-authorized hosted fixture tests.
   Do not disable `--network none` merely to reach a target.
2. Trusted controller's Docker daemon API is powerful on the founder machine;
   this is an isolated **development** qualification, not a hardened production
   multi-tenant worker scheduler or horizontally scalable orchestration.
3. No privileged DB key exists locally; live hosted controller execution
   intentionally fail-closed. Real customer ownership+consent, full RLS
   browser session and distributed crash-restart scheduling still need hosted
   authorization tests. Existing DB 20-second stale lease fencing and
   generation-2 claim were tested independently with rollback-only SQL.
4. The cached browser CI image is large and **not minimal / independently
   signed for production**. Production worker kernel/seccomp/image/AppArmor
   review, syscall profile, image provenance and resource abuse tests remain.
5. Hard-disabled customer `POST /v1/assessments/web` HTTP 423 unchanged.
   No production DNS, scans, paid cloud, billing, customer targets, secrets
   or production deployments.
6. Full commercial features—evidence-backed canonical Findings,
   reviewer ownership, remediation status/actions, proof-backed retest,
   professional PDF/report exports, web and API advanced engine integration,
   monitoring/scheduling, billing/entitlements, enterprise SSO/compliance,
   Google TOTP recovery and independent pen test—remain part of unchanged
   master roadmap. The next customer product milestone can prepare those
   workflows while release activation remains gated.

**Next milestone after independent egress/hosted acceptance:**
Evidence-backed Findings, Remediation Workflow, Retesting and Professional
Reporting. All observations remain explicitly *review-only passive signals*.
