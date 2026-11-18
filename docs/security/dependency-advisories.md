# Dependency advisory register

Last review: 2026-11-18. This is a living register, not an assertion of production-readiness.

## GHSA-fc5q-39xc-vjpf — picomatch ReDoS

- Advisory: https://github.com/advisories/GHSA-fc5q-39xc-vjpf
- CVE: CVE-2026-112366.
- Severity: HIGH.
- Affected versions: picomatch <= 4.0.7.
- Patched version: none listed in the npm audit advisory on 2026-11-18.
- Found by: `pnpm audit --audit-level high`, transitive dependency through Vitest/Vite and other development tools.
- Current production dependency check: `pnpm audit --prod --audit-level high` reported no known vulnerabilities.
- Mitigation: no untrusted customer-controlled glob pattern is accepted by a LumicSec application endpoint. Keep developer/build tooling private and do not treat the vulnerable dev package as safe. Recheck advisory and upgrade as soon as a fixed version is published.
- Status: OPEN. No false claim of a resolved vulnerability.
- Release gate: review this risk before production deployment.

Do not suppress the advisory silently. The production dependency audit is a targeted gate, not a full dependency security certification.
