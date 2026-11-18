# LumicSec

**Unified Web Application Security and API Security workspace.**

LumicSec is being built as a multi-tenant security SaaS for authorized websites and APIs. The repository is in active development and is **not production-ready**.

## Current implementation

- React + TypeScript + Vite customer application.
- Fastify + TypeScript API with Google OAuth PKCE and mandatory TOTP flow scaffolding.
- Supabase Auth cookie-backed sessions; no browser password, email OTP, SMS or alternative social-login UI.
- Development Supabase organization/asset schema with tenant RLS; protected customer organization and pending asset entrypoints and dashboard view.
- Offline OpenAPI / Swagger specification inventory and deterministic API observations.
- Bounded passive Web assessment discovery and response-analysis primitives.
- Source-engine provenance, qualification notes and security gates.

The API specification assessment is **SPEC_ONLY**. It does not send requests to the customer's API, verify runtime authorization, or prove exploitability. All registered customer assets stay PENDING, and website network scanning remains disabled until ownership verification and the complete SSRF-safe transport are integrated and tested.

## Stack

- Node.js 26 LTS, pnpm workspaces.
- React, TypeScript, Vite, Tailwind CSS and shadcn-style local UI components.
- Fastify, Zod, OpenAPI and structured logging.
- Supabase PostgreSQL and Supabase Auth only.
- Cloudflare Pages and Google Cloud Run are deployment targets; no production resources or DNS have been changed.

## Local development

1. Install Node.js 26.13.0 and enable Corepack.
2. Run corepack prepare pnpm@12.19.0 --activate.
3. Copy .env.example to .env and configure the Supabase URL and publishable key.
4. Run pnpm install --frozen-lockfile.
5. Run pnpm dev.
6. Open http://localhost:5173.

See the local-development and Supabase deployment guides.

## Security status

Do not scan assets until ownership is verified. Do not treat specification observations or passive configuration signals as confirmed vulnerabilities. No production deployment, payment activation, paid cloud resource creation, or DNS modification is authorized by this repository.
