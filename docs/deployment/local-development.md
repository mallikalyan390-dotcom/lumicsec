# Local development

The local workflow is designed for a laptop with 8 GB RAM and does not require Docker, Kubernetes, Redis or Elasticsearch.

## Requirements

- Node.js 26.13.0 LTS.
- Corepack with pnpm 12.19.0.
- Git.
- A Supabase development project.

## Commands

1. Clone the main branch.
2. Enable Corepack and activate pnpm 12.19.0.
3. Copy .env.example to .env.
4. Add SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY from the Supabase project Connect dialog.
5. Run pnpm install --frozen-lockfile.
6. Run pnpm dev.
7. Open http://localhost:5173.

The dev script builds the workspace packages, starts Vite on port 5173 and Fastify on port 8787. Vite proxies /auth, /v1 and /healthz to Fastify.

The first Google OAuth sign-in requires Google provider activation in Supabase Auth and the local API callback URL in the Supabase redirect allowlist. The callback is http://localhost:8787/auth/callback.

## Resource limits

Do not run local Supabase containers on the 8 GB laptop. Use the existing remote development project. Do not create paid cloud services or production infrastructure from local scripts.
