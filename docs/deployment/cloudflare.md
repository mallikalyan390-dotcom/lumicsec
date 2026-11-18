# Cloudflare Pages preparation

The React/Vite application is intended for Cloudflare Pages. This document is preparation only.

- Build command: pnpm --filter @lumicsec/web build.
- Output directory: apps/web/dist.
- Configure the approved app origin and API base URL only after the founder confirms the domain.
- Configure SPA fallback routing.
- Keep Supabase secret keys and Google OAuth secrets out of Pages environment variables.
- Do not modify DNS, existing records or custom domains without explicit approval.
- No Pages project or domain has been created by this commit.
