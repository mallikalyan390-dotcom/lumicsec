import { createServerClient } from "@supabase/ssr";
import type { FastifyReply, FastifyRequest } from "fastify";
import { cookieSecure, env } from "../env.js";

export function createSupabaseForRequest(request: FastifyRequest, reply: FastifyReply) {
  if (
    !env.SUPABASE_URL
    || env.SUPABASE_URL.includes("YOUR_PROJECT_REF")
    || !env.SUPABASE_PUBLISHABLE_KEY
    || env.SUPABASE_PUBLISHABLE_KEY.includes("REPLACE_ME")
  ) {
    return null;
  }

  return createServerClient(env.SUPABASE_URL, env.SUPABASE_PUBLISHABLE_KEY, {
    auth: {
      flowType: "pkce",
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false,
    },
    cookies: {
      getAll() {
        return Object.entries(request.cookies ?? {}).flatMap(([name, value]) => typeof value === "string" ? [{ name, value }] : []);
      },
      setAll(cookiesToSet) {
        for (const cookie of cookiesToSet) {
          reply.setCookie(cookie.name, cookie.value, {
            ...cookie.options,
            path: "/",
            httpOnly: true,
            secure: cookieSecure,
            sameSite: "lax",
            ...(env.COOKIE_DOMAIN ? { domain: env.COOKIE_DOMAIN } : {}),
          });
        }
      },
    },
  });
}

export function clearLumicSecCookie(reply: FastifyReply, name: string) {
  reply.clearCookie(name, {
    path: "/",
    secure: cookieSecure,
    sameSite: "lax",
    ...(env.COOKIE_DOMAIN ? { domain: env.COOKIE_DOMAIN } : {}),
  });
}
