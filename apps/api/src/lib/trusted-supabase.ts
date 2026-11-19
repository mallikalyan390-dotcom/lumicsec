import { createClient } from "@supabase/supabase-js";
import { env } from "../env.js";

/** Backend-only elevated client. Never send its credentials or instance to a browser. */
export function createTrustedSupabase() {
  if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY
    || env.SUPABASE_SECRET_KEY.includes("REPLACE_ME")) return null;
  return createClient(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}
