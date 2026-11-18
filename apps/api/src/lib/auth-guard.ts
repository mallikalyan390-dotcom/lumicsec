import type { FastifyReply, FastifyRequest } from "fastify";
import { isGoogleAal2, isGoogleIdentity } from "./auth-policy.js";
import { createSupabaseForRequest } from "./supabase.js";

export async function requireGoogleAal2(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const supabase = createSupabaseForRequest(request, reply);
  if (!supabase) {
    reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    return;
  }

  const { data: userData, error: userError } = await supabase.auth.getUser();
  if (userError || !userData.user) {
    reply.code(401).send({ error: "AUTHENTICATION_REQUIRED" });
    return;
  }

  if (!isGoogleIdentity(userData.user)) {
    reply.code(403).send({ error: "GOOGLE_OAUTH_REQUIRED" });
    return;
  }

  const [claimsResult, assuranceResult] = await Promise.all([
    supabase.auth.getClaims(),
    supabase.auth.mfa.getAuthenticatorAssuranceLevel(),
  ]);

  if (claimsResult.error || assuranceResult.error || !claimsResult.data?.claims || !assuranceResult.data) {
    reply.code(401).send({ error: "SESSION_VERIFICATION_FAILED" });
    return;
  }

  if (!isGoogleAal2(userData.user, claimsResult.data.claims, assuranceResult.data)) {
    reply.code(403).send({ error: "AAL2_REQUIRED" });
    return;
  }

  request.authUser = {
    id: userData.user.id,
    email: userData.user.email ?? null,
  };
}
