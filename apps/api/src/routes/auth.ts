import { randomBytes } from "node:crypto";
import type { FastifyInstance, FastifyReply } from "fastify";
import { mfaCodeSchema, normalizeTotpSvgQrDataUrl, totpQrFormatMetadata } from "@lumicsec/validation";
import { cookieSecure, env } from "../env.js";
import { ensureCsrfToken } from "../lib/csrf.js";
import { isGoogleIdentity, isGoogleAal2 } from "../lib/auth-policy.js";
import { managedUnverifiedTotp, selectTotpChallengeFactor } from "../lib/mfa-factors.js";
import { createTotpQrPngDataUrl } from "../lib/totp-qr-image.js";
import { clearLumicSecCookie, createSupabaseForRequest } from "../lib/supabase.js";

function setPendingFactorCookie(reply: FastifyReply, factorId: string) {
  reply.setCookie("lumicsec_pending_totp", factorId, {
    path: "/",
    httpOnly: true,
    secure: cookieSecure,
    sameSite: "lax",
    maxAge: 600,
    ...(env.COOKIE_DOMAIN ? { domain: env.COOKIE_DOMAIN } : {}),
  });
}

export async function authRoutes(app: FastifyInstance) {
  app.get("/auth/session", async (request, reply) => {
    reply.header("cache-control", "no-store");
    const csrfToken = ensureCsrfToken(request, reply);
    const supabase = createSupabaseForRequest(request, reply);

    if (!supabase) {
      return { state: "unconfigured", configured: false, csrfToken, message: "Supabase Auth is not configured." };
    }

    const { data: userData, error: userError } = await supabase.auth.getUser();
    if (userError || !userData.user) {
      return { state: "anonymous", configured: true, csrfToken };
    }

    if (!isGoogleIdentity(userData.user)) {
      await supabase.auth.signOut();
      return { state: "anonymous", configured: true, csrfToken, message: "Google OAuth is the only permitted sign-in provider." };
    }

    const { data: factorData, error: factorError } = await supabase.auth.mfa.listFactors();
    if (factorError || !factorData) {
      return reply.code(503).send({ error: "MFA_STATUS_UNAVAILABLE", csrfToken });
    }

    const verifiedTotp = factorData.totp.filter((factor) => factor.status === "verified");
    if (verifiedTotp.length === 0) {
      return {
        state: "needs_enrollment",
        configured: true,
        csrfToken,
        user: { id: userData.user.id, email: userData.user.email ?? null },
      };
    }

    const [claimsResult, assuranceResult] = await Promise.all([
      supabase.auth.getClaims(),
      supabase.auth.mfa.getAuthenticatorAssuranceLevel(),
    ]);

    if (claimsResult.error || assuranceResult.error || !claimsResult.data?.claims || !assuranceResult.data) {
      return { state: "needs_challenge", configured: true, csrfToken };
    }

    if (!isGoogleAal2(userData.user, claimsResult.data.claims, assuranceResult.data)) {
      return {
        state: "needs_challenge",
        configured: true,
        csrfToken,
        user: { id: userData.user.id, email: userData.user.email ?? null },
      };
    }

    return {
      state: "authenticated",
      configured: true,
      csrfToken,
      user: { id: userData.user.id, email: userData.user.email ?? null },
    };
  });

  app.get("/auth/google", async (request, reply) => {
    const supabase = createSupabaseForRequest(request, reply);
    if (!supabase) {
      return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    }

    const callbackUrl = new URL("/auth/callback", env.API_BASE_URL).toString();
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: "google",
      options: { redirectTo: callbackUrl },
    });

    if (error || !data.url) {
      request.log.warn({ errorCode: error?.code }, "Google OAuth initiation failed");
      return reply.code(502).send({ error: "GOOGLE_OAUTH_UNAVAILABLE" });
    }

    reply.header("cache-control", "no-store");
    return reply.redirect(data.url);
  });

  app.get<{ Querystring: { code?: string; error?: string } }>("/auth/callback", async (request, reply) => {
    const supabase = createSupabaseForRequest(request, reply);
    const destination = new URL("/", env.APP_BASE_URL);

    if (!supabase || request.query.error || !request.query.code) {
      destination.searchParams.set("authError", "oauth_callback_failed");
      return reply.redirect(destination.toString());
    }

    const { error } = await supabase.auth.exchangeCodeForSession(request.query.code);
    if (error) {
      request.log.warn({ errorCode: error.code }, "OAuth code exchange failed");
      destination.searchParams.set("authError", "oauth_callback_failed");
      return reply.redirect(destination.toString());
    }

    const appUrl = new URL("/app", env.APP_BASE_URL);
    reply.header("cache-control", "no-store");
    return reply.redirect(appUrl.toString());
  });

  app.post("/auth/mfa/enroll", {
    config: { rateLimit: { max: 5, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const supabase = createSupabaseForRequest(request, reply);
    if (!supabase) {
      return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    }

    const { data: userData, error: userError } = await supabase.auth.getUser();
    if (userError || !userData.user || !isGoogleIdentity(userData.user)) {
      return reply.code(401).send({ error: "GOOGLE_AUTHENTICATION_REQUIRED" });
    }

    const { data: factors, error: factorsError } = await supabase.auth.mfa.listFactors();
    const { data: assurance } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
    if (factorsError || !factors || !assurance) {
      return reply.code(503).send({ error: "MFA_STATUS_UNAVAILABLE" });
    }

    const verified = factors.totp.filter((factor) => factor.status === "verified");
    if (verified.length > 0 && assurance.currentLevel !== "aal2") {
      return reply.code(403).send({ error: "AAL2_REQUIRED_TO_ADD_BACKUP_FACTOR" });
    }

    // Rotate abandoned factors from this app only. Other providers' factors and
    // ALL verified factors remain intact. Never use admin privileges here.
    for (const factor of managedUnverifiedTotp(factors)) {
      const { error: cleanupError } = await supabase.auth.mfa.unenroll({ factorId: factor.id });
      if (cleanupError) {
        request.log.warn({ errorCode: cleanupError.code }, "Abandoned enrollment cleanup failed");
        return reply.code(503).send({ error: "MFA_ENROLLMENT_CLEANUP_FAILED" });
      }
    }
    clearLumicSecCookie(reply, "lumicsec_pending_totp");

    const friendlyName = "LumicSec Authenticator " + randomBytes(2).toString("hex");
    const { data, error } = await supabase.auth.mfa.enroll({
      factorType: "totp",
      friendlyName,
    });

    // The secret + factor ID, not the SVG, are required for enrollment. If a
    // provider changes its QR format, keep the same unverified factor and let
    // the user enroll through manual TOTP entry. Never delete verified factors.
    if (error || !data?.id || typeof data.totp?.secret !== "string"
      || data.totp.secret.length < 16 || data.totp.secret.length > 256) {
      request.log.warn({ errorCode: error?.code }, "TOTP enrollment failed");
      return reply.code(400).send({ error: "TOTP_ENROLLMENT_FAILED" });
    }

    const qrCodeSvg = normalizeTotpSvgQrDataUrl(data.totp.qr_code);
    if (!qrCodeSvg) {
      // Strictly categorical diagnostics: no SVG, OTP URI, factor ID, secret,
      // cookies, tokens, or user identifier is ever included in logs.
      request.log.warn({ qrFormat: totpQrFormatMetadata(data.totp.qr_code) },
        "Supabase QR not suitable for safe display; manual TOTP enrollment remains available");
    }

    // Render a standard 256px PNG locally from this SAME pending factor's
    // secret. Supabase SVG layout differences no longer determine QR success.
    const qrCodePng = await createTotpQrPngDataUrl(data.totp.secret, userData.user.email);
    if (!qrCodePng) {
      request.log.warn("Local TOTP PNG encoding unavailable; manual entry remains available");
    }

    setPendingFactorCookie(reply, data.id);
    reply.header("cache-control", "no-store");
    return { qrCodePng, qrCodeSvg, secret: data.totp.secret };
  });

  app.post<{ Body: { code?: string } }>("/auth/mfa/verify", {
    config: { rateLimit: { max: 5, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const parsedCode = mfaCodeSchema.safeParse(request.body?.code);
    if (!parsedCode.success) {
      return reply.code(400).send({ error: "INVALID_TOTP_CODE" });
    }

    const supabase = createSupabaseForRequest(request, reply);
    if (!supabase) {
      return reply.code(503).send({ error: "AUTH_NOT_CONFIGURED" });
    }

    const { data: userData, error: userError } = await supabase.auth.getUser();
    if (userError || !userData.user || !isGoogleIdentity(userData.user)) {
      return reply.code(401).send({ error: "GOOGLE_AUTHENTICATION_REQUIRED" });
    }

    const { data: factorData, error: factorError } = await supabase.auth.mfa.listFactors();
    if (factorError || !factorData) {
      return reply.code(503).send({ error: "MFA_STATUS_UNAVAILABLE" });
    }

    const pendingFactorId = request.cookies?.["lumicsec_pending_totp"];
    const factor = selectTotpChallengeFactor(factorData, pendingFactorId);

    if (!factor) {
      if (pendingFactorId) {
        clearLumicSecCookie(reply, "lumicsec_pending_totp");
      }
      return reply.code(409).send({
        error: pendingFactorId ? "TOTP_ENROLLMENT_EXPIRED_REGENERATE" : "TOTP_FACTOR_NOT_FOUND",
      });
    }

    const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({
      factorId: factor.id,
    });

    if (challengeError || !challenge?.id) {
      return reply.code(400).send({ error: "MFA_CHALLENGE_FAILED" });
    }

    const { error: verifyError } = await supabase.auth.mfa.verify({
      factorId: factor.id,
      challengeId: challenge.id,
      code: parsedCode.data,
    });

    if (verifyError) {
      return reply.code(401).send({ error: "MFA_VERIFICATION_FAILED" });
    }

    clearLumicSecCookie(reply, "lumicsec_pending_totp");
    const { data: assurance } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
    if (assurance?.currentLevel !== "aal2") {
      return reply.code(403).send({ error: "AAL2_NOT_CONFIRMED" });
    }

    reply.header("cache-control", "no-store");
    return { verified: true, assuranceLevel: "aal2" };
  });

  app.post("/auth/logout", async (request, reply) => {
    const supabase = createSupabaseForRequest(request, reply);
    if (supabase) {
      await supabase.auth.signOut();
    }
    clearLumicSecCookie(reply, "lumicsec_pending_totp");
    return { signedOut: true };
  });
}
