import { randomBytes } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import { allowedOrigins, cookieSecure, env } from "../env.js";

const csrfCookieName = "lumicsec_csrf";

export function ensureCsrfToken(request: FastifyRequest, reply: FastifyReply): string {
  const existing = request.cookies?.[csrfCookieName];
  if (existing && /^[a-f0-9]{64}$/.test(existing)) {
    return existing;
  }

  const token = randomBytes(32).toString("hex");
  reply.setCookie(csrfCookieName, token, {
    path: "/",
    httpOnly: false,
    secure: cookieSecure,
    sameSite: "lax",
    ...(env.COOKIE_DOMAIN ? { domain: env.COOKIE_DOMAIN } : {}),
  });
  return token;
}

export function isValidCsrfRequest(request: FastifyRequest): boolean {
  const origin = request.headers.origin;
  const header = request.headers["x-csrf-token"];
  const cookie = request.cookies?.[csrfCookieName];

  return typeof origin === "string"
    && allowedOrigins.includes(origin)
    && typeof header === "string"
    && typeof cookie === "string"
    && header === cookie;
}
