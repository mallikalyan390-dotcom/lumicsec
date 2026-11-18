import Fastify from "fastify";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { allowedOrigins, env } from "./env.js";
import { isValidCsrfRequest } from "./lib/csrf.js";
import { authRoutes } from "./routes/auth.js";
import { apiSpecRoutes } from "./routes/api-specs.js";

export function buildApp() {
  const app = Fastify({
    bodyLimit: 1_200_000,
    requestIdHeader: "x-request-id",
    logger: {
      level: env.LOG_LEVEL,
      redact: {
        paths: [
          "req.headers.cookie",
          "req.headers.authorization",
          "req.body.content",
          "req.body.code",
          "req.body.secret",
          "res.headers.set-cookie",
        ],
        remove: true,
      },
    },
  });

  app.register(cookie);
  app.register(cors, {
    origin: allowedOrigins,
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["content-type", "x-csrf-token", "x-request-id"],
  });
  app.register(helmet, { contentSecurityPolicy: false });
  app.register(rateLimit, { max: 120, timeWindow: "1 minute" });

  app.addHook("onRequest", async (request, reply) => {
    if (request.method === "POST" && !isValidCsrfRequest(request)) {
      reply.code(403).send({ error: "CSRF_ORIGIN_CHECK_FAILED" });
      return;
    }
  });

  app.get("/healthz", async () => ({
    status: "ok",
    service: "lumicsec-api",
    version: "0.1.0",
  }));

  app.register(authRoutes);
  app.register(apiSpecRoutes);

  app.setNotFoundHandler(async (_request, reply) => {
    return reply.code(404).send({ error: "NOT_FOUND" });
  });

  app.setErrorHandler(async (error, request, reply) => {
    request.log.error({ err: error }, "Unhandled API error");
    const status = typeof error.statusCode === "number" && error.statusCode >= 400 ? error.statusCode : 500;
    return reply.code(status).send({
      error: status >= 500 ? "INTERNAL_ERROR" : "REQUEST_FAILED",
      requestId: request.id,
    });
  });

  return app;
}
