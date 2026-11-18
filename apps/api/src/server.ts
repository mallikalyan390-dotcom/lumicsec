import { buildApp } from "./app.js";
import { env } from "./env.js";

const app = buildApp();

try {
  await app.listen({ port: env.PORT, host: env.HOST });
} catch (error) {
  app.log.error({ err: error }, "LumicSec API failed to start");
  process.exitCode = 1;
}
