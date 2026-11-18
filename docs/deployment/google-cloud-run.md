# Google Cloud Run preparation

The Fastify API and future workers are intended for Cloud Run. This document is preparation only.

- Build a minimal Node.js 26 container after the application build is qualified.
- Bind to the PORT environment variable and 0.0.0.0 in Cloud Run.
- Use scale-to-zero, bounded concurrency and maximum instances.
- Put secrets in Secret Manager; never commit credentials.
- Add Cloud Tasks, Scheduler, Storage, Artifact Registry, Logging and Monitoring only when required and after budget approval.
- Set usage alerts and budget limits before creating paid resources.
- No Cloud Run service or paid resource has been created by this commit.
