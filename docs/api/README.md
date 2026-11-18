# API contract notes

The initial public health route is GET /healthz.

The protected API specification route is POST /v1/api-specs/assess. It requires a Google-authenticated AAL2 session and a valid CSRF token. The request contains a bounded JSON body with a content string and optional filename.

The route imports OpenAPI / Swagger documents offline. It does not send requests to the declared servers and does not persist the raw specification. Results are SPEC_ONLY observations or inventory-only output, not confirmed runtime vulnerabilities.

Auth routes:
- GET /auth/google
- GET /auth/callback
- GET /auth/session
- POST /auth/mfa/enroll
- POST /auth/mfa/verify
- POST /auth/logout
