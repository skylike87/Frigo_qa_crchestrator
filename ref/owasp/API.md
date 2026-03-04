# API - Extracted Security Focus for This Project

## Source Priority
- Requested whitepaper link (OpenText): `.qa/ref/owasp/pdfs/API_Security_2023_OpenText.pdf`
  - Current status: access denied response from origin (non-PDF content).
- OWASP API Security Top 10 (2023): `https://owasp.org/API-Security/editions/2023/en/0x11-t10/`
- Local mirror snippet: `.qa/ref/owasp/sources/owasp_api_top10_2023_header.html`

## OWASP API Top 10 (2023) Needed Coverage
- API1:2023 Broken Object Level Authorization
- API2:2023 Broken Authentication
- API3:2023 Broken Object Property Level Authorization
- API4:2023 Unrestricted Resource Consumption
- API5:2023 Broken Function Level Authorization
- API6:2023 Unrestricted Access to Sensitive Business Flows
- API7:2023 Server Side Request Forgery
- API8:2023 Security Misconfiguration
- API9:2023 Improper Inventory Management
- API10:2023 Unsafe Consumption of APIs

## Extracted Needed Parts (Project-Applied)

### Access Control (API1/API3/API5)
- Enforce object/function/property level authorization on every request.
- Never trust client-provided object IDs, roles, or action flags.
- Verify least-privilege scope for each API route.

### Authentication & Session (API2)
- Require strong token validation, expiry, and refresh controls.
- Block token reuse/replay and enforce server-side session invalidation.
- Standardize authentication patterns across APIs (avoid mixed, ad-hoc auth schemes).
- Review authentication controls regularly against OWASP ASVS requirements.

### Abuse / Business Flow Protection (API4/API6)
- Apply rate limits and quotas for expensive or business-critical endpoints.
- Protect sensitive flows (e.g., automation-prone actions) with step-up controls.
- Enforce hard resource ceilings, not only request rate:
  - memory allocation per request/tenant,
  - worker/process count,
  - file descriptor count and file size limits.

### Outbound / Integration Risk (API7/API10)
- Validate and constrain remote calls to prevent SSRF.
- Treat upstream API data as untrusted; validate schema and failure handling.
- Encapsulate outbound HTTP/resource fetch logic in a dedicated internal module.
- Disable automatic HTTP redirect following for outbound fetch by default.
- Use explicit allowlists for remote destinations/protocols.
- Restrict external/cloud integration entry points with IP allowlists where applicable.

### Operational Hygiene (API8/API9)
- Keep strict inventory of active/deprecated endpoints and versions.
- Ensure secure defaults, minimum exposed metadata, and robust error handling.
- Never use production data in development/staging/test environments.
- For mobile-backed APIs, enforce local data-at-rest encryption guidance in clients
  (e.g., SQLCipher or equivalent secure storage profile).
- Apply security-as-code checks in CI/CD for config/secrets/policy drift before deploy.

### Data Exposure Guardrails (API3)
- Avoid generic serialization outputs such as `to_json()` / `to_string()` for API responses.
- Define explicit response DTO/schema per endpoint and return only allowlisted fields.
- Enforce schema-based response validation in CI/runtime gates where feasible.

### Authorization Enforcement Details (API5)
- Start from `deny by default` and explicitly grant per role/action.
- Validate permission per HTTP method (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`) independently.
- Do not infer function-level permission from UI visibility or client workflow.

## Immediate Test Checklist for This Repo
- [ ] API request paths mapped and privilege model documented.
- [ ] BOLA/BFLA checks executed for every resource-changing call.
- [ ] Rate limits verified for high-cost/high-risk endpoints.
- [ ] Resource ceilings validated (memory/process/fd/file-size) for high-risk endpoints.
- [ ] External call surfaces reviewed for SSRF-style misuse.
- [ ] Outbound redirects disabled by default and destination allowlists enforced.
- [ ] Stale/unused endpoints and test routes inventoried.
- [ ] No production data is used in dev/staging/test datasets.
- [ ] Third-party API response validation and timeout/retry policies verified.
- [ ] API responses use explicit schema/DTO allowlists (no generic object dumps).
- [ ] Authorization checks are method-specific and default-deny.
- [ ] CI/CD security-as-code checks cover secrets and insecure config drift.
