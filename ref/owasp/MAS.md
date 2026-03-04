# MAS (Mobile) - Extracted Security Focus for This Project

## Source Priority
- MASTG source repo: `https://github.com/OWASP/mastg`
- Local snapshot: `.qa/ref/owasp/sources/mastg`
- Key reference chapter: `Document/0x03-Overview.md`

## Why This Is Mandatory Here
This project is a Flutter mobile app with local storage, API calls, and AI-assisted flows. Based on MASTG/MASVS mapping, the highest-value categories are:
- `MASVS-STORAGE`
- `MASVS-CRYPTO`
- `MASVS-AUTH`
- `MASVS-NETWORK`
- `MASVS-CODE`
- `MASVS-RESILIENCE`

## Extracted Needed Parts (Project-Applied)

### 1) MASVS-STORAGE (local DB / cache / files)
- Verify sensitive data is not stored in plaintext in local DB/files.
- Ensure tokens/session artifacts are not persisted insecurely.
- Validate backup/export paths do not leak app data.
- For this repo: prioritize `drift/sqlite` usage and any receipt/image temp artifacts.
- Verify local knowledge/RAG source files use integrity controls (trusted source, checksum,
  controlled write path) before being consumed by AI features.

### 2) MASVS-CRYPTO (key handling / crypto usage)
- Use platform-approved crypto primitives and avoid custom crypto.
- Ensure secure random generation and key lifecycle controls.
- Verify no hardcoded keys/secrets in app code/resources.

### 3) MASVS-AUTH (session / token / local auth)
- Backend must enforce authz on every privileged endpoint (client-side state is untrusted).
- Validate token handling (expiry, refresh, revocation, replay resistance).
- Ensure local authentication cannot be a sole trust anchor for server-side authorization.

### 4) MASVS-NETWORK (TLS / transport integrity)
- Enforce secure TLS usage and reject insecure transport fallbacks.
- Validate certificate trust model and protect against MITM downgrade paths.
- Verify sensitive payloads are never sent over weak channels.

### 5) MASVS-CODE (injection / unsafe components / WebView)
- Check for client-side injection vectors in local DB queries and content handling.
- Review WebView or dynamic rendering sinks if present.
- Ensure secure build settings and dependency hygiene.
- Ensure AI/tool bridge code validates command/function arguments with explicit schema
  (type/range constraints) before invocation.

### 6) MASVS-RESILIENCE (tampering / reverse engineering)
- Assess how easily attacker can patch or instrument app logic.
- Check anti-tamper/anti-debug assumptions and whether critical checks are server-verified.

## Immediate Test Checklist for This Repo
- [ ] Local DB schema + DAO queries reviewed for sensitive field exposure.
- [ ] AI/RAG source files have integrity and write-permission controls.
- [ ] Token/session persistence paths reviewed (including logs).
- [ ] Network client configuration reviewed for TLS and trust behavior.
- [ ] API authz assumptions reviewed against server-enforced controls.
- [ ] Build artifacts/resources scanned for embedded secrets.
- [ ] AI/tool bridge inputs are schema-validated before execution.
- [ ] High-risk flows validated against runtime tampering assumptions.

## Evidence Anchors (MASTG files used)
- `Document/0x03-Overview.md`
- `Document/0x04e-Testing-Authentication-and-Session-Management.md`
- `Document/0x04h-Testing-Code-Quality.md`
- `Document/0x05d-Testing-Data-Storage.md`
- `Document/0x05g-Testing-Network-Communication.md`
- `Document/0x06d-Testing-Data-Storage.md`
- `Document/0x06g-Testing-Network-Communication.md`
