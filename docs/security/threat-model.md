# Sentinel Vault Threat Model

## Scope

This threat model covers the Sentinel Vault web console, Express API, JSON and SQLite stores, Windows package, Docker deployment, browser autofill extension, Windows companion helper, OIDC/Entra federated sign-in, SIEM webhook delivery, ITSM ticket validation, and DevOps service-token retrieval API.

Out of scope until implemented:

- Signed native Windows credential-provider components.
- LDAP, SAML, passkey, SOAR, PAM, and provider-specific CI/CD connectors.
- Provider SDK-backed KMS/HSM operations and externally hosted managed signing services.

## Assets

- Secret material encrypted with AES-256-GCM before persistence.
- Vault metadata, usernames, URLs, tags, notes, and risk posture.
- User identities, roles, permissions, and MFA metadata.
- Access requests, approval records, and temporary grants.
- Service tokens used by DevOps retrieval APIs.
- Audit records and compliance evidence.
- `VAULT_ROOT_KEY` and future KMS/HSM references.
- Windows installer configuration and `sentinel.env`.

## Trust Boundaries

- Browser to Express API.
- Express API to local JSON or SQLite store.
- Express API to OIDC/Entra identity provider discovery, token, and JWKS endpoints.
- Express API to SIEM webhook, ITSM ticket validation, DevOps retrieval, and future KMS integrations.
- Windows installer scripts to installed application folder and scheduled task.
- IIS reverse proxy to local Node API.
- Browser extension to local Sentinel Vault console.
- Windows companion to DPAPI, clipboard, scheduled tasks, and guarded autotype surfaces.

## Primary Threats

| Threat | Current mitigation | Remaining work |
| --- | --- | --- |
| Brute-force login | Login rate limit, temporary account lockout, OIDC/Entra MFA claim enforcement, identity-provider conformance preflight evidence, and device trust evidence gate | Deployment-specific IP/device trust evidence |
| Direct-object access | Role, vault, and tenant metadata checks in service layer, broader cross-tenant negative tests, documented tenant isolation model, and tenant-isolation evidence gate | Completed deployment-specific tenant isolation evidence |
| Secret disclosure in logs | API avoids intentional value logging and uses a structured logger with recursive sensitive-field, bearer-token, and error redaction | Centralized log shipping redaction tests in the target SIEM |
| Compromised root key | Production requires non-demo key, key-provider boundary supports external KMS/HSM modes, and key ceremony evidence templates exist | Provider SDK integration and completed provider evidence |
| Audit tampering | Tamper-evident audit hash chaining, signed ledger export, append-only JSONL ledger for file-backed deployments, and WORM/external-signing evidence gate | Completed deployment-specific WORM storage evidence |
| Backup exposure | Admin-only backup endpoints, SHA-256 manifests, AES-GCM encrypted backup artifacts, restore-validation dry runs, and backup recovery ceremony evidence | Completed deployment-specific recovery drill evidence |
| Session replay | Expiring in-memory sessions, logout invalidation, admin session review, forced revocation, persistent device inventory metadata, one-time OIDC PKCE state, and device trust evidence gate | Refresh-token design after approved provider policy |
| Service-token abuse | Scoped token retrieval, audit, last-used metadata, use counts, rotation, keyed HMAC token hashes, legacy hash migration on successful use, and DevOps token response preflight evidence | Production pipeline compromise response exercises |
| Webhook spoofing | SIEM payload HMAC signing, signing key IDs, previous-key rotation metadata, delivery IDs, nonces, timestamps, bounded delivery retries, and replay-window guidance | Completed receiver rotation evidence |
| Unapproved privileged work | Live ITSM ticket lookup rejects invalid, inactive, unapproved-state, and out-of-window tickets before access requests are created, and Sentinel posts redacted request IDs/status updates into ITSM work notes | Deployment-specific approval-state and work-note evidence |
| Supply-chain compromise | Lockfile, CI verify, secret scanning, high-severity dependency audit, generated release provenance, SAST evidence gate, release attestation evidence gate, Windows signing helper, and penetration-test scope evidence | Completed signed release attestations from a certificate-backed host |
| Misconfigured IIS/TLS | IIS guidance, production HSTS, environment-aware CSP, and TLS/IIS deployment evidence gate exist | Deployment-specific TLS/IIS evidence |

## Security Backlog

1. Add provider SDK-backed KMS/HSM integration after dependency and environment approval.
2. Add signed native Windows credential-provider implementation after approval.

## Abuse Cases To Test

- Auditor attempts policy, storage, and service-token actions.
- Vault operator rotates or reveals secrets outside assigned vaults.
- Requester attempts to approve their own access request.
- Expired temporary grant attempts reveal.
- Revoked service token attempts DevOps retrieval.
- Invalid origin attempts browser API access.
- Production boot attempts with demo root key.
