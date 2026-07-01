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
| Brute-force login | Login rate limit, temporary account lockout, and OIDC/Entra MFA claim enforcement | IP/device trust policy and provider conformance evidence |
| Direct-object access | Role, vault, and tenant metadata checks in service layer | Broader negative tests and production tenant isolation model |
| Secret disclosure in logs | API avoids intentional value logging and uses a structured logger with recursive sensitive-field, bearer-token, and error redaction | Centralized log shipping redaction tests in the target SIEM |
| Compromised root key | Production requires non-demo key, key-provider boundary supports external KMS/HSM modes, and key ceremony evidence templates exist | Provider SDK integration and completed provider evidence |
| Audit tampering | Tamper-evident audit hash chaining, signed ledger export, and append-only JSONL ledger for file-backed deployments | External signing service and WORM storage |
| Backup exposure | Admin-only backup endpoints, SHA-256 manifests, AES-GCM encrypted backup artifacts, and restore-validation dry runs | Offline recovery ceremony and scheduled restore drills |
| Session replay | Expiring in-memory sessions, logout invalidation, admin session review, forced revocation, persistent device inventory metadata, and one-time OIDC PKCE state | Refresh-token design and device trust policy |
| Service-token abuse | Scoped token retrieval, audit, last-used metadata, and use counts | Rotation and token hashing review |
| Webhook spoofing | SIEM payload HMAC signing, delivery IDs, nonces, timestamps, bounded delivery retries, and replay-window guidance | Key rotation and completed receiver evidence |
| Unapproved privileged work | Live ITSM ticket lookup rejects invalid or inactive tickets before access requests are created | Provider-specific approval-state lookup and work-note updates |
| Supply-chain compromise | Lockfile, CI verify, secret scanning, high-severity dependency audit, generated release provenance, and Windows signing helper | Broader SAST and signed release attestations from a certificate-backed host |
| Misconfigured IIS/TLS | IIS guidance, production HSTS, and environment-aware CSP exist | TLS automation and deployment checklist |

## Security Backlog

1. Add provider-specific OIDC/Entra conformance evidence.
2. Add provider SDK-backed KMS/HSM integration after dependency and environment approval.
3. Add signed native Windows credential-provider implementation after approval.
4. Add Windows installer hardening review for filesystem ACLs, service identity, and upgrade flow.
5. Add documented penetration-test scope using `PENTEST_SCOPE_TEMPLATE.md`.

## Abuse Cases To Test

- Auditor attempts policy, storage, and service-token actions.
- Vault operator rotates or reveals secrets outside assigned vaults.
- Requester attempts to approve their own access request.
- Expired temporary grant attempts reveal.
- Revoked service token attempts DevOps retrieval.
- Invalid origin attempts browser API access.
- Production boot attempts with demo root key.
