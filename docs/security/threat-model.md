# Sentinel Vault Threat Model

## Scope

This threat model covers the Sentinel Vault web console, Express API, local JSON prototype store, Windows package, Docker deployment, and planned enterprise extensions.

Out of scope until implemented:

- Browser extension autofill.
- Native Windows tray or credential-provider components.
- External OIDC, Entra ID, LDAP, SAML, passkey, KMS, HSM, SIEM, ITSM, SOAR, PAM, and CI/CD providers.

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
- Express API to local store or future database.
- Express API to future identity provider.
- Express API to future SIEM, ITSM, DevOps, and KMS integrations.
- Windows installer scripts to installed application folder and scheduled task.
- IIS reverse proxy to local Node API.

## Primary Threats

| Threat | Current mitigation | Remaining work |
| --- | --- | --- |
| Brute-force login | Login rate limit and temporary account lockout | MFA and IP/device review |
| Direct-object access | Role, vault, and tenant metadata checks in service layer | Broader negative tests and production tenant isolation model |
| Secret disclosure in logs | API does not intentionally log values | Redaction policy and structured logger |
| Compromised root key | Production requires non-demo key, key-provider boundary supports external KMS/HSM modes, and key ceremony evidence templates exist | Provider SDK integration and completed provider evidence |
| Audit tampering | Tamper-evident audit hash chaining, signed ledger export, and append-only JSONL ledger for file-backed deployments | External signing service and WORM storage |
| Backup exposure | Admin-only backup endpoints, SHA-256 manifests, AES-GCM encrypted backup artifacts, and restore-validation dry runs | Offline recovery ceremony and scheduled restore drills |
| Session replay | Expiring in-memory sessions, logout invalidation, admin session review, forced revocation, and persistent device inventory metadata | Refresh-token design and device trust policy |
| Service-token abuse | Scoped token retrieval, audit, last-used metadata, and use counts | Rotation and token hashing review |
| Webhook spoofing | SIEM payload HMAC signing and bounded delivery retries | Key rotation and receiver-side replay-window guidance |
| Unapproved privileged work | Live ITSM ticket lookup rejects invalid or inactive tickets before access requests are created | Provider-specific approval-state lookup and work-note updates |
| Supply-chain compromise | Lockfile, CI verify, secret scanning, high-severity dependency audit, and generated release provenance | Broader SAST and signed release attestations |
| Misconfigured IIS/TLS | IIS guidance, production HSTS, and environment-aware CSP exist | TLS automation and deployment checklist |

## Security Backlog

1. Add MFA verification.
2. Add provider SDK-backed KMS/HSM integration after dependency and environment approval.
3. Add OIDC/Entra token-validation review before implementation.
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
