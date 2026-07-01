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
| Brute-force login | Basic login rate limit | Account lockout, MFA, IP/device review |
| Direct-object access | Role and vault checks in service layer | Broader negative tests and tenant model |
| Secret disclosure in logs | API does not intentionally log values | Redaction policy and structured logger |
| Compromised root key | Production requires non-demo key | KMS/HSM integration and key rotation |
| Audit tampering | Audit events are stored | Append-only storage and signing |
| Backup exposure | Admin-only backup endpoint | Backup encryption and restore validation |
| Session replay | Expiring in-memory sessions | Logout invalidation, device review, refresh-token design |
| Service-token abuse | Scoped token retrieval and audit | Rotation, last-used metadata, token hashing review |
| Supply-chain compromise | Lockfile and CI verify | Dependency audit and secret scanning in CI |
| Misconfigured IIS/TLS | IIS guidance exists | TLS automation, headers review, deployment checklist |

## Security Backlog

1. Add dependency and secret scanning to CI.
2. Add production CSP review and environment-specific security headers.
3. Add server-side logout and session invalidation endpoint.
4. Add account lockout and MFA verification.
5. Add append-only or signed audit log strategy.
6. Add encrypted backup and restore validation.
7. Add KMS/HSM key-management design.
8. Add OIDC/Entra token-validation review before implementation.
9. Add Windows installer hardening review for filesystem ACLs, service identity, and upgrade flow.
10. Add documented penetration-test scope using `PENTEST_SCOPE_TEMPLATE.md`.

## Abuse Cases To Test

- Auditor attempts policy, storage, and service-token actions.
- Vault operator rotates or reveals secrets outside assigned vaults.
- Requester attempts to approve their own access request.
- Expired temporary grant attempts reveal.
- Revoked service token attempts DevOps retrieval.
- Invalid origin attempts browser API access.
- Production boot attempts with demo root key.
