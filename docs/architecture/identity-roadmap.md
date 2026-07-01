# Identity Roadmap

Sentinel Vault currently uses seeded local users with hashed demo passwords. Configuration placeholders already exist for OIDC and Microsoft Entra ID, but real federation is not implemented yet.

## Target Identity Modes

| Mode | Purpose | Status |
| --- | --- | --- |
| `local` | Demo identities and isolated development | Implemented |
| `oidc` | Generic OpenID Connect provider | RS256 ID-token validation implemented |
| `entra` | Microsoft Entra ID with group-to-role mapping | RS256 ID-token validation implemented |
| `saml` | Enterprise SAML deployments | Future |

## Authentication Requirements

- External identity must verify issuer, audience, signature, expiry, nonce, and state.
- The backend federated login endpoint validates compact RS256 ID tokens through OIDC discovery and JWKS, then requires matching issuer, audience, signature, expiry, MFA claim, group-to-role mapping, and a locally provisioned enabled user.
- Role assignment must come from configured groups or explicit admin mapping.
- `IDENTITY_ROLE_SECURITY_ADMIN`, `IDENTITY_ROLE_VAULT_OPERATOR`, and `IDENTITY_ROLE_AUDITOR` define external group mappings.
- `IDENTITY_GROUP_CLAIM` defines the token claim used for role mapping.
- Users must be disabled locally when access is revoked.
- Session creation must audit provider, subject, groups, and resulting role without logging tokens.
- Local demo login must remain available only when `IDENTITY_PROVIDER=local`.
- Local password login is disabled when `IDENTITY_PROVIDER` is `oidc` or `entra`; use `POST /api/login/federated` with an identity-provider ID token.
- `GET /api/identity/status` exposes provider mode and claim mapping metadata before login so the console can switch between local and federated sign-in modes.

Deployment evidence is captured in `docs/templates/identity-provider-evidence.json` and validated with:

```powershell
pnpm validate:identity-evidence docs/templates/identity-provider-evidence.json
```

When evidence is marked `pilot` or `production`, the validator rejects placeholders and requires issuer/JWKS, audience, signature, expiry, MFA claim, role mapping, logout revocation, rollback, and approval checks to pass.

## MFA Requirements

Current MFA is metadata and policy only. Production MFA should support:

- Enrollment state per user.
- Challenge verification during login.
- Admin reset and recovery workflow.
- Audit events for enrollment, reset, success, and failure.
- Policy enforcement for privileged roles.
- `IDENTITY_MFA_CLAIM` and `IDENTITY_MFA_REQUIRED_VALUE` define the expected provider MFA assertion for future token validation.

## Session Requirements

- Server-side logout and session invalidation are implemented.
- Admin session review and forced revocation APIs are implemented for active in-memory sessions.
- Add refresh or renewal only after replay protections are defined.
- Session source and user-agent metadata are recorded for admin review.
- Enforce idle timeout and absolute timeout.
- Avoid persistent sessions for the local demo unless explicitly configured.

## Implementation Notes

No OIDC, SAML, passkey, or MFA dependency has been added. The current OIDC/Entra implementation uses built-in Node.js crypto and fetch APIs for RS256 ID-token validation. The console can submit an externally acquired ID token in federated mode. Future production hardening should add nonce/state binding for browser redirects, provider-specific conformance tests, refresh-token replay protections, and optional approved identity SDK support.
