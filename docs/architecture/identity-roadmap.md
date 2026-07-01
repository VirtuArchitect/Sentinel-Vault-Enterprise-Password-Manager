# Identity Roadmap

Sentinel Vault currently uses seeded local users with hashed demo passwords. Configuration placeholders already exist for OIDC and Microsoft Entra ID, but real federation is not implemented yet.

## Target Identity Modes

| Mode | Purpose | Status |
| --- | --- | --- |
| `local` | Demo identities and isolated development | Implemented |
| `oidc` | Generic OpenID Connect provider | Provider config ready; token validation planned |
| `entra` | Microsoft Entra ID with group-to-role mapping | Provider config ready; token validation planned |
| `saml` | Enterprise SAML deployments | Future |

## Authentication Requirements

- External identity must verify issuer, audience, signature, expiry, nonce, and state.
- Role assignment must come from configured groups or explicit admin mapping.
- `IDENTITY_ROLE_SECURITY_ADMIN`, `IDENTITY_ROLE_VAULT_OPERATOR`, and `IDENTITY_ROLE_AUDITOR` define external group mappings.
- `IDENTITY_GROUP_CLAIM` defines the token claim used for role mapping.
- Users must be disabled locally when access is revoked.
- Session creation must audit provider, subject, groups, and resulting role without logging tokens.
- Local demo login must remain available only when `IDENTITY_PROVIDER=local`.

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

No OIDC, SAML, passkey, or MFA dependency has been added yet. The repository instructions require asking before new runtime dependencies. External identity modes are intentionally configuration-gated until a token validation library and provider metadata are approved.
