# Tenant Isolation Model

Sentinel Vault enforces tenant isolation through vault membership and service-layer object checks. Tenant metadata groups vaults by business or operational boundary, while vault membership is the authorization boundary used by secret, access-request, offline-cache, and administration workflows.

## Enforcement Rules

- HTTP routes apply coarse RBAC checks before entering service logic.
- Service methods re-check vault or secret access before reveal, rotate, update, delete, restore, share, approve, deny, or revoke operations.
- Security admins can administer tenant metadata and all vaults; non-admin operators only receive vaults and secrets that are directly accessible through vault membership, explicit sharing, or an active just-in-time grant.
- Tenant lists and administration metadata exports are available only to `policy:write` users.
- Console payload filtering is not treated as the security boundary; API service checks are the authority.

## Production Evidence

Production deployments should attach negative authorization evidence showing that a user from one tenant or vault cannot:

- reveal or rotate a secret from another tenant vault;
- mutate, delete, restore, or version-restore another tenant vault secret;
- share another tenant vault secret;
- approve, deny, or revoke access requests for another tenant vault secret;
- obtain another tenant vault through console or offline-cache payloads.

This evidence should be included with penetration-test and SAST evidence in the deployment evidence bundle.
