# KMS and HSM Roadmap

## Current Provider Boundary

Sentinel Vault now exposes a key-provider boundary with three configured modes:

- `local-root-key`: demo and prototype mode using `VAULT_ROOT_KEY`.
- `external-kms`: envelope-key mode with optional dependency-free HTTP gateway signing before future cloud or enterprise KMS SDK integration.
- `hsm`: envelope-key mode with optional dependency-free HTTP gateway signing before future hardware security module integration.

Operational evidence templates:

- `docs/operations/kms-hsm-key-ceremony.md`
- `docs/templates/kms-hsm-provider-evidence.json`

Validate provider evidence with:

```powershell
pnpm validate:kms-hsm-evidence docs/templates/kms-hsm-provider-evidence.json
```

Validate a live HTTP KMS/HSM gateway preflight with:

```powershell
pnpm preflight:kms-hsm -- --provider external-kms --endpoint "https://kms-gateway.example" --key-id "sentinel-prod-key"
```

When evidence is marked `approved` or `active`, the validator rejects placeholders, requires a concrete `external-kms` or `hsm` provider boundary, requires a SHA-256 policy hash, and requires all operational checks to pass.

The current implementation does not add provider SDK dependencies. Non-local modes require `KMS_KEY_ID` so deployments cannot silently claim external key management without a key reference. When `KMS_ENDPOINT` is set, runtime signing calls the deployment-owned HTTP gateway `POST /sign` with `keyId`, `purpose`, and `value`, validates the returned key ID and signature shape, and reports `signingMode: gateway-sign` in the crypto status. Without `KMS_ENDPOINT`, Sentinel remains in `envelope-reference-hmac` signing mode for non-local providers.

The gateway preflight expects the same deployment-owned adapter with `GET /status?keyId=...` and `POST /sign`; it validates provider identity, key ID, disabled key export, audit logging, advertised sign capability, and returned signature metadata.

## Required Production Follow-Up

- Select the approved provider SDK or Windows CNG/HSM interface.
- Attach the preflight evidence to the environment-specific provider approval record.
- Move root wrapping material out of process environment variables.
- Add key unwrap operations through the provider API.
- Add key rotation with old-version decrypt and new-version encrypt.
- Add operational recovery procedures for lost, disabled, or rotated keys.
- Add cryptographic review before storing production secrets.
