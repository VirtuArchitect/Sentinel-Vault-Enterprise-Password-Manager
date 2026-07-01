# KMS and HSM Roadmap

## Current Provider Boundary

Sentinel Vault now exposes a key-provider boundary with three configured modes:

- `local-root-key`: demo and prototype mode using `VAULT_ROOT_KEY`.
- `external-kms`: envelope-key mode for future cloud or enterprise KMS SDK integration.
- `hsm`: envelope-key mode for future hardware security module integration.

The current implementation does not add provider SDK dependencies. Non-local modes require `KMS_KEY_ID` so deployments cannot silently claim external key management without a key reference.

## Required Production Follow-Up

- Select the approved provider SDK or Windows CNG/HSM interface.
- Move root wrapping material out of process environment variables.
- Add key unwrap/sign operations through the provider API.
- Add key rotation with old-version decrypt and new-version encrypt.
- Add operational recovery procedures for lost, disabled, or rotated keys.
- Add cryptographic review before storing production secrets.
