# Offline Read-Only Cache

Sentinel Vault can export a per-user offline cache artifact for controlled read-only scenarios.

## API

- `POST /api/offline-cache/export`
- `POST /api/offline-cache/verify`

The export is scoped to the requesting user's accessible vaults and shared secrets. Temporary just-in-time grants are not promoted into long-lived offline access.

## Artifact Boundary

The cache manifest is readable and includes counts, expiry, key version, and `plaintextIncluded: false`.

The cache body is encrypted with AES-256-GCM and contains:

- Tenant-aware vault metadata.
- Secret metadata required for lookup.
- Existing encrypted secret payloads.

Plaintext passwords are never written into the offline cache artifact.

## Remaining Native Work

A production Windows offline reader should protect its local unlock key with DPAPI or an approved enterprise KMS/HSM flow, enforce read-only mode in the UI, and delete expired artifacts automatically.
