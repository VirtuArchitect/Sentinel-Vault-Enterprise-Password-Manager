# Administration Metadata Import and Export

Sentinel Vault supports a safe administration metadata exchange for standing up tenant and vault structures without moving secret material.

## Export

`GET /api/admin/export` returns:

- Tenant hierarchy metadata.
- Vault group metadata and membership.
- Public user metadata.
- Policy settings.

The export intentionally excludes password hashes, password salts, encrypted secret payloads, service tokens, sessions, device bearer material, and audit records.

## Import

`POST /api/admin/import` accepts tenant and vault metadata only. It rejects payloads containing secrets, service tokens, sessions, or audit records.

Tenants can be created or updated by ID. Parent tenant references are validated and hierarchy cycles are rejected. Vault imports validate tenant references and user membership IDs before creating or updating vault metadata.

## Production Boundary

Bulk secret import remains a separate production workflow because it needs duplicate detection, escrow review, import provenance, malware-safe file handling, and two-person approval before secret material enters a managed vault.
