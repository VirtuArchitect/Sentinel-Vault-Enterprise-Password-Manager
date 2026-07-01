# Storage Roadmap

Sentinel Vault currently uses a JSON-backed prototype store. That keeps the demo easy to run, but production storage needs transactions, migrations, concurrency control, backup validation, and operational observability.

## Target Storage Modes

| Mode | Purpose | Status |
| --- | --- | --- |
| `json` | Local demo and development state | Implemented |
| `sqlite` | Single-node production prototype and Windows installer default | Planned |
| `postgres` | Multi-node and HA deployment target | Planned |

## Store Boundary

The current `store` module should become an adapter boundary with these responsibilities:

- Load and normalize state.
- Persist users, vaults, secrets, audit events, access requests, service tokens, policies, integrations, and metadata.
- Provide transaction helpers for multi-record workflows such as reveal audit, access approval, and secret rotation.
- Enforce state version and migration checks before the server starts.
- Expose health, backup, restore, and retention metadata to admin-only endpoints.

## SQLite Phase

SQLite is the recommended next implementation step because it fits the Windows installer and avoids external database setup.

Planned work:

- Add a `STORAGE_PROVIDER=sqlite` configuration option.
- Add `DATABASE_URL` or `SQLITE_PATH` configuration.
- Create migration scripts for the current JSON entities.
- Add import/export from the existing JSON state file.
- Use transactions for secret lifecycle operations.
- Extend the implemented backup integrity manifests into encrypted backup and restore validation workflows.
- Add tests that run the same API suite against JSON and SQLite modes.

No SQLite runtime dependency has been added yet. The repository instructions require asking before new runtime dependencies.

## Postgres Phase

Postgres should follow once the store adapter and migration model are proven.

Planned work:

- Add connection pooling.
- Add migration locking.
- Add row-level ownership checks where appropriate.
- Add backup and restore runbooks.
- Add HA deployment guidance.

## Data Protection Requirements

- Secrets remain encrypted before persistence.
- Secret fingerprints remain non-reversible and scoped to a vault.
- Session records must not be persisted unless refresh-token support is deliberately added.
- Audit records must not include secret values.
- Backup files must inherit the same filesystem protections as the primary state.
