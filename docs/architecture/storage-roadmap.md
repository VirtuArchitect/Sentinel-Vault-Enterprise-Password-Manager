# Storage Roadmap

Sentinel Vault currently uses a JSON-backed prototype store. That keeps the demo easy to run, but production storage needs transactions, migrations, concurrency control, backup validation, and operational observability.

## Target Storage Modes

| Mode | Purpose | Status |
| --- | --- | --- |
| `json` | Local demo and development state | Implemented |
| `sqlite` | Single-node production prototype and Windows installer default | Implemented with built-in Node SQLite runtime |
| `postgres` | Multi-node and HA deployment target | Provider config ready; runtime planned |

## Store Boundary

The current `store` module exposes an explicit provider boundary through `STORAGE_PROVIDER`. JSON remains the default demo provider, and SQLite is available for single-node Windows/server prototypes through Node's built-in `node:sqlite` runtime. The adapter boundary has these responsibilities:

- Load and normalize state.
- Persist users, vaults, secrets, audit events, access requests, service tokens, policies, integrations, and metadata.
- Provide transaction helpers for multi-record workflows such as reveal audit, access approval, and secret rotation.
- Enforce state version and migration checks before the server starts.
- Expose health, backup, restore, and retention metadata to admin-only endpoints.

Migration readiness evidence can be generated from a JSON state file:

```powershell
pnpm inspect:storage -- --state ".\data\sentinel-state.json"
```

The default evidence output is `artifacts/storage/storage-migration-evidence.json`.

## SQLite Phase

SQLite fits the Windows installer and avoids external database setup.

Implemented:

- Use the implemented `STORAGE_PROVIDER=sqlite` and `SQLITE_PATH` configuration.
- Persist the normalized Sentinel Vault state in a SQLite database with full synchronous durability.
- Initialize a new SQLite database from the current seed state.
- Mirror users, device inventory, tenants, vaults, secrets, service tokens, imports, access requests, integration outbox records, audit events, and policies into relational SQLite tables in the same transaction as the canonical snapshot.
- Preserve the same encrypted secret payloads, audit records, tenant metadata, access requests, integrations, policies, and service-token metadata as JSON mode.
- Include SQLite database copies in the existing backup manifest flow.
- Enforce migration-readiness evidence before JSON-to-SQLite cutover and write the same relational mirror tables during migration.
- Use repository-level transaction helpers so secret lifecycle mutations, audit events, integration outbox records, and persistence commits succeed or roll back together.
- Validate encrypted backups with a dry-run restore drill that verifies the manifest checksum, decrypts the AES-GCM payload, checks state collections, and writes restore evidence.
- Migrate an existing JSON state file into a SQLite database with redacted migration evidence:

```powershell
pnpm migrate:sqlite -- --state ".\data\sentinel-state.json" --sqlite ".\data\sentinel-vault.sqlite"
```

- Test persistence across separate Node.js processes.
- Run the same API and service test suite in JSON mode and SQLite mode through `pnpm test` and `pnpm test:sqlite`; CI runs SQLite parity on Node.js 24.

Remaining:

- Postgres provider implementation after dependency and deployment target approval.

No SQLite npm dependency has been added. SQLite mode requires a Node.js runtime that exposes `node:sqlite`.

## Postgres Phase

Postgres should follow once the store adapter and migration model are proven.

Planned work:

- Use the implemented `STORAGE_PROVIDER=postgres` and `DATABASE_URL` configuration.
- Add connection pooling.
- Add migration locking.
- Use `docs/templates/storage-migration-evidence.json` as required cutover evidence.
- Add row-level ownership checks where appropriate.
- Add backup and restore runbooks.
- Add HA deployment guidance.

## Data Protection Requirements

- Secrets remain encrypted before persistence.
- Secret fingerprints remain non-reversible and scoped to a vault.
- Session records must not be persisted unless refresh-token support is deliberately added.
- Audit records must not include secret values.
- Backup files must inherit the same filesystem protections as the primary state.
