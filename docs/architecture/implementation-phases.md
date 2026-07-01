# Implementation Phases

This tracker translates the remaining roadmap into implementable phases. It should be updated whenever a phase moves from planned to implemented.

## Phase 1: Demo and Developer Experience

Status: Implemented

- Branded login and console UI.
- Browser favicon and Windows package icon asset.
- `scripts/start-demo.ps1` with `pnpm` and `npx pnpm@11.7.0` fallback.
- README quick start and troubleshooting for `pnpm`, Corepack, Node.js, and port `5173`.
- Repeatable smoke tests in `docs/testing/smoke-tests.md`.

## Phase 2: Production Storage

Status: SQLite runtime implemented, Postgres implementation pending dependency approval

- JSON store remains the demo provider.
- `STORAGE_PROVIDER`, `SQLITE_PATH`, and `DATABASE_URL` configuration boundaries are validated.
- JSON state migration-readiness inspector and evidence template exist.
- SQLite provider persists normalized state using Node's built-in SQLite runtime for Windows and single-node production prototypes.
- SQLite mode mirrors normalized entities into relational tables in the same transaction as the canonical state snapshot for inspection, reporting, and migration readiness.
- JSON-to-SQLite cutover enforces migration-readiness checks and writes the same relational mirror tables as the runtime provider.
- JSON-to-SQLite migration script writes the current normalized state snapshot and redacted migration evidence.
- `pnpm test:sqlite` runs the API and service suite against the SQLite provider, and CI executes it on Node.js 24.
- Secret lifecycle operations use a repository-level transaction boundary with rollback for state, audit, integration outbox, and deferred commit hooks.
- `pnpm validate:restore-drill` performs encrypted-backup restore dry runs and writes restore evidence without changing live state.
- Postgres target schema and `pnpm plan:postgres` migration-planning evidence are available without adding a runtime database dependency.
- Postgres should follow for HA deployments.
- See `storage-roadmap.md`.

## Phase 3: Real Authentication

Status: Backend OIDC/Entra ID-token validation and PKCE browser redirect implemented

- Local seeded users remain demo-only.
- OIDC and Entra ID placeholders exist in configuration.
- External provider role, group-claim, tenant, and MFA-claim settings are validated.
- Identity-provider evidence template and validator exist for OIDC/Entra readiness.
- `POST /api/login/federated` validates RS256 ID tokens with OIDC discovery/JWKS, issuer, audience, expiry, MFA claim, group-to-role mapping, and local enabled-user provisioning.
- `GET /api/identity/status` and the console login screen switch between local demo unlock and external ID-token sign-in.
- `POST /api/login/federated/start` and `/callback` implement authorization-code PKCE with short-lived state, nonce validation, and replay rejection.
- MFA is enforced as an identity-provider token claim; interactive challenge UX remains provider-owned.
- See `identity-roadmap.md`.

## Phase 4: Vault Administration

Status: Implemented

Implemented:

- Add, reveal, rotate, share, request access, approve, deny, revoke, soft delete, and restore APIs.
- RBAC and object-level vault checks.
- Edit-secret UI.
- Deleted-items view with restore action.
- Version-history UI with restore action.
- Vault/group creation and membership management.
- User enable/disable and role management UI.
- Tenant hierarchy metadata with cycle prevention.
- Tenant-aware vault creation and update.
- Safe bulk administration metadata export for tenants, vaults, users, and policies.
- Safe bulk administration metadata import for tenants and vaults.
- Bulk secret import with encrypted escrow, duplicate detection, and independent approval.
- Bulk import runbook and source-system mapping templates.
- CSV source-export adapter with redacted migration evidence output.

Remaining:
- Deployment-specific proprietary source export adapters.

## Phase 5: Enterprise Integrations

Status: Partially implemented

Implemented:

- Integration status.
- Integration outbox metadata.
- Scoped DevOps service-token retrieval API.
- Last-used, use-count, and rotation metadata for service tokens.
- SIEM webhook delivery worker with bounded retries.
- HMAC signing for SIEM webhook payloads.
- SIEM webhook delivery IDs, timestamps, nonces, signed-envelope verification, and replay-window guidance.
- ITSM ticket format validation and live ticket lookup for active/open change or incident records.
- Integration configuration UI.
- Production connector certification checklist for SIEM, ITSM, and DevOps integrations.
- Connector certification evidence template and validator.
- Deployment evidence bundle validator for connector, browser, identity, KMS/HSM, Windows release, storage, and provenance evidence.

Remaining:
- Completed live receiver evidence files for each deployment environment.

## Phase 6: Windows Installer Hardening

Status: Partially implemented

Implemented:

- Windows zip package.
- PowerShell installer and uninstaller.
- Scheduled Task supervisor.
- Installer storage-provider switches for JSON and SQLite deployments.
- Optional IIS front-end configuration.
- Package icon asset.
- Start Menu shortcut.
- Upgrade backup and rollback script.
- Code-signing documentation.
- TLS/IIS setup checklist with certificate guidance.
- Signed-EXE-ready Inno Setup authoring and build script.
- Windows release signature verification helper and release evidence template.
- Deployment evidence bundle validator that includes Windows release evidence with the wider production gate.
- Windows artifact signing helper with certificate-store and PFX support.
- MSI WiX authoring scaffold and WiX build/validation script.
- MSIX manifest authoring scaffold and Windows SDK build/validation script.

Remaining:

- MSI/MSIX signing execution evidence from an approved certificate-backed release host.

## Phase 7: Security Hardening

Status: Started

Implemented:

- Security headers.
- Environment-aware CSP with production HSTS and stricter browser isolation headers.
- Config validation.
- Login rate limiting.
- Temporary account lockout after repeated failed login attempts.
- Server-side logout and session invalidation.
- Active session count and TTL surfaced in the Management panel.
- Admin session review and forced active-session revocation APIs.
- Persistent device inventory metadata for future refresh-token workflows.
- Service-token last-used source, last-used secret, and use-count metadata.
- Dependency audit in CI.
- Secret scanning in CI for private keys, common token formats, and suspicious committed assignments.
- Release provenance generator for source commit, lockfile, dependency inventory, and artifact hashes.
- Tamper-evident audit hash chaining.
- Signed audit ledger export and append-only JSONL ledger for file-backed deployments.
- Backup SHA-256 manifests and admin verification API.
- AES-GCM encrypted backup artifacts and restore-validation dry run API.
- Key-provider boundary for local root key, external KMS, and HSM readiness.
- KMS/HSM key ceremony runbook and provider evidence template.
- KMS/HSM provider evidence validator.
- KMS/HSM HTTP gateway preflight for live status and sign-operation evidence without adding cloud SDK dependencies.
- Threat model.
- Security review checklist.

Remaining:

- Provider SDK-backed KMS/HSM integration after dependency and environment approval.

## Phase 8: Browser and Desktop Extensions

Status: Started

Implemented:

- Browser extension Manifest V3 scaffold.
- Explicit browser autofill flow with local-console login, URL matching, audited reveal, and active-tab field injection.
- Windows clipboard/tray helper PowerShell prototype.
- Clipboard auto-clear companion implementation with Sentinel-owned marker hashes.
- Windows tray UI mode for console launch and Sentinel-owned clipboard clear.
- Encrypted read-only offline cache export and verification APIs.
- DPAPI-protected Windows offline cache storage and manifest inspection helper.
- Current-user scheduled cleanup for expired DPAPI-protected offline caches.
- Read-only native offline cache metadata browser.
- Online rehydration for encrypted offline cache entries through live server authorization.
- Guarded native autotype proof of concept in the Windows companion.
- Credential-provider proof-of-concept boundary and formal autotype security review.
- Browser extension packaging script, enterprise policy templates, and store review checklist.
- Browser extension enterprise rollout evidence template and validator.
- Browser enterprise policy renderer for completed rollout evidence.
- Offline cache and native autotype architecture roadmap.
- Extension artifact validation gate.

Remaining:

- Completed deployment-specific browser extension rollout evidence files with production extension IDs.
- Signed native credential-provider implementation after approval.
