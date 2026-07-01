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
- Live identity-provider preflight evidence for OIDC discovery, JWKS, RS256 token validation, MFA claim, audience, and role-mapping conformance.
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
- Tenant isolation model and broader cross-tenant negative authorization tests for reveal, update, delete, restore, rotate, share, and access approval operations.
- Tenant isolation evidence template and validator for deployment-specific cross-tenant control gates.
- Safe bulk administration metadata export for tenants, vaults, users, and policies.
- Safe bulk administration metadata import for tenants and vaults.
- Bulk secret import with encrypted escrow, duplicate detection, and independent approval.
- Bulk import runbook and source-system mapping templates.
- CSV source-export adapter with redacted migration evidence output.
- Bitwarden, Dashlane, LastPass, and 1Password CSV source-export adapters that normalize into the escrow import pipeline with redacted evidence.
- Configurable mapped-CSV source export adapter and column-map template for proprietary migration exports without code changes.

Remaining:
- Deployment-specific proprietary source column maps, migration evidence files, and completed tenant-isolation evidence for each deployment.

## Phase 5: Enterprise Integrations

Status: Partially implemented

Implemented:

- Integration status.
- Integration outbox metadata.
- Scoped DevOps service-token retrieval API.
- Last-used, use-count, and rotation metadata for service tokens.
- Keyed HMAC service-token hashing with public hash-version metadata and legacy SHA-256 hash migration on successful scoped use.
- DevOps service-token compromise-response preflight evidence for revoked-token rejection, replacement-token retrieval, scope enforcement, and redacted output.
- DevOps service-token compromise-response evidence template and validator included in deployment evidence bundles.
- SIEM webhook delivery worker with bounded retries.
- HMAC signing for SIEM webhook payloads.
- SIEM webhook delivery IDs, timestamps, nonces, signed-envelope verification, and replay-window guidance.
- SIEM webhook signing key IDs and previous-key rotation metadata for receiver rotation windows.
- ITSM ticket format validation and live ticket lookup for active/open change or incident records.
- Configurable ITSM allowed-state and change-window enforcement for privileged access requests and connector preflight evidence.
- Redacted ITSM work-note updates for access request, approval, denial, and revocation events.
- Integration configuration UI.
- Production connector certification checklist for SIEM, ITSM, and DevOps integrations.
- Connector certification evidence template and validator.
- SIEM receiver signing-key rotation evidence template and validator.
- Deployment evidence bundle validator for connector, browser, identity, KMS/HSM, Windows release, storage, and provenance evidence.
- Deployment evidence workspace generator for environment-specific bundles copied from templates.
- Live SIEM/ITSM connector preflight evidence generator for signed delivery and ticket validation checks.

Remaining:
- Completed production live receiver and ITSM work-note evidence files for each deployment environment.

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
- TLS/IIS deployment evidence template and validator for certificate, redirect, HSTS, reverse proxy, health checks, and redaction.
- Signed-EXE-ready Inno Setup authoring and build script.
- Windows release signature verification helper and release evidence template.
- Windows release evidence validator for signed MSI/MSIX/EXE artifacts and rollback evidence.
- Windows release evidence generator for artifact hashes, source commit, release host metadata, and planned signing status.
- Release attestation evidence template and validator for provenance, artifact hashes, signer identity, redaction, and approvals.
- Deployment evidence bundle validator that includes Windows release evidence with the wider production gate.
- Windows artifact signing helper with certificate-store and PFX support.
- MSI WiX authoring scaffold and WiX build/validation script.
- MSIX manifest authoring scaffold and Windows SDK build/validation script.
- Windows install hardening evidence template and validator for ACL, service identity, IIS/TLS, health check, upgrade, rollback, and uninstall gates.

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
- Brute-force and IP/source rate-limit evidence template and validator for lockout drills, proxy/WAF controls, alerts, and redaction.
- Server-side logout and session invalidation.
- Active session count and TTL surfaced in the Management panel.
- Admin session review and forced active-session revocation APIs.
- Persistent device inventory metadata for future refresh-token workflows.
- Optional external-identity refresh-session flow with hashed refresh tokens, one-time rotation, replay family revocation, bounded TTL, and admin/session revocation cleanup.
- Service-token last-used source, last-used secret, and use-count metadata.
- Service-token keyed HMAC hashing and legacy hash migration.
- Dependency audit in CI.
- Secret scanning in CI for private keys, common token formats, and suspicious committed assignments.
- SAST evidence template and validator for scanner coverage, critical/high finding gates, remediation, retest, and redaction.
- Centralized log-shipping redaction evidence template and validator for SIEM/log sink samples, parser health, retention, and leaked-secret findings.
- Release provenance generator for source commit, lockfile, dependency inventory, and artifact hashes.
- Penetration-test scope evidence template and validator for authorized scope, required abuse cases, redaction requirements, remediation, retest, and approvals.
- Tamper-evident audit hash chaining.
- Signed audit ledger export and append-only JSONL ledger for file-backed deployments.
- Audit WORM evidence template and validator for external signing, immutable retention, object lock, legal hold, readback verification, redaction, and approvals.
- Backup SHA-256 manifests and admin verification API.
- AES-GCM encrypted backup artifacts and restore-validation dry run API.
- Backup recovery evidence template and validator for restore cadence, break-glass roles, key escrow, two-person control, retention, offsite copy, immutability, RPO/RTO, and redaction.
- Device trust evidence template and validator for trusted-device policy, new-device MFA, stale-device review, forced session revocation, replay drills, and session-token redaction.
- Key-provider boundary for local root key, external KMS, and HSM readiness.
- KMS/HSM key ceremony runbook and provider evidence template.
- KMS/HSM provider evidence validator.
- KMS/HSM HTTP gateway preflight for live status and sign-operation evidence without adding cloud SDK dependencies.
- Dependency-free KMS/HSM HTTP gateway runtime signing for non-local key-provider modes with key-ID and signature-shape validation.
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
- Browser extension rollout evidence generator for packaged artifact SHA-256, manifest version, and planned enterprise rollout metadata.
- Browser enterprise policy renderer for completed rollout evidence.
- Native companion and credential-provider release evidence template and validator for signed-artifact, abuse-test, rollback, and approval gates.
- Offline cache and native autotype architecture roadmap.
- Extension artifact validation gate.

Remaining:

- Completed deployment-specific browser extension rollout evidence files with production extension IDs.
- Signed native credential-provider implementation after approval.
