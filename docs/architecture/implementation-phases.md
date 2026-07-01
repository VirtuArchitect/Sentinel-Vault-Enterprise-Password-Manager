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

Status: Architecture ready, implementation pending dependency approval

- JSON store remains the demo provider.
- SQLite should be the next provider for Windows and single-node production prototypes.
- Postgres should follow for HA deployments.
- See `storage-roadmap.md`.

## Phase 3: Real Authentication

Status: Architecture ready, implementation pending dependency approval

- Local seeded users remain demo-only.
- OIDC and Entra ID placeholders exist in configuration.
- MFA is currently policy metadata, not real challenge verification.
- See `identity-roadmap.md`.

## Phase 4: Vault Administration

Status: Partially implemented

Implemented:

- Add, reveal, rotate, share, request access, approve, deny, revoke, soft delete, and restore APIs.
- RBAC and object-level vault checks.
- Edit-secret UI.
- Deleted-items view with restore action.
- Version-history UI with restore action.
- Vault/group creation and membership management.
- User enable/disable and role management UI.

Remaining:
- Tenant hierarchy and bulk import/export administration.

## Phase 5: Enterprise Integrations

Status: Partially implemented

Implemented:

- Integration status.
- Integration outbox metadata.
- Scoped DevOps service-token retrieval API.
- Last-used, use-count, and rotation metadata for service tokens.
- SIEM webhook delivery worker with bounded retries.
- HMAC signing for SIEM webhook payloads.
- ITSM ticket validation.
- Integration configuration UI.

Remaining:
- Receiver-side replay guidance and production connector certification.

## Phase 6: Windows Installer Hardening

Status: Partially implemented

Implemented:

- Windows zip package.
- PowerShell installer and uninstaller.
- Scheduled Task supervisor.
- Optional IIS front-end configuration.
- Package icon asset.
- Start Menu shortcut.
- Upgrade backup and rollback script.
- Code-signing documentation.
- TLS/IIS setup checklist with certificate guidance.

Remaining:

- MSI/MSIX or signed EXE installer.

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
- Tamper-evident audit hash chaining.
- Signed audit ledger export and append-only JSONL ledger for file-backed deployments.
- Backup SHA-256 manifests and admin verification API.
- AES-GCM encrypted backup artifacts and restore-validation dry run API.
- Threat model.
- Security review checklist.

Remaining:

- KMS/HSM design and implementation.

## Phase 8: Browser and Desktop Extensions

Status: Planned

Remaining:

- Browser extension autofill.
- Clipboard auto-clear companion.
- Windows tray helper.
- Offline read-only cache.
- Native autotype or credential-provider research.
