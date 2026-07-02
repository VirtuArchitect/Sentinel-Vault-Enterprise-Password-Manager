# Implementation Phases

This tracker translates the remaining roadmap into implementable phases. It should be updated whenever a phase moves from planned to implemented.

## Phase 1: Demo and Developer Experience

Status: Implemented

- Branded login and console UI.
- Browser favicon and Windows package icon asset.
- `scripts/start-demo.ps1` with `pnpm` and `npx pnpm@11.8.0` fallback.
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
- `pnpm validate:storage-migration` validates storage migration-readiness evidence before cutover or deployment bundle assembly.
- Postgres target schema and `pnpm plan:postgres` migration-planning evidence are available without adding a runtime database dependency.
- Postgres HA approval evidence template, generator, validator, and deployment-bundle gate for dependency, environment, cutover, rollback, and redaction approvals.
- Postgres should follow for HA deployments.
- See `storage-roadmap.md`.

## Phase 3: Real Authentication

Status: Backend OIDC/Entra ID-token validation and PKCE browser redirect implemented

- Local seeded users remain demo-only.
- OIDC and Entra ID placeholders exist in configuration.
- External provider role, group-claim, tenant, and MFA-claim settings are validated.
- Identity-provider evidence template and validator exist for OIDC/Entra readiness.
- Live identity-provider preflight evidence for OIDC discovery, JWKS, RS256 token validation, MFA claim, audience, and role-mapping conformance.
- Identity-provider evidence generator for preflight summaries, issuer/JWKS/client metadata, claim mappings, role mappings, rollback proof, and approvals.
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
- Tenant isolation evidence generator for scope counts, cross-tenant negative-test summaries, secret/session-token redaction checks, tenant identifier scoping, and approvals.
- Safe bulk administration metadata export for tenants, vaults, users, and policies.
- Safe bulk administration metadata import for tenants and vaults.
- Bulk secret import with encrypted escrow, duplicate detection, and independent approval.
- Bulk import runbook and source-system mapping templates.
- CSV source-export adapter with redacted migration evidence output.
- Bitwarden, Dashlane, LastPass, and 1Password CSV source-export adapters that normalize into the escrow import pipeline with redacted evidence.
- Configurable mapped-CSV source export adapter and column-map template for proprietary migration exports without code changes.
- Source migration evidence template, generator, validator, and deployment-bundle gate that bind proprietary column maps, redacted adapter evidence, normalized import output, storage migration evidence, and tenant-isolation proof.

Remaining:
- Completed deployment-specific proprietary source migration evidence and completed tenant-isolation evidence for each deployment.

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
- DevOps service-token compromise-response evidence generator for preflight enrichment, deployment status, owner metadata, approvals, and incident/change ticket binding.
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
- Connector certification evidence generator for live preflight summaries, least-privilege scope review, replay protection, redaction evidence, failure modes, rollback, and approvals.
- ITSM work-note evidence template, generator, validator, and deployment-bundle gate for redacted access request, approval, denial, and revocation work-note samples.
- SIEM receiver signing-key rotation evidence template and validator.
- SIEM receiver signing-key rotation evidence generator for receiver metadata, key-window checks, replay rejection, delivery samples, redaction review, and approvals.
- Deployment evidence bundle validator for connector, browser, identity, KMS/HSM, Windows release, storage, and provenance evidence.
- Deployment evidence workspace generator for environment-specific bundles copied from templates.
- Deployment evidence workspace manifest and validator that hash the copied bundle, README, and evidence templates before operator edits.
- Deployment evidence workspace template-drift check that rejects stale workspaces when new required evidence gates are added.
- Deployment evidence status reporter for operator-facing placeholder, validation, and production-readiness blockers.
- Deployment evidence status report validator and production release-gate check for stale or not-ready deployment evidence status.
- Deployment evidence redaction reporter, validator, and release-gate check that scan every bundle evidence file for private keys, service tokens, provider tokens, generic secret assignments, stale reports, and not-ready evidence.
- External evidence request generator for owner-ready Phase 2-8 deployment, signing, provider approval, extension ID, and native credential-provider inputs.
- External evidence request validator for strict operator handoff checks across remaining Phase 2-8 gates.
- External evidence request evidence-key mapping and validator drift check against the deployment evidence bundle template.
- External evidence request command-script summary and validator drift check against `package.json` scripts.
- Combined Phase 2-8 completion audit and readiness reporter that composes roadmap, deployment evidence status, and strict external evidence request validation.
- Phase readiness report command-script and evidence-key coverage summary from strict external request validation.
- Phase readiness report validator and production release-gate check for stale or not-ready readiness artifacts.
- Phase completion audit validator that rejects stale roadmap counts, uncovered remaining work, and request-pack drift.
- Fail-on-blockers readiness mode for CI or release gates that must stop when Phase 2-8 evidence is incomplete.
- CI coverage for deployment readiness and handoff tooling, including expected failure of placeholder deployment evidence under the strict release gate.
- Phase handoff checklist generator that converts readiness blockers and external evidence requests into owner-action checklists.
- Phase handoff checklist validator that detects stale or edited owner-action checklists before release gate review.
- Phase handoff checklist command-script coverage binding for owner validation commands.
- Composite production release gate check for direct phase handoff checklist consistency.
- Phase evidence pack manifest generator that records SHA-256 hashes for the deployment workspace manifest, readiness, handoff, deployment status, redaction, and deployment evidence review artifacts.
- Phase evidence pack validator that recomputes artifact hashes and checks manifest metadata against readiness and deployment status reports.
- Phase evidence pack external request command-script and evidence-key summary binding.
- Composite phase gate validator that validates the workspace, external request pack, completion audit, handoff checklist, phase evidence manifest, and readiness blocker summary in one command.
- Phase gate validation report external request command-script and evidence-key summary binding.
- Phase gate validation report validator and production release-gate check for stale or not-ready gate artifacts.
- Phase action register generator and validator that turn the validated gate and external evidence requests into owner-specific action records with deployment-bundle evidence-key traceability.
- Phase action register command-script coverage binding to the validated phase gate and request pack.
- Phase action register markdown command coverage validation for owner-facing action records.
- Phase gap matrix generator and validator that map every remaining blocker to deployment-bundle evidence keys and supporting artifacts.
- Phase gap matrix command-script coverage binding to the strict external request pack.
- Phase decision record generator and validator that convert the gate, actions, and gap matrix into an explicit phase closure go/no-go decision.
- Phase decision record command-script coverage binding across action and gap artifacts.
- Phase signoff matrix generator and validator that group remaining owner actions by approval role for deployment review.
- Phase signoff matrix command-script coverage binding for approval owner views.
- Phase decision and signoff evidence-key propagation so go/no-go records and approval views remain traceable to deployment-bundle gates.
- Phase evidence intake generator and validator that turn external owner requests into deployment-specific intake folders, expected files, validation commands, and redaction checks.
- Phase evidence intake and attachment inventory evidence-key propagation so owner files remain traceable to deployment-bundle gates.
- Phase evidence intake command-script coverage binding to owner validation commands.
- Phase attachment inventory generator and validator that hash attached intake evidence, report missing files, and flag redaction findings before closure review.
- Phase attachment inventory command-script coverage binding to evidence intake commands.
- Phase waiver register generator and validator that turn missing or redaction-flagged evidence into explicit proposed exceptions with evidence-key traceability, approval, expiry, and compensating-control fields.
- Phase waiver register command-script coverage binding to attachment inventory commands.
- Phase review bundle evidence-key summary that surfaces waived deployment-bundle gates and rejects stale review manifests.
- Phase review bundle evidence-key summary binding for decision and signoff artifacts.
- Phase review bundle command-script coverage binding for decision and signoff artifacts.
- Phase review bundle command-script coverage binding for waiver artifacts.
- Phase closure and release archive evidence-key summary binding so final archives preserve waived deployment-bundle gate traceability.
- Phase closure archive command-script coverage binding for final review manifests.
- Production release-gate evidence-key summary output and closure/review consistency check for waived deployment-bundle gates.
- Production release-gate command-script coverage output and closure/review consistency check.
- Release-mode phase review and closure validation that rejects proposed, expired, placeholder, or control-free waivers before final archive approval.
- Final phase review bundle manifest and validator that hash the phase evidence pack and phase gate validation reports for release review.
- Phase closure archive manifest and validator that bind the final review bundle to the current Git commit, branch, remote, and source tree state.
- Composite production release gate that validates deployment evidence, readiness, approved waivers, final review, closure archive provenance, and clean source state in one command.
- Production release-gate report validator that rejects stale archived gate output and can require release-ready status.
- Composite production release gate check for deployment workspace manifest integrity and evidence-template drift.
- Composite production release gate check for strict external evidence request-pack completeness.
- Composite production release gate check for direct phase evidence pack integrity.
- Composite production release gate check for direct phase gate validation without mutating reviewed artifacts.
- Composite production release gate checks for phase action register, gap matrix, decision record, and signoff matrix consistency.
- Composite production release gate checks for phase evidence intake, attachment inventory, and approved waiver consistency.
- Composite production release gate check for direct phase completion audit consistency and fail-on-remaining enforcement.
- README release-sequence drift test that requires the documented operator workflow to include every final-gate validation command.
- Production release archive manifest and validator that hash-bind the closure archive to the saved production release-gate report.
- Production release archive command-script coverage binding across closure and release-gate reports.
- Live SIEM/ITSM connector preflight evidence generator for signed delivery and ticket validation checks.

Remaining:
- Completed production live receiver, SIEM rotation, and ITSM work-note evidence files for each deployment environment.

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
- TLS/IIS deployment evidence generator for IIS binding and reverse-proxy review, certificate metadata, security headers, health checks, redaction findings, and approvals.
- Signed-EXE-ready Inno Setup authoring and build script.
- Windows release signature verification helper and release evidence template.
- Windows release evidence validator for signed MSI/MSIX/EXE artifacts and rollback evidence.
- Windows release evidence generator for artifact hashes, source commit, release host metadata, and planned signing status.
- Release attestation evidence template and validator for provenance, artifact hashes, signer identity, redaction, and approvals.
- Release attestation evidence generator for source provenance, lockfile and artifact hashes, attestation statements, signature metadata, release checks, redaction review, and approvals.
- Deployment evidence bundle validator that includes Windows release evidence with the wider production gate.
- Windows artifact signing helper with certificate-store and PFX support.
- MSI WiX authoring scaffold and WiX build/validation script.
- MSIX manifest authoring scaffold and Windows SDK build/validation script.
- Windows install hardening evidence template and validator for ACL, service identity, IIS/TLS, health check, upgrade, rollback, and uninstall gates.
- Windows install hardening evidence generator for local install layout checks, runtime-secret review, log redaction review, and supplied installer drill results.
- Windows signing execution evidence template, generator, validator, and deployment-bundle gate for MSI/MSIX signing on an approved certificate-backed release host.

Remaining:

- Completed MSI/MSIX signing execution evidence from an approved certificate-backed release host for each release environment.

## Phase 7: Security Hardening

Status: Started

Implemented:

- Security headers.
- Environment-aware CSP with production HSTS and stricter browser isolation headers.
- Config validation.
- Login rate limiting.
- Temporary account lockout after repeated failed login attempts.
- Brute-force and IP/source rate-limit evidence template and validator for lockout drills, proxy/WAF controls, alerts, and redaction.
- Brute-force evidence generator for lockout drill summaries, failed-attempt/source/alert counts, leaked password/token detection, network-control status, and deployment approvals.
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
- SAST evidence generator for scan-report severity counts, source commit metadata, coverage surfaces, redaction checks, and deployment approvals.
- Centralized log-shipping redaction evidence template and validator for SIEM/log sink samples, parser health, retention, and leaked-secret findings.
- Log-redaction evidence generator for local or receiver sample review, synthetic secret/token counts, parser failures, leaked-value detection, retention, controls, and approvals.
- Release provenance generator for source commit, lockfile, dependency inventory, and artifact hashes.
- Penetration-test scope evidence template and validator for authorized scope, required abuse cases, redaction requirements, remediation, retest, and approvals.
- Penetration-test scope evidence generator for finding severity summaries, required Sentinel surfaces, abuse-case dispositions, evidence requirements, remediation, and approvals.
- Tamper-evident audit hash chaining.
- Signed audit ledger export and append-only JSONL ledger for file-backed deployments.
- Audit WORM evidence template and validator for external signing, immutable retention, object lock, legal hold, readback verification, redaction, and approvals.
- Audit WORM evidence generator for signed ledger export hashes, event counts, redaction checks, external signing metadata, immutable retention controls, and approvals.
- Backup SHA-256 manifests and admin verification API.
- AES-GCM encrypted backup artifacts and restore-validation dry run API.
- Backup recovery evidence template and validator for restore cadence, break-glass roles, key escrow, two-person control, retention, offsite copy, immutability, RPO/RTO, and redaction.
- Backup recovery evidence generator for restore-drill results, recovery ceremony, key escrow, retention controls, RPO/RTO, redaction, and approvals.
- Device trust evidence template and validator for trusted-device policy, new-device MFA, stale-device review, forced session revocation, replay drills, and session-token redaction.
- Device trust evidence generator for trusted-device inventory counts, stale/unknown/disabled-user device detection, fingerprint hashing review, token leakage checks, replay control status, and approvals.
- Key-provider boundary for local root key, external KMS, and HSM readiness.
- KMS/HSM key ceremony runbook and provider evidence template.
- KMS/HSM provider evidence validator.
- KMS/HSM HTTP gateway preflight for live status and sign-operation evidence without adding cloud SDK dependencies.
- KMS/HSM provider evidence generator for gateway preflight summaries, provider/key metadata, policy hash, rotation dates, audit/backup/restore checks, and approvals.
- KMS/HSM provider SDK approval evidence template, generator, validator, and deployment-bundle gate for dependency, supply-chain, environment, operation-proof, rollback, and redaction approval before any provider SDK is added.
- Dependency-free KMS/HSM HTTP gateway runtime signing for non-local key-provider modes with key-ID and signature-shape validation.
- Threat model.
- Security review checklist.

Remaining:

- Provider SDK-backed KMS/HSM implementation after completed dependency, environment, and operation-proof approval evidence.

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
- Browser extension identity evidence template, generator, validator, and deployment-bundle gate for production Chrome/Edge extension IDs, private-channel review, enterprise policy assignment, rollback ownership, and redaction checks.
- Browser enterprise policy renderer for completed rollout evidence.
- Native companion and credential-provider release evidence template and validator for signed-artifact, abuse-test, rollback, and approval gates.
- Native companion release evidence generator for artifact hashes, architecture metadata, native messaging metadata, and planned credential-provider release gates.
- Credential-provider approval evidence template, generator, validator, and deployment-bundle gate for implementation approval, LSASS/secure desktop risk review, signed DLL evidence, install/uninstall, rollback, and redaction checks.
- Offline cache and native autotype architecture roadmap.
- Extension artifact validation gate.

Remaining:

- Completed deployment-specific browser extension identity and rollout evidence files with production extension IDs.
- Signed native credential-provider implementation after completed approval evidence.
