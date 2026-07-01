# Sentinel Vault Enterprise Password Manager

Sentinel Vault is a KeePass-inspired, multi-user enterprise password manager prototype with a web console and an Express API. It is designed as a defence-grade reference interface: group tree, entry table, database-style tabs, entry details, password generator, audit trail, RBAC, policy controls, and encrypted vault records.

<img width="1168" height="186" alt="image" src="https://github.com/user-attachments/assets/428f5d89-8840-444d-8aaf-47b40d64f131" />


**Demo:** [Open the local Sentinel Vault console](http://127.0.0.1:5173) after starting the app with `pnpm demo` or `.\scripts\start-demo.ps1`.

![Sentinel Vault logo](src/assets/sentinel-vault-mark.svg)

The local demo opens directly into the Sentinel Vault console experience with seeded demo identities, branded favicon/app icon assets, and a Windows-console-inspired vault workbench.

## Features

- KeePass-style vault workbench with menu bar, toolbar, group tree, entry grid, preview pane, and status bar
- Branded Sentinel Vault logo, browser favicon, and Windows package icon asset
- Branded loading, locked, error, and empty-result states for the demo console
- Multi-user demo identities with role-based access control
- Server-side RBAC checks for vault read/write/share, audit, users, and policy operations
- AES-256-GCM encrypted secret payloads in the API layer
- Add, reveal, rotate, share, request access, and approve temporary access workflows
- Password, API key, token, certificate, SSH key, directory account, registry token, and connection string secret metadata
- Secret health reporting for stale, reused, high-risk, and rotated records
- Secret edit, soft delete, deleted-items restore, version-history restore, and scoped DevOps service-token retrieval/rotation APIs
- Password generator with configurable character classes and quality feedback
- Audit trail for login, reveal, rotate, share, create, policy, and access approval actions
- Enterprise policy controls for MFA, JIT access, rotation, clipboard TTL, minimum length, and session duration with server-side validation
- JIT approval metadata with ticket references, requested duration, approval counts, and high-risk approval requirements
- Session expiry enforcement and permission-scoped console payloads
- Persistent device inventory metadata for admin session review without storing bearer tokens
- Optional external-identity refresh tokens with hashed storage, one-time rotation, replay family revocation, and bounded lifetime
- Identity provider metadata for local, OIDC, and Microsoft Entra ID configuration
- Key lifecycle metadata for encryption algorithm, key version, derivation salt, and future KMS mode
- Key-provider boundary for local root key, external KMS, HSM readiness, and dependency-free HTTP gateway signing
- Integration status, signed SIEM webhook delivery with retries, ITSM ticket validation, configuration controls, and DevOps API readiness
- Compliance evidence report for ISO/IEC 27001, NIS2, SOC 2, and PCI DSS control categories
- Browser extension autofill and Windows companion scaffolds for clipboard auto-clear, offline cache, and autotype research
- Startup configuration validation, login rate limiting, and temporary account lockout
- CI dependency audit gate for high-severity advisories
- CI secret scanning gate for private keys and common committed token formats
- Configurable CORS allowlist with environment-aware browser security headers and production HSTS

## Demo Accounts

All seeded demo accounts use this password:

```text
Passw0rd!
```

| User | Email | Role |
| --- | --- | --- |
| Commander Ada | `ada@defence.local` | Security Admin |
| Morgan Vale | `morgan@defence.local` | Vault Operator |
| Iris Chen | `iris@defence.local` | Auditor |

## Requirements

- Node.js 20+
- pnpm, or npm/npx for the fallback demo command

## Run Locally

PowerShell quick start:

```powershell
cd "C:\Users\john\OneDrive\09 Profile\Documents\GitHub\Sentinel-Vault-Enterprise-Password-Manager"
.\scripts\start-demo.ps1
```

Open the demo console at [http://127.0.0.1:5173](http://127.0.0.1:5173).

Manual pnpm start:

```powershell
pnpm install
pnpm dev
```

If `pnpm` is not recognized, use the no-global-install fallback:

```powershell
npx pnpm@11.7.0 install
npx pnpm@11.7.0 dev
```

Or enable pnpm permanently from an elevated PowerShell:

```powershell
corepack enable
corepack prepare pnpm@11.7.0 --activate
pnpm --version
```

### Demo Troubleshooting

- `pnpm` is not recognized: run `.\scripts\start-demo.ps1` or use the `npx pnpm@11.7.0 ...` fallback.
- `corepack enable` returns `EPERM`: reopen PowerShell as Administrator, or skip Corepack and use the `npx` fallback.
- Port `5173` is already in use: open [http://127.0.0.1:5173](http://127.0.0.1:5173) to check whether the demo is already running, or stop the process using that port.
- Browser shows a blank page: hard refresh with `Ctrl+F5`, then restart the demo script if needed.
- Node.js is missing: install Node.js 20+ and reopen PowerShell so `node`, `npm`, and `npx` are on `PATH`.

## Build

```bash
pnpm typecheck
pnpm test
pnpm build
pnpm preview
```

Run the full local quality gate:

```bash
pnpm verify
```

Run the security gates used by CI:

```bash
pnpm scan:secrets
pnpm audit:deps
pnpm release:sast -- --report ".\artifacts\security\sast-report.json"
pnpm validate:sast -- docs/templates/sast-evidence.json
pnpm release:log-redaction -- --samples ".\artifacts\security\log-samples"
pnpm validate:log-redaction -- docs/templates/log-redaction-evidence.json
pnpm release:pentest-scope -- --report ".\artifacts\security\pentest-findings.json"
pnpm validate:pentest-scope -- docs/templates/pentest-scope-evidence.json
pnpm release:audit-worm -- --ledger ".\artifacts\security\sentinel-audit-ledger.json"
pnpm validate:audit-worm -- docs/templates/audit-worm-evidence.json
pnpm release:backup-recovery -- --restore-evidence ".\artifacts\storage\encrypted-backup-restore-evidence.json"
pnpm validate:backup-recovery -- docs/templates/backup-recovery-evidence.json
pnpm inspect:storage -- --state ".\data\sentinel-state.json"
pnpm validate:storage-migration -- docs/templates/storage-migration-evidence.json
pnpm release:postgres-ha -- --status planned --out ".\artifacts\storage\postgres-ha-approval-evidence.json"
pnpm validate:postgres-ha -- docs/templates/postgres-ha-approval-evidence.json
pnpm release:device-trust -- --device-inventory ".\artifacts\security\device-inventory.json"
pnpm validate:device-trust -- docs/templates/device-trust-evidence.json
pnpm release:brute-force -- --report ".\artifacts\security\brute-force-drill.json"
pnpm validate:brute-force -- docs/templates/brute-force-evidence.json
pnpm release:tenant-isolation -- --report ".\artifacts\security\tenant-isolation-tests.json"
pnpm validate:tenant-isolation -- docs/templates/tenant-isolation-evidence.json
pnpm release:source-migration -- --status planned --out ".\artifacts\import\source-migration-evidence.json"
pnpm validate:source-migration -- docs/templates/source-migration-evidence.json
pnpm release:browser-identity -- --status planned --out ".\artifacts\browser\browser-extension-identity-evidence.json"
pnpm validate:browser-identity -- docs/templates/browser-extension-identity-evidence.json
pnpm release:connector-evidence -- --preflight ".\artifacts\integrations\connector-live-preflight.json"
pnpm validate:connector-evidence -- docs/templates/connector-certification-evidence.json
pnpm release:itsm-worknotes -- --status planned --out ".\artifacts\integrations\itsm-worknote-evidence.json"
pnpm validate:itsm-worknotes -- docs/templates/itsm-worknote-evidence.json
pnpm release:devops-token-response -- --preflight ".\artifacts\integrations\devops-token-response-evidence.json"
pnpm validate:devops-token-response -- docs/templates/devops-token-response-evidence.json
pnpm release:identity-evidence -- --preflight ".\artifacts\identity\identity-provider-preflight.json"
pnpm validate:identity-evidence -- docs/templates/identity-provider-evidence.json
pnpm release:kms-hsm-sdk-approval -- --status planned --out ".\artifacts\security\kms-hsm-sdk-approval-evidence.json"
pnpm validate:kms-hsm-sdk-approval -- docs/templates/kms-hsm-sdk-approval-evidence.json
pnpm release:kms-hsm -- --preflight ".\artifacts\security\kms-hsm-gateway-preflight.json"
pnpm validate:kms-hsm-evidence -- docs/templates/kms-hsm-provider-evidence.json
pnpm release:siem-rotation -- --report ".\artifacts\integrations\siem-receiver-rotation.json"
pnpm validate:siem-rotation -- docs/templates/siem-receiver-rotation-evidence.json
pnpm release:tls-iis -- --report ".\artifacts\windows\tls-iis-review.json"
pnpm validate:tls-iis -- docs/templates/tls-iis-evidence.json
pnpm release:attestation -- --provenance ".\artifacts\release\release-provenance.json"
pnpm validate:release-attestation -- docs/templates/release-attestation-evidence.json
pnpm release:credential-provider-approval -- --status planned --out ".\artifacts\native\credential-provider-approval-evidence.json"
pnpm validate:credential-provider-approval -- docs/templates/credential-provider-approval-evidence.json
```

## Project Structure

```text
src/
  api/              Frontend API client
  lib/              Frontend utilities
  server/
    crypto/         Password hashing and vault encryption
    data/           Seed state and store abstraction
    middleware/     Auth, RBAC, and error middleware
    rbac/           Role-permission model
    routes/         API route modules
    services/       Vault, audit, and session services
  types.ts          Shared frontend contracts
tests/              Node test suites
extensions/         Browser autofill companion scaffold
companions/         Windows desktop companion prototypes
.github/workflows/ CI quality gate
```

## Docker

```bash
docker compose up --build
```

The production container serves the compiled Vite frontend from the Express API.

## Windows Server Package

Build a Windows deployment zip:

```powershell
pnpm package:windows
```

The package includes installer scripts for running Sentinel Vault on Windows Server and optionally configuring IIS as the web front end. See `deployments/windows/README.md`.

Build the browser autofill extension package:

```powershell
pnpm package:extension
```

Generate planned browser extension rollout evidence from the package:

```powershell
pnpm release:browser-rollout -- --artifact ".\artifacts\browser\sentinel-vault-autofill.zip"
```

Prepare a bulk secret import payload and redacted evidence from a CSV export:

```powershell
pnpm prepare:bulk-import -- --csv ".\docs\templates\bulk-secret-import-template.csv" --mapping ".\docs\templates\bulk-secret-import-mapping.json"
```

Inspect a JSON state file before a future SQLite/Postgres migration:

```powershell
pnpm inspect:storage -- --state ".\data\sentinel-state.json"
```

Windows deployment hardening guides:

- `docs/deployment/windows-code-signing.md`
- `docs/deployment/tls-iis-checklist.md`
- `docs/architecture/connector-certification.md`
- `docs/operations/bulk-secret-import-runbook.md`
- `docs/security/autotype-credential-provider-review.md`
- `docs/deployment/browser-extension-enterprise-policy.md`
- `docs/operations/kms-hsm-key-ceremony.md`

Validate native companion and credential-provider release evidence:

```powershell
pnpm release:credential-provider-approval -- --status planned --out ".\artifacts\native\credential-provider-approval-evidence.json"
pnpm validate:credential-provider-approval -- docs/templates/credential-provider-approval-evidence.json
pnpm release:native-companion -- --artifact ".\artifacts\native\SentinelVault.Companion.exe"
pnpm validate:native-companion -- docs/templates/native-companion-evidence.json
```

Prepare an environment-specific deployment evidence workspace:

```powershell
pnpm prepare:deployment-evidence -- --environment "pilot" --owner "Platform Security" --out-dir ".\artifacts\deployment\pilot"
pnpm validate:deployment-workspace -- --manifest ".\artifacts\deployment\pilot\deployment-evidence-workspace-manifest.json" --bundle ".\artifacts\deployment\pilot\deployment-evidence-bundle.json"
pnpm report:external-evidence -- --environment "pilot" --owner "Platform Security" --out ".\artifacts\deployment\pilot\external-evidence-requests.json" --markdown-out ".\artifacts\deployment\pilot\external-evidence-requests.md"
pnpm validate:external-evidence -- --requests ".\artifacts\deployment\pilot\external-evidence-requests.json" --strict
pnpm report:deployment-evidence -- --bundle ".\artifacts\deployment\pilot\deployment-evidence-bundle.json" --out ".\artifacts\deployment\pilot\deployment-evidence-status.json"
pnpm report:deployment-redaction -- --bundle ".\artifacts\deployment\pilot\deployment-evidence-bundle.json" --out ".\artifacts\deployment\pilot\deployment-redaction-report.json" --markdown-out ".\artifacts\deployment\pilot\deployment-redaction-report.md" --fail-on-findings
pnpm report:phase-completion -- --external-requests ".\artifacts\deployment\pilot\external-evidence-requests.json" --out ".\artifacts\deployment\pilot\phase-completion-audit.json" --markdown-out ".\artifacts\deployment\pilot\phase-completion-audit.md"
pnpm validate:phase-completion -- --audit ".\artifacts\deployment\pilot\phase-completion-audit.json" --external-requests ".\artifacts\deployment\pilot\external-evidence-requests.json"
pnpm report:phase-readiness -- --bundle ".\artifacts\deployment\pilot\deployment-evidence-bundle.json" --external-requests ".\artifacts\deployment\pilot\external-evidence-requests.json" --out ".\artifacts\deployment\pilot\phase-readiness.json" --markdown-out ".\artifacts\deployment\pilot\phase-readiness.md"
pnpm prepare:phase-handoff -- --readiness ".\artifacts\deployment\pilot\phase-readiness.json" --external-requests ".\artifacts\deployment\pilot\external-evidence-requests.json" --out ".\artifacts\deployment\pilot\phase-handoff-checklist.md"
pnpm validate:phase-handoff -- --checklist ".\artifacts\deployment\pilot\phase-handoff-checklist.md" --readiness ".\artifacts\deployment\pilot\phase-readiness.json" --external-requests ".\artifacts\deployment\pilot\external-evidence-requests.json"
pnpm package:phase-evidence -- --dir ".\artifacts\deployment\pilot" --out ".\artifacts\deployment\pilot\phase-evidence-pack-manifest.json"
pnpm validate:phase-evidence -- --manifest ".\artifacts\deployment\pilot\phase-evidence-pack-manifest.json"
pnpm validate:phase-gate -- --dir ".\artifacts\deployment\pilot" --out ".\artifacts\deployment\pilot\phase-gate-validation.json" --markdown-out ".\artifacts\deployment\pilot\phase-gate-validation.md"
pnpm prepare:phase-actions -- --dir ".\artifacts\deployment\pilot" --out ".\artifacts\deployment\pilot\phase-action-register.json" --markdown-out ".\artifacts\deployment\pilot\phase-action-register.md"
pnpm validate:phase-actions -- --register ".\artifacts\deployment\pilot\phase-action-register.json" --phase-gate ".\artifacts\deployment\pilot\phase-gate-validation.json" --external-requests ".\artifacts\deployment\pilot\external-evidence-requests.json"
pnpm prepare:phase-gaps -- --dir ".\artifacts\deployment\pilot" --out ".\artifacts\deployment\pilot\phase-gap-matrix.json" --markdown-out ".\artifacts\deployment\pilot\phase-gap-matrix.md"
pnpm validate:phase-gaps -- --matrix ".\artifacts\deployment\pilot\phase-gap-matrix.json" --bundle ".\artifacts\deployment\pilot\deployment-evidence-bundle.json" --external-requests ".\artifacts\deployment\pilot\external-evidence-requests.json"
pnpm prepare:phase-decision -- --dir ".\artifacts\deployment\pilot" --out ".\artifacts\deployment\pilot\phase-decision-record.json" --markdown-out ".\artifacts\deployment\pilot\phase-decision-record.md"
pnpm validate:phase-decision -- --record ".\artifacts\deployment\pilot\phase-decision-record.json" --phase-gate ".\artifacts\deployment\pilot\phase-gate-validation.json" --phase-actions ".\artifacts\deployment\pilot\phase-action-register.json" --phase-gaps ".\artifacts\deployment\pilot\phase-gap-matrix.json"
pnpm prepare:phase-signoffs -- --dir ".\artifacts\deployment\pilot" --out ".\artifacts\deployment\pilot\phase-signoff-matrix.json" --markdown-out ".\artifacts\deployment\pilot\phase-signoff-matrix.md"
pnpm validate:phase-signoffs -- --matrix ".\artifacts\deployment\pilot\phase-signoff-matrix.json" --phase-decision ".\artifacts\deployment\pilot\phase-decision-record.json" --phase-actions ".\artifacts\deployment\pilot\phase-action-register.json"
pnpm prepare:phase-intake -- --dir ".\artifacts\deployment\pilot" --out ".\artifacts\deployment\pilot\phase-evidence-intake.json" --markdown-out ".\artifacts\deployment\pilot\phase-evidence-intake.md"
pnpm validate:phase-intake -- --intake ".\artifacts\deployment\pilot\phase-evidence-intake.json" --external-requests ".\artifacts\deployment\pilot\external-evidence-requests.json" --phase-gaps ".\artifacts\deployment\pilot\phase-gap-matrix.json" --phase-signoffs ".\artifacts\deployment\pilot\phase-signoff-matrix.json"
pnpm prepare:phase-attachments -- --dir ".\artifacts\deployment\pilot" --out ".\artifacts\deployment\pilot\phase-attachment-inventory.json" --markdown-out ".\artifacts\deployment\pilot\phase-attachment-inventory.md"
pnpm validate:phase-attachments -- --inventory ".\artifacts\deployment\pilot\phase-attachment-inventory.json" --intake ".\artifacts\deployment\pilot\phase-evidence-intake.json"
pnpm prepare:phase-waivers -- --dir ".\artifacts\deployment\pilot" --out ".\artifacts\deployment\pilot\phase-waiver-register.json" --markdown-out ".\artifacts\deployment\pilot\phase-waiver-register.md"
pnpm validate:phase-waivers -- --register ".\artifacts\deployment\pilot\phase-waiver-register.json" --attachments ".\artifacts\deployment\pilot\phase-attachment-inventory.json" --phase-decision ".\artifacts\deployment\pilot\phase-decision-record.json"
pnpm package:phase-review -- --dir ".\artifacts\deployment\pilot" --out ".\artifacts\deployment\pilot\phase-review-bundle-manifest.json"
pnpm validate:phase-review -- --manifest ".\artifacts\deployment\pilot\phase-review-bundle-manifest.json"
pnpm package:phase-closure -- --dir ".\artifacts\deployment\pilot" --out ".\artifacts\deployment\pilot\phase-closure-archive-manifest.json"
pnpm validate:phase-closure -- --manifest ".\artifacts\deployment\pilot\phase-closure-archive-manifest.json" --phase-review ".\artifacts\deployment\pilot\phase-review-bundle-manifest.json"
pnpm validate:phase-review -- --manifest ".\artifacts\deployment\pilot\phase-review-bundle-manifest.json" --require-approved-waivers
pnpm validate:phase-closure -- --manifest ".\artifacts\deployment\pilot\phase-closure-archive-manifest.json" --phase-review ".\artifacts\deployment\pilot\phase-review-bundle-manifest.json" --require-approved-waivers --require-clean
pnpm validate:release-gate -- --dir ".\artifacts\deployment\pilot" --target "production" --require-clean --out ".\artifacts\deployment\pilot\production-release-gate.json"
pnpm report:phase-readiness -- --bundle ".\artifacts\deployment\pilot\deployment-evidence-bundle.json" --external-requests ".\artifacts\deployment\pilot\external-evidence-requests.json" --target "pilot" --fail-on-blockers
pnpm validate:deployment-evidence -- ".\artifacts\deployment\pilot\deployment-evidence-bundle.json"
```

Use the `--fail-on-blockers` readiness command as the release or CI gate for a completed deployment bundle. Use the `--require-approved-waivers` review and closure commands only after every missing or redaction-flagged evidence item has an approved waiver, future expiry date, approval reference, and compensating control. Use `validate:release-gate` as the final production gate that composes deployment evidence validation, phase readiness, final review, closure archive provenance, approved waivers, and clean source-state checks. These commands are expected to fail for newly generated placeholder workspaces until the deployment-specific evidence is replaced or explicitly approved.

Build a signed-EXE-ready setup package with Inno Setup installed:

```powershell
pnpm package:windows:installer
```

Generate Windows release evidence from built artifacts:

```powershell
pnpm release:windows-evidence -- --artifact ".\artifacts\windows\SentinelVault-Windows.zip"
pnpm release:windows-signing -- --status signed --report ".\artifacts\windows\signing-report.json" --out ".\artifacts\windows\windows-signing-execution-evidence.json"
pnpm validate:windows-signing -- ".\artifacts\windows\windows-signing-execution-evidence.json"
```

Generate Windows install hardening evidence from an installed layout:

```powershell
pnpm release:windows-hardening -- --install-path "C:\Program Files\Sentinel Vault" --sentinel-env "C:\Program Files\Sentinel Vault\sentinel.env"
```

## Enterprise Roadmap Status

Implemented in this prototype:

- Encrypted in-memory vault records and secret metadata
- JSON-backed local persistence for prototype state
- JSON state schema versioning, backup manifests, and backup integrity checks for prototype deployments
- AES-GCM encrypted backup artifacts with restore-validation dry runs
- RBAC-protected API routes with object-level vault checks
- JIT access request and approval records
- Ticket-linked approval workflow metadata and high-risk multi-approval support
- Temporary reveal access after approval
- Console workflows for editing entries, reviewing deleted items, and restoring previous versions
- Admin workflows for vault group creation, membership updates, and user role/status management
- Tenant hierarchy metadata and tenant-aware vault groups
- Safe bulk administration metadata import/export for tenants, vaults, users, and policies
- Bulk secret import with encrypted escrow and independent approval
- Policy validation and session timeout enforcement
- Tamper-evident audit event hash chaining for security-sensitive actions
- Signed audit ledger export and append-only JSONL ledger for file-backed deployments
- SIEM webhook delivery with HMAC signed-envelope replay metadata
- Encrypted read-only offline cache export with verification
- Secret fingerprinting for reuse detection without storing plaintext
- Compliance report endpoint for audit-ready control summaries

Still intentionally out of scope for the prototype:

- Postgres HA storage until the runtime database dependency is approved
- LDAP, SAML, passkey, provider-owned MFA challenge UX, and approved identity SDK integrations
- Completed production browser extension rollout evidence with real store/private extension IDs
- Production-certified SIEM, ITSM, PAM, SOAR, Kubernetes, and CI/CD connectors
- HA clustering, backup, replication, and disaster recovery
- Provider SDK-backed HSM/KMS operations and independent cryptographic review
- Session recording and privileged session brokering

## Configuration

Copy `.env.example` to `.env` for local development and set:

```text
PORT=5173
CORS_ORIGINS=http://127.0.0.1:5173,http://localhost:5173
FAILED_LOGIN_LIMIT=5
LOGIN_LOCKOUT_MINUTES=15
REFRESH_TOKENS_ENABLED=false
REFRESH_TOKEN_DAYS=7
VAULT_ROOT_KEY=your-local-development-root-key
VAULT_KEY_VERSION=demo-root-v1
VAULT_KEY_SALT=sentinel-vault
KMS_PROVIDER=local-root-key
KMS_KEY_ID=
KMS_ENDPOINT=
KMS_GATEWAY_TIMEOUT_MS=5000
STORAGE_PROVIDER=json
DATA_DIR=./data
STATE_FILE=sentinel-state.json
SQLITE_PATH=
DATABASE_URL=
IDENTITY_PROVIDER=local
OIDC_ISSUER=
OIDC_CLIENT_ID=
ENTRA_TENANT_ID=
IDENTITY_GROUP_CLAIM=groups
IDENTITY_MFA_CLAIM=amr
IDENTITY_MFA_REQUIRED_VALUE=mfa
IDENTITY_ROLE_SECURITY_ADMIN=Sentinel Vault Admins
IDENTITY_ROLE_VAULT_OPERATOR=Sentinel Vault Operators
IDENTITY_ROLE_AUDITOR=Sentinel Vault Auditors
SIEM_WEBHOOK_URL=
SIEM_WEBHOOK_SECRET=
SIEM_MAX_ATTEMPTS=5
SIEM_RETRY_SECONDS=60
ITSM_BASE_URL=
ITSM_TICKET_PREFIXES=INC,CHG,REQ
ITSM_ALLOWED_STATES=open,active,approved,in_progress,scheduled
DEVOPS_API_ENABLED=false
INTEGRATION_OUTBOX_LIMIT=100
```

## Important Security Note

This is a functional prototype and reference implementation, not a certified production password manager. A real defence deployment would still need hardened persistence, HSM/KMS-backed key management, SSO/MFA integration, formal threat modeling, secure backup and recovery, cryptographic review, rate limiting, logging hardening, supply-chain controls, and independent penetration testing.
