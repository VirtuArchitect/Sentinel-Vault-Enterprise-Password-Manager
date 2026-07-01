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
- Secret edit, soft delete, version restore, and scoped DevOps service-token retrieval APIs
- Password generator with configurable character classes and quality feedback
- Audit trail for login, reveal, rotate, share, create, policy, and access approval actions
- Enterprise policy controls for MFA, JIT access, rotation, clipboard TTL, minimum length, and session duration with server-side validation
- JIT approval metadata with ticket references, requested duration, approval counts, and high-risk approval requirements
- Session expiry enforcement and permission-scoped console payloads
- Identity provider metadata for local, OIDC, and Microsoft Entra ID configuration
- Key lifecycle metadata for encryption algorithm, key version, derivation salt, and future KMS mode
- Integration status and audit outbox for SIEM, ITSM, and DevOps API readiness
- Compliance evidence report for ISO/IEC 27001, NIS2, SOC 2, and PCI DSS control categories
- Startup configuration validation and login rate limiting
- Configurable CORS allowlist and baseline browser security headers

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

## Enterprise Roadmap Status

Implemented in this prototype:

- Encrypted in-memory vault records and secret metadata
- JSON-backed local persistence for prototype state
- JSON state schema versioning and backup support for prototype deployments
- RBAC-protected API routes with object-level vault checks
- JIT access request and approval records
- Ticket-linked approval workflow metadata and high-risk multi-approval support
- Temporary reveal access after approval
- Policy validation and session timeout enforcement
- Audit events for security-sensitive actions
- Secret fingerprinting for reuse detection without storing plaintext
- Compliance report endpoint for audit-ready control summaries

Still intentionally out of scope for the prototype:

- Production database storage with migrations
- AD, Entra ID, LDAP, SAML, OIDC, passkey, or real MFA integration
- Browser extension autofill
- SIEM, ITSM, PAM, SOAR, Kubernetes, and CI/CD integrations
- HA clustering, backup, replication, and disaster recovery
- HSM/KMS-backed key management and independent cryptographic review
- Session recording and privileged session brokering

## Configuration

Copy `.env.example` to `.env` for local development and set:

```text
PORT=5173
CORS_ORIGINS=http://127.0.0.1:5173,http://localhost:5173
VAULT_ROOT_KEY=your-local-development-root-key
VAULT_KEY_VERSION=demo-root-v1
VAULT_KEY_SALT=sentinel-vault
KMS_PROVIDER=local-root-key
DATA_DIR=./data
STATE_FILE=sentinel-state.json
IDENTITY_PROVIDER=local
OIDC_ISSUER=
OIDC_CLIENT_ID=
ENTRA_TENANT_ID=
IDENTITY_GROUP_CLAIM=groups
SIEM_WEBHOOK_URL=
ITSM_BASE_URL=
DEVOPS_API_ENABLED=false
INTEGRATION_OUTBOX_LIMIT=100
```

## Important Security Note

This is a functional prototype and reference implementation, not a certified production password manager. A real defence deployment would still need hardened persistence, HSM/KMS-backed key management, SSO/MFA integration, formal threat modeling, secure backup and recovery, cryptographic review, rate limiting, logging hardening, supply-chain controls, and independent penetration testing.
