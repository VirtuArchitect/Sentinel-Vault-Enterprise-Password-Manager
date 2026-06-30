# Sentinel Vault Enterprise Password Manager

Sentinel Vault is a KeePass-inspired, multi-user enterprise password manager prototype with a web console and an Express API. It is designed as a defence-grade reference interface: group tree, entry table, database-style tabs, entry details, password generator, audit trail, RBAC, policy controls, and encrypted vault records.

## Features

- KeePass-style vault workbench with menu bar, toolbar, group tree, entry grid, preview pane, and status bar
- Multi-user demo identities with role-based access control
- Server-side RBAC checks for vault read/write/share, audit, users, and policy operations
- AES-256-GCM encrypted secret payloads in the API layer
- Add, reveal, rotate, share, request access, and approve temporary access workflows
- Password, API key, token, certificate, SSH key, directory account, registry token, and connection string secret metadata
- Password generator with configurable character classes and quality feedback
- Audit trail for login, reveal, rotate, share, create, policy, and access approval actions
- Enterprise policy controls for MFA, JIT access, rotation, clipboard TTL, minimum length, and session duration with server-side validation
- Session expiry enforcement and permission-scoped console payloads

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
- pnpm

## Run Locally

```bash
pnpm install
pnpm dev
```

Demo dashboard / console:

```text
http://127.0.0.1:5173
```

Open:

```text
http://127.0.0.1:5173
```

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
- RBAC-protected API routes with object-level vault checks
- JIT access request and approval records
- Temporary reveal access after approval
- Policy validation and session timeout enforcement
- Audit events for security-sensitive actions

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
VAULT_ROOT_KEY=your-local-development-root-key
```

## Important Security Note

This is a functional prototype and reference implementation, not a certified production password manager. A real defence deployment would still need hardened persistence, HSM/KMS-backed key management, SSO/MFA integration, formal threat modeling, secure backup and recovery, cryptographic review, rate limiting, logging hardening, supply-chain controls, and independent penetration testing.
