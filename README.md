# Sentinel Vault Enterprise Password Manager

Sentinel Vault is a KeePass-inspired, multi-user enterprise password manager prototype with a web console and an Express API. It is designed as a defence-grade reference interface: group tree, entry table, database-style tabs, entry details, password generator, audit trail, RBAC, policy controls, and encrypted vault records.

## Features

- KeePass-style vault workbench with menu bar, toolbar, group tree, entry grid, preview pane, and status bar
- Multi-user demo identities with role-based access control
- Server-side RBAC checks for vault read/write/share, audit, users, and policy operations
- AES-256-GCM encrypted secret payloads in the API layer
- Add, reveal, rotate, and share credential workflows
- Password generator with configurable character classes and quality feedback
- Audit trail for login, reveal, rotate, share, create, and policy actions
- Enterprise policy controls for MFA, JIT access, rotation, clipboard TTL, minimum length, and session duration

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

Open:

```text
http://127.0.0.1:5173
```

## Build

```bash
pnpm typecheck
pnpm build
pnpm preview
```

## Configuration

Copy `.env.example` to `.env` for local development and set:

```text
PORT=5173
VAULT_ROOT_KEY=your-local-development-root-key
```

## Important Security Note

This is a functional prototype and reference implementation, not a certified production password manager. A real defence deployment would still need hardened persistence, HSM/KMS-backed key management, SSO/MFA integration, formal threat modeling, secure backup and recovery, cryptographic review, rate limiting, logging hardening, supply-chain controls, and independent penetration testing.
