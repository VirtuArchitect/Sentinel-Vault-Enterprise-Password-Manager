# Repository Structure

The project is organized around explicit application boundaries:

```text
src/
  api/              Browser API client
  lib/              Frontend utility functions
  server/
    auth/           Future identity provider adapters
    crypto/         Password hashing and vault encryption boundary
    data/           Seed state and repository/store abstraction
    middleware/     Express middleware for auth, permissions, and errors
    rbac/           Role and permission model
    routes/         HTTP route modules
    services/       Business operations for audit, sessions, and vaults
  types.ts          Shared frontend data contracts
tests/              Node test runner suites
deployments/        Deployment notes and manifests
```

The current persistence layer is still in-memory seed state behind `src/server/data/store.mjs`. The next production step is to replace that store with a PostgreSQL-backed repository while keeping route and service contracts stable.

## Current Domain Model

The prototype models the core enterprise password manager entities in memory:

- Users with RBAC roles and MFA metadata
- Vaults with members, classification, owner unit, and health
- Secrets with type, tags, risk, rotation history, sharing, notes, and encrypted payloads
- Access requests for just-in-time approvals and temporary grants
- Policies for rotation, minimum length, MFA, JIT access, clipboard TTL, and session duration
- Audit events for security-sensitive workflows

## Security Boundaries

Routes perform coarse permission checks with RBAC middleware. Service methods then enforce object-level vault or secret access before revealing, rotating, sharing, approving, or denying sensitive records. Console payloads are scoped so users only receive users and audit records when their role grants those permissions.

See `docs/architecture/tenant-isolation.md` for the production tenant isolation model and required negative authorization evidence.
