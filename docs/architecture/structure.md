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
