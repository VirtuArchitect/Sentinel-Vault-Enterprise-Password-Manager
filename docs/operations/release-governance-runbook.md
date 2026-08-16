# Release Governance Runbook

Use this runbook for every Sentinel Vault code, documentation, deployment, or
security update.

## Required Update Checklist

Every future update must review and update these items when applicable:

1. Version marker in `package.json` and `src/version.ts`.
2. `CHANGELOG.md` entry for the current version.
3. README current-version line and local demo link.
4. Runbooks under `docs/operations/`.
5. Architecture, deployment, testing, and security documentation affected by the
   change.
6. `docs/testing/smoke-tests.md`, especially the local demo URL and expected
   smoke evidence.
7. Evidence templates, generators, validators, and release-gate commands affected
   by the change.
8. Security notes for authentication, authorization, sessions, secrets, storage,
   integrations, logging, dependencies, or deployment changes.

The canonical local demo URL is:

```text
http://127.0.0.1:5173
```

## Developer Methodology

Use these practices where feasible:

- Work on a `codex/*` branch; avoid direct pushes to `main`.
- Keep changes focused and preserve existing architecture boundaries.
- Update docs and runbooks in the same change as behavior, deployment, or
  evidence tooling changes.
- Add or update targeted tests for the changed behavior.
- Run `pnpm validate:release-integrity` for all repository updates.
- Run `pnpm typecheck`, targeted tests, and broader tests when shared behavior
  changes.
- Run `pnpm scan:secrets` and dependency audit for security-sensitive,
  dependency, or release changes.
- Run `pnpm build` for frontend, packaging, or public documentation changes that
  affect the browser console.
- Perform a smoke test that exercises the changed path.
- Open a PR, wait for CI, merge through GitHub, and verify local `main` matches
  `origin/main`.

## Versioning

Use semantic versioning:

- Patch for compatible fixes, documentation, evidence tooling, security
  hardening, and dependency refreshes.
- Minor for new workflows, new deployment modes, or new compatible API/evidence
  features.
- Major for incompatible API, storage, packaging, identity, or deployment
  contract changes.

Do not publish release evidence that references a version absent from
`CHANGELOG.md`, `package.json`, and `src/version.ts`.

## Documentation Scope

When updating implementation behavior, check:

- `README.md`
- `CHANGELOG.md`
- `docs/architecture/implementation-phases.md`
- relevant files in `docs/architecture/`
- relevant files in `docs/deployment/`
- relevant files in `docs/operations/`
- `docs/testing/smoke-tests.md`

If no documentation update is needed, the PR description should say why.
