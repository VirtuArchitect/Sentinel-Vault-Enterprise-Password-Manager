# Changelog

All notable changes to Sentinel Vault Enterprise Password Manager are tracked in
this file. Update this changelog with every user-visible, security-sensitive,
deployment, documentation, or release-process change.

This project follows semantic versioning for the reference implementation:

- Patch: documentation, tests, evidence tooling, dependency refreshes, and
  compatible hardening fixes.
- Minor: new user-facing workflows, new deployment modes, new evidence gates,
  and compatible API additions.
- Major: incompatible API, storage, packaging, or operational contract changes.

## [1.0.0] - 2026-08-16

### Added

- Formal product version marker shown in the console and Management panel.
- Release-governance runbook for version, changelog, demo-link, runbook, and
  developer-methodology updates.
- Release-integrity validation command that guards version, changelog,
  README/demo-link, smoke-test, and runbook alignment.

### Security

- Browser sessions use HttpOnly cookies with CSRF protection for unsafe
  cookie-authenticated requests.
- Direct reveal of soft-deleted secrets is denied by the server-side vault
  service.
- Strict production profile validation rejects local-only identity, local
  root-key KMS, JSON persistence, demo key metadata, and non-HTTPS browser
  endpoints.
