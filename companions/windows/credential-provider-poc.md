# Credential Provider Proof-of-Concept Boundary

This directory intentionally does not include a Windows Credential Provider binary.

A Credential Provider is a signed native COM component loaded into Windows logon flows. Sentinel Vault should only add one after a separate native project, code-signing flow, secure desktop test plan, and independent security review are approved.

## Proposed PoC Shape

- Native project: C++ or Rust-generated COM provider.
- Build host: isolated Windows release runner.
- Signing: organization code-signing certificate with timestamping.
- Supported mode: explicit allow-list of Sentinel Vault entries eligible for OS logon.
- Offline mode: DPAPI-protected cache only, with expiry and read-only enforcement.
- Online mode: short-lived broker token, never a long-lived web session token.

## Non-Goals

- No passwordless Windows logon replacement in the prototype.
- No LSASS integration.
- No plaintext credential persistence.
- No release without the security review in `docs/security/autotype-credential-provider-review.md`.
