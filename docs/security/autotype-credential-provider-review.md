# Autotype and Credential Provider Security Review

This review is required before expanding the Windows companion into a native autotype broker or Windows Credential Provider.

## Current Proof of Concept

The PowerShell companion includes a guarded autotype proof of concept:

- Requires `-AutoType`.
- Requires a target `-WindowTitle`.
- Requires `-IUnderstandAutotypeRisk`.
- Sends username, tab, and password only after explicit invocation.
- Escapes SendKeys control characters before sending input.
- Does not log the username or password values.

## Required Native Broker Controls

- Explicit user confirmation for every fill operation.
- Target process and window title displayed before fill.
- Refuse to type into elevated windows from a non-elevated broker.
- Refuse to type into secure desktop, lock screen, or UAC prompts.
- Refuse wildcard or empty target selectors.
- Keep plaintext secret material in memory only for the minimum fill window.
- Clear clipboard and transient buffers after fill.
- Record audit metadata without secret values.
- Enforce high-risk and approval-required prompts.

## Credential Provider Boundary

Windows Credential Provider integration must remain out of process until reviewed. A future proof of concept must include:

- Separate signed native project and build pipeline.
- Test certificate only for development builds.
- No storage of plaintext credentials in the provider.
- Strict allow-list of vault entries eligible for OS logon.
- Offline behavior documented separately from online unlock.
- Independent review of LSASS, secure desktop, and credential serialization risk.

## Abuse Cases

- Malicious window captures autotype meant for another app.
- User changes focus between confirmation and keystroke send.
- Elevated target receives input from non-elevated broker.
- Credential provider exposes secrets in crash dumps or event logs.
- Offline cache is stale, revoked, or belongs to another Windows user.
- Browser extension and native companion race to fill conflicting values.

## Approval Gate

Native autotype or credential-provider code must not be released until:

1. This checklist is completed.
2. The binary is code signed.
3. A clean Windows host install/uninstall test passes.
4. An abuse-case test pass is attached to the release.
5. A rollback and disable procedure is documented.

Record the implementation approval with `docs/templates/credential-provider-approval-evidence.json`, then record the release gate with `docs/templates/native-companion-evidence.json` and validate both with:

```powershell
pnpm validate:native-artifacts -- --artifact ".\artifacts\native\SentinelVault.CredentialProvider.dll" --require-signature --out ".\artifacts\native\native-artifact-validation.json"
pnpm release:credential-provider-approval -- --status approved --report ".\artifacts\native\credential-provider-approval-report.json" --native-companion-evidence ".\artifacts\native\native-companion-evidence.json" --artifact ".\artifacts\native\SentinelVault.CredentialProvider.dll" --out ".\artifacts\native\credential-provider-approval-evidence.json"
pnpm validate:credential-provider-approval -- ".\artifacts\native\credential-provider-approval-evidence.json"
pnpm release:native-companion -- --artifact ".\artifacts\native\SentinelVault.Companion.exe" --out ".\artifacts\native\native-companion-evidence.json"
pnpm validate:native-companion -- docs/templates/native-companion-evidence.json
```

Pilot and production evidence cannot contain placeholders. It must include valid Authenticode signatures for native `.exe` and `.dll` artifacts, passing security controls, clean install/uninstall results, abuse-case test results, rollback testing, and security, desktop engineering, release, and change approvals.
