# Windows Code-Signing Checklist

Use this checklist before publishing a Sentinel Vault Windows package outside a controlled demo environment.

## Signing Material

- Use an organization-issued code-signing certificate from a trusted CA.
- Store the private key in a hardware-backed key store or managed signing service.
- Restrict signing access to release maintainers and require approval for production builds.
- Timestamp every signature with the CA timestamp service so signatures remain valid after certificate expiry.

## Artifacts To Sign

- `SentinelVault-Windows.zip` after packaging.
- `SentinelVault-Windows-Setup.exe` when built with `pnpm package:windows:installer`.
- `SentinelVault-Windows.msi` when built with `pnpm package:windows:msi`.
- `SentinelVault-Windows.msix` when built with `pnpm package:windows:msix`.
- PowerShell scripts in the package when policy requires `AllSigned` execution.
- Any native helper binaries added for tray, autotype, credential provider, or service supervision.

## Release Gate

1. Run `pnpm verify`.
2. Run `pnpm scan:secrets`.
3. Generate or attach release attestation evidence and validate it with `pnpm validate:release-attestation -- docs/templates/release-attestation-evidence.json`.
4. Run `pnpm audit:deps`.
5. Build the package with `pnpm package:windows`.
6. Optionally build the setup executable with `pnpm package:windows:installer`.
7. Optionally validate or build MSI authoring with `pnpm package:windows:msi -ValidateOnly` or `pnpm package:windows:msi`.
8. Optionally validate or build MSIX authoring with `pnpm package:windows:msix -ValidateOnly` or `pnpm package:windows:msix`.
9. Generate release provenance with `pnpm release:provenance -- --artifact ".\artifacts\windows\SentinelVault-Windows.zip"`.
10. Sign the release artifacts with `pnpm sign:windows`.
11. Verify the signature on a clean Windows host before publishing.

Validate signing inputs without accessing a certificate:

```powershell
pnpm sign:windows -ValidateOnly
```

Sign with a certificate in the Windows certificate store:

```powershell
pnpm sign:windows -CertificateThumbprint "replace-with-thumbprint"
```

Sign with a PFX on an approved release host:

```powershell
pnpm sign:windows `
  -CertificatePath "D:\secure\sentinel-vault-code-signing.pfx" `
  -CertificatePassword "replace-with-secure-secret"
```

Example verification:

```powershell
Get-AuthenticodeSignature .\SentinelVault-Windows.zip
Get-AuthenticodeSignature .\SentinelVault-Windows-Setup.exe
Get-AuthenticodeSignature .\SentinelVault-Windows.msi
Get-AuthenticodeSignature .\SentinelVault-Windows.msix
pnpm verify:windows:signatures
```

The status must be `Valid` and the signer must match the expected publishing certificate.

Record release evidence with `docs/templates/windows-release-evidence.json`.
Record install hardening evidence with `docs/templates/windows-install-hardening-evidence.json`.

Validate planned or completed release evidence with:

```powershell
pnpm validate:windows-release -- docs/templates/windows-release-evidence.json
pnpm validate:windows-hardening -- docs/templates/windows-install-hardening-evidence.json
```

When `checks.signatureVerification` is `valid` or `passed`, the validator requires real artifact SHA-256 values, valid Authenticode status for `.exe`, `.msi`, and `.msix` artifacts, signer thumbprints, a Git source commit, passing verification gates, and tested rollback evidence.
Record source, lockfile, dependency, and artifact provenance with `docs/templates/release-provenance-template.json` or generate it with `pnpm release:provenance`.
