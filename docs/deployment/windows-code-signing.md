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
3. Run `pnpm audit:deps`.
4. Build the package with `pnpm package:windows`.
5. Optionally build the setup executable with `pnpm package:windows:installer`.
6. Optionally validate or build MSI authoring with `pnpm package:windows:msi -ValidateOnly` or `pnpm package:windows:msi`.
7. Optionally validate or build MSIX authoring with `pnpm package:windows:msix -ValidateOnly` or `pnpm package:windows:msix`.
8. Generate release provenance with `pnpm release:provenance -- --artifact ".\artifacts\windows\SentinelVault-Windows.zip"`.
9. Sign the release artifact.
10. Verify the signature on a clean Windows host before publishing.

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
Record source, lockfile, dependency, and artifact provenance with `docs/templates/release-provenance-template.json` or generate it with `pnpm release:provenance`.
