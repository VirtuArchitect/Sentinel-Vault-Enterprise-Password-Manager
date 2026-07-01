# Windows Code-Signing Checklist

Use this checklist before publishing a Sentinel Vault Windows package outside a controlled demo environment.

## Signing Material

- Use an organization-issued code-signing certificate from a trusted CA.
- Store the private key in a hardware-backed key store or managed signing service.
- Restrict signing access to release maintainers and require approval for production builds.
- Timestamp every signature with the CA timestamp service so signatures remain valid after certificate expiry.

## Artifacts To Sign

- `SentinelVault-Windows.zip` after packaging.
- Future MSI/MSIX or signed EXE installer artifacts.
- PowerShell scripts in the package when policy requires `AllSigned` execution.
- Any native helper binaries added for tray, autotype, credential provider, or service supervision.

## Release Gate

1. Run `pnpm verify`.
2. Run `pnpm scan:secrets`.
3. Run `pnpm audit:deps`.
4. Build the package with `pnpm package:windows`.
5. Sign the release artifact.
6. Verify the signature on a clean Windows host before publishing.

Example verification:

```powershell
Get-AuthenticodeSignature .\SentinelVault-Windows.zip
```

The status must be `Valid` and the signer must match the expected publishing certificate.
