# Windows Deployment

Sentinel Vault can be packaged for Windows Server as a self-contained application folder with a PowerShell installer.

The package runs the Node/Express API on localhost and can optionally configure IIS as the Windows Web Server front end. In IIS mode, IIS serves the built React files from `dist/` and proxies `/api/*` to the local Node API.

## Prerequisites

- Windows Server 2019+ or Windows 10/11 for local testing
- Node.js 20+
- Node.js 24+ when installing with `-StorageProvider sqlite`
- PowerShell 5.1+
- Administrator PowerShell session for install/uninstall
- Optional IIS mode:
  - Web Server (IIS)
  - IIS URL Rewrite
  - Application Request Routing (ARR) with proxy enabled

No service-wrapper dependency such as NSSM or WinSW is required. The installer uses a Windows Scheduled Task running as `SYSTEM` to supervise the Node process at startup.

## Build Package

From the repository root:

```powershell
pnpm package:windows
```

The package is created at:

```text
artifacts/windows/SentinelVault-Windows.zip
```

Validate the zip with Windows-native extraction and a local production startup smoke test:

```powershell
pnpm validate:windows-package
```

The zip also includes `assets/sentinel-vault-app-icon.svg` for installer shortcuts, MSI/WiX authoring, or IIS site branding.

The zip includes the Windows companion helper at:

```text
companions/windows/sentinel-tray-helper.ps1
```

## Build Signed-EXE-Ready Installer

The repository includes Inno Setup authoring for a Windows setup executable. Install Inno Setup 6 on the build host, then run:

```powershell
pnpm package:windows:installer
```

The installer is created at:

```text
artifacts/windows/SentinelVault-Windows-Setup.exe
```

If `ISCC.exe` is not on `PATH`, pass its location directly:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-windows-installer.ps1 -InnoSetupCompiler "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
```

Sign the generated `.exe` with your organization code-signing certificate before distribution.

## Build MSI Package

The repository includes WiX Toolset v3 authoring for MSI release hosts. Validate the MSI authoring files from any development machine:

```powershell
pnpm package:windows:msi -ValidateOnly
```

On a WiX build host, create the `.msi` package:

```powershell
pnpm package:windows:msi `
  -ProductVersion "1.0.0" `
  -Manufacturer "VirtuArchitect" `
  -UpgradeCode "11111111-2222-3333-4444-555555555555"
```

The package is created at:

```text
artifacts/windows/SentinelVault-Windows.msi
```

Replace the sample `UpgradeCode` with the stable product GUID approved for your release channel and sign the generated `.msi` before distribution.

## Build MSIX Package

The repository also includes an MSIX authoring scaffold for certificate-backed Windows release hosts. Validate the manifest and tool discovery from any development machine:

```powershell
pnpm package:windows:msix -ValidateOnly
```

On a Windows SDK build host, create the `.msix` package:

```powershell
pnpm package:windows:msix `
  -MsixIdentityName "VirtuArchitect.SentinelVault" `
  -Publisher "CN=VirtuArchitect" `
  -PublisherDisplayName "VirtuArchitect" `
  -Version "1.0.0.0"
```

The package is created at:

```text
artifacts/windows/SentinelVault-Windows.msix
```

Sign the generated `.msix` with the same approved release certificate used for the executable installer before distribution.

## Install Without IIS

Extract the zip on the target server, then run:

```powershell
.\install.ps1 -Port 5173 -VaultRootKey "replace-with-production-secret"
```

Open:

```text
http://127.0.0.1:5173
```

The installer creates a Start Menu shortcut named `Sentinel Vault` unless `-SkipStartMenuShortcut` is passed.

For remote access without IIS, pass a host binding such as:

```powershell
.\install.ps1 -HostName "0.0.0.0" -Port 5173 -VaultRootKey "replace-with-production-secret"
```

Install with the SQLite storage provider on a Node.js 24+ host:

```powershell
.\install.ps1 `
  -Port 5173 `
  -VaultRootKey "replace-with-production-secret" `
  -StorageProvider sqlite `
  -SqlitePath "C:\Program Files\Sentinel Vault\data\sentinel-vault.sqlite"
```

## Install With IIS Front End

Install IIS, URL Rewrite, and ARR first. Then run:

```powershell
.\install.ps1 `
  -Port 5173 `
  -VaultRootKey "replace-with-production-secret" `
  -ConfigureIis `
  -SiteName "Sentinel Vault" `
  -SitePort 8080
```

Open:

```text
http://localhost:8080
```

In this mode:

- IIS serves the frontend assets.
- IIS rewrites SPA routes to `index.html`.
- IIS proxies `/api/*` to `http://127.0.0.1:5173/api/*`.
- Node remains bound to localhost by default.

## Operations

Scheduled task:

```powershell
Get-ScheduledTask -TaskName SentinelVault
Start-ScheduledTask -TaskName SentinelVault
Stop-ScheduledTask -TaskName SentinelVault
```

Logs:

```text
C:\Program Files\Sentinel Vault\logs
```

Health check:

```powershell
.\healthcheck.ps1 -Url "http://127.0.0.1:5173/healthz"
```

Clipboard companion:

```powershell
.\companions\windows\sentinel-tray-helper.ps1 -Value "temporary-secret" -ClipboardTtlSeconds 30
.\companions\windows\sentinel-tray-helper.ps1 -Watch -ClipboardTtlSeconds 30
.\companions\windows\sentinel-tray-helper.ps1 -Tray
```

The companion clears only a clipboard value it wrote itself. If the user copies something else before the TTL expires, the helper leaves the clipboard unchanged.

Tray mode adds a notification-area menu for opening the console and clearing Sentinel-owned clipboard values.

DPAPI-protect an exported offline cache for the current Windows user:

```powershell
.\companions\windows\sentinel-tray-helper.ps1 -ProtectOfflineCache -OfflineCachePath ".\sentinel-offline-cache.json"
.\companions\windows\sentinel-tray-helper.ps1 -ShowOfflineCache
.\companions\windows\sentinel-tray-helper.ps1 -BrowseOfflineCache
.\companions\windows\sentinel-tray-helper.ps1 -InstallOfflineCacheCleanupTask
```

Guarded autotype proof of concept:

```powershell
.\companions\windows\sentinel-tray-helper.ps1 `
  -AutoType `
  -WindowTitle "Target Login Window" `
  -Username "user@example.test" `
  -Password "temporary-secret" `
  -IUnderstandAutotypeRisk
```

Autotype sends keystrokes to the active desktop, so it requires an explicit target window title and acknowledgement switch.

Runtime configuration:

```text
C:\Program Files\Sentinel Vault\sentinel.env
```

The installer restricts `sentinel.env` to Administrators and SYSTEM because it contains `VAULT_ROOT_KEY`.

Record Windows install hardening evidence with:

```powershell
pnpm release:windows-hardening -- --install-path "C:\Program Files\Sentinel Vault" --sentinel-env "C:\Program Files\Sentinel Vault\sentinel.env"
pnpm validate:windows-hardening -- docs/templates/windows-install-hardening-evidence.json
```

Pilot and production evidence must show restricted filesystem ACLs, non-interactive service identity, localhost Node binding, non-demo runtime secrets, clean install, upgrade backup, rollback, uninstall, and health-check results. If IIS is enabled, the evidence must also include TLS termination and reverse-proxy validation.

## Upgrade and Rollback

Running `install.ps1` over an existing install creates a timestamped rollback backup beside the installation directory before files are overwritten.

Rollback from an elevated PowerShell session:

```powershell
.\rollback.ps1 `
  -BackupDir "C:\Program Files\Sentinel Vault Rollbacks\backup-YYYYMMDD-HHMMSS" `
  -InstallDir "C:\Program Files\Sentinel Vault"
```

The rollback script stops the scheduled task, restores the backed-up application files, and restarts the task if it exists. Runtime `logs` and `data` folders are not restored by default.

## Uninstall

Remove the scheduled task and leave installed files:

```powershell
.\uninstall.ps1
```

Remove the scheduled task, IIS site/app pool, and installed files:

```powershell
.\uninstall.ps1 -RemoveIis -RemoveData
```

## Production Notes

This deployment package is suitable for a controlled prototype or internal demo. Before production use, replace the in-memory store with persistent storage, move `VAULT_ROOT_KEY` into a managed secret store, add real SSO/MFA, configure TLS in IIS, and place the service behind enterprise monitoring and backup controls.

See also:

- `docs/deployment/windows-code-signing.md`
- `docs/deployment/tls-iis-checklist.md`
