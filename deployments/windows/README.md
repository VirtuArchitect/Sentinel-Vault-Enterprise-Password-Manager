# Windows Deployment

Sentinel Vault can be packaged for Windows Server as a self-contained application folder with a PowerShell installer.

The package runs the Node/Express API on localhost and can optionally configure IIS as the Windows Web Server front end. In IIS mode, IIS serves the built React files from `dist/` and proxies `/api/*` to the local Node API.

## Prerequisites

- Windows Server 2019+ or Windows 10/11 for local testing
- Node.js 20+
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

## Install Without IIS

Extract the zip on the target server, then run:

```powershell
.\install.ps1 -Port 5173 -VaultRootKey "replace-with-production-secret"
```

Open:

```text
http://127.0.0.1:5173
```

For remote access without IIS, pass a host binding such as:

```powershell
.\install.ps1 -HostName "0.0.0.0" -Port 5173 -VaultRootKey "replace-with-production-secret"
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

Runtime configuration:

```text
C:\Program Files\Sentinel Vault\sentinel.env
```

The installer restricts `sentinel.env` to Administrators and SYSTEM because it contains `VAULT_ROOT_KEY`.

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
