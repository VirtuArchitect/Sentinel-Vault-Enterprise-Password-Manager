# Smoke Tests

## Local Demo Console

Name: Local demo console starts and accepts a seeded admin login

Purpose: Prove that a cloned checkout can launch the browser console without a global pnpm install.

Prerequisites:

- Node.js 20+
- PowerShell 5.1+
- Port `5173` available, or an existing Sentinel Vault demo already listening on that port

Steps:

```powershell
cd "<repo root>"
.\scripts\start-demo.ps1
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173), then sign in:

```text
User name: avery.stone@enterprise.example
Master key: Passw0rd!
```

Expected result:

- The login card shows Sentinel Vault branding.
- The console opens to the KeePass-style workbench.
- The status bar shows loaded groups and entries.

Evidence:

- Browser reaches `http://127.0.0.1:5173`.
- `/healthz` returns `{"ok":true,"service":"sentinel-vault"}`.

## Windows Package

Name: Windows zip package builds with branding assets

Purpose: Prove the Windows deployment package includes the compiled app, scripts, and app icon.

Steps:

```powershell
pnpm package:windows
pnpm validate:windows-package
```

Expected result:

- `artifacts/windows/SentinelVault-Windows.zip` exists.
- The zip extracts with Windows-native tooling.
- The zip contains `assets/sentinel-vault-app-icon.svg`.
- The zip contains `app/dist/favicon.svg`.
- The zip contains `install.ps1`, `uninstall.ps1`, `run-sentinel.ps1`, and `healthcheck.ps1`.
- The extracted production app passes `/healthz`.
