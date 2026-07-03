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
pnpm validate:windows-package -- -Out ".\artifacts\windows\windows-package-validation.json"
```

Expected result:

- `artifacts/windows/SentinelVault-Windows.zip` exists.
- The zip extracts with Windows-native tooling.
- The zip contains `assets/sentinel-vault-app-icon.svg`.
- The zip contains `app/dist/favicon.svg`.
- The zip contains `install.ps1`, `uninstall.ps1`, `run-sentinel.ps1`, and `healthcheck.ps1`.
- The extracted production app passes `/healthz`.
- `artifacts/windows/windows-package-validation.json` records the package validation result for release evidence.

## Browser Extension Package

Name: Browser autofill extension package validates for enterprise review

Purpose: Prove the extension package includes only the reviewed files, uses Manifest V3, and keeps host permissions scoped to the local Sentinel Vault console.

Steps:

```powershell
pnpm package:extension
pnpm validate:extension-package -- --out ".\artifacts\browser\browser-extension-package-validation.json"
```

Expected result:

- `artifacts/browser/sentinel-vault-autofill.zip` exists.
- The package extracts with the required extension files.
- The manifest uses Manifest V3.
- The package does not request wildcard web host permissions.
- `artifacts/browser/browser-extension-package-validation.json` records the package hash, required file count, permissions, and host permissions for rollout evidence.

## Native Companion Artifact

Name: Native companion artifact validation records release metadata

Purpose: Prove native companion artifacts can be hashed and classified before signed credential-provider release approval.

Steps:

```powershell
pnpm validate:native-artifacts -- --artifact ".\companions\windows\sentinel-tray-helper.ps1" --out ".\artifacts\native\native-artifact-validation.json"
```

Expected result:

- `artifacts/native/native-artifact-validation.json` records the artifact name, type, size, SHA-256 hash, and signature status.
- Script artifacts are classified as `script`.
- Signed `.exe`, `.dll`, `.msi`, and `.msix` release artifacts can be rechecked with `--require-signature` on the release host.
