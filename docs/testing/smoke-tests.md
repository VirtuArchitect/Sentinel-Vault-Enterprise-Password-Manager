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

If a previous local run shows old sample data, stop the running demo and archive/reset the ignored local state first:

```powershell
.\scripts\start-demo.ps1 -ResetState
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
- The zip contains `preflight.ps1`, `install.ps1`, `uninstall.ps1`, `run-sentinel.ps1`, and `healthcheck.ps1`.
- The extracted production app passes `/healthz`.
- `artifacts/windows/windows-package-validation.json` records the package validation result and package SHA-256 for release evidence.
- Signed Windows release evidence must include the package validation report and match the validated package SHA-256 to a release artifact.

Optional VM preflight:

```powershell
.\preflight.ps1 -Port 5173 -Out ".\windows-target-preflight.json"
```

Expected result:

- The report format is `sentinel-windows-target-preflight-v1`.
- Package layout, Node.js version, selected ports, and optional IIS prerequisites are checked before installation.
- Missing Node.js or occupied ports fail before `install.ps1` is run.

## Browser Extension Package

Name: Browser autofill extension package validates for enterprise review

Purpose: Prove the extension package includes only the reviewed files, uses Manifest V3, and keeps host permissions scoped to the local Sentinel Vault console.

Steps:

```powershell
pnpm package:extension
pnpm validate:extension-package -- --out ".\artifacts\browser\browser-extension-package-validation.json"
pnpm release:browser-rollout -- --artifact ".\artifacts\browser\sentinel-vault-autofill.zip" --package-validation ".\artifacts\browser\browser-extension-package-validation.json" --out ".\artifacts\browser\browser-extension-rollout-evidence.json"
pnpm validate:browser-rollout -- ".\artifacts\browser\browser-extension-rollout-evidence.json"
```

Expected result:

- `artifacts/browser/sentinel-vault-autofill.zip` exists.
- The package extracts with the required extension files.
- The manifest uses Manifest V3.
- The package does not request wildcard web host permissions.
- `artifacts/browser/browser-extension-package-validation.json` records the package hash, required file count, permissions, and host permissions for rollout evidence.
- Browser rollout evidence records the package validation report and cannot pass deployed rollout gates without a validated package hash match.

## Native Companion Artifact

Name: Native companion artifact validation records release metadata

Purpose: Prove native companion artifacts can be hashed and classified before signed credential-provider release approval.

Steps:

```powershell
pnpm validate:native-artifacts -- --artifact ".\companions\windows\sentinel-tray-helper.ps1" --out ".\artifacts\native\native-artifact-validation.json"
```

Expected result:

- `artifacts/native/native-artifact-validation.json` records the artifact name, type, size, SHA-256 hash, and signature status.
- Native companion release evidence generated with `--artifact-validation` must match the validated artifact names, types, and SHA-256 hashes.
- Script artifacts are classified as `script`.
- Signed `.exe`, `.dll`, `.msi`, and `.msix` release artifacts can be rechecked with `--require-signature` on the release host.

## Postgres Schema

Name: Postgres schema validation records target shape evidence

Purpose: Prove the planned Postgres schema has the required JSONB mirror tables, generated columns, indexes, and migration bookkeeping before a database driver is approved.

Steps:

```powershell
pnpm validate:postgres-schema -- --out ".\artifacts\storage\postgres-schema-validation.json"
```

Expected result:

- `artifacts/storage/postgres-schema-validation.json` records the schema SHA-256 hash.
- Required mirror tables and indexes are present.
- Generated columns used by planned queries are present.
- The schema is wrapped in `BEGIN` / `COMMIT`.

## Source Column Map

Name: Proprietary source column map validates before conversion

Purpose: Prove source migration mappings define required Sentinel fields, keep evidence redacted, and account for source CSV columns before conversion.

Steps:

```powershell
pnpm validate:source-map -- --mapping ".\docs\templates\source-export-column-map.json" --out ".\artifacts\import\source-column-map-validation.json"
```

Expected result:

- `artifacts/import/source-column-map-validation.json` records the mapping SHA-256 hash.
- Required fields `name`, `username`, and `password` are present.
- Redaction settings do not allow password or OTP values in evidence.
- When `--source` is supplied, every source CSV column is mapped or explicitly ignored.
- Deployed source migration evidence must include the normalized-import validation report and match its CSV hash, row count, adapter evidence, and password-redaction status.

## Connector Preflight Evidence

Name: Connector live preflight evidence validates before certification

Purpose: Prove SIEM and ITSM preflight evidence can be independently checked before connector certification evidence is generated.

Steps:

```powershell
pnpm validate:connector-preflight -- --preflight ".\artifacts\integrations\connector-live-preflight.json"
```

Expected result:

- The preflight evidence has format `sentinel-enterprise-connector-live-preflight-v1`.
- All preflight checks are boolean and passing.
- SIEM evidence, when present, is signed and accepted by the receiver.
- ITSM evidence, when present, proves an active allowed-state ticket inside the change window.
- Redacted output does not include connector secrets.
- Certified connector evidence generated with `--preflight` includes live preflight summary checks that match the certified connector target.
- Certified SIEM receiver rotation evidence includes receiver report summary checks and delivery IDs that match the reviewed receiver evidence.
- Production ITSM work-note evidence includes reviewed report hashes for every required lifecycle work note.
