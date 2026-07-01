# Offline Read-Only Cache

Sentinel Vault can export a per-user offline cache artifact for controlled read-only scenarios.

## API

- `POST /api/offline-cache/export`
- `POST /api/offline-cache/verify`

The export is scoped to the requesting user's accessible vaults and shared secrets. Temporary just-in-time grants are not promoted into long-lived offline access.

## Artifact Boundary

The cache manifest is readable and includes counts, expiry, key version, and `plaintextIncluded: false`.

The cache body is encrypted with AES-256-GCM and contains:

- Tenant-aware vault metadata.
- Secret metadata required for lookup.
- Existing encrypted secret payloads.

Plaintext passwords are never written into the offline cache artifact.

## Remaining Native Work

The Windows companion can protect an exported cache artifact with DPAPI for the current Windows user:

```powershell
.\companions\windows\sentinel-tray-helper.ps1 `
  -ProtectOfflineCache `
  -OfflineCachePath ".\sentinel-offline-cache.json"
```

Inspect the DPAPI-protected cache manifest without exposing secret payloads:

```powershell
.\companions\windows\sentinel-tray-helper.ps1 -ShowOfflineCache
```

Remove an expired protected cache:

```powershell
.\companions\windows\sentinel-tray-helper.ps1 -RemoveExpiredOfflineCache
```

Install or remove hourly cleanup for the current Windows user:

```powershell
.\companions\windows\sentinel-tray-helper.ps1 -InstallOfflineCacheCleanupTask
.\companions\windows\sentinel-tray-helper.ps1 -RemoveOfflineCacheCleanupTask
```

## Remaining Native Work

A production offline reader should add a dedicated read-only UI for browsing decrypted records after online verification and use an approved enterprise KMS/HSM flow where DPAPI alone is not sufficient.
