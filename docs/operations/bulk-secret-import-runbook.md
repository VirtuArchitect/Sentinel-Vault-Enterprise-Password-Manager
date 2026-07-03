# Bulk Secret Import Runbook

Use this runbook when migrating secrets from another password store into Sentinel Vault.

## Preparation

1. Confirm migration approval and ticket reference.
2. Export from the source system into an encrypted working folder.
3. Map source fields with `docs/templates/bulk-secret-import-mapping.json`.
4. Stage data with the CSV shape in `docs/templates/bulk-secret-import-template.csv`.
5. Remove sample values and confirm no production import file is committed to Git.

Build a redacted evidence file and API payload from a staged CSV export:

```powershell
pnpm prepare:bulk-import -- --csv ".\secure-work\source-export.csv" --mapping ".\docs\templates\bulk-secret-import-mapping.json"
```

For Bitwarden, Dashlane credentials CSV, LastPass, or 1Password CSV exports, first normalize the source export into Sentinel's staged CSV shape:

```powershell
pnpm convert:source-export -- --source ".\secure-work\bitwarden-export.csv" --format bitwarden-csv --vault-id "v1" --out ".\secure-work\source-export.csv"
pnpm convert:source-export -- --source ".\secure-work\dashlane-credentials.csv" --format dashlane-csv --vault-id "v1" --out ".\secure-work\source-export.csv"
pnpm convert:source-export -- --source ".\secure-work\lastpass-export.csv" --format lastpass-csv --vault-id "v1" --out ".\secure-work\source-export.csv"
pnpm convert:source-export -- --source ".\secure-work\1password-export.csv" --format onepassword-csv --vault-id "v1" --out ".\secure-work\source-export.csv"
```

For a proprietary CSV export, copy `docs/templates/source-export-column-map.json`, map the source columns, and run:

```powershell
pnpm validate:source-map -- --mapping ".\secure-work\source-export-column-map.json" --source ".\secure-work\vendor-export.csv" --out ".\secure-work\source-column-map-validation.json"
pnpm convert:source-export -- --source ".\secure-work\vendor-export.csv" --format mapped-csv --mapping ".\secure-work\source-export-column-map.json" --vault-id "v1" --out ".\secure-work\source-export.csv"
pnpm validate:normalized-import -- --csv ".\secure-work\source-export.csv" --out ".\secure-work\normalized-import-validation.json"
```

If the source CSV is supplied, validation requires every source column to be mapped or listed in `ignoredColumns` before conversion.

Default outputs:

```text
artifacts/import/bulk-secret-import-payload.json
artifacts/import/bulk-secret-import-evidence.json
```

## Validation

- Confirm `vaultId` exists and is the intended target vault.
- Confirm each row has `name`, `username`, and `password`.
- Confirm source adapter evidence has `passwordValuesIncluded=false`.
- For `mapped-csv`, confirm the source map excludes OTP, token seed, recovery-code, and attachment fields unless they are intentionally imported through approved notes.
- Confirm duplicate detection results are reviewed.
- Confirm high-risk records are flagged with `risk=high`.
- Confirm import rows do not contain expired, disabled, or test-only credentials.

## Submission

Submit through `POST /api/secret-imports` with:

- `vaultId`
- `reason`
- `entries`
- optional `allowDuplicates` only for controlled recovery scenarios

The generated payload can be sent as the request body after security review.

The submitting admin cannot approve their own import batch.

## Approval

An independent security admin reviews the pending batch metadata, duplicate report, source ticket, and migration evidence. If acceptable, approve with:

```text
POST /api/secret-imports/:id/approve
```

If the evidence is incomplete, deny with:

```text
POST /api/secret-imports/:id/deny
```

## Cleanup

- Delete source export files from the working folder.
- Confirm imported entries appear in the target vault.
- Rotate imported high-risk secrets where source-system compromise is possible.
- Attach the Sentinel import batch ID to the migration ticket.
- Attach the redacted evidence JSON to the migration ticket.
