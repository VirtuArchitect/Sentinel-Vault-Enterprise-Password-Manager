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

Default outputs:

```text
artifacts/import/bulk-secret-import-payload.json
artifacts/import/bulk-secret-import-evidence.json
```

## Validation

- Confirm `vaultId` exists and is the intended target vault.
- Confirm each row has `name`, `username`, and `password`.
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
