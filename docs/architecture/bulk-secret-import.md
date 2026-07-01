# Bulk Secret Import

Sentinel Vault supports bulk secret import through an encrypted escrow workflow.

## API

- `GET /api/secret-imports`
- `POST /api/secret-imports`
- `POST /api/secret-imports/:id/approve`
- `POST /api/secret-imports/:id/deny`

## Workflow

1. A security admin submits import entries for a vault.
2. Sentinel Vault validates vault access, required fields, and duplicate secret material.
3. Submitted passwords are encrypted immediately and stored only inside the pending import batch.
4. The requester cannot approve or deny their own batch.
5. A second security admin approves the batch, creating live vault entries from the encrypted escrow records.
6. Denied batches remain as metadata evidence without exposing secret material.

## Duplicate Detection

Imports are checked against:

- Existing active secrets in the target vault.
- Other entries in the same import batch.

Duplicate secret material is rejected unless `allowDuplicates` is explicitly set for a controlled recovery scenario.

## Security Boundary

Public import listings expose batch metadata, counts, status, duplicate reasons, and imported IDs only. They do not expose plaintext passwords, encrypted payloads, fingerprints, or historical secret material.
