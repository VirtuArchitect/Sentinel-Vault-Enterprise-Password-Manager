# KMS/HSM Key Ceremony

Use this runbook before enabling `KMS_PROVIDER=external-kms` or `KMS_PROVIDER=hsm`.

## Preconditions

- Provider owner and security approver are named.
- Key purpose is limited to Sentinel Vault envelope operations.
- Key ID is recorded in `KMS_KEY_ID`.
- Provider endpoint is recorded in `KMS_ENDPOINT` where applicable.
- Break-glass recovery owner is named.
- Backup and restore drills are scheduled.

## Creation

1. Create the key in the approved provider.
2. Disable plaintext key export.
3. Enable audit logging on key usage.
4. Restrict key usage to the Sentinel Vault service identity.
5. Record provider, key ID, endpoint, region, and policy hash.
6. Record provider evidence in `docs/templates/kms-hsm-provider-evidence.json` or an environment-specific copy.
7. Run `pnpm validate:kms-hsm-evidence <evidence-file>`.
8. Run `pnpm verify`.
9. Start Sentinel Vault with non-local KMS settings in a non-production environment.
10. Confirm `/api/reports/compliance` reports the expected key provider status.

## Rotation

1. Create the replacement key.
2. Update `KMS_KEY_ID` and `VAULT_KEY_VERSION`.
3. Restart Sentinel Vault in a test environment.
4. Export and verify a signed audit ledger.
5. Export and validate encrypted backups.
6. Run a restore-validation dry run.
7. Promote the new key version during an approved maintenance window.
8. Retain the previous key until all backups protected by it have expired or been re-encrypted.

## Revocation

1. Disable access for the compromised service identity.
2. Stop Sentinel Vault.
3. Rotate `VAULT_ROOT_KEY` or provider wrapping key as applicable.
4. Invalidate active sessions and service tokens.
5. Export incident evidence from audit and SIEM.
6. Restore from the last known-good encrypted backup if required.
