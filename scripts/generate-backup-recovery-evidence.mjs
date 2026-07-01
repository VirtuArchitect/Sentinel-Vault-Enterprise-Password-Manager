import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const allowedStatuses = new Set(["planned", "scheduled", "completed", "expired"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const frequencies = new Set(["hourly", "daily", "weekly", "monthly", "quarterly"]);
const outputPath = args.get("--out") || "artifacts/security/backup-recovery-evidence.json";
const status = args.get("--status") || "planned";
const restoreEvidencePath = args.get("--restore-evidence") || "artifacts/storage/encrypted-backup-restore-evidence.json";

assert.ok(allowedStatuses.has(status), "status must be planned, scheduled, completed, or expired");

const toIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const addDays = (iso, days) => {
  const date = new Date(iso);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
};
const argStatus = (name, fallback) => {
  const value = args.get(name) || fallback;
  assert.ok(checkStatuses.has(value), `${name} must be planned, passed, failed, or not-applicable`);
  return value;
};
const boolToStatus = (value) => (value === true ? "passed" : value === false ? "failed" : "planned");

const restoreEvidence = existsSync(restoreEvidencePath)
  ? JSON.parse(readFileSync(restoreEvidencePath, "utf8").replace(/^\uFEFF/, ""))
  : null;
const checks = restoreEvidence?.checks || {};
const findingsText = restoreEvidence ? JSON.stringify(restoreEvidence.findings || {}) : "";
const checkedAt = restoreEvidence?.checkedAt || (status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : toIso());

const encryptedBackupFrequency = args.get("--encrypted-backup-frequency") || "daily";
const restoreDrillFrequency = args.get("--restore-drill-frequency") || "quarterly";
assert.ok(frequencies.has(encryptedBackupFrequency), "encrypted-backup-frequency is unsupported");
assert.ok(frequencies.has(restoreDrillFrequency), "restore-drill-frequency is unsupported");

const nextRestoreDrillDue = args.get("--next-restore-drill-due")
  || (status === "planned" ? "YYYY-MM-DD" : addDays(checkedAt, restoreDrillFrequency === "monthly" ? 30 : restoreDrillFrequency === "quarterly" ? 92 : 7));

const secretValuesFound = /secret(Value)?\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{8,}|Passw0rd!/i.test(findingsText);
const rootKeyValuesFound = /VAULT_ROOT_KEY\s*[:=]|rootKey\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{8,}/i.test(findingsText);
const tokenValuesFound = /bearer\s+(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}|token\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}/i.test(findingsText);

const evidence = {
  format: "sentinel-backup-recovery-evidence-v1",
  status,
  environment: args.get("--environment") || "replace-with-environment",
  schedule: {
    encryptedBackupFrequency,
    restoreDrillFrequency,
    lastRestoreDrillAt: args.get("--last-restore-drill-at") || checkedAt,
    nextRestoreDrillDue
  },
  ceremony: {
    breakGlassOwner: args.get("--break-glass-owner") || "replace-with-owner",
    recoveryOperator: args.get("--recovery-operator") || "replace-with-operator",
    securityApprover: args.get("--security-approver") || "replace-with-approver",
    recordsOwner: args.get("--records-owner") || "replace-with-owner",
    twoPersonControl: argStatus("--two-person-control", "planned"),
    offlineRunbook: args.get("--offline-runbook") || "replace-with-runbook-link"
  },
  escrow: {
    rootKeyEscrowed: argStatus("--root-key-escrowed", "planned"),
    escrowLocation: args.get("--escrow-location") || "replace-with-escrow-location",
    accessReviewCurrent: argStatus("--access-review-current", "planned"),
    sealedCopyTested: argStatus("--sealed-copy-tested", "planned"),
    noSinglePersonRecovery: argStatus("--no-single-person-recovery", "planned")
  },
  restoreDrill: {
    evidencePath: restoreEvidencePath,
    checksumVerified: argStatus("--checksum-verified", boolToStatus(checks.checksumVerified)),
    decryptedAndParsed: argStatus("--decrypted-and-parsed", boolToStatus(checks.decryptedAndParsed)),
    requiredCollectionsPresent: argStatus("--required-collections-present", boolToStatus(checks.requiredCollectionsPresent)),
    transientCollectionsExcluded: argStatus("--transient-collections-excluded", boolToStatus(checks.transientCollectionsExcluded)),
    encryptedSecretPayloadsPresent: argStatus("--encrypted-secret-payloads-present", boolToStatus(checks.encryptedSecretPayloadsPresent)),
    orphanReferencesAbsent: argStatus("--orphan-references-absent", boolToStatus(checks.orphanSecretsAbsent === true && checks.orphanVaultMembersAbsent === true)),
    rpoMinutes: Number(args.get("--rpo-minutes") || 60),
    rtoMinutes: Number(args.get("--rto-minutes") || 240)
  },
  retention: {
    backupRetentionDays: Number(args.get("--backup-retention-days") || 90),
    offsiteCopyEnabled: argStatus("--offsite-copy-enabled", "planned"),
    immutabilityEnabled: argStatus("--immutability-enabled", "planned"),
    expiredBackupPurgeReviewed: argStatus("--expired-backup-purge-reviewed", "planned")
  },
  redaction: {
    secretValuesFound: args.get("--secret-values-found") === "true" ? true : args.get("--secret-values-found") === "false" ? false : secretValuesFound,
    rootKeyValuesFound: args.get("--root-key-values-found") === "true" ? true : args.get("--root-key-values-found") === "false" ? false : rootKeyValuesFound,
    tokenValuesFound: args.get("--token-values-found") === "true" ? true : args.get("--token-values-found") === "false" ? false : tokenValuesFound
  },
  approvals: {
    securityOwner: args.get("--security-owner") || "replace-with-owner",
    operationsOwner: args.get("--operations-owner") || "replace-with-owner",
    businessOwner: args.get("--business-owner") || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || "replace-with-ticket"
  }
};

assert.ok(Number.isInteger(evidence.restoreDrill.rpoMinutes) && evidence.restoreDrill.rpoMinutes >= 0, "rpo-minutes must be a non-negative integer");
assert.ok(Number.isInteger(evidence.restoreDrill.rtoMinutes) && evidence.restoreDrill.rtoMinutes >= 0, "rto-minutes must be a non-negative integer");
assert.ok(Number.isInteger(evidence.retention.backupRetentionDays) && evidence.retention.backupRetentionDays >= 1, "backup-retention-days must be a positive integer");

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Backup recovery evidence written: ${outputPath}`);
