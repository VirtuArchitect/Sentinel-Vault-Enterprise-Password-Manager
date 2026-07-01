import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/backup-recovery-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "scheduled", "completed", "expired"]);
const strictStatuses = new Set(["completed"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const frequencies = new Set(["hourly", "daily", "weekly", "monthly", "quarterly"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const isoDate = /^\d{4}-\d{2}-\d{2}$/;

assert.equal(evidence.format, "sentinel-backup-recovery-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported backup recovery evidence status");
assert.ok(evidence.environment, "environment is required");
assert.ok(frequencies.has(evidence.schedule?.encryptedBackupFrequency), "Unsupported encryptedBackupFrequency");
assert.ok(frequencies.has(evidence.schedule?.restoreDrillFrequency), "Unsupported restoreDrillFrequency");
assert.ok(evidence.schedule?.lastRestoreDrillAt, "schedule.lastRestoreDrillAt is required");
assert.ok(evidence.schedule?.nextRestoreDrillDue, "schedule.nextRestoreDrillDue is required");

assert.ok(evidence.ceremony?.breakGlassOwner, "ceremony.breakGlassOwner is required");
assert.ok(evidence.ceremony?.recoveryOperator, "ceremony.recoveryOperator is required");
assert.ok(evidence.ceremony?.securityApprover, "ceremony.securityApprover is required");
assert.ok(evidence.ceremony?.recordsOwner, "ceremony.recordsOwner is required");
assert.ok(checkStatuses.has(evidence.ceremony?.twoPersonControl), "Unsupported ceremony.twoPersonControl status");
assert.ok(evidence.ceremony?.offlineRunbook, "ceremony.offlineRunbook is required");

for (const name of ["rootKeyEscrowed", "accessReviewCurrent", "sealedCopyTested", "noSinglePersonRecovery"]) {
  assert.ok(checkStatuses.has(evidence.escrow?.[name]), `Unsupported escrow status for ${name}`);
}
assert.ok(evidence.escrow?.escrowLocation, "escrow.escrowLocation is required");

assert.ok(evidence.restoreDrill?.evidencePath, "restoreDrill.evidencePath is required");
for (const name of ["checksumVerified", "decryptedAndParsed", "requiredCollectionsPresent", "transientCollectionsExcluded", "encryptedSecretPayloadsPresent", "orphanReferencesAbsent"]) {
  assert.ok(checkStatuses.has(evidence.restoreDrill?.[name]), `Unsupported restore drill status for ${name}`);
}
assert.ok(Number.isInteger(evidence.restoreDrill?.rpoMinutes) && evidence.restoreDrill.rpoMinutes >= 0, "restoreDrill.rpoMinutes must be a non-negative integer");
assert.ok(Number.isInteger(evidence.restoreDrill?.rtoMinutes) && evidence.restoreDrill.rtoMinutes >= 0, "restoreDrill.rtoMinutes must be a non-negative integer");

assert.ok(Number.isInteger(evidence.retention?.backupRetentionDays) && evidence.retention.backupRetentionDays >= 1, "retention.backupRetentionDays must be a positive integer");
for (const name of ["offsiteCopyEnabled", "immutabilityEnabled", "expiredBackupPurgeReviewed"]) {
  assert.ok(checkStatuses.has(evidence.retention?.[name]), `Unsupported retention status for ${name}`);
}

assert.equal(typeof evidence.redaction?.secretValuesFound, "boolean", "redaction.secretValuesFound must be boolean");
assert.equal(typeof evidence.redaction?.rootKeyValuesFound, "boolean", "redaction.rootKeyValuesFound must be boolean");
assert.equal(typeof evidence.redaction?.tokenValuesFound, "boolean", "redaction.tokenValuesFound must be boolean");
assert.ok(evidence.approvals?.securityOwner, "approvals.securityOwner is required");
assert.ok(evidence.approvals?.operationsOwner, "approvals.operationsOwner is required");
assert.ok(evidence.approvals?.businessOwner, "approvals.businessOwner is required");
assert.ok(evidence.approvals?.changeTicket, "approvals.changeTicket is required");

if (strictStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "completed backup recovery evidence cannot contain placeholders");
  assert.ok(isoTimestamp.test(evidence.schedule.lastRestoreDrillAt), "lastRestoreDrillAt must be an ISO timestamp");
  assert.ok(isoDate.test(evidence.schedule.nextRestoreDrillDue), "nextRestoreDrillDue must be YYYY-MM-DD");
  assert.ok(Date.parse(evidence.schedule.nextRestoreDrillDue) > Date.parse(evidence.schedule.lastRestoreDrillAt), "nextRestoreDrillDue must be after lastRestoreDrillAt");
  assert.equal(evidence.ceremony.twoPersonControl, "passed", "two-person recovery control must pass");
  for (const name of ["rootKeyEscrowed", "accessReviewCurrent", "sealedCopyTested", "noSinglePersonRecovery"]) {
    assert.equal(evidence.escrow[name], "passed", `${name} must pass for completed recovery evidence`);
  }
  for (const name of ["checksumVerified", "decryptedAndParsed", "requiredCollectionsPresent", "transientCollectionsExcluded", "encryptedSecretPayloadsPresent", "orphanReferencesAbsent"]) {
    assert.equal(evidence.restoreDrill[name], "passed", `${name} must pass for completed recovery evidence`);
  }
  assert.equal(evidence.retention.offsiteCopyEnabled, "passed", "offsite copy must pass for completed recovery evidence");
  assert.equal(evidence.retention.immutabilityEnabled, "passed", "immutability must pass for completed recovery evidence");
  assert.equal(evidence.retention.expiredBackupPurgeReviewed, "passed", "expired backup purge review must pass for completed recovery evidence");
  assert.equal(evidence.redaction.secretValuesFound, false, "recovery evidence cannot contain secret values");
  assert.equal(evidence.redaction.rootKeyValuesFound, false, "recovery evidence cannot contain root key values");
  assert.equal(evidence.redaction.tokenValuesFound, false, "recovery evidence cannot contain token values");
}

console.log(`Backup recovery evidence validated: ${evidencePath}`);
