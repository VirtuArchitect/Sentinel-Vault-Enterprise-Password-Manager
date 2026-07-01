import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-backup-recovery-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "backup-recovery-evidence.json"), "utf8"));

const completedEvidence = () => {
  const evidence = template();
  evidence.status = "completed";
  evidence.environment = "prod";
  evidence.schedule = {
    encryptedBackupFrequency: "daily",
    restoreDrillFrequency: "quarterly",
    lastRestoreDrillAt: "2026-07-01T10:00:00Z",
    nextRestoreDrillDue: "2026-10-01"
  };
  evidence.ceremony = {
    breakGlassOwner: "Break Glass Owner",
    recoveryOperator: "Recovery Operator",
    securityApprover: "Security Approver",
    recordsOwner: "Records Owner",
    twoPersonControl: "passed",
    offlineRunbook: "https://runbooks.example.test/sentinel/recovery"
  };
  evidence.escrow = {
    rootKeyEscrowed: "passed",
    escrowLocation: "HSM-backed sealed vault",
    accessReviewCurrent: "passed",
    sealedCopyTested: "passed",
    noSinglePersonRecovery: "passed"
  };
  evidence.restoreDrill = {
    evidencePath: "artifacts/storage/encrypted-backup-restore-evidence.json",
    checksumVerified: "passed",
    decryptedAndParsed: "passed",
    requiredCollectionsPresent: "passed",
    transientCollectionsExcluded: "passed",
    encryptedSecretPayloadsPresent: "passed",
    orphanReferencesAbsent: "passed",
    rpoMinutes: 60,
    rtoMinutes: 180
  };
  evidence.retention = {
    backupRetentionDays: 180,
    offsiteCopyEnabled: "passed",
    immutabilityEnabled: "passed",
    expiredBackupPurgeReviewed: "passed"
  };
  evidence.redaction = {
    secretValuesFound: false,
    rootKeyValuesFound: false,
    tokenValuesFound: false
  };
  evidence.approvals = {
    securityOwner: "Security Owner",
    operationsOwner: "Operations Owner",
    businessOwner: "Business Owner",
    changeTicket: "CHG-80001"
  };
  return evidence;
};

test("backup recovery evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "backup-recovery-evidence.json")), /validated/);
});

test("completed backup recovery evidence validates ceremony and restore drill", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-backup-recovery-"));
  try {
    const evidencePath = path.join(dir, "backup-recovery.json");
    writeFileSync(evidencePath, JSON.stringify(completedEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("completed backup recovery evidence rejects missing two-person control", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-backup-recovery-control-fail-"));
  try {
    const evidence = completedEvidence();
    evidence.ceremony.twoPersonControl = "planned";
    const evidencePath = path.join(dir, "backup-recovery.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /two-person recovery control/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("completed backup recovery evidence rejects leaked root key values", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-backup-recovery-redaction-fail-"));
  try {
    const evidence = completedEvidence();
    evidence.redaction.rootKeyValuesFound = true;
    const evidencePath = path.join(dir, "backup-recovery.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /root key values/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
