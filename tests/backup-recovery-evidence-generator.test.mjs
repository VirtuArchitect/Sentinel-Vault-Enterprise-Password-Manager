import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-backup-recovery-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-backup-recovery-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

const writeRestoreEvidence = (filePath, checks = {}) => {
  const evidence = {
    format: "sentinel-encrypted-backup-restore-drill-v1",
    checkedAt: "2026-07-01T10:00:00Z",
    restoreMode: "dry-run",
    backupFile: "backup.json.enc",
    manifestFile: "backup.json.enc.sha256.json",
    checks: {
      checksumVerified: true,
      decryptedAndParsed: true,
      requiredCollectionsPresent: true,
      transientCollectionsExcluded: true,
      encryptedSecretPayloadsPresent: true,
      orphanSecretsAbsent: true,
      orphanVaultMembersAbsent: true,
      ...checks
    },
    findings: {}
  };
  writeFileSync(filePath, JSON.stringify(evidence, null, 2));
};

test("backup recovery generator summarizes planned restore drill evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-backup-recovery-generator-"));
  try {
    const restoreEvidencePath = path.join(dir, "restore-evidence.json");
    const evidencePath = path.join(dir, "backup-recovery.json");
    writeRestoreEvidence(restoreEvidencePath);

    assert.match(runGenerator([
      "--restore-evidence", restoreEvidencePath,
      "--environment", "lab",
      "--out", evidencePath
    ]), /Backup recovery evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.environment, "lab");
    assert.equal(evidence.schedule.lastRestoreDrillAt, "2026-07-01T10:00:00Z");
    assert.equal(evidence.restoreDrill.checksumVerified, "passed");
    assert.equal(evidence.restoreDrill.orphanReferencesAbsent, "passed");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("backup recovery generator reflects failed restore drill checks", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-backup-recovery-generator-fail-"));
  try {
    const restoreEvidencePath = path.join(dir, "restore-evidence.json");
    const evidencePath = path.join(dir, "backup-recovery.json");
    writeRestoreEvidence(restoreEvidencePath, { checksumVerified: false });

    runGenerator([
      "--restore-evidence", restoreEvidencePath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.restoreDrill.checksumVerified, "failed");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("backup recovery generator creates completed evidence from supplied ceremony controls", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-backup-recovery-generator-completed-"));
  try {
    const restoreEvidencePath = path.join(dir, "restore-evidence.json");
    const evidencePath = path.join(dir, "backup-recovery.json");
    writeRestoreEvidence(restoreEvidencePath);

    runGenerator([
      "--status", "completed",
      "--environment", "prod",
      "--restore-evidence", restoreEvidencePath,
      "--next-restore-drill-due", "2026-10-01",
      "--break-glass-owner", "Break Glass Owner",
      "--recovery-operator", "Recovery Operator",
      "--security-approver", "Security Approver",
      "--records-owner", "Records Owner",
      "--two-person-control", "passed",
      "--offline-runbook", "https://runbooks.example.test/sentinel/recovery",
      "--root-key-escrowed", "passed",
      "--escrow-location", "HSM-backed sealed vault",
      "--access-review-current", "passed",
      "--sealed-copy-tested", "passed",
      "--no-single-person-recovery", "passed",
      "--offsite-copy-enabled", "passed",
      "--immutability-enabled", "passed",
      "--expired-backup-purge-reviewed", "passed",
      "--security-owner", "Security Owner",
      "--operations-owner", "Operations Owner",
      "--business-owner", "Business Owner",
      "--change-ticket", "CHG-80001",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
