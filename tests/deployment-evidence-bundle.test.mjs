import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runBundleValidator = (bundlePath) => execFileSync(process.execPath, [
  "scripts/validate-deployment-evidence-bundle.mjs",
  bundlePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const writeBundleFixture = (dir, overrides = {}) => {
  const evidenceDir = path.join(dir, "evidence");
  mkdirSync(evidenceDir, { recursive: true });
  const copies = {
    connector: "connector-certification-evidence.json",
    browserRollout: "browser-extension-rollout-evidence.json",
    nativeCompanion: "native-companion-evidence.json",
    identityProvider: "identity-provider-evidence.json",
    kmsHsm: "kms-hsm-provider-evidence.json",
    windowsRelease: "windows-release-evidence.json",
    windowsInstallHardening: "windows-install-hardening-evidence.json",
    tlsIis: "tls-iis-evidence.json",
    pentestScope: "pentest-scope-evidence.json",
    auditWorm: "audit-worm-evidence.json",
    backupRecovery: "backup-recovery-evidence.json",
    deviceTrust: "device-trust-evidence.json",
    bruteForce: "brute-force-evidence.json",
    tenantIsolation: "tenant-isolation-evidence.json",
    siemReceiverRotation: "siem-receiver-rotation-evidence.json",
    sast: "sast-evidence.json",
    logRedaction: "log-redaction-evidence.json",
    storageMigration: "storage-migration-evidence.json",
    releaseAttestation: "release-attestation-evidence.json",
    releaseProvenance: "release-provenance-template.json"
  };
  for (const file of Object.values(copies)) {
    copyFileSync(path.join(rootDir, "docs", "templates", file), path.join(evidenceDir, file));
  }
  const bundle = {
    format: "sentinel-deployment-evidence-bundle-v1",
    environment: "lab",
    status: "planned",
    owner: "platform-team",
    generatedAt: "YYYY-MM-DDTHH:mm:ssZ",
    evidence: Object.fromEntries(Object.entries(copies).map(([name, file]) => [name, path.join("evidence", file)])),
    approvals: {
      securityOwner: "security-team",
      operationsOwner: "operations-team",
      releaseOwner: "release-team"
    },
    ...overrides
  };
  const bundlePath = path.join(dir, "deployment-evidence-bundle.json");
  writeFileSync(bundlePath, JSON.stringify(bundle, null, 2));
  return bundlePath;
};

test("deployment evidence bundle validates referenced evidence files", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir);
    const output = runBundleValidator(bundlePath);
    const validation = JSON.parse(output);

    assert.equal(validation.format, "sentinel-deployment-evidence-bundle-validation-v1");
    assert.equal(validation.status, "planned");
    assert.equal(validation.results.connector.validated, true);
    assert.equal(validation.results.browserRollout.validated, true);
    assert.equal(validation.results.nativeCompanion.validated, true);
    assert.equal(validation.results.windowsInstallHardening.validated, true);
    assert.equal(validation.results.tlsIis.validated, true);
    assert.equal(validation.results.pentestScope.validated, true);
    assert.equal(validation.results.auditWorm.validated, true);
    assert.equal(validation.results.backupRecovery.validated, true);
    assert.equal(validation.results.deviceTrust.validated, true);
    assert.equal(validation.results.bruteForce.validated, true);
    assert.equal(validation.results.tenantIsolation.validated, true);
    assert.equal(validation.results.siemReceiverRotation.validated, true);
    assert.equal(validation.results.sast.validated, true);
    assert.equal(validation.results.logRedaction.validated, true);
    assert.equal(validation.results.releaseAttestation.validated, true);
    assert.equal(validation.results.windowsRelease.validated, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment evidence bundle rejects missing referenced evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-fail-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir, {
      evidence: {
        connector: "evidence/missing.json",
        browserRollout: "evidence/browser-extension-rollout-evidence.json",
        nativeCompanion: "evidence/native-companion-evidence.json",
        identityProvider: "evidence/identity-provider-evidence.json",
        kmsHsm: "evidence/kms-hsm-provider-evidence.json",
        windowsRelease: "evidence/windows-release-evidence.json",
        windowsInstallHardening: "evidence/windows-install-hardening-evidence.json",
        tlsIis: "evidence/tls-iis-evidence.json",
        pentestScope: "evidence/pentest-scope-evidence.json",
        auditWorm: "evidence/audit-worm-evidence.json",
        backupRecovery: "evidence/backup-recovery-evidence.json",
        deviceTrust: "evidence/device-trust-evidence.json",
        bruteForce: "evidence/brute-force-evidence.json",
        tenantIsolation: "evidence/tenant-isolation-evidence.json",
        siemReceiverRotation: "evidence/siem-receiver-rotation-evidence.json",
        sast: "evidence/sast-evidence.json",
        logRedaction: "evidence/log-redaction-evidence.json",
        storageMigration: "evidence/storage-migration-evidence.json",
        releaseAttestation: "evidence/release-attestation-evidence.json",
        releaseProvenance: "evidence/release-provenance-template.json"
      }
    });

    assert.throws(() => runBundleValidator(bundlePath), /connector evidence file not found/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployed evidence bundle cannot contain placeholders", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-deployed-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir, {
      status: "production",
      generatedAt: "2026-07-01T10:00:00Z",
      owner: "replace-with-owner"
    });
    assert.throws(() => runBundleValidator(bundlePath), /deployed bundle cannot contain placeholders/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
