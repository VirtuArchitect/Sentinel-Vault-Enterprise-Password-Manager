import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-audit-worm-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "audit-worm-evidence.json"), "utf8"));
const hex = (char) => char.repeat(64);

const productionEvidence = () => {
  const evidence = template();
  evidence.status = "production";
  evidence.environment = "prod";
  evidence.ledgerExport = {
    exportedAt: "2026-07-01T10:00:00Z",
    eventCount: 128,
    payloadHash: hex("a"),
    signatureAlgorithm: "HMAC-SHA256",
    manifestSignaturePresent: "passed",
    localVerification: "passed"
  };
  evidence.externalSigning = {
    provider: "Enterprise signing service",
    keyId: "audit-ledger-signing-key-v1",
    algorithm: "ECDSA-SHA256",
    signatureHash: hex("b"),
    timestampAuthority: "https://tsa.example.test",
    verification: "passed"
  };
  evidence.wormStorage = {
    provider: "Object storage with immutable retention",
    location: "sentinel-audit-ledger-prod",
    retentionMode: "compliance",
    retentionDays: 2555,
    objectLockEnabled: "passed",
    versioningEnabled: "passed",
    deleteProtectionEnabled: "passed",
    legalHoldTested: "passed",
    readbackVerified: "passed"
  };
  evidence.redaction = {
    secretValuesFound: false,
    tokenValuesFound: false,
    screenshotsRedacted: "passed"
  };
  evidence.approvals = {
    securityOwner: "Security Owner",
    recordsOwner: "Records Owner",
    operationsOwner: "Operations Owner",
    changeTicket: "CHG-70001"
  };
  return evidence;
};

test("audit WORM evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "audit-worm-evidence.json")), /validated/);
});

test("production audit WORM evidence validates immutable storage controls", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-audit-worm-"));
  try {
    const evidencePath = path.join(dir, "audit-worm.json");
    writeFileSync(evidencePath, JSON.stringify(productionEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production audit WORM evidence rejects missing object lock", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-audit-worm-lock-fail-"));
  try {
    const evidence = productionEvidence();
    evidence.wormStorage.objectLockEnabled = "planned";
    const evidencePath = path.join(dir, "audit-worm.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /objectLockEnabled must pass/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production audit WORM evidence rejects leaked token values", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-audit-worm-redaction-fail-"));
  try {
    const evidence = productionEvidence();
    evidence.redaction.tokenValuesFound = true;
    const evidencePath = path.join(dir, "audit-worm.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /token values/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
