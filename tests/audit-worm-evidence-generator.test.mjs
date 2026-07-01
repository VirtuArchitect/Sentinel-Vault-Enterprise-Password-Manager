import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-audit-worm-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-audit-worm-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const sha256Hex = (value) => crypto.createHash("sha256").update(value).digest("hex");

const writeLedger = (filePath, events = [{ id: "audit-1", action: "LOGIN" }]) => {
  const payloadHash = sha256Hex(JSON.stringify(events));
  const ledger = {
    manifest: {
      exportedAt: "2026-07-01T10:00:00Z",
      count: events.length,
      payloadHash,
      signatureAlgorithm: "HMAC-SHA256",
      signature: sha256Hex(`signature:${payloadHash}`)
    },
    events
  };
  writeFileSync(filePath, JSON.stringify({ ledger }, null, 2));
  return ledger;
};

test("audit WORM generator summarizes planned signed ledger evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-audit-worm-generator-"));
  try {
    const ledgerPath = path.join(dir, "ledger.json");
    const evidencePath = path.join(dir, "audit-worm.json");
    const ledger = writeLedger(ledgerPath);

    assert.match(runGenerator([
      "--ledger", ledgerPath,
      "--environment", "lab",
      "--out", evidencePath
    ]), /Audit WORM evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.environment, "lab");
    assert.equal(evidence.ledgerExport.eventCount, 1);
    assert.equal(evidence.ledgerExport.payloadHash, ledger.manifest.payloadHash);
    assert.equal(evidence.ledgerExport.manifestSignaturePresent, "passed");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("audit WORM generator flags leaked token values in ledger exports", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-audit-worm-generator-token-"));
  try {
    const ledgerPath = path.join(dir, "ledger.json");
    const evidencePath = path.join(dir, "audit-worm.json");
    writeLedger(ledgerPath, [{ id: "audit-1", detail: "bearer abcdefghijklmnopqrstuvwxyz" }]);

    runGenerator([
      "--ledger", ledgerPath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.redaction.tokenValuesFound, true);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("audit WORM generator creates validated production evidence from supplied controls", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-audit-worm-generator-prod-"));
  try {
    const ledgerPath = path.join(dir, "ledger.json");
    const evidencePath = path.join(dir, "audit-worm.json");
    writeLedger(ledgerPath, [{ id: "audit-1", action: "LOGIN" }, { id: "audit-2", action: "REVEAL" }]);

    runGenerator([
      "--status", "production",
      "--environment", "prod",
      "--ledger", ledgerPath,
      "--signing-provider", "Enterprise signing service",
      "--key-id", "audit-ledger-signing-key-v1",
      "--signing-algorithm", "ECDSA-SHA256",
      "--external-signature", "external-signature-material",
      "--timestamp-authority", "https://tsa.example.test",
      "--external-verification", "passed",
      "--worm-provider", "Object storage with immutable retention",
      "--worm-location", "sentinel-audit-ledger-prod",
      "--retention-mode", "compliance",
      "--retention-days", "2555",
      "--object-lock-enabled", "passed",
      "--versioning-enabled", "passed",
      "--delete-protection-enabled", "passed",
      "--legal-hold-tested", "passed",
      "--readback-verified", "passed",
      "--screenshots-redacted", "passed",
      "--security-owner", "Security Owner",
      "--records-owner", "Records Owner",
      "--operations-owner", "Operations Owner",
      "--change-ticket", "CHG-70001",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
