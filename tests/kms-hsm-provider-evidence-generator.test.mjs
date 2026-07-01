import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-kms-hsm-provider-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-kms-hsm-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const writePreflight = (filePath, extra = {}) => {
  writeFileSync(filePath, JSON.stringify({
    format: "sentinel-kms-hsm-gateway-preflight-v1",
    checkedAt: "2026-07-01T10:00:00Z",
    provider: "external-kms",
    endpoint: "https://kms.example.test",
    keyId: "sentinel-key-2026-07",
    status: {
      provider: "external-kms",
      keyId: "sentinel-key-2026-07",
      keyVersion: "v3",
      keyExportDisabled: true,
      auditLoggingEnabled: true
    },
    checks: {
      providerMatches: true,
      keyIdMatches: true,
      keyExportDisabled: true,
      auditLoggingEnabled: true,
      statusEndpointReachable: true,
      signEndpointReachable: true,
      signatureReturned: true
    },
    ...extra
  }, null, 2));
};

test("kms hsm generator creates planned provider evidence from preflight", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-kms-hsm-generator-"));
  try {
    const preflightPath = path.join(dir, "kms-hsm-gateway-preflight.json");
    const evidencePath = path.join(dir, "kms-hsm-provider-evidence.json");
    writePreflight(preflightPath);

    assert.match(runGenerator([
      "--preflight", preflightPath,
      "--environment", "lab",
      "--out", evidencePath
    ]), /KMS\/HSM provider evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.provider, "external-kms");
    assert.equal(evidence.keyId, "sentinel-key-2026-07");
    assert.equal(evidence.keyVersion, "v3");
    assert.equal(evidence.keyExportDisabled, true);
    assert.equal(evidence.checks.configValidation, "passed");
    assert.match(evidence.policyHash, /^[a-f0-9]{64}$/);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("kms hsm generator reflects failed gateway checks", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-kms-hsm-failed-generator-"));
  try {
    const preflightPath = path.join(dir, "kms-hsm-gateway-preflight.json");
    const evidencePath = path.join(dir, "kms-hsm-provider-evidence.json");
    writePreflight(preflightPath, { checks: { providerMatches: false, keyIdMatches: true } });

    runGenerator([
      "--preflight", preflightPath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.checks.configValidation, "failed");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("kms hsm generator creates active evidence with approvals", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-kms-hsm-active-generator-"));
  try {
    const preflightPath = path.join(dir, "kms-hsm-gateway-preflight.json");
    const evidencePath = path.join(dir, "kms-hsm-provider-evidence.json");
    writePreflight(preflightPath);

    runGenerator([
      "--status", "active",
      "--preflight", preflightPath,
      "--provider-name", "Example Managed KMS",
      "--environment", "prod",
      "--region", "eu-west-1",
      "--service-identity", "sentinel-vault-prod",
      "--previous-key-id", "sentinel-key-2026-06",
      "--previous-key-retire-after", "2026-08-01",
      "--audit-ledger-export", "passed",
      "--encrypted-backup-validation", "passed",
      "--restore-dry-run", "passed",
      "--security-owner", "Security Owner",
      "--platform-owner", "Platform Owner",
      "--change-ticket", "CHG-98001",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
