import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-device-trust-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-device-trust-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

const writeInventory = (filePath, devices, extra = {}) => {
  writeFileSync(filePath, JSON.stringify({
    exportedAt: "2026-07-01T10:00:00Z",
    devices,
    ...extra
  }, null, 2));
};

test("device trust generator summarizes planned inventory evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-device-trust-generator-"));
  try {
    const inventoryPath = path.join(dir, "device-inventory.json");
    const evidencePath = path.join(dir, "device-trust.json");
    writeInventory(inventoryPath, [
      {
        userId: "ada",
        userStatus: "active",
        trustStatus: "trusted",
        lastSeenAt: "2026-06-30T09:00:00Z",
        fingerprintHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      },
      {
        userId: "grace",
        userStatus: "active",
        trustStatus: "trusted",
        lastSeenAt: "2026-01-01T09:00:00Z",
        fingerprintHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      },
      {
        userId: "unknown",
        userStatus: "disabled",
        trustStatus: "unknown",
        lastSeenAt: "2026-06-20T09:00:00Z",
        fingerprintHash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      }
    ]);

    assert.match(runGenerator([
      "--device-inventory", inventoryPath,
      "--environment", "lab",
      "--out", evidencePath
    ]), /Device trust evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.environment, "lab");
    assert.equal(evidence.inventory.deviceCount, 3);
    assert.equal(evidence.inventory.staleDeviceCount, 1);
    assert.equal(evidence.inventory.unknownDeviceCount, 1);
    assert.equal(evidence.inventory.disabledUserDeviceCount, 1);
    assert.equal(evidence.redaction.sessionTokensFound, false);
    assert.equal(evidence.redaction.deviceFingerprintsHashed, "passed");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("device trust generator flags leaked session and refresh tokens", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-device-trust-token-generator-"));
  try {
    const inventoryPath = path.join(dir, "device-inventory.json");
    const samplesPath = path.join(dir, "samples.log");
    const evidencePath = path.join(dir, "device-trust.json");
    writeInventory(inventoryPath, [
      {
        userId: "ada",
        userStatus: "active",
        trustStatus: "trusted",
        lastSeenAt: "2026-06-30T09:00:00Z",
        fingerprint: "plain-browser-fingerprint"
      }
    ]);
    writeFileSync(samplesPath, [
      "session_token=",
      "sampleleakedvalue12345",
      "\nrefresh_token=",
      "samplerefreshvalue67890"
    ].join(""));

    runGenerator([
      "--device-inventory", inventoryPath,
      "--samples", samplesPath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.redaction.sessionTokensFound, true);
    assert.equal(evidence.redaction.deviceFingerprintsHashed, "failed");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("device trust generator creates production evidence from supplied controls", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-device-trust-production-generator-"));
  try {
    const inventoryPath = path.join(dir, "device-inventory.json");
    const evidencePath = path.join(dir, "device-trust.json");
    writeInventory(inventoryPath, [
      {
        userId: "ada",
        userStatus: "active",
        trustStatus: "trusted",
        lastSeenAt: "2026-06-30T09:00:00Z",
        fingerprintHash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      }
    ], { refreshTokensEnabled: true });

    runGenerator([
      "--status", "production",
      "--environment", "prod",
      "--device-inventory", inventoryPath,
      "--trusted-device-required", "passed",
      "--mfa-required-for-new-device", "passed",
      "--device-fingerprinting-documented", "passed",
      "--new-device-mfa-challenged", "passed",
      "--admin-review-available", "passed",
      "--forced-session-revocation-tested", "passed",
      "--disabled-user-sessions-revoked", "passed",
      "--logout-invalidates-session", "passed",
      "--refresh-token-replay-blocked", "passed",
      "--stale-devices-removed", "passed",
      "--lost-device-revocation", "passed",
      "--stolen-session-replay", "passed",
      "--disabled-user-access", "passed",
      "--expired-session-access", "passed",
      "--ip-addresses-redacted-or-scoped", "passed",
      "--identity-owner", "Identity Owner",
      "--security-reviewer", "Security Reviewer",
      "--operations-owner", "Operations Owner",
      "--change-ticket", "CHG-91001",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
