import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-device-trust-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "device-trust-evidence.json"), "utf8"));

const productionEvidence = () => {
  const evidence = template();
  evidence.status = "production";
  evidence.environment = "prod";
  evidence.policy = {
    trustedDeviceRequired: "passed",
    maxDeviceAgeDays: 90,
    sessionTtlMinutes: 15,
    refreshTokensEnabled: false,
    mfaRequiredForNewDevice: "passed",
    deviceInventoryReviewCadence: "monthly"
  };
  evidence.inventory = {
    exportedAt: "2026-07-01T10:00:00Z",
    deviceCount: 42,
    staleDeviceCount: 0,
    unknownDeviceCount: 0,
    disabledUserDeviceCount: 0
  };
  evidence.controls = {
    deviceFingerprintingDocumented: "passed",
    newDeviceMfaChallenged: "passed",
    adminReviewAvailable: "passed",
    forcedSessionRevocationTested: "passed",
    disabledUserSessionsRevoked: "passed",
    logoutInvalidatesSession: "passed",
    refreshTokenReplayBlocked: "not-applicable",
    staleDevicesRemoved: "passed"
  };
  evidence.drills = {
    lostDeviceRevocation: "passed",
    stolenSessionReplay: "passed",
    disabledUserAccess: "passed",
    expiredSessionAccess: "passed"
  };
  evidence.redaction = {
    sessionTokensFound: false,
    deviceFingerprintsHashed: "passed",
    ipAddressesRedactedOrScoped: "passed"
  };
  evidence.approvals = {
    identityOwner: "Identity Owner",
    securityReviewer: "Security Reviewer",
    operationsOwner: "Operations Owner",
    changeTicket: "CHG-90001"
  };
  return evidence;
};

test("device trust evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "device-trust-evidence.json")), /validated/);
});

test("production device trust evidence validates policy, drills, and redaction", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-device-trust-"));
  try {
    const evidencePath = path.join(dir, "device-trust.json");
    writeFileSync(evidencePath, JSON.stringify(productionEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production device trust evidence rejects stale devices", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-device-trust-stale-"));
  try {
    const evidence = productionEvidence();
    evidence.inventory.staleDeviceCount = 1;
    const evidencePath = path.join(dir, "device-trust.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /stale trusted devices/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production device trust evidence rejects leaked session tokens", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-device-trust-token-"));
  try {
    const evidence = productionEvidence();
    evidence.redaction.sessionTokensFound = true;
    const evidencePath = path.join(dir, "device-trust.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /session tokens/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
