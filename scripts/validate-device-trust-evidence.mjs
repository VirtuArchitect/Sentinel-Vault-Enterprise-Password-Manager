import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/device-trust-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const deployedStatuses = new Set(["pilot", "production"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const drillStatuses = new Set(["not-run", "passed", "failed", "not-applicable"]);
const frequencies = new Set(["weekly", "monthly", "quarterly"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

assert.equal(evidence.format, "sentinel-device-trust-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported device trust evidence status");
assert.ok(evidence.environment, "environment is required");

assert.ok(checkStatuses.has(evidence.policy?.trustedDeviceRequired), "Unsupported trustedDeviceRequired status");
assert.ok(Number.isInteger(evidence.policy?.maxDeviceAgeDays) && evidence.policy.maxDeviceAgeDays >= 1 && evidence.policy.maxDeviceAgeDays <= 365, "policy.maxDeviceAgeDays must be 1-365");
assert.ok(Number.isInteger(evidence.policy?.sessionTtlMinutes) && evidence.policy.sessionTtlMinutes >= 1 && evidence.policy.sessionTtlMinutes <= 1440, "policy.sessionTtlMinutes must be 1-1440");
assert.equal(typeof evidence.policy?.refreshTokensEnabled, "boolean", "policy.refreshTokensEnabled must be boolean");
assert.ok(checkStatuses.has(evidence.policy?.mfaRequiredForNewDevice), "Unsupported mfaRequiredForNewDevice status");
assert.ok(frequencies.has(evidence.policy?.deviceInventoryReviewCadence), "Unsupported deviceInventoryReviewCadence");

assert.ok(evidence.inventory?.exportedAt, "inventory.exportedAt is required");
for (const name of ["deviceCount", "staleDeviceCount", "unknownDeviceCount", "disabledUserDeviceCount"]) {
  assert.ok(Number.isInteger(evidence.inventory?.[name]) && evidence.inventory[name] >= 0, `inventory.${name} must be a non-negative integer`);
}

for (const name of ["deviceFingerprintingDocumented", "newDeviceMfaChallenged", "adminReviewAvailable", "forcedSessionRevocationTested", "disabledUserSessionsRevoked", "logoutInvalidatesSession", "refreshTokenReplayBlocked", "staleDevicesRemoved"]) {
  assert.ok(checkStatuses.has(evidence.controls?.[name]), `Unsupported control status for ${name}`);
}

for (const name of ["lostDeviceRevocation", "stolenSessionReplay", "disabledUserAccess", "expiredSessionAccess"]) {
  assert.ok(drillStatuses.has(evidence.drills?.[name]), `Unsupported drill status for ${name}`);
}

assert.equal(typeof evidence.redaction?.sessionTokensFound, "boolean", "redaction.sessionTokensFound must be boolean");
assert.ok(checkStatuses.has(evidence.redaction?.deviceFingerprintsHashed), "Unsupported deviceFingerprintsHashed status");
assert.ok(checkStatuses.has(evidence.redaction?.ipAddressesRedactedOrScoped), "Unsupported ipAddressesRedactedOrScoped status");
assert.ok(evidence.approvals?.identityOwner, "approvals.identityOwner is required");
assert.ok(evidence.approvals?.securityReviewer, "approvals.securityReviewer is required");
assert.ok(evidence.approvals?.operationsOwner, "approvals.operationsOwner is required");
assert.ok(evidence.approvals?.changeTicket, "approvals.changeTicket is required");

if (deployedStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed device trust evidence cannot contain placeholders");
  assert.ok(isoTimestamp.test(evidence.inventory.exportedAt), "inventory.exportedAt must be an ISO timestamp");
  assert.equal(evidence.policy.trustedDeviceRequired, "passed", "trusted device policy must pass for deployed evidence");
  assert.equal(evidence.policy.mfaRequiredForNewDevice, "passed", "new-device MFA policy must pass for deployed evidence");
  assert.equal(evidence.inventory.staleDeviceCount, 0, "deployed evidence cannot include stale trusted devices");
  assert.equal(evidence.inventory.unknownDeviceCount, 0, "deployed evidence cannot include unknown trusted devices");
  assert.equal(evidence.inventory.disabledUserDeviceCount, 0, "deployed evidence cannot include devices for disabled users");
  for (const name of ["deviceFingerprintingDocumented", "newDeviceMfaChallenged", "adminReviewAvailable", "forcedSessionRevocationTested", "disabledUserSessionsRevoked", "logoutInvalidatesSession", "staleDevicesRemoved"]) {
    assert.equal(evidence.controls[name], "passed", `${name} must pass for deployed evidence`);
  }
  if (evidence.policy.refreshTokensEnabled) {
    assert.equal(evidence.controls.refreshTokenReplayBlocked, "passed", "refresh-token replay blocking must pass when refresh tokens are enabled");
  }
  for (const name of ["lostDeviceRevocation", "stolenSessionReplay", "disabledUserAccess", "expiredSessionAccess"]) {
    assert.equal(evidence.drills[name], "passed", `${name} drill must pass for deployed evidence`);
  }
  assert.equal(evidence.redaction.sessionTokensFound, false, "device trust evidence cannot contain session tokens");
  assert.equal(evidence.redaction.deviceFingerprintsHashed, "passed", "device fingerprints must be hashed for deployed evidence");
  assert.equal(evidence.redaction.ipAddressesRedactedOrScoped, "passed", "IP addresses must be redacted or scoped for deployed evidence");
}

console.log(`Device trust evidence validated: ${evidencePath}`);
