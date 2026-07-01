import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const drillStatuses = new Set(["not-run", "passed", "failed", "not-applicable"]);
const frequencies = new Set(["weekly", "monthly", "quarterly"]);
const outputPath = args.get("--out") || "artifacts/security/device-trust-evidence.json";
const inventoryPath = args.get("--device-inventory") || "artifacts/security/device-inventory.json";
const status = args.get("--status") || "planned";

assert.ok(allowedStatuses.has(status), "status must be planned, pilot, production, or retired");

const toIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const readText = (filePath) => readFileSync(filePath, "utf8").replace(/^\uFEFF/, "");
const asBool = (value, fallback) => {
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  return fallback;
};
const argStatus = (name, fallback) => {
  const value = args.get(name) || fallback;
  assert.ok(checkStatuses.has(value), `${name} must be planned, passed, failed, or not-applicable`);
  return value;
};
const argDrill = (name, fallback) => {
  const value = args.get(name) || fallback;
  assert.ok(drillStatuses.has(value), `${name} must be not-run, passed, failed, or not-applicable`);
  return value;
};
const maxDeviceAgeDays = Number(args.get("--max-device-age-days") || 90);
const sessionTtlMinutes = Number(args.get("--session-ttl-minutes") || 15);
assert.ok(Number.isInteger(maxDeviceAgeDays) && maxDeviceAgeDays >= 1 && maxDeviceAgeDays <= 365, "max-device-age-days must be 1-365");
assert.ok(Number.isInteger(sessionTtlMinutes) && sessionTtlMinutes >= 1 && sessionTtlMinutes <= 1440, "session-ttl-minutes must be 1-1440");

const inventorySource = existsSync(inventoryPath) ? readJson(inventoryPath) : null;
const devices = Array.isArray(inventorySource)
  ? inventorySource
  : Array.isArray(inventorySource?.devices)
    ? inventorySource.devices
    : [];
const exportedAt = args.get("--exported-at")
  || inventorySource?.exportedAt
  || (status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : toIso());
const referenceTime = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(exportedAt) ? new Date(exportedAt).getTime() : Date.now();
const maxAgeMs = maxDeviceAgeDays * 24 * 60 * 60 * 1000;

const normalize = (value) => String(value ?? "").trim().toLowerCase();
const isDisabledUserDevice = (device) => device.userDisabled === true
  || normalize(device.userStatus) === "disabled"
  || normalize(device.ownerStatus) === "disabled";
const isUnknownDevice = (device) => device.unknown === true
  || normalize(device.trustStatus) === "unknown"
  || normalize(device.status) === "unknown"
  || normalize(device.owner) === "unknown"
  || normalize(device.userId) === "unknown";
const isStaleDevice = (device) => {
  const lastSeen = Date.parse(device.lastSeenAt || device.lastSeen || device.updatedAt || "");
  return Number.isFinite(lastSeen) && referenceTime - lastSeen > maxAgeMs;
};
const looksHashed = (value) => !value
  || /^\[REDACTED\]$/i.test(String(value))
  || /^sha256:[a-f0-9]{64}$/i.test(String(value))
  || /^[a-f0-9]{64}$/i.test(String(value));
const allFingerprintsHashed = devices.length === 0
  ? undefined
  : devices.every((device) => looksHashed(device.fingerprintHash || device.deviceFingerprintHash || device.fingerprint || device.deviceFingerprint));

const readSamples = (samplePath) => {
  if (!samplePath || !existsSync(samplePath)) {
    return "";
  }
  if (statSync(samplePath).isDirectory()) {
    return "";
  }
  return readText(samplePath);
};
const sampleText = readSamples(args.get("--samples"));
const inventoryText = inventorySource ? JSON.stringify(inventorySource) : "";
const sessionTokensFound = /bearer\s+(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}|refresh[_-]?token\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}|session[_-]?token\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}/i.test(`${inventoryText}\n${sampleText}`);
const ipAddressesFound = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(`${inventoryText}\n${sampleText}`);

const refreshTokensEnabled = asBool(
  args.get("--refresh-tokens-enabled"),
  Boolean(inventorySource?.policy?.refreshTokensEnabled ?? inventorySource?.refreshTokensEnabled)
);
const staleDeviceCount = devices.filter(isStaleDevice).length;
const unknownDeviceCount = devices.filter(isUnknownDevice).length;
const disabledUserDeviceCount = devices.filter(isDisabledUserDevice).length;
const fingerprintStatus = allFingerprintsHashed === true ? "passed" : allFingerprintsHashed === false ? "failed" : "planned";

const evidence = {
  format: "sentinel-device-trust-evidence-v1",
  status,
  environment: args.get("--environment") || "replace-with-environment",
  policy: {
    trustedDeviceRequired: argStatus("--trusted-device-required", "planned"),
    maxDeviceAgeDays,
    sessionTtlMinutes,
    refreshTokensEnabled,
    mfaRequiredForNewDevice: argStatus("--mfa-required-for-new-device", "planned"),
    deviceInventoryReviewCadence: args.get("--device-inventory-review-cadence") || "monthly"
  },
  inventory: {
    exportedAt,
    deviceCount: Number(args.get("--device-count") || devices.length),
    staleDeviceCount: Number(args.get("--stale-device-count") || staleDeviceCount),
    unknownDeviceCount: Number(args.get("--unknown-device-count") || unknownDeviceCount),
    disabledUserDeviceCount: Number(args.get("--disabled-user-device-count") || disabledUserDeviceCount)
  },
  controls: {
    deviceFingerprintingDocumented: argStatus("--device-fingerprinting-documented", "planned"),
    newDeviceMfaChallenged: argStatus("--new-device-mfa-challenged", "planned"),
    adminReviewAvailable: argStatus("--admin-review-available", "planned"),
    forcedSessionRevocationTested: argStatus("--forced-session-revocation-tested", "planned"),
    disabledUserSessionsRevoked: argStatus("--disabled-user-sessions-revoked", "planned"),
    logoutInvalidatesSession: argStatus("--logout-invalidates-session", "planned"),
    refreshTokenReplayBlocked: argStatus("--refresh-token-replay-blocked", refreshTokensEnabled ? "planned" : "not-applicable"),
    staleDevicesRemoved: argStatus("--stale-devices-removed", "planned")
  },
  drills: {
    lostDeviceRevocation: argDrill("--lost-device-revocation", "not-run"),
    stolenSessionReplay: argDrill("--stolen-session-replay", "not-run"),
    disabledUserAccess: argDrill("--disabled-user-access", "not-run"),
    expiredSessionAccess: argDrill("--expired-session-access", "not-run")
  },
  redaction: {
    sessionTokensFound: asBool(args.get("--session-tokens-found"), sessionTokensFound),
    deviceFingerprintsHashed: argStatus("--device-fingerprints-hashed", fingerprintStatus),
    ipAddressesRedactedOrScoped: argStatus("--ip-addresses-redacted-or-scoped", ipAddressesFound ? "planned" : "passed")
  },
  approvals: {
    identityOwner: args.get("--identity-owner") || "replace-with-owner",
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    operationsOwner: args.get("--operations-owner") || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || "replace-with-ticket"
  }
};

assert.ok(frequencies.has(evidence.policy.deviceInventoryReviewCadence), "device-inventory-review-cadence is unsupported");
for (const name of ["deviceCount", "staleDeviceCount", "unknownDeviceCount", "disabledUserDeviceCount"]) {
  assert.ok(Number.isInteger(evidence.inventory[name]) && evidence.inventory[name] >= 0, `${name} must be a non-negative integer`);
}

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Device trust evidence written: ${outputPath}`);
