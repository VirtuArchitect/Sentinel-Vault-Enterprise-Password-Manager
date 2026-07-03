import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
const args = new Map();
for (let index = 0; index < cliArgs.length; index += 1) {
  const arg = cliArgs[index];
  if (arg.startsWith("--")) {
    const next = cliArgs[index + 1];
    if (!next || next.startsWith("--")) {
      args.set(arg, true);
    } else {
      args.set(arg, next);
      index += 1;
    }
  }
}

const evidencePath = args.get("--preflight") || args.get("--evidence") || cliArgs.find((arg) => !arg.startsWith("--")) || "artifacts/integrations/connector-live-preflight.json";
const requireSiem = args.has("--require-siem");
const requireItsm = args.has("--require-itsm");
const evidence = JSON.parse(readFileSync(evidencePath, "utf8").replace(/^\uFEFF/, ""));
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const base64urlSha = /^[A-Za-z0-9_-]{43}$/;
const deliveryIdPattern = /^[0-9a-f-]{36}$/i;
const secretLeakPattern = /(replace-with-secret|preflight-secret|SIEM_WEBHOOK_SECRET|ITSM_TOKEN|Bearer\s+[A-Za-z0-9._-]+)/i;

assert.equal(evidence.format, "sentinel-enterprise-connector-live-preflight-v1");
assert.ok(isoTimestamp.test(evidence.checkedAt), "checkedAt must be an ISO timestamp");
assert.ok(evidence.connectors && typeof evidence.connectors === "object", "connectors are required");
assert.ok(evidence.checks && typeof evidence.checks === "object", "checks are required");

const hasSiem = Boolean(evidence.connectors.siem);
const hasItsm = Boolean(evidence.connectors.itsm);
assert.ok(hasSiem || hasItsm, "at least one connector result is required");
if (requireSiem) assert.ok(hasSiem, "--require-siem requires connectors.siem");
if (requireItsm) assert.ok(hasItsm, "--require-itsm requires connectors.itsm");

for (const [name, passed] of Object.entries(evidence.checks)) {
  assert.equal(typeof passed, "boolean", `checks.${name} must be boolean`);
  assert.equal(passed, true, `checks.${name} must pass`);
}

if (hasSiem) {
  const siem = evidence.connectors.siem;
  assert.ok(siem.endpointHost, "connectors.siem.endpointHost is required");
  assert.equal(typeof siem.status, "number", "connectors.siem.status must be numeric");
  assert.equal(siem.ok, true, "connectors.siem.ok must be true");
  assert.ok(deliveryIdPattern.test(siem.deliveryId || ""), "connectors.siem.deliveryId must be a UUID");
  assert.equal(siem.signed, true, "SIEM preflight must be HMAC signed");
  assert.ok(Number.isInteger(siem.replayWindowSeconds) && siem.replayWindowSeconds > 0, "connectors.siem.replayWindowSeconds must be positive");
  assert.ok(base64urlSha.test(siem.requestBodySha256 || ""), "connectors.siem.requestBodySha256 must be a SHA-256 base64url digest");
  assert.equal(siem.receiver?.accepted, true, "SIEM receiver must accept the preflight");
  assert.notEqual(siem.receiver?.replayStored, false, "SIEM receiver must not report missing replay storage");
}

if (hasItsm) {
  const itsm = evidence.connectors.itsm;
  assert.ok(itsm.endpointHost, "connectors.itsm.endpointHost is required");
  assert.ok(itsm.ticketRef, "connectors.itsm.ticketRef is required");
  assert.equal(typeof itsm.status, "number", "connectors.itsm.status must be numeric");
  assert.equal(itsm.ok, true, "connectors.itsm.ok must be true");
  assert.equal(itsm.active, true, "ITSM ticket must be active");
  assert.equal(itsm.stateAllowed, true, "ITSM ticket state must be allowed");
  assert.ok(Array.isArray(itsm.allowedStates) && itsm.allowedStates.length > 0, "ITSM allowed states are required");
  if (itsm.changeWindow) {
    assert.equal(itsm.changeWindow.valid, true, "ITSM change window must be parseable");
    assert.equal(itsm.changeWindow.started, true, "ITSM change window must have started");
    assert.equal(itsm.changeWindow.notExpired, true, "ITSM change window must not be expired");
  }
}

const serialized = JSON.stringify(evidence);
assert.doesNotMatch(serialized, secretLeakPattern, "connector preflight evidence appears to contain secret material");
assert.equal(evidence.checks.redactedOutput, true, "connector preflight output must be redacted");

console.log(JSON.stringify({
  format: "sentinel-connector-preflight-validation-v1",
  evidencePath,
  hasSiem,
  hasItsm,
  checkCount: Object.keys(evidence.checks).length,
  validated: true
}, null, 2));
