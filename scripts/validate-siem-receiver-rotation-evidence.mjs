import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/siem-receiver-rotation-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "pilot", "certified", "expired"]);
const strictStatuses = new Set(["pilot", "certified"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

assert.equal(evidence.format, "sentinel-siem-receiver-rotation-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported SIEM receiver rotation evidence status");
assert.ok(evidence.environment, "environment is required");
assert.ok(evidence.receiver?.system, "receiver.system is required");
assert.ok(evidence.receiver?.endpointHost, "receiver.endpointHost is required");
assert.ok(evidence.receiver?.owner, "receiver.owner is required");
assert.ok(evidence.receiver?.supportQueue, "receiver.supportQueue is required");

assert.ok(evidence.rotation?.activeKeyId, "rotation.activeKeyId is required");
assert.ok(evidence.rotation?.previousKeyId, "rotation.previousKeyId is required");
assert.ok(evidence.rotation?.rotatedAt, "rotation.rotatedAt is required");
assert.ok(evidence.rotation?.previousKeyRetireAfter, "rotation.previousKeyRetireAfter is required");
assert.ok(evidence.rotation?.changeTicket, "rotation.changeTicket is required");

for (const name of [
  "activeKeyAccepted",
  "previousKeyAcceptedDuringWindow",
  "previousKeyRejectedAfterWindow",
  "signatureVerified",
  "timestampRejectedOutsideReplayWindow",
  "nonceReplayRejected",
  "deliveryIdStored",
  "redactedLogsReviewed",
  "receiverAlertingConfirmed"
]) {
  assert.ok(checkStatuses.has(evidence.checks?.[name]), `Unsupported check status for ${name}`);
}

assert.ok(evidence.samples?.activeDeliveryId, "samples.activeDeliveryId is required");
assert.ok(evidence.samples?.previousKeyDeliveryId, "samples.previousKeyDeliveryId is required");
assert.ok(evidence.samples?.replayAttemptId, "samples.replayAttemptId is required");
assert.ok(evidence.samples?.receiverEvidencePath, "samples.receiverEvidencePath is required");
assert.equal(typeof evidence.redaction?.signingSecretsFound, "boolean", "redaction.signingSecretsFound must be boolean");
assert.equal(typeof evidence.redaction?.payloadSecretValuesFound, "boolean", "redaction.payloadSecretValuesFound must be boolean");
assert.equal(typeof evidence.redaction?.tokenValuesFound, "boolean", "redaction.tokenValuesFound must be boolean");
assert.ok(evidence.approvals?.siemOwner, "approvals.siemOwner is required");
assert.ok(evidence.approvals?.securityReviewer, "approvals.securityReviewer is required");
assert.ok(evidence.approvals?.operationsOwner, "approvals.operationsOwner is required");

if (strictStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "strict SIEM receiver rotation evidence cannot contain placeholders");
  assert.ok(isoTimestamp.test(evidence.rotation.rotatedAt), "rotation.rotatedAt must be an ISO timestamp");
  assert.ok(isoTimestamp.test(evidence.rotation.previousKeyRetireAfter), "rotation.previousKeyRetireAfter must be an ISO timestamp");
  assert.ok(Date.parse(evidence.rotation.previousKeyRetireAfter) > Date.parse(evidence.rotation.rotatedAt), "previousKeyRetireAfter must be after rotatedAt");
  assert.notEqual(evidence.rotation.activeKeyId, evidence.rotation.previousKeyId, "active and previous key IDs must differ");
  for (const name of Object.keys(evidence.checks)) {
    assert.equal(evidence.checks[name], "passed", `${name} must pass for strict SIEM receiver rotation evidence`);
  }
  assert.equal(evidence.redaction.signingSecretsFound, false, "rotation evidence cannot contain SIEM signing secrets");
  assert.equal(evidence.redaction.payloadSecretValuesFound, false, "rotation evidence cannot contain payload secret values");
  assert.equal(evidence.redaction.tokenValuesFound, false, "rotation evidence cannot contain token values");
}

console.log(`SIEM receiver rotation evidence validated: ${evidencePath}`);
