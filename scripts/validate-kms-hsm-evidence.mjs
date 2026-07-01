import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/kms-hsm-provider-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
const allowedProviders = new Set(["external-kms", "hsm", "external-kms-or-hsm"]);
const allowedStatuses = new Set(["planned", "pilot", "approved", "active", "retired"]);
const strictStatuses = new Set(["approved", "active"]);
const placeholder = /replace-with|YYYY-MM-DD|external-kms-or-hsm/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const isoDate = /^\d{4}-\d{2}-\d{2}$/;
const hashPattern = /^[a-f0-9]{64}$/i;

assert.equal(evidence.format, "sentinel-kms-hsm-provider-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported evidence status");
assert.ok(allowedProviders.has(evidence.provider), "Unsupported KMS/HSM provider type");
assert.ok(evidence.providerName, "providerName is required");
assert.ok(evidence.environment, "environment is required");
assert.ok(evidence.keyId, "keyId is required");
assert.ok(evidence.keyVersion, "keyVersion is required");
assert.equal(evidence.keyExportDisabled, true, "key export must be disabled");
assert.equal(evidence.auditLoggingEnabled, true, "provider audit logging must be enabled");
assert.ok(evidence.serviceIdentity, "serviceIdentity is required");
assert.ok(evidence.rotation?.createdAt, "rotation.createdAt is required");
assert.ok(evidence.rotation?.activatedAt, "rotation.activatedAt is required");
assert.ok(evidence.rotation?.previousKeyRetireAfter, "rotation.previousKeyRetireAfter is required");
assert.ok(evidence.approvals?.securityOwner, "securityOwner approval field is required");
assert.ok(evidence.approvals?.platformOwner, "platformOwner approval field is required");
assert.ok(evidence.approvals?.changeTicket, "changeTicket approval field is required");

for (const [name, result] of Object.entries(evidence.checks || {})) {
  assert.ok(["planned", "passed", "failed", "not-applicable"].includes(result), `Unsupported check result for ${name}`);
}

if (strictStatuses.has(evidence.status)) {
  assert.ok(["external-kms", "hsm"].includes(evidence.provider), "approved or active evidence must name a concrete provider boundary");
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "approved or active evidence cannot contain placeholders");
  assert.ok(hashPattern.test(evidence.policyHash), "policyHash must be a SHA-256 hash");
  assert.ok(isoTimestamp.test(evidence.rotation.createdAt), "rotation.createdAt must be an ISO timestamp");
  assert.ok(isoTimestamp.test(evidence.rotation.activatedAt), "rotation.activatedAt must be an ISO timestamp");
  assert.ok(isoDate.test(evidence.rotation.previousKeyRetireAfter), "rotation.previousKeyRetireAfter must be an ISO date");
  for (const [name, result] of Object.entries(evidence.checks || {})) {
    assert.equal(result, "passed", `${name} must be passed for approved or active provider evidence`);
  }
}

console.log(`KMS/HSM provider evidence validated: ${evidencePath}`);
