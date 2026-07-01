import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/kms-hsm-sdk-approval-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
const placeholder = /replace-with|YYYY-MM-DD|external-kms-or-hsm/i;
const sha256Pattern = /^[a-f0-9]{64}$/i;
const allowedStatuses = new Set(["planned", "approved", "retired"]);
const allowedProviders = new Set(["external-kms", "hsm", "external-kms-or-hsm"]);
const passValues = new Set(["passed", "approved", true]);
const plannedValues = new Set(["planned", "pending", "not-applicable", false]);
const assertPassed = (value, message) => assert.ok(passValues.has(value), message);
const assertFalse = (value, message) => assert.equal(value, false, message);

assert.equal(evidence.format, "sentinel-kms-hsm-sdk-approval-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported KMS/HSM SDK approval status");
assert.ok(evidence.environment, "environment is required");
assert.ok(allowedProviders.has(evidence.provider), "Unsupported KMS/HSM provider type");
assert.ok(evidence.sdk?.packageName, "sdk.packageName is required");
assert.ok(evidence.sdk?.packageVersion, "sdk.packageVersion is required");
assert.ok(evidence.sdk?.license, "sdk.license is required");
assert.ok(evidence.sdk?.registry, "sdk.registry is required");
assert.ok(evidence.sdk?.packageSha256, "sdk.packageSha256 is required");
assert.ok(evidence.sdk?.approvalReference, "sdk.approvalReference is required");
assert.ok(evidence.targetEnvironment?.providerTenant, "targetEnvironment.providerTenant is required");
assert.ok(evidence.targetEnvironment?.region, "targetEnvironment.region is required");
assert.ok(evidence.targetEnvironment?.keyId, "targetEnvironment.keyId is required");
assert.ok(evidence.targetEnvironment?.serviceIdentity, "targetEnvironment.serviceIdentity is required");
assert.ok(evidence.operationProof?.preflightPath, "operationProof.preflightPath is required");
assert.ok(evidence.operationProof?.providerEvidencePath, "operationProof.providerEvidencePath is required");
assert.ok(evidence.approvals?.securityArchitectureOwner, "approvals.securityArchitectureOwner is required");
assert.ok(evidence.approvals?.platformOwner, "approvals.platformOwner is required");
assert.ok(evidence.approvals?.releaseOwner, "approvals.releaseOwner is required");
assert.ok(evidence.approvals?.changeTicket, "approvals.changeTicket is required");

for (const value of [
  evidence.sdk.maintenanceStatus,
  evidence.sdk.supplyChainReview,
  evidence.sdk.securityReview,
  evidence.targetEnvironment.networkIsolation,
  evidence.targetEnvironment.auditSinkConfigured,
  evidence.targetEnvironment.breakGlassProcedure,
  evidence.operationProof.signOrUnwrapOperation,
  evidence.operationProof.keyExportBlocked,
  evidence.operationProof.auditEventCaptured,
  evidence.operationProof.rollbackTested
]) {
  assert.ok(passValues.has(value) || plannedValues.has(value), `Unsupported KMS/HSM SDK approval value: ${value}`);
}

if (evidence.status === "approved") {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "approved KMS/HSM SDK approval evidence cannot contain placeholders");
  assert.ok(["external-kms", "hsm"].includes(evidence.provider), "approved SDK evidence must name a concrete provider boundary");
  assert.ok(sha256Pattern.test(evidence.sdk.packageSha256), "sdk.packageSha256 must be a SHA-256 hex digest");
  assert.ok(existsSync(evidence.operationProof.preflightPath), "operationProof.preflightPath must exist for approved evidence");
  assert.ok(existsSync(evidence.operationProof.providerEvidencePath), "operationProof.providerEvidencePath must exist for approved evidence");
  assertPassed(evidence.sdk.maintenanceStatus, "sdk.maintenanceStatus must be passed");
  assertPassed(evidence.sdk.supplyChainReview, "sdk.supplyChainReview must be passed");
  assertPassed(evidence.sdk.securityReview, "sdk.securityReview must be passed");
  assertPassed(evidence.targetEnvironment.networkIsolation, "targetEnvironment.networkIsolation must be passed");
  assertPassed(evidence.targetEnvironment.auditSinkConfigured, "targetEnvironment.auditSinkConfigured must be passed");
  assertPassed(evidence.targetEnvironment.breakGlassProcedure, "targetEnvironment.breakGlassProcedure must be passed");
  assertPassed(evidence.operationProof.signOrUnwrapOperation, "operationProof.signOrUnwrapOperation must be passed");
  assertPassed(evidence.operationProof.keyExportBlocked, "operationProof.keyExportBlocked must be passed");
  assertPassed(evidence.operationProof.auditEventCaptured, "operationProof.auditEventCaptured must be passed");
  assertPassed(evidence.operationProof.rollbackTested, "operationProof.rollbackTested must be passed");
  assertFalse(evidence.redaction.containsCredentials, "approved evidence cannot contain credentials");
  assertFalse(evidence.redaction.containsKeyMaterial, "approved evidence cannot contain key material");
  assertFalse(evidence.redaction.containsProviderTokens, "approved evidence cannot contain provider tokens");
  assertFalse(evidence.redaction.containsConnectionStrings, "approved evidence cannot contain connection strings");
}

console.log(`KMS/HSM SDK approval evidence validated: ${evidencePath}`);
