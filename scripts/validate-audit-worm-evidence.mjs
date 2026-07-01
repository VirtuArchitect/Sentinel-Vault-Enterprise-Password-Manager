import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/audit-worm-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const deployedStatuses = new Set(["pilot", "production"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const retentionModes = new Set(["governance", "compliance", "governance-or-compliance"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const sha256Pattern = /^[a-f0-9]{64}$/i;

assert.equal(evidence.format, "sentinel-audit-worm-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported audit WORM evidence status");
assert.ok(evidence.environment, "environment is required");
assert.ok(evidence.ledgerExport?.exportedAt, "ledgerExport.exportedAt is required");
assert.ok(Number.isInteger(evidence.ledgerExport?.eventCount) && evidence.ledgerExport.eventCount >= 0, "ledgerExport.eventCount must be a non-negative integer");
assert.ok(evidence.ledgerExport?.payloadHash, "ledgerExport.payloadHash is required");
assert.ok(evidence.ledgerExport?.signatureAlgorithm, "ledgerExport.signatureAlgorithm is required");
assert.ok(checkStatuses.has(evidence.ledgerExport?.manifestSignaturePresent), "Unsupported manifestSignaturePresent status");
assert.ok(checkStatuses.has(evidence.ledgerExport?.localVerification), "Unsupported localVerification status");

assert.ok(evidence.externalSigning?.provider, "externalSigning.provider is required");
assert.ok(evidence.externalSigning?.keyId, "externalSigning.keyId is required");
assert.ok(evidence.externalSigning?.algorithm, "externalSigning.algorithm is required");
assert.ok(evidence.externalSigning?.signatureHash, "externalSigning.signatureHash is required");
assert.ok(evidence.externalSigning?.timestampAuthority, "externalSigning.timestampAuthority is required");
assert.ok(checkStatuses.has(evidence.externalSigning?.verification), "Unsupported external signing verification status");

assert.ok(evidence.wormStorage?.provider, "wormStorage.provider is required");
assert.ok(evidence.wormStorage?.location, "wormStorage.location is required");
assert.ok(retentionModes.has(evidence.wormStorage?.retentionMode), "Unsupported wormStorage.retentionMode");
assert.ok(Number.isInteger(evidence.wormStorage?.retentionDays) && evidence.wormStorage.retentionDays >= 1, "wormStorage.retentionDays must be a positive integer");
for (const name of ["objectLockEnabled", "versioningEnabled", "deleteProtectionEnabled", "legalHoldTested", "readbackVerified"]) {
  assert.ok(checkStatuses.has(evidence.wormStorage?.[name]), `Unsupported WORM storage status for ${name}`);
}

assert.equal(typeof evidence.redaction?.secretValuesFound, "boolean", "redaction.secretValuesFound must be boolean");
assert.equal(typeof evidence.redaction?.tokenValuesFound, "boolean", "redaction.tokenValuesFound must be boolean");
assert.ok(checkStatuses.has(evidence.redaction?.screenshotsRedacted), "Unsupported screenshotsRedacted status");
assert.ok(evidence.approvals?.securityOwner, "approvals.securityOwner is required");
assert.ok(evidence.approvals?.recordsOwner, "approvals.recordsOwner is required");
assert.ok(evidence.approvals?.operationsOwner, "approvals.operationsOwner is required");
assert.ok(evidence.approvals?.changeTicket, "approvals.changeTicket is required");

if (deployedStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed audit WORM evidence cannot contain placeholders");
  assert.ok(isoTimestamp.test(evidence.ledgerExport.exportedAt), "ledgerExport.exportedAt must be an ISO timestamp");
  assert.ok(sha256Pattern.test(evidence.ledgerExport.payloadHash), "ledgerExport.payloadHash must be a SHA-256 hex digest");
  assert.ok(sha256Pattern.test(evidence.externalSigning.signatureHash), "externalSigning.signatureHash must be a SHA-256 hex digest");
  assert.ok(evidence.ledgerExport.eventCount > 0, "deployed audit WORM evidence must include exported events");
  assert.equal(evidence.ledgerExport.manifestSignaturePresent, "passed", "manifest signature must be present for deployed evidence");
  assert.equal(evidence.ledgerExport.localVerification, "passed", "local ledger verification must pass for deployed evidence");
  assert.equal(evidence.externalSigning.verification, "passed", "external signing verification must pass for deployed evidence");
  assert.ok(["governance", "compliance"].includes(evidence.wormStorage.retentionMode), "deployed WORM evidence must use a concrete retention mode");
  for (const name of ["objectLockEnabled", "versioningEnabled", "deleteProtectionEnabled", "legalHoldTested", "readbackVerified"]) {
    assert.equal(evidence.wormStorage[name], "passed", `${name} must pass for deployed WORM evidence`);
  }
  assert.equal(evidence.redaction.secretValuesFound, false, "audit WORM evidence cannot contain secret values");
  assert.equal(evidence.redaction.tokenValuesFound, false, "audit WORM evidence cannot contain token values");
  assert.equal(evidence.redaction.screenshotsRedacted, "passed", "screenshot redaction must pass for deployed evidence");
}

console.log(`Audit WORM evidence validated: ${evidencePath}`);
