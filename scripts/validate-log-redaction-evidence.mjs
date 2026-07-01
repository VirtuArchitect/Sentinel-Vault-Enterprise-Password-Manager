import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/log-redaction-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const deployedStatuses = new Set(["pilot", "production"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

assert.equal(evidence.format, "sentinel-log-redaction-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported log redaction evidence status");
assert.ok(evidence.environment, "environment is required");
assert.ok(evidence.collectedAt, "collectedAt is required");
assert.ok(evidence.sink?.name, "sink.name is required");
assert.ok(evidence.sink?.type, "sink.type is required");
assert.ok(evidence.sink?.environment, "sink.environment is required");
assert.ok(Number.isInteger(evidence.sink?.retentionDays) && evidence.sink.retentionDays >= 0, "sink.retentionDays must be a non-negative integer");

for (const name of ["api", "siemWebhook", "windowsInstaller", "browserExtension", "nativeCompanion"]) {
  assert.ok(checkStatuses.has(evidence.sources?.[name]), `Unsupported source status for ${name}`);
}

assert.ok(Number.isInteger(evidence.samples?.eventsShipped) && evidence.samples.eventsShipped >= 0, "samples.eventsShipped must be a non-negative integer");
assert.ok(Number.isInteger(evidence.samples?.syntheticSecretEvents) && evidence.samples.syntheticSecretEvents >= 0, "samples.syntheticSecretEvents must be a non-negative integer");
assert.ok(Number.isInteger(evidence.samples?.syntheticTokenEvents) && evidence.samples.syntheticTokenEvents >= 0, "samples.syntheticTokenEvents must be a non-negative integer");
assert.ok(Number.isInteger(evidence.samples?.parserFailures) && evidence.samples.parserFailures >= 0, "samples.parserFailures must be a non-negative integer");

for (const name of ["recursiveSensitiveFields", "bearerTokens", "sentinelServiceTokens", "privateKeys", "passwordValues", "errorStacks", "ticketWorkNotes", "auditLedgerExports"]) {
  assert.ok(checkStatuses.has(evidence.redaction?.[name]), `Unsupported redaction status for ${name}`);
}

for (const name of ["schemaValidated", "receiverSearchCompleted", "alertingConfigured", "retentionPolicyVerified", "accessReviewCompleted"]) {
  assert.ok(checkStatuses.has(evidence.controls?.[name]), `Unsupported control status for ${name}`);
}

assert.equal(typeof evidence.findings?.secretValuesFound, "boolean", "findings.secretValuesFound must be boolean");
assert.equal(typeof evidence.findings?.tokensFound, "boolean", "findings.tokensFound must be boolean");
assert.equal(typeof evidence.findings?.privateKeysFound, "boolean", "findings.privateKeysFound must be boolean");
assert.equal(typeof evidence.findings?.plaintextPasswordsFound, "boolean", "findings.plaintextPasswordsFound must be boolean");
assert.ok(evidence.approvals?.securityReviewer, "approvals.securityReviewer is required");
assert.ok(evidence.approvals?.siemOwner, "approvals.siemOwner is required");
assert.ok(evidence.approvals?.operationsOwner, "approvals.operationsOwner is required");
assert.ok(evidence.approvals?.changeTicket, "approvals.changeTicket is required");

if (deployedStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed log redaction evidence cannot contain placeholders");
  assert.ok(isoTimestamp.test(evidence.collectedAt), "collectedAt must be an ISO timestamp");
  assert.ok(evidence.sink.retentionDays >= 30, "deployed log sink retention must be at least 30 days");
  for (const name of ["api", "siemWebhook"]) {
    assert.equal(evidence.sources[name], "passed", `${name} source must pass for deployed evidence`);
  }
  assert.ok(evidence.samples.eventsShipped >= 1, "deployed evidence must include shipped log events");
  assert.ok(evidence.samples.syntheticSecretEvents >= 1, "deployed evidence must include synthetic secret redaction events");
  assert.ok(evidence.samples.syntheticTokenEvents >= 1, "deployed evidence must include synthetic token redaction events");
  assert.equal(evidence.samples.parserFailures, 0, "deployed evidence cannot include parser failures");
  for (const name of ["recursiveSensitiveFields", "bearerTokens", "sentinelServiceTokens", "privateKeys", "passwordValues", "errorStacks", "ticketWorkNotes", "auditLedgerExports"]) {
    assert.equal(evidence.redaction[name], "passed", `${name} redaction must pass for deployed evidence`);
  }
  for (const name of ["schemaValidated", "receiverSearchCompleted", "alertingConfigured", "retentionPolicyVerified", "accessReviewCompleted"]) {
    assert.equal(evidence.controls[name], "passed", `${name} control must pass for deployed evidence`);
  }
  assert.equal(evidence.findings.secretValuesFound, false, "log evidence cannot contain secret values");
  assert.equal(evidence.findings.tokensFound, false, "log evidence cannot contain tokens");
  assert.equal(evidence.findings.privateKeysFound, false, "log evidence cannot contain private keys");
  assert.equal(evidence.findings.plaintextPasswordsFound, false, "log evidence cannot contain plaintext passwords");
}

console.log(`Log redaction evidence validated: ${evidencePath}`);
