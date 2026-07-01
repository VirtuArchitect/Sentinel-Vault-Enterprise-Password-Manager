import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/devops-token-response-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const deployedStatuses = new Set(["pilot", "production"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const sha256Base64Url = /^[A-Za-z0-9_-]{43}$/;

assert.equal(evidence.format, "sentinel-devops-token-response-preflight-v1");
assert.ok(allowedStatuses.has(evidence.status || "planned"), "Unsupported DevOps token response evidence status");
assert.ok(evidence.checkedAt, "checkedAt is required");
assert.ok(evidence.target?.endpointHost, "target.endpointHost is required");
assert.ok(evidence.target?.secretId, "target.secretId is required");
assert.ok(evidence.tokenFingerprints?.revokedTokenSha256, "revoked token fingerprint is required");
assert.ok(evidence.tokenFingerprints?.replacementTokenSha256, "replacement token fingerprint is required");

for (const name of ["revokedTokenRejected", "replacementTokenAccepted", "replacementScopeEnforced", "redactedOutput"]) {
  assert.equal(typeof evidence.checks?.[name], "boolean", `checks.${name} must be boolean`);
}

assert.ok(Number.isInteger(evidence.results?.revokedTokenStatus), "results.revokedTokenStatus is required");
assert.ok(Number.isInteger(evidence.results?.replacementTokenStatus), "results.replacementTokenStatus is required");
assert.ok(evidence.results.blockedScopeStatus === null || Number.isInteger(evidence.results.blockedScopeStatus), "results.blockedScopeStatus must be null or integer");
assert.ok(evidence.results.replacementReturnedValueSha256 === null || sha256Base64Url.test(evidence.results.replacementReturnedValueSha256), "replacement returned value must be represented only by a SHA-256 base64url hash");

if (deployedStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed DevOps token response evidence cannot contain placeholders");
  assert.ok(isoTimestamp.test(evidence.checkedAt), "checkedAt must be an ISO timestamp");
  assert.ok(evidence.environment, "environment is required for deployed evidence");
  assert.ok(evidence.owner, "owner is required for deployed evidence");
  assert.ok(sha256Base64Url.test(evidence.tokenFingerprints.revokedTokenSha256), "revoked token fingerprint must be SHA-256 base64url");
  assert.ok(sha256Base64Url.test(evidence.tokenFingerprints.replacementTokenSha256), "replacement token fingerprint must be SHA-256 base64url");
  assert.notEqual(evidence.tokenFingerprints.revokedTokenSha256, evidence.tokenFingerprints.replacementTokenSha256, "revoked and replacement token fingerprints must differ");
  assert.equal(evidence.checks.revokedTokenRejected, true, "revoked token must be rejected");
  assert.equal(evidence.checks.replacementTokenAccepted, true, "replacement token must be accepted");
  assert.equal(evidence.checks.replacementScopeEnforced, true, "replacement token scope must be enforced");
  assert.equal(evidence.checks.redactedOutput, true, "DevOps token response evidence output must be redacted");
  assert.ok([401, 403].includes(evidence.results.revokedTokenStatus), "revoked token status must be 401 or 403");
  assert.ok(evidence.results.replacementTokenStatus >= 200 && evidence.results.replacementTokenStatus < 300, "replacement token status must be 2xx");
  if (evidence.target.blockedSecretId) {
    assert.ok([401, 403, 404].includes(evidence.results.blockedScopeStatus), "blocked scope status must be 401, 403, or 404");
  }
  assert.ok(evidence.approvals?.securityReviewer, "approvals.securityReviewer is required for deployed evidence");
  assert.ok(evidence.approvals?.devopsOwner, "approvals.devopsOwner is required for deployed evidence");
  assert.ok(evidence.approvals?.operationsOwner, "approvals.operationsOwner is required for deployed evidence");
  assert.ok(evidence.approvals?.incidentOrChangeTicket, "approvals.incidentOrChangeTicket is required for deployed evidence");
}

console.log(`DevOps token response evidence validated: ${evidencePath}`);
