import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/browser-extension-identity-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
const allowedStatuses = new Set(["planned", "pilot", "production", "suspended"]);
const deployedStatuses = new Set(["pilot", "production"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const sha256Pattern = /^[a-f0-9]{64}$/i;
const extensionIdPattern = /^[a-p]{32}$/;
const passValues = new Set(["passed", "approved", true]);
const plannedValues = new Set(["planned", "pending", "not-applicable", false]);
const assertPassed = (value, message) => assert.ok(passValues.has(value), message);
const assertFalse = (value, message) => assert.equal(value, false, message);

assert.equal(evidence.format, "sentinel-browser-extension-identity-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported browser extension identity status");
assert.ok(evidence.environment, "environment is required");
assert.equal(evidence.extensionName, "Sentinel Vault Autofill");
assert.ok(evidence.packageSha256, "packageSha256 is required");

const enabledBrowsers = ["chrome", "edge"].filter((browser) => evidence[browser]?.enabled);
assert.ok(enabledBrowsers.length > 0, "At least one browser identity must be enabled");

for (const browser of enabledBrowsers) {
  const item = evidence[browser];
  assert.ok(item.extensionId, `${browser}.extensionId is required`);
  assert.ok(item.channel, `${browser}.channel is required`);
  assert.ok(item.publisher, `${browser}.publisher is required`);
  assert.ok(passValues.has(item.reviewStatus) || plannedValues.has(item.reviewStatus), `${browser}.reviewStatus is invalid`);
  assert.ok(passValues.has(item.policyAssignment) || plannedValues.has(item.policyAssignment), `${browser}.policyAssignment is invalid`);
}

for (const [name, value] of Object.entries(evidence.controls || {})) {
  assert.ok(passValues.has(value) || plannedValues.has(value), `controls.${name} is invalid`);
}

assert.ok(evidence.approvals?.endpointPlatformOwner, "approvals.endpointPlatformOwner is required");
assert.ok(evidence.approvals?.securityReviewer, "approvals.securityReviewer is required");
assert.ok(evidence.approvals?.businessOwner, "approvals.businessOwner is required");
assert.ok(evidence.approvals?.changeTicket, "approvals.changeTicket is required");

if (deployedStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed browser extension identity evidence cannot contain placeholders");
  assert.ok(sha256Pattern.test(evidence.packageSha256), "packageSha256 must be a SHA-256 hex digest");
  for (const browser of enabledBrowsers) {
    assert.ok(extensionIdPattern.test(evidence[browser].extensionId), `${browser}.extensionId must be a production browser extension ID`);
    assertPassed(evidence[browser].reviewStatus, `${browser}.reviewStatus must be passed`);
    assertPassed(evidence[browser].policyAssignment, `${browser}.policyAssignment must be passed`);
  }
  for (const [name, value] of Object.entries(evidence.controls || {})) {
    assertPassed(value, `controls.${name} must be passed`);
  }
  assertFalse(evidence.redaction.containsCredentials, "deployed evidence cannot contain credentials");
  assertFalse(evidence.redaction.containsInternalHostnames, "deployed evidence cannot contain internal hostnames");
  assertFalse(evidence.redaction.containsCustomerData, "deployed evidence cannot contain customer data");
}

console.log(`Browser extension identity evidence validated: ${evidencePath}`);
