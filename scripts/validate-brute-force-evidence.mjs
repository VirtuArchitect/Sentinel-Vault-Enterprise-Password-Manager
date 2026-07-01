import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/brute-force-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const deployedStatuses = new Set(["pilot", "production"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

assert.equal(evidence.format, "sentinel-brute-force-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported brute-force evidence status");
assert.ok(evidence.environment, "environment is required");
assert.ok(evidence.testedAt, "testedAt is required");

assert.ok(Number.isInteger(evidence.appControls?.failedLoginLimit) && evidence.appControls.failedLoginLimit >= 1 && evidence.appControls.failedLoginLimit <= 25, "appControls.failedLoginLimit must be 1-25");
assert.ok(Number.isInteger(evidence.appControls?.lockoutMinutes) && evidence.appControls.lockoutMinutes >= 1 && evidence.appControls.lockoutMinutes <= 1440, "appControls.lockoutMinutes must be 1-1440");
for (const name of ["temporaryAccountLockout", "sessionInvalidationAfterLogout", "mfaClaimRequired", "identityProviderPreflight"]) {
  assert.ok(checkStatuses.has(evidence.appControls?.[name]), `Unsupported app control status for ${name}`);
}

assert.ok(evidence.networkControls?.edgeName, "networkControls.edgeName is required");
for (const name of ["sourceIpPreserved", "trustedProxyConfigured", "perIpRateLimit", "distributedAttackDetection", "geoOrAsnPolicy", "wafOrReverseProxyLogging"]) {
  assert.ok(checkStatuses.has(evidence.networkControls?.[name]), `Unsupported network control status for ${name}`);
}

for (const name of ["singleAccountLockout", "singleIpSpray", "distributedSpray", "validUserAfterLockout", "mfaRequiredAfterNewDevice"]) {
  assert.ok(checkStatuses.has(evidence.drills?.[name]), `Unsupported drill status for ${name}`);
}
assert.ok(Number.isInteger(evidence.samples?.failedAttempts) && evidence.samples.failedAttempts >= 0, "samples.failedAttempts must be a non-negative integer");
assert.ok(Number.isInteger(evidence.samples?.distinctSourceIps) && evidence.samples.distinctSourceIps >= 0, "samples.distinctSourceIps must be a non-negative integer");
assert.ok(Number.isInteger(evidence.samples?.lockedAccounts) && evidence.samples.lockedAccounts >= 0, "samples.lockedAccounts must be a non-negative integer");
assert.ok(Number.isInteger(evidence.samples?.alertsGenerated) && evidence.samples.alertsGenerated >= 0, "samples.alertsGenerated must be a non-negative integer");

for (const name of ["siemAlertCreated", "ticketOrIncidentCreated", "dashboardReviewed", "falsePositiveDisposition"]) {
  assert.ok(checkStatuses.has(evidence.monitoring?.[name]), `Unsupported monitoring status for ${name}`);
}

assert.equal(typeof evidence.redaction?.passwordsFound, "boolean", "redaction.passwordsFound must be boolean");
assert.equal(typeof evidence.redaction?.tokensFound, "boolean", "redaction.tokensFound must be boolean");
assert.ok(checkStatuses.has(evidence.redaction?.sourceIpsScopedOrHashed), "Unsupported sourceIpsScopedOrHashed status");
assert.ok(evidence.approvals?.identityOwner, "approvals.identityOwner is required");
assert.ok(evidence.approvals?.securityReviewer, "approvals.securityReviewer is required");
assert.ok(evidence.approvals?.operationsOwner, "approvals.operationsOwner is required");
assert.ok(evidence.approvals?.changeTicket, "approvals.changeTicket is required");

if (deployedStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed brute-force evidence cannot contain placeholders");
  assert.ok(isoTimestamp.test(evidence.testedAt), "testedAt must be an ISO timestamp");
  for (const name of ["temporaryAccountLockout", "sessionInvalidationAfterLogout", "mfaClaimRequired", "identityProviderPreflight"]) {
    assert.equal(evidence.appControls[name], "passed", `${name} must pass for deployed evidence`);
  }
  for (const name of ["sourceIpPreserved", "trustedProxyConfigured", "perIpRateLimit", "distributedAttackDetection", "wafOrReverseProxyLogging"]) {
    assert.equal(evidence.networkControls[name], "passed", `${name} must pass for deployed evidence`);
  }
  for (const name of ["singleAccountLockout", "singleIpSpray", "distributedSpray", "validUserAfterLockout"]) {
    assert.equal(evidence.drills[name], "passed", `${name} drill must pass for deployed evidence`);
  }
  assert.ok(evidence.samples.failedAttempts >= evidence.appControls.failedLoginLimit, "deployed evidence must include enough failed attempts to prove lockout");
  assert.ok(evidence.samples.distinctSourceIps >= 1, "deployed evidence must include at least one source IP or scoped source bucket");
  assert.ok(evidence.samples.lockedAccounts >= 1, "deployed evidence must include at least one locked account");
  assert.ok(evidence.samples.alertsGenerated >= 1, "deployed evidence must include at least one generated alert");
  for (const name of ["siemAlertCreated", "ticketOrIncidentCreated", "dashboardReviewed", "falsePositiveDisposition"]) {
    assert.equal(evidence.monitoring[name], "passed", `${name} monitoring control must pass for deployed evidence`);
  }
  assert.equal(evidence.redaction.passwordsFound, false, "brute-force evidence cannot contain passwords");
  assert.equal(evidence.redaction.tokensFound, false, "brute-force evidence cannot contain tokens");
  assert.equal(evidence.redaction.sourceIpsScopedOrHashed, "passed", "source IPs must be scoped or hashed for deployed evidence");
}

console.log(`Brute-force evidence validated: ${evidencePath}`);
