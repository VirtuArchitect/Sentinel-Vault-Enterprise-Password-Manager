import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/tenant-isolation-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const deployedStatuses = new Set(["pilot", "production"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const frequencies = new Set(["per-release", "monthly", "quarterly"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

assert.equal(evidence.format, "sentinel-tenant-isolation-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported tenant isolation evidence status");
assert.ok(evidence.environment, "environment is required");
assert.ok(evidence.testedAt, "testedAt is required");

for (const name of ["tenantCount", "vaultCount", "userCount", "sampledTenantPairs"]) {
  assert.ok(Number.isInteger(evidence.scope?.[name]) && evidence.scope[name] >= 0, `scope.${name} must be a non-negative integer`);
}
assert.ok(evidence.scope.sampledTenantPairs <= evidence.scope.tenantCount * Math.max(evidence.scope.tenantCount - 1, 0), "sampledTenantPairs exceeds possible directed tenant pairs");
assert.ok(frequencies.has(evidence.scope?.testCadence), "Unsupported tenant isolation test cadence");
assert.ok(evidence.testReport && typeof evidence.testReport === "object", "testReport is required");
assert.ok(evidence.testReport.reportPath, "testReport.reportPath is required");
assert.ok(evidence.testReport.scope && typeof evidence.testReport.scope === "object", "testReport.scope is required");
assert.ok(evidence.testReport.negativeTests && typeof evidence.testReport.negativeTests === "object", "testReport.negativeTests are required");

for (const name of ["serviceLayerObjectChecks", "routeRbacChecks", "consolePayloadFiltering", "offlineCacheScoping", "adminMetadataExportRestricted", "jitGrantTenantBoundary"]) {
  assert.ok(checkStatuses.has(evidence.controls?.[name]), `Unsupported control status for ${name}`);
}

for (const name of ["reveal", "update", "delete", "restore", "versionRestore", "rotate", "share", "approveAccess", "denyAccess", "revokeAccess", "consoleVaultEnumeration", "offlineCacheEnumeration"]) {
  assert.ok(checkStatuses.has(evidence.negativeTests?.[name]), `Unsupported negative test status for ${name}`);
}

assert.equal(typeof evidence.redaction?.secretValuesFound, "boolean", "redaction.secretValuesFound must be boolean");
assert.equal(typeof evidence.redaction?.sessionTokensFound, "boolean", "redaction.sessionTokensFound must be boolean");
assert.ok(checkStatuses.has(evidence.redaction?.tenantIdentifiersScoped), "Unsupported tenantIdentifiersScoped status");
assert.ok(evidence.approvals?.securityReviewer, "approvals.securityReviewer is required");
assert.ok(evidence.approvals?.operationsOwner, "approvals.operationsOwner is required");
assert.ok(evidence.approvals?.changeTicket, "approvals.changeTicket is required");

if (deployedStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed tenant isolation evidence cannot contain placeholders");
  assert.ok(isoTimestamp.test(evidence.testedAt), "testedAt must be an ISO timestamp");
  assert.equal(evidence.testReport.validated, true, "deployed tenant isolation evidence requires a validated test report");
  assert.equal(evidence.testReport.testedAt, evidence.testedAt, "testReport.testedAt must match evidence testedAt");
  assert.ok(evidence.scope.tenantCount >= 2, "deployed evidence must include at least two tenants");
  assert.ok(evidence.scope.vaultCount >= 2, "deployed evidence must include at least two vaults");
  assert.ok(evidence.scope.userCount >= 2, "deployed evidence must include at least two users");
  assert.ok(evidence.scope.sampledTenantPairs >= 1, "deployed evidence must sample at least one cross-tenant pair");
  for (const name of ["tenantCount", "vaultCount", "userCount", "sampledTenantPairs", "testCadence"]) {
    assert.equal(evidence.testReport.scope[name], evidence.scope[name], `testReport.scope.${name} must match evidence scope`);
  }
  for (const name of ["serviceLayerObjectChecks", "routeRbacChecks", "consolePayloadFiltering", "offlineCacheScoping", "adminMetadataExportRestricted", "jitGrantTenantBoundary"]) {
    assert.equal(evidence.controls[name], "passed", `${name} must pass for deployed evidence`);
  }
  for (const name of ["reveal", "update", "delete", "restore", "versionRestore", "rotate", "share", "approveAccess", "denyAccess", "revokeAccess", "consoleVaultEnumeration", "offlineCacheEnumeration"]) {
    assert.equal(evidence.negativeTests[name], "passed", `${name} negative test must pass for deployed evidence`);
    assert.equal(evidence.testReport.negativeTests[name], "passed", `testReport.negativeTests.${name} must pass for deployed evidence`);
  }
  assert.equal(evidence.redaction.secretValuesFound, false, "tenant isolation evidence cannot contain secret values");
  assert.equal(evidence.redaction.sessionTokensFound, false, "tenant isolation evidence cannot contain session tokens");
  assert.equal(evidence.redaction.tenantIdentifiersScoped, "passed", "tenant identifiers must be redacted or deployment-scoped");
}

console.log(`Tenant isolation evidence validated: ${evidencePath}`);
