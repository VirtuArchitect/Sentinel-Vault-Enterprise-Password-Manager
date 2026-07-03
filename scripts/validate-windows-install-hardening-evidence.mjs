import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/windows-install-hardening-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const deployedStatuses = new Set(["pilot", "production"]);
const allowedStorageProviders = new Set(["json", "sqlite", "postgres"]);
const allowedServiceSupervisors = new Set(["scheduled-task", "windows-service", "iis-node-proxy"]);
const allowedReviewValues = new Set(["passed", "failed", "planned", "not-applicable"]);
const allowedCheckValues = new Set(["passed", "failed", "not-run", "not-applicable"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoDate = /^\d{4}-\d{2}-\d{2}$/;

assert.equal(evidence.format, "sentinel-windows-install-hardening-evidence-v1");
assert.ok(allowedStatuses.has(evidence.deploymentStatus), "Unsupported deploymentStatus");
assert.ok(evidence.environment, "environment is required");
assert.ok(evidence.reviewDate, "reviewDate is required");
assert.ok(evidence.installHost, "installHost is required");
assert.ok(/^C:\\/i.test(evidence.installPath || ""), "installPath must be an absolute Windows path");
assert.ok(allowedStorageProviders.has(evidence.storageProvider), "Unsupported storageProvider");

assert.ok(evidence.nodeBinding?.host, "nodeBinding.host is required");
assert.ok(Number(evidence.nodeBinding?.port) > 0, "nodeBinding.port is required");
assert.equal(typeof evidence.nodeBinding.iisFrontend, "boolean", "nodeBinding.iisFrontend must be boolean");
assert.ok(evidence.nodeBinding.tlsTermination, "nodeBinding.tlsTermination is required");
assert.ok(evidence.targetPreflight?.reportPath, "targetPreflight.reportPath is required");
assert.equal(evidence.targetPreflight?.format, "sentinel-windows-target-preflight-v1", "targetPreflight.format is unsupported");
assert.ok(allowedReviewValues.has(evidence.targetPreflight?.result), "Unsupported targetPreflight.result");
assert.equal(typeof evidence.targetPreflight?.ready, "boolean", "targetPreflight.ready must be boolean");
assert.ok(Number.isInteger(evidence.targetPreflight?.failedCount) && evidence.targetPreflight.failedCount >= 0, "targetPreflight.failedCount must be a non-negative integer");
assert.ok(Number.isInteger(evidence.targetPreflight?.warningCount) && evidence.targetPreflight.warningCount >= 0, "targetPreflight.warningCount must be a non-negative integer");
assert.ok(evidence.targetPreflight?.checkedAt, "targetPreflight.checkedAt is required");

if (existsSync(evidence.targetPreflight.reportPath)) {
  const preflight = JSON.parse(readFileSync(evidence.targetPreflight.reportPath, "utf8"));
  assert.equal(preflight.format, "sentinel-windows-target-preflight-v1", "target preflight report format is unsupported");
  assert.equal(preflight.ready, evidence.targetPreflight.ready, "targetPreflight.ready does not match report");
  assert.equal(preflight.failedCount, evidence.targetPreflight.failedCount, "targetPreflight.failedCount does not match report");
  assert.equal(preflight.warningCount, evidence.targetPreflight.warningCount, "targetPreflight.warningCount does not match report");
}

assert.ok(allowedServiceSupervisors.has(evidence.serviceIdentity?.supervisor), "Unsupported service supervisor");
assert.ok(evidence.serviceIdentity?.runAs, "serviceIdentity.runAs is required");
assert.equal(typeof evidence.serviceIdentity.interactiveLogonAllowed, "boolean", "serviceIdentity.interactiveLogonAllowed must be boolean");
assert.ok(allowedReviewValues.has(evidence.serviceIdentity.leastPrivilegeReview), "Unsupported leastPrivilegeReview result");

for (const [name, result] of Object.entries(evidence.filesystemAcls || {})) {
  assert.ok(allowedReviewValues.has(result), `Unsupported filesystem ACL result for ${name}`);
}
for (const [name, result] of Object.entries(evidence.runtimeSecrets || {})) {
  assert.ok(allowedReviewValues.has(result), `Unsupported runtime secret result for ${name}`);
}
for (const [name, result] of Object.entries(evidence.installerChecks || {})) {
  assert.ok(allowedCheckValues.has(result), `Unsupported installer check result for ${name}`);
}

assert.ok(evidence.approvals?.windowsOwner, "windowsOwner approval is required");
assert.ok(evidence.approvals?.securityReviewer, "securityReviewer approval is required");
assert.ok(evidence.approvals?.operationsReviewer, "operationsReviewer approval is required");
assert.ok(evidence.approvals?.changeTicket, "changeTicket approval is required");

if (deployedStatuses.has(evidence.deploymentStatus)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed Windows install hardening evidence cannot contain placeholders");
  assert.ok(isoDate.test(evidence.reviewDate), "reviewDate must be YYYY-MM-DD for deployed evidence");
  assert.ok(isoDate.test(evidence.targetPreflight.checkedAt), "targetPreflight.checkedAt must be YYYY-MM-DD for deployed evidence");
  assert.equal(evidence.nodeBinding.host, "127.0.0.1", "Node should bind to localhost behind IIS or local access in deployed Windows evidence");
  assert.equal(evidence.targetPreflight.result, "passed", "targetPreflight.result must pass for deployed Windows install hardening evidence");
  assert.equal(evidence.targetPreflight.ready, true, "targetPreflight.ready must be true for deployed Windows install hardening evidence");
  assert.equal(evidence.targetPreflight.failedCount, 0, "targetPreflight.failedCount must be 0 for deployed Windows install hardening evidence");
  assert.equal(evidence.serviceIdentity.interactiveLogonAllowed, false, "service identity must not allow interactive logon");
  assert.equal(evidence.serviceIdentity.leastPrivilegeReview, "passed", "least privilege review must pass for deployed evidence");

  for (const [name, result] of Object.entries(evidence.filesystemAcls || {})) {
    assert.equal(result, "passed", `${name} must pass for deployed Windows install hardening evidence`);
  }
  for (const [name, result] of Object.entries(evidence.runtimeSecrets || {})) {
    assert.equal(result, "passed", `${name} must pass for deployed Windows install hardening evidence`);
  }

  assert.equal(evidence.installerChecks.cleanInstall, "passed", "cleanInstall must pass for deployed evidence");
  assert.equal(evidence.installerChecks.upgradeBackupCreated, "passed", "upgradeBackupCreated must pass for deployed evidence");
  assert.equal(evidence.installerChecks.rollbackRestoresPreviousVersion, "passed", "rollbackRestoresPreviousVersion must pass for deployed evidence");
  assert.equal(evidence.installerChecks.uninstallRemovesScheduledTask, "passed", "uninstallRemovesScheduledTask must pass for deployed evidence");
  assert.equal(evidence.installerChecks.healthCheckPassed, "passed", "healthCheckPassed must pass for deployed evidence");
  if (evidence.nodeBinding.iisFrontend) {
    assert.equal(evidence.installerChecks.iisReverseProxyValidated, "passed", "iisReverseProxyValidated must pass when IIS is enabled");
    assert.notEqual(evidence.nodeBinding.tlsTermination, "not-applicable", "TLS termination must be documented when IIS is enabled");
  }
}

console.log(`Windows install hardening evidence validated: ${evidencePath}`);
