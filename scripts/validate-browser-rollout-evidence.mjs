import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/browser-extension-rollout-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
const allowedStatuses = new Set(["planned", "pilot", "production", "suspended"]);
const deployedStatuses = new Set(["pilot", "production"]);
const allowedHosts = new Set(["http://127.0.0.1:5173/*", "http://localhost:5173/*"]);
const blockedPermissions = new Set(["history", "bookmarks", "downloads"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const extensionIdPattern = /^[a-p]{32}$/;
const sha256Pattern = /^[a-f0-9]{64}$/i;

assert.equal(evidence.format, "sentinel-browser-extension-rollout-evidence-v1");
assert.ok(allowedStatuses.has(evidence.deploymentStatus), "Unsupported deploymentStatus");
assert.equal(evidence.extensionName, "Sentinel Vault Autofill");
assert.equal(evidence.package?.manifestVersion, 3, "Manifest V3 evidence is required");
assert.ok(evidence.package?.artifactPath, "package.artifactPath is required");
assert.ok(evidence.packageValidation?.reportPath, "packageValidation.reportPath is required");
assert.equal(evidence.packageValidation?.format, "sentinel-browser-extension-package-validation-v1", "packageValidation.format is unsupported");
assert.equal(typeof evidence.packageValidation?.validated, "boolean", "packageValidation.validated must be boolean");
assert.ok(Number.isInteger(evidence.packageValidation?.requiredFileCount) && evidence.packageValidation.requiredFileCount >= 0, "packageValidation.requiredFileCount must be a non-negative integer");
assert.ok(Number.isInteger(evidence.packageValidation?.hostPermissionCount) && evidence.packageValidation.hostPermissionCount >= 0, "packageValidation.hostPermissionCount must be a non-negative integer");
assert.ok(Number.isInteger(evidence.packageValidation?.permissionCount) && evidence.packageValidation.permissionCount >= 0, "packageValidation.permissionCount must be a non-negative integer");
if (evidence.packageValidation.packageSha256 && !placeholder.test(evidence.packageValidation.packageSha256)) {
  assert.ok(sha256Pattern.test(evidence.packageValidation.packageSha256), "packageValidation.packageSha256 must be a SHA-256 hash");
}
if (existsSync(evidence.packageValidation.reportPath)) {
  const validation = JSON.parse(readFileSync(evidence.packageValidation.reportPath, "utf8"));
  assert.equal(validation.format, "sentinel-browser-extension-package-validation-v1", "browser package validation report format is unsupported");
  assert.equal(validation.validated, evidence.packageValidation.validated, "packageValidation.validated does not match report");
  assert.equal(validation.packageSha256, evidence.packageValidation.packageSha256, "packageValidation.packageSha256 does not match report");
  assert.equal(validation.requiredFileCount, evidence.packageValidation.requiredFileCount, "packageValidation.requiredFileCount does not match report");
}
assert.ok(Array.isArray(evidence.runtimeAllowedHosts), "runtimeAllowedHosts must be an array");
assert.ok(Array.isArray(evidence.blockedPermissions), "blockedPermissions must be an array");

for (const host of evidence.runtimeAllowedHosts) {
  assert.ok(allowedHosts.has(host), `Unexpected runtime host permission: ${host}`);
}
for (const permission of evidence.blockedPermissions) {
  assert.ok(blockedPermissions.has(permission), `Unexpected blocked permission: ${permission}`);
}

const enabledBrowsers = ["chrome", "edge"].filter((browser) => evidence[browser]?.enabled);
assert.ok(enabledBrowsers.length > 0, "At least one browser rollout must be enabled");

for (const browser of enabledBrowsers) {
  const config = evidence[browser];
  assert.ok(config.extensionId, `${browser}.extensionId is required`);
  assert.ok(config.updateUrl, `${browser}.updateUrl is required`);
  assert.ok(config.policyPath, `${browser}.policyPath is required`);
  if (deployedStatuses.has(evidence.deploymentStatus)) {
    assert.ok(extensionIdPattern.test(config.extensionId), `${browser}.extensionId must be a production browser extension ID`);
  }
}

assert.ok(Array.isArray(evidence.rolloutRings), "rolloutRings must be an array");
assert.ok(evidence.rolloutRings.length >= 1, "At least one rollout ring is required");
for (const ring of evidence.rolloutRings) {
  assert.ok(ring.name, "rollout ring name is required");
  assert.ok(ring.scope, `rollout ring ${ring.name} scope is required`);
  assert.ok(["planned", "active", "passed", "failed", "rolled-back"].includes(ring.status), `Unsupported rollout ring status: ${ring.status}`);
}

assert.equal(evidence.storeReview?.manifestV3, true, "Manifest V3 review must pass");
assert.equal(evidence.storeReview?.leastPrivilegePermissions, true, "Least privilege permission review must pass");
assert.equal(evidence.storeReview?.noWildcardWebHosts, true, "Wildcard web hosts must be rejected");
assert.ok(evidence.rollback?.disableProcedure, "rollback.disableProcedure is required");
assert.ok(evidence.approvals?.securityReviewer, "security reviewer approval field is required");
assert.ok(evidence.approvals?.desktopEngineering, "desktop engineering approval field is required");

if (deployedStatuses.has(evidence.deploymentStatus)) {
  assert.ok(sha256Pattern.test(evidence.package.sha256), "package.sha256 must be a real SHA-256 hash for deployed rollouts");
  assert.equal(evidence.packageValidation.validated, true, "validated browser extension package report is required for deployed rollouts");
  assert.equal(evidence.packageValidation.packageSha256, evidence.package.sha256, "package validation hash must match rollout package hash");
  assert.ok(evidence.packageValidation.requiredFileCount >= 6, "package validation must cover required browser extension files");
  assert.equal(evidence.storeReview.privacyStatementApproved, true, "privacy statement approval is required for deployed rollouts");
  assert.equal(evidence.storeReview.screenshotsRedacted, true, "redacted screenshots are required for deployed rollouts");
  assert.equal(evidence.rollback.tested, true, "rollback must be tested for deployed rollouts");
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed rollout evidence cannot contain placeholders");
}

console.log(`Browser extension rollout evidence validated: ${evidencePath}`);
