import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/postgres-ha-approval-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8").replace(/^\uFEFF/, ""));
const placeholder = /replace-with|YYYY-MM-DD/i;
const timestampOrPlaceholder = /^YYYY-MM-DDTHH:mm:ssZ$|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const allowedStatuses = new Set(["planned", "approved", "active"]);
const passStatuses = new Set(["approved", "passed", "complete", "completed", "enabled", "verified"]);
const failStatuses = new Set(["failed", "fail", "missing", "rejected", "not-approved"]);

assert.equal(evidence.format, "sentinel-postgres-ha-approval-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "status must be planned, approved, or active");
assert.ok(evidence.environment, "environment is required");
assert.match(evidence.reviewedAt || "", timestampOrPlaceholder, "reviewedAt must be an ISO timestamp or placeholder");

for (const field of ["packageName", "packageVersion", "license", "supplyChainReview", "securityReview", "approvalReference"]) {
  assert.ok(evidence.dependencyApproval?.[field], `dependencyApproval.${field} is required`);
}
for (const field of ["clusterName", "haMode", "networkIsolation", "tlsRequired", "leastPrivilegeRole", "backupPolicy", "restoreDrill", "monitoringAlerts"]) {
  assert.ok(evidence.targetEnvironment?.[field], `targetEnvironment.${field} is required`);
}
for (const field of ["migrationPlanPath", "storageMigrationEvidencePath", "rollbackPlan", "maintenanceWindow", "ownerApproval"]) {
  assert.ok(evidence.cutover?.[field], `cutover.${field} is required`);
}
for (const field of ["platformDataOwner", "securityReviewer", "operationsOwner"]) {
  assert.ok(evidence.approvals?.[field], `approvals.${field} is required`);
}
for (const field of ["containsCredentials", "containsConnectionStrings", "containsCustomerData"]) {
  assert.ok(evidence.redaction?.[field], `redaction.${field} is required`);
}

const allValues = [
  evidence.dependencyApproval.supplyChainReview,
  evidence.dependencyApproval.securityReview,
  evidence.targetEnvironment.networkIsolation,
  evidence.targetEnvironment.tlsRequired,
  evidence.targetEnvironment.leastPrivilegeRole,
  evidence.targetEnvironment.backupPolicy,
  evidence.targetEnvironment.restoreDrill,
  evidence.targetEnvironment.monitoringAlerts,
  evidence.cutover.rollbackPlan,
  evidence.cutover.ownerApproval
];

for (const value of allValues) {
  assert.ok(!failStatuses.has(String(value).toLowerCase()), `failing status is not allowed: ${value}`);
}

const hasPlaceholders = placeholder.test(JSON.stringify(evidence));
if (!hasPlaceholders) {
  assert.ok(["approved", "active"].includes(evidence.status), "completed Postgres HA evidence must be approved or active");
  for (const value of allValues) {
    assert.ok(passStatuses.has(String(value).toLowerCase()), `completed evidence requires passing status: ${value}`);
  }
  assert.equal(String(evidence.redaction.containsCredentials).toLowerCase(), "false", "completed evidence cannot include credentials");
  assert.equal(String(evidence.redaction.containsConnectionStrings).toLowerCase(), "false", "completed evidence cannot include connection strings");
  assert.equal(String(evidence.redaction.containsCustomerData).toLowerCase(), "false", "completed evidence cannot include customer data");
  if (evidence.cutover.migrationPlanPath) {
    assert.ok(existsSync(evidence.cutover.migrationPlanPath), "migration plan path must exist for completed evidence");
  }
  if (evidence.cutover.storageMigrationEvidencePath) {
    assert.ok(existsSync(evidence.cutover.storageMigrationEvidencePath), "storage migration evidence path must exist for completed evidence");
  }
}

console.log(`Postgres HA approval evidence validated: ${evidencePath}`);
