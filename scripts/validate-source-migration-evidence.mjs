import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/source-migration-evidence.json";
const rootDir = path.resolve(import.meta.dirname, "..");
const evidence = JSON.parse(readFileSync(evidencePath, "utf8").replace(/^\uFEFF/, ""));
const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const deployedStatuses = new Set(["pilot", "production"]);
const passStatuses = new Set(["passed", "approved", "complete", "completed", "validated"]);
const failStatuses = new Set(["failed", "fail", "missing", "rejected"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const timestampOrPlaceholder = /^YYYY-MM-DDTHH:mm:ssZ$|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

const runValidator = (script, filePath) => execFileSync(process.execPath, [script, filePath], {
  cwd: rootDir,
  stdio: "pipe",
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));

assert.equal(evidence.format, "sentinel-source-migration-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "status must be planned, pilot, production, or retired");
assert.ok(evidence.environment, "environment is required");
assert.ok(evidence.sourceSystem, "sourceSystem is required");
assert.match(evidence.reviewedAt || "", timestampOrPlaceholder, "reviewedAt must be an ISO timestamp or placeholder");

for (const field of ["columnMapPath", "sourceAdapterEvidencePath", "normalizedImportPath", "storageMigrationEvidencePath", "tenantIsolationEvidencePath"]) {
  assert.ok(evidence.artifacts?.[field], `artifacts.${field} is required`);
}
for (const field of ["allColumnsMappedOrIgnored", "sourceEvidenceRedacted", "normalizedImportReviewed", "storageMigrationValidated", "tenantIsolationValidated", "rollbackPlanReviewed"]) {
  assert.ok(evidence.checks?.[field], `checks.${field} is required`);
  assert.ok(!failStatuses.has(String(evidence.checks[field]).toLowerCase()), `checks.${field} cannot be failing`);
}
for (const field of ["sourceRowCount", "convertedRowCount", "ignoredColumnCount"]) {
  assert.ok(Number.isInteger(evidence.summary?.[field]) && evidence.summary[field] >= 0, `summary.${field} must be a non-negative integer`);
}
for (const field of ["migrationOwner", "securityReviewer", "operationsOwner", "changeTicket"]) {
  assert.ok(evidence.approvals?.[field], `approvals.${field} is required`);
}
for (const field of ["containsPlaintextSecrets", "containsOtpValues", "containsCustomerOnlyFields"]) {
  assert.ok(evidence.redaction?.[field] !== undefined, `redaction.${field} is required`);
}

if (deployedStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed source migration evidence cannot contain placeholders");
  for (const [field, status] of Object.entries(evidence.checks)) {
    assert.ok(passStatuses.has(String(status).toLowerCase()), `${field} must pass for deployed evidence`);
  }
  assert.equal(String(evidence.redaction.containsPlaintextSecrets).toLowerCase(), "false", "deployed evidence cannot contain plaintext secrets");
  assert.equal(String(evidence.redaction.containsOtpValues).toLowerCase(), "false", "deployed evidence cannot contain OTP values");
  assert.equal(String(evidence.redaction.containsCustomerOnlyFields).toLowerCase(), "false", "deployed evidence cannot contain customer-only fields");

  const artifactPaths = Object.fromEntries(Object.entries(evidence.artifacts).map(([name, filePath]) => [name, path.resolve(filePath)]));
  for (const [name, filePath] of Object.entries(artifactPaths)) {
    assert.ok(existsSync(filePath), `${name} must exist for deployed evidence: ${filePath}`);
  }

  const columnMap = readJson(artifactPaths.columnMapPath);
  assert.equal(columnMap.format, "sentinel-source-export-column-map-v1");
  assert.equal(columnMap.sourceSystem, evidence.sourceSystem, "column map source system must match evidence");
  assert.equal(columnMap.redaction?.evidenceIncludesPasswordValues, false, "column map evidence cannot include password values");
  assert.equal(columnMap.redaction?.evidenceIncludesOtpValues, false, "column map evidence cannot include OTP values");
  for (const field of ["name", "username", "password"]) {
    assert.ok(columnMap.fields?.[field], `column map fields.${field} is required`);
  }

  const adapterEvidence = readJson(artifactPaths.sourceAdapterEvidencePath);
  assert.equal(adapterEvidence.format, "sentinel-source-export-adapter-evidence-v1");
  assert.equal(adapterEvidence.passwordValuesIncluded, false, "source adapter evidence cannot include password values");
  assert.equal(adapterEvidence.mappingSourceSystem || evidence.sourceSystem, evidence.sourceSystem, "source adapter mapping system must match evidence");
  assert.equal(path.resolve(adapterEvidence.outputCsv), artifactPaths.normalizedImportPath, "source adapter output CSV must match normalized import path");
  assert.equal(evidence.summary.sourceRowCount, adapterEvidence.rowCount, "source row count mismatch");
  assert.equal(evidence.summary.convertedRowCount, adapterEvidence.convertedCount, "converted row count mismatch");
  assert.ok(adapterEvidence.convertedCount > 0, "deployed migration evidence must include converted rows");

  runValidator("scripts/validate-storage-migration-evidence.mjs", artifactPaths.storageMigrationEvidencePath);
  runValidator("scripts/validate-tenant-isolation-evidence.mjs", artifactPaths.tenantIsolationEvidencePath);
}

console.log(`Source migration evidence validated: ${evidencePath}`);
