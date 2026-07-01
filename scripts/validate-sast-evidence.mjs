import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/sast-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "completed", "accepted-risk", "expired"]);
const strictStatuses = new Set(["completed", "accepted-risk"]);
const retestStatuses = new Set(["planned", "not-required", "in-progress", "passed", "accepted-risk"]);
const requiredSurfaces = [
  "web-console",
  "express-api",
  "windows-packaging",
  "browser-extension",
  "windows-companion",
  "scripts"
];
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const gitShaPattern = /^[a-f0-9]{7,40}$/i;

assert.equal(evidence.format, "sentinel-sast-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported SAST evidence status");
assert.ok(evidence.environment, "environment is required");
assert.ok(evidence.scan?.tool, "scan.tool is required");
assert.ok(evidence.scan?.toolVersion, "scan.toolVersion is required");
assert.ok(evidence.scan?.profile, "scan.profile is required");
assert.ok(evidence.scan?.startedAt, "scan.startedAt is required");
assert.ok(evidence.scan?.completedAt, "scan.completedAt is required");
assert.ok(evidence.scan?.reportPath, "scan.reportPath is required");
assert.ok(evidence.source?.commit, "source.commit is required");
assert.ok(evidence.source?.branch, "source.branch is required");
assert.equal(typeof evidence.source?.dirty, "boolean", "source.dirty must be boolean");

assert.ok(Array.isArray(evidence.coverage?.includedSurfaces), "coverage.includedSurfaces must be an array");
for (const surface of requiredSurfaces) {
  assert.ok(evidence.coverage.includedSurfaces.includes(surface), `coverage must include ${surface}`);
}
assert.ok(Array.isArray(evidence.coverage?.excludedPaths), "coverage.excludedPaths must be an array");
assert.ok(Array.isArray(evidence.coverage?.rulesets), "coverage.rulesets must be an array");
assert.ok(evidence.coverage.rulesets.length > 0, "coverage.rulesets must not be empty");

for (const severity of ["critical", "high", "medium", "low", "informational", "suppressed"]) {
  assert.ok(Number.isInteger(evidence.results?.[severity]) && evidence.results[severity] >= 0, `results.${severity} must be a non-negative integer`);
}

assert.ok(evidence.remediation?.trackingProject, "remediation.trackingProject is required");
assert.ok(evidence.remediation?.owner, "remediation.owner is required");
assert.ok(Number.isInteger(evidence.remediation?.criticalDueDays), "remediation.criticalDueDays is required");
assert.ok(Number.isInteger(evidence.remediation?.highDueDays), "remediation.highDueDays is required");
assert.ok(Number.isInteger(evidence.remediation?.mediumDueDays), "remediation.mediumDueDays is required");
assert.ok(retestStatuses.has(evidence.remediation?.retestStatus), "Unsupported remediation.retestStatus");

assert.equal(typeof evidence.redaction?.secretValuesFound, "boolean", "redaction.secretValuesFound must be boolean");
assert.equal(typeof evidence.redaction?.tokensFound, "boolean", "redaction.tokensFound must be boolean");
assert.equal(typeof evidence.redaction?.privateKeysFound, "boolean", "redaction.privateKeysFound must be boolean");
assert.ok(evidence.approvals?.securityReviewer, "approvals.securityReviewer is required");
assert.ok(evidence.approvals?.engineeringOwner, "approvals.engineeringOwner is required");
assert.ok(evidence.approvals?.releaseOwner, "approvals.releaseOwner is required");

if (strictStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "strict SAST evidence cannot contain placeholders");
  assert.ok(isoTimestamp.test(evidence.scan.startedAt), "scan.startedAt must be an ISO timestamp");
  assert.ok(isoTimestamp.test(evidence.scan.completedAt), "scan.completedAt must be an ISO timestamp");
  assert.ok(Date.parse(evidence.scan.completedAt) > Date.parse(evidence.scan.startedAt), "scan.completedAt must be after scan.startedAt");
  assert.ok(gitShaPattern.test(evidence.source.commit), "source.commit must be a Git SHA");
  assert.equal(evidence.source.dirty, false, "SAST evidence must be tied to a clean source tree");
  assert.ok(["passed", "not-required", "accepted-risk"].includes(evidence.remediation.retestStatus), "strict SAST evidence requires completed retest disposition");
  if (evidence.status === "completed") {
    assert.equal(evidence.results.critical, 0, "completed SAST evidence cannot have open critical findings");
    assert.equal(evidence.results.high, 0, "completed SAST evidence cannot have open high findings");
  }
  assert.equal(evidence.redaction.secretValuesFound, false, "SAST evidence cannot contain secret values");
  assert.equal(evidence.redaction.tokensFound, false, "SAST evidence cannot contain tokens");
  assert.equal(evidence.redaction.privateKeysFound, false, "SAST evidence cannot contain private keys");
}

console.log(`SAST evidence validated: ${evidencePath}`);
