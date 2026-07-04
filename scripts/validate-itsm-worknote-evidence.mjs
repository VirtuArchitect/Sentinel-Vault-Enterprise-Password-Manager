import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/itsm-worknote-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8").replace(/^\uFEFF/, ""));
const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const deployedStatuses = new Set(["pilot", "production"]);
const requiredActions = ["access_requested", "access_approved", "access_denied", "access_revoked"];
const passStatuses = new Set(["passed", "approved", "complete", "completed", "validated"]);
const failStatuses = new Set(["failed", "fail", "missing", "rejected"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const timestampOrPlaceholder = /^YYYY-MM-DDTHH:mm:ssZ$|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const sha256OrPlaceholder = /^replace-with-sha256$|^[a-f0-9]{64}$/;

assert.equal(evidence.format, "sentinel-itsm-worknote-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "status must be planned, pilot, production, or retired");
assert.ok(evidence.environment, "environment is required");
assert.ok(evidence.system, "system is required");
assert.ok(evidence.ticketRef, "ticketRef is required");
assert.match(evidence.reviewedAt || "", timestampOrPlaceholder, "reviewedAt must be an ISO timestamp or placeholder");
assert.ok(evidence.workNoteReport && typeof evidence.workNoteReport === "object", "workNoteReport is required");
assert.ok(evidence.workNoteReport.reportPath, "workNoteReport.reportPath is required");
assert.ok(Array.isArray(evidence.workNoteReport.requiredActions), "workNoteReport.requiredActions must be an array");
assert.ok(evidence.workNoteReport.bodySha256ByAction && typeof evidence.workNoteReport.bodySha256ByAction === "object", "workNoteReport.bodySha256ByAction is required");
assert.ok(Array.isArray(evidence.workNotes), "workNotes must be an array");

for (const note of evidence.workNotes) {
  assert.ok(requiredActions.includes(note.action), `unsupported work note action: ${note.action}`);
  assert.ok(note.workNoteId, "workNoteId is required");
  assert.ok(note.ticketRef, "work note ticketRef is required");
  assert.match(note.createdAt || "", timestampOrPlaceholder, "work note createdAt must be an ISO timestamp or placeholder");
  assert.match(note.bodySha256 || "", sha256OrPlaceholder, "work note bodySha256 must be a SHA-256 hex digest or placeholder");
  assert.ok(note.redacted !== undefined, "work note redacted status is required");
}
for (const field of ["ticketLookupPassed", "allowedStateConfirmed", "changeWindowConfirmed", "requestLifecycleCovered", "workNotesRedacted", "rollbackReviewed"]) {
  assert.ok(evidence.checks?.[field], `checks.${field} is required`);
  assert.ok(!failStatuses.has(String(evidence.checks[field]).toLowerCase()), `checks.${field} cannot be failing`);
}
for (const field of ["containsSecretValues", "containsSessionTokens", "containsCustomerOnlyFields"]) {
  assert.ok(evidence.redaction?.[field] !== undefined, `redaction.${field} is required`);
}
for (const field of ["integrationOwner", "securityReviewer", "operationsOwner", "changeTicket"]) {
  assert.ok(evidence.approvals?.[field], `approvals.${field} is required`);
}

if (deployedStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed ITSM work-note evidence cannot contain placeholders");
  assert.equal(evidence.workNoteReport.validated, true, "deployed ITSM work-note evidence requires a validated work-note report");
  assert.equal(evidence.workNoteReport.ticketRef, evidence.ticketRef, "workNoteReport.ticketRef must match evidence ticketRef");
  assert.ok(evidence.workNoteReport.actionCount >= requiredActions.length, "workNoteReport.actionCount must cover required lifecycle actions");
  for (const action of requiredActions) {
    assert.ok(evidence.workNotes.some((note) => note.action === action), `deployed evidence must include ${action}`);
    assert.ok(evidence.workNoteReport.requiredActions.includes(action), `workNoteReport.requiredActions must include ${action}`);
  }
  for (const [field, status] of Object.entries(evidence.checks)) {
    assert.ok(passStatuses.has(String(status).toLowerCase()), `${field} must pass for deployed evidence`);
  }
  for (const note of evidence.workNotes) {
    assert.equal(note.ticketRef, evidence.ticketRef, "work note ticketRef must match evidence ticketRef");
    assert.ok(timestampOrPlaceholder.test(note.createdAt) && !placeholder.test(note.createdAt), "deployed work note createdAt must be an ISO timestamp");
    assert.match(note.bodySha256, /^[a-f0-9]{64}$/, "deployed work note bodySha256 must be a SHA-256 hex digest");
    assert.equal(evidence.workNoteReport.bodySha256ByAction[note.action], note.bodySha256, `${note.action} hash must match workNoteReport`);
    assert.equal(String(note.redacted).toLowerCase(), "true", "deployed work notes must be redacted");
  }
  assert.equal(String(evidence.redaction.containsSecretValues).toLowerCase(), "false", "deployed evidence cannot contain secret values");
  assert.equal(String(evidence.redaction.containsSessionTokens).toLowerCase(), "false", "deployed evidence cannot contain session tokens");
  assert.equal(String(evidence.redaction.containsCustomerOnlyFields).toLowerCase(), "false", "deployed evidence cannot contain customer-only fields");
}

console.log(`ITSM work-note evidence validated: ${evidencePath}`);
