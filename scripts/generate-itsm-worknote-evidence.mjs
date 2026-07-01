import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const requiredActions = ["access_requested", "access_approved", "access_denied", "access_revoked"];
const outputPath = path.resolve(args.get("--out") || "artifacts/integrations/itsm-worknote-evidence.json");
const status = args.get("--status") || "planned";
const reviewedAt = status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const reportPath = args.get("--report");
const report = reportPath && existsSync(reportPath) ? JSON.parse(readFileSync(reportPath, "utf8")) : null;
const ticketRef = args.get("--ticket-ref") || report?.ticketRef || "replace-with-ticket";
const statusOrPlanned = (flag) => args.get(flag) || (status === "planned" ? "planned" : "passed");
const boolOrPlanned = (flag) => args.get(flag) || (status === "planned" ? "planned" : "false");
const sha256Hex = (value) => crypto.createHash("sha256").update(String(value || ""), "utf8").digest("hex");

const reportNotes = Array.isArray(report?.workNotes) ? report.workNotes : [];
const workNotes = requiredActions.map((action) => {
  const sample = reportNotes.find((note) => note.action === action) || {};
  const bodySha256 = sample.bodySha256 || (sample.body ? sha256Hex(sample.body) : "replace-with-sha256");
  return {
    action,
    workNoteId: sample.workNoteId || sample.id || "replace-with-worknote-id",
    createdAt: sample.createdAt || (status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : reviewedAt),
    bodySha256,
    redacted: sample.redacted !== undefined ? String(sample.redacted) : (status === "planned" ? "planned" : "true"),
    ticketRef: sample.ticketRef || ticketRef
  };
});

const evidence = {
  format: "sentinel-itsm-worknote-evidence-v1",
  status,
  environment: args.get("--environment") || report?.environment || "replace-with-environment",
  system: args.get("--system") || report?.system || "replace-with-itsm-system",
  reviewedAt,
  ticketRef,
  workNotes,
  checks: {
    ticketLookupPassed: statusOrPlanned("--ticket-lookup-passed"),
    allowedStateConfirmed: statusOrPlanned("--allowed-state-confirmed"),
    changeWindowConfirmed: statusOrPlanned("--change-window-confirmed"),
    requestLifecycleCovered: statusOrPlanned("--request-lifecycle-covered"),
    workNotesRedacted: statusOrPlanned("--work-notes-redacted"),
    rollbackReviewed: statusOrPlanned("--rollback-reviewed")
  },
  redaction: {
    containsSecretValues: boolOrPlanned("--contains-secret-values"),
    containsSessionTokens: boolOrPlanned("--contains-session-tokens"),
    containsCustomerOnlyFields: boolOrPlanned("--contains-customer-only-fields")
  },
  approvals: {
    integrationOwner: args.get("--integration-owner") || "replace-with-owner",
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    operationsOwner: args.get("--operations-owner") || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || ticketRef
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));

console.log(JSON.stringify({
  format: "sentinel-itsm-worknote-evidence-result-v1",
  outputPath,
  status: evidence.status,
  environment: evidence.environment,
  workNoteCount: evidence.workNotes.length
}, null, 2));
