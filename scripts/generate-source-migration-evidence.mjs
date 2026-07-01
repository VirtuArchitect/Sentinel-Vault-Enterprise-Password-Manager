import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const outputPath = path.resolve(args.get("--out") || "artifacts/import/source-migration-evidence.json");
const status = args.get("--status") || "planned";
const sourceSystem = args.get("--source-system") || "replace-with-source-system";
const reviewedAt = status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const artifact = (flag, placeholder) => args.get(flag) || placeholder;
const statusOrPlanned = (flag) => args.get(flag) || (status === "planned" ? "planned" : "passed");
const boolOrPlanned = (flag) => args.get(flag) || (status === "planned" ? "planned" : "false");
const readJsonIfExists = (filePath) => existsSync(filePath) ? JSON.parse(readFileSync(filePath, "utf8")) : null;

const sourceAdapterEvidencePath = artifact("--source-adapter-evidence", "replace-with-source-adapter-evidence.json");
const adapterEvidence = readJsonIfExists(sourceAdapterEvidencePath);

const evidence = {
  format: "sentinel-source-migration-evidence-v1",
  status,
  environment: args.get("--environment") || "replace-with-environment",
  sourceSystem,
  reviewedAt,
  artifacts: {
    columnMapPath: artifact("--column-map", "replace-with-column-map.json"),
    sourceAdapterEvidencePath,
    normalizedImportPath: artifact("--normalized-import", adapterEvidence?.outputCsv || "replace-with-normalized-import.csv"),
    storageMigrationEvidencePath: artifact("--storage-migration-evidence", "replace-with-storage-migration-evidence.json"),
    tenantIsolationEvidencePath: artifact("--tenant-isolation-evidence", "replace-with-tenant-isolation-evidence.json")
  },
  checks: {
    allColumnsMappedOrIgnored: statusOrPlanned("--all-columns-mapped"),
    sourceEvidenceRedacted: statusOrPlanned("--source-evidence-redacted"),
    normalizedImportReviewed: statusOrPlanned("--normalized-import-reviewed"),
    storageMigrationValidated: statusOrPlanned("--storage-migration-validated"),
    tenantIsolationValidated: statusOrPlanned("--tenant-isolation-validated"),
    rollbackPlanReviewed: statusOrPlanned("--rollback-plan-reviewed")
  },
  summary: {
    sourceRowCount: Number(args.get("--source-row-count") || adapterEvidence?.rowCount || 0),
    convertedRowCount: Number(args.get("--converted-row-count") || adapterEvidence?.convertedCount || 0),
    ignoredColumnCount: Number(args.get("--ignored-column-count") || 0)
  },
  approvals: {
    migrationOwner: args.get("--migration-owner") || "replace-with-owner",
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    operationsOwner: args.get("--operations-owner") || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || "replace-with-ticket"
  },
  redaction: {
    containsPlaintextSecrets: boolOrPlanned("--contains-plaintext-secrets"),
    containsOtpValues: boolOrPlanned("--contains-otp-values"),
    containsCustomerOnlyFields: boolOrPlanned("--contains-customer-only-fields")
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));

console.log(JSON.stringify({
  format: "sentinel-source-migration-evidence-result-v1",
  outputPath,
  status: evidence.status,
  environment: evidence.environment,
  sourceSystem: evidence.sourceSystem,
  convertedRowCount: evidence.summary.convertedRowCount
}, null, 2));
