import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const outputPath = path.resolve(args.get("--out") || "artifacts/storage/postgres-ha-approval-evidence.json");
const status = args.get("--status") || "planned";
const reviewedAt = status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const statusOrPlanned = (flag) => args.get(flag) || (status === "planned" ? "planned" : "approved");
const boolOrPlanned = (flag) => args.get(flag) || (status === "planned" ? "planned" : "false");

const evidence = {
  format: "sentinel-postgres-ha-approval-evidence-v1",
  status,
  environment: args.get("--environment") || "replace-with-environment",
  reviewedAt,
  dependencyApproval: {
    packageName: args.get("--package-name") || "replace-with-postgres-client-package",
    packageVersion: args.get("--package-version") || "replace-with-version",
    license: args.get("--license") || "replace-with-license",
    supplyChainReview: statusOrPlanned("--supply-chain-review"),
    securityReview: statusOrPlanned("--security-review"),
    approvalReference: args.get("--approval-reference") || "replace-with-approval-ticket"
  },
  targetEnvironment: {
    clusterName: args.get("--cluster-name") || "replace-with-cluster-name",
    haMode: args.get("--ha-mode") || "replace-with-ha-mode",
    networkIsolation: statusOrPlanned("--network-isolation"),
    tlsRequired: statusOrPlanned("--tls-required"),
    leastPrivilegeRole: statusOrPlanned("--least-privilege-role"),
    backupPolicy: statusOrPlanned("--backup-policy"),
    restoreDrill: statusOrPlanned("--restore-drill"),
    monitoringAlerts: statusOrPlanned("--monitoring-alerts")
  },
  cutover: {
    migrationPlanPath: args.get("--migration-plan") || "replace-with-postgres-migration-plan.json",
    storageMigrationEvidencePath: args.get("--storage-migration-evidence") || "replace-with-storage-migration-evidence.json",
    rollbackPlan: statusOrPlanned("--rollback-plan"),
    maintenanceWindow: args.get("--maintenance-window") || "replace-with-window",
    ownerApproval: statusOrPlanned("--owner-approval")
  },
  approvals: {
    platformDataOwner: args.get("--platform-data-owner") || "replace-with-owner",
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    operationsOwner: args.get("--operations-owner") || "replace-with-owner"
  },
  redaction: {
    containsCredentials: boolOrPlanned("--contains-credentials"),
    containsConnectionStrings: boolOrPlanned("--contains-connection-strings"),
    containsCustomerData: boolOrPlanned("--contains-customer-data")
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));

console.log(JSON.stringify({
  format: "sentinel-postgres-ha-approval-evidence-result-v1",
  outputPath,
  status: evidence.status,
  environment: evidence.environment
}, null, 2));
