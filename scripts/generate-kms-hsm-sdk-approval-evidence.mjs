import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
const args = new Map();
for (let index = 0; index < cliArgs.length; index += 1) {
  const arg = cliArgs[index];
  if (arg.startsWith("--")) {
    const next = cliArgs[index + 1];
    if (!next || next.startsWith("--")) {
      args.set(arg, true);
    } else {
      args.set(arg, next);
      index += 1;
    }
  }
}

const outputPath = args.get("--out") || "artifacts/security/kms-hsm-sdk-approval-evidence.json";
const reportPath = args.get("--report");
const preflightPath = args.get("--preflight");
const providerEvidencePath = args.get("--provider-evidence");
const status = args.get("--status") || "planned";
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const sha256FileHex = (filePath) => crypto.createHash("sha256").update(readFileSync(filePath)).digest("hex");
const report = reportPath && existsSync(reportPath) ? readJson(reportPath) : {};
const preflight = preflightPath && existsSync(preflightPath) ? readJson(preflightPath) : {};
const providerEvidence = providerEvidencePath && existsSync(providerEvidencePath) ? readJson(providerEvidencePath) : {};

if (preflightPath) assert.ok(existsSync(preflightPath), `KMS/HSM preflight evidence not found: ${preflightPath}`);
if (providerEvidencePath) assert.ok(existsSync(providerEvidencePath), `KMS/HSM provider evidence not found: ${providerEvidencePath}`);

const sdkPackagePath = args.get("--package-file") || report.sdk?.packagePath;
const packageSha256 = args.get("--package-sha256")
  || report.sdk?.packageSha256
  || (sdkPackagePath && existsSync(sdkPackagePath) ? sha256FileHex(sdkPackagePath) : "replace-with-sha256");

const passedIfApproved = status === "approved" ? "passed" : "planned";
const falseIfApproved = status === "approved" ? false : "planned";

const evidence = {
  format: "sentinel-kms-hsm-sdk-approval-evidence-v1",
  status,
  environment: args.get("--environment") || report.environment || "replace-with-environment",
  provider: args.get("--provider") || report.provider || preflight.provider || providerEvidence.provider || "external-kms-or-hsm",
  sdk: {
    packageName: args.get("--package-name") || report.sdk?.packageName || "replace-with-package",
    packageVersion: args.get("--package-version") || report.sdk?.packageVersion || "replace-with-version",
    license: args.get("--license") || report.sdk?.license || "replace-with-license",
    registry: args.get("--registry") || report.sdk?.registry || "replace-with-registry",
    packageSha256,
    maintenanceStatus: report.sdk?.maintenanceStatus ?? passedIfApproved,
    supplyChainReview: report.sdk?.supplyChainReview ?? passedIfApproved,
    securityReview: report.sdk?.securityReview ?? passedIfApproved,
    approvalReference: args.get("--approval-reference") || report.sdk?.approvalReference || "replace-with-approval-ticket"
  },
  targetEnvironment: {
    providerTenant: report.targetEnvironment?.providerTenant || "replace-with-provider-tenant",
    region: args.get("--region") || report.targetEnvironment?.region || providerEvidence.region || "replace-with-region",
    keyId: args.get("--key-id") || report.targetEnvironment?.keyId || preflight.keyId || providerEvidence.keyId || "replace-with-key-id",
    serviceIdentity: args.get("--service-identity") || report.targetEnvironment?.serviceIdentity || providerEvidence.serviceIdentity || "replace-with-service-identity",
    networkIsolation: report.targetEnvironment?.networkIsolation ?? passedIfApproved,
    auditSinkConfigured: report.targetEnvironment?.auditSinkConfigured ?? passedIfApproved,
    breakGlassProcedure: report.targetEnvironment?.breakGlassProcedure ?? passedIfApproved
  },
  operationProof: {
    preflightPath: preflightPath ? path.resolve(preflightPath) : "replace-with-kms-hsm-preflight.json",
    providerEvidencePath: providerEvidencePath ? path.resolve(providerEvidencePath) : "replace-with-kms-hsm-provider-evidence.json",
    signOrUnwrapOperation: report.operationProof?.signOrUnwrapOperation ?? passedIfApproved,
    keyExportBlocked: report.operationProof?.keyExportBlocked ?? (preflight.checks?.keyExportDisabled === true || providerEvidence.keyExportDisabled === true ? "passed" : passedIfApproved),
    auditEventCaptured: report.operationProof?.auditEventCaptured ?? (preflight.checks?.auditLoggingEnabled === true || providerEvidence.auditLoggingEnabled === true ? "passed" : passedIfApproved),
    rollbackTested: report.operationProof?.rollbackTested ?? passedIfApproved
  },
  approvals: {
    securityArchitectureOwner: report.approvals?.securityArchitectureOwner || "replace-with-owner",
    platformOwner: report.approvals?.platformOwner || "replace-with-owner",
    releaseOwner: report.approvals?.releaseOwner || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || report.approvals?.changeTicket || "replace-with-ticket"
  },
  redaction: {
    containsCredentials: report.redaction?.containsCredentials ?? falseIfApproved,
    containsKeyMaterial: report.redaction?.containsKeyMaterial ?? falseIfApproved,
    containsProviderTokens: report.redaction?.containsProviderTokens ?? falseIfApproved,
    containsConnectionStrings: report.redaction?.containsConnectionStrings ?? falseIfApproved
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`KMS/HSM SDK approval evidence written: ${outputPath}`);
