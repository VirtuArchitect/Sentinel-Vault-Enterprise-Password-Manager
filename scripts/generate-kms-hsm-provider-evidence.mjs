import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const outputPath = args.get("--out") || "artifacts/security/kms-hsm-provider-evidence.json";
const preflightPath = args.get("--preflight") || "artifacts/security/kms-hsm-gateway-preflight.json";
const policyPath = args.get("--policy");
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const preflight = existsSync(preflightPath) ? readJson(preflightPath) : null;
const providerStatus = preflight?.status || {};
const checks = preflight?.checks || {};
const checkedAt = preflight?.checkedAt || new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const status = args.get("--status") || "planned";
const checkStatus = (argName, fallback) => {
  const value = args.get(argName) || fallback;
  const allowed = new Set(["planned", "passed", "failed", "not-applicable"]);
  if (!allowed.has(value)) {
    throw new Error(`${argName} must be planned, passed, failed, or not-applicable`);
  }
  return value;
};
const asBool = (value, fallback) => {
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  return fallback;
};
const statusFrom = (value) => value === true ? "passed" : value === false ? "failed" : "planned";
const policyMaterial = policyPath && existsSync(policyPath)
  ? readFileSync(policyPath)
  : Buffer.from(JSON.stringify({ provider: preflight?.provider, endpoint: preflight?.endpoint, keyId: preflight?.keyId, checks }, null, 2));

const evidence = {
  format: "sentinel-kms-hsm-provider-evidence-v1",
  status,
  provider: args.get("--provider") || preflight?.provider || "external-kms-or-hsm",
  providerName: args.get("--provider-name") || "replace-with-provider",
  environment: args.get("--environment") || "replace-with-environment",
  keyId: args.get("--key-id") || preflight?.keyId || providerStatus.keyId || "replace-with-key-id",
  keyVersion: args.get("--key-version") || providerStatus.keyVersion || "replace-with-vault-key-version",
  endpoint: args.get("--endpoint") || preflight?.endpoint || "replace-with-endpoint-or-empty",
  region: args.get("--region") || "replace-with-region",
  keyExportDisabled: asBool(args.get("--key-export-disabled"), providerStatus.keyExportDisabled === true || checks.keyExportDisabled === true),
  auditLoggingEnabled: asBool(args.get("--audit-logging-enabled"), providerStatus.auditLoggingEnabled === true || checks.auditLoggingEnabled === true),
  serviceIdentity: args.get("--service-identity") || "replace-with-service-identity",
  policyHash: args.get("--policy-hash") || (preflight || policyPath ? sha256(policyMaterial) : "replace-with-policy-hash"),
  rotation: {
    createdAt: args.get("--created-at") || checkedAt,
    activatedAt: args.get("--activated-at") || checkedAt,
    previousKeyId: args.get("--previous-key-id") || "replace-with-previous-key-id",
    previousKeyRetireAfter: args.get("--previous-key-retire-after") || "YYYY-MM-DD"
  },
  checks: {
    configValidation: checkStatus("--config-validation", statusFrom(checks.providerMatches && checks.keyIdMatches)),
    complianceEndpoint: checkStatus("--compliance-endpoint", statusFrom(checks.statusEndpointReachable && checks.signEndpointReachable && checks.signatureReturned)),
    auditLedgerExport: checkStatus("--audit-ledger-export", "planned"),
    encryptedBackupValidation: checkStatus("--encrypted-backup-validation", "planned"),
    restoreDryRun: checkStatus("--restore-dry-run", "planned")
  },
  approvals: {
    securityOwner: args.get("--security-owner") || "replace-with-owner",
    platformOwner: args.get("--platform-owner") || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || "replace-with-ticket"
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`KMS/HSM provider evidence written: ${outputPath}`);
