import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const allowedStorageProviders = new Set(["json", "sqlite", "postgres"]);
const allowedResults = new Set(["passed", "failed", "planned", "not-applicable"]);
const allowedCheckResults = new Set(["passed", "failed", "not-run", "not-applicable"]);

const outputPath = args.get("--out") || "artifacts/windows/windows-install-hardening-evidence.json";
const deploymentStatus = args.get("--status") || "planned";
const storageProvider = args.get("--storage-provider") || "sqlite";
const installPath = args.get("--install-path") || "C:\\Program Files\\Sentinel Vault";
const sentinelEnvPath = args.get("--sentinel-env") || path.join(installPath, "sentinel.env");
const dataDir = args.get("--data-dir") || path.join(installPath, "data");
const logsDir = args.get("--logs-dir") || path.join(installPath, "logs");
const rollbackDir = args.get("--rollback-dir") || "C:\\Program Files\\Sentinel Vault Rollbacks";
const iisFrontend = args.get("--iis-frontend") === "true";
const targetPreflightPath = args.get("--target-preflight-report") || "";

assert.ok(allowedStatuses.has(deploymentStatus), "status must be planned, pilot, production, or retired");
assert.ok(allowedStorageProviders.has(storageProvider), "storage-provider must be json, sqlite, or postgres");

const today = () => new Date().toISOString().slice(0, 10);
const boolResult = (value) => (value ? "passed" : "failed");
const argResult = (name, fallback, allowed = allowedResults) => {
  const value = args.get(name) || fallback;
  assert.ok(allowed.has(value), `${name} must be one of ${[...allowed].join(", ")}`);
  return value;
};

const readEnv = (filePath) => {
  if (!existsSync(filePath)) return {};
  return Object.fromEntries(readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && line.includes("="))
    .map((line) => {
      const separator = line.indexOf("=");
      return [line.slice(0, separator), line.slice(separator + 1)];
    }));
};

const walkFiles = (dir, limit = 200) => {
  if (!existsSync(dir)) return [];
  const files = [];
  const visit = (current) => {
    if (files.length >= limit) return;
    const stats = statSync(current);
    if (stats.isFile()) {
      files.push(current);
      return;
    }
    if (!stats.isDirectory()) return;
    for (const entry of readdirSync(current)) visit(path.join(current, entry));
  };
  visit(dir);
  return files;
};

const containsPlaintextSecretMarker = (dir) => {
  const marker = /(VAULT_ROOT_KEY|Passw0rd!|password\s*=|api[_-]?key\s*=|bearer\s+[A-Za-z0-9._-]+)/i;
  return walkFiles(dir).some((filePath) => {
    const stats = statSync(filePath);
    if (stats.size > 1024 * 1024) return false;
    return marker.test(readFileSync(filePath, "utf8"));
  });
};

const env = readEnv(sentinelEnvPath);
const targetPreflight = targetPreflightPath && existsSync(targetPreflightPath)
  ? JSON.parse(readFileSync(targetPreflightPath, "utf8"))
  : null;
const configuredHost = args.get("--node-host") || env.HOST || env.HOSTNAME || "127.0.0.1";
const configuredPort = Number(args.get("--node-port") || env.PORT || 5173);
const vaultRootKey = env.VAULT_ROOT_KEY || "";
const vaultRootKeyNotDemo = vaultRootKey.length >= 16 && !/replace-with|demo|Passw0rd/i.test(vaultRootKey);

const evidence = {
  format: "sentinel-windows-install-hardening-evidence-v1",
  deploymentStatus,
  environment: args.get("--environment") || "replace-with-environment",
  reviewDate: args.get("--review-date") || (deploymentStatus === "planned" ? "YYYY-MM-DD" : today()),
  installHost: args.get("--install-host") || os.hostname(),
  installPath,
  storageProvider,
  nodeBinding: {
    host: configuredHost,
    port: configuredPort,
    iisFrontend,
    tlsTermination: args.get("--tls-termination") || (iisFrontend ? "replace-with-iis-tls-termination" : "not-applicable")
  },
  targetPreflight: {
    reportPath: targetPreflightPath || "replace-with-windows-target-preflight-report",
    format: targetPreflight?.format || "sentinel-windows-target-preflight-v1",
    result: argResult("--target-preflight-result", targetPreflight ? (targetPreflight.ready ? "passed" : "failed") : "planned", allowedResults),
    ready: Boolean(targetPreflight?.ready),
    failedCount: Number(targetPreflight?.failedCount || 0),
    warningCount: Number(targetPreflight?.warningCount || 0),
    checkedAt: args.get("--target-preflight-checked-at") || (targetPreflight?.generatedAt ? String(targetPreflight.generatedAt).slice(0, 10) : (deploymentStatus === "planned" ? "YYYY-MM-DD" : today()))
  },
  serviceIdentity: {
    supervisor: args.get("--supervisor") || "scheduled-task",
    runAs: args.get("--run-as") || "SYSTEM",
    interactiveLogonAllowed: args.get("--interactive-logon-allowed") === "true",
    leastPrivilegeReview: argResult("--least-privilege-review", "planned")
  },
  filesystemAcls: {
    installDirRestricted: argResult("--install-dir-restricted", existsSync(installPath) ? "planned" : "failed"),
    sentinelEnvRestricted: argResult("--sentinel-env-restricted", existsSync(sentinelEnvPath) ? "planned" : "failed"),
    dataDirRestricted: argResult("--data-dir-restricted", existsSync(dataDir) ? "planned" : "failed"),
    logsDirWritableByServiceOnly: argResult("--logs-dir-writable-by-service-only", existsSync(logsDir) ? "planned" : "failed"),
    rollbackDirRestricted: argResult("--rollback-dir-restricted", existsSync(rollbackDir) ? "planned" : "failed")
  },
  runtimeSecrets: {
    vaultRootKeyNotDemo: argResult("--vault-root-key-not-demo", existsSync(sentinelEnvPath) ? boolResult(vaultRootKeyNotDemo) : "planned"),
    sentinelEnvExcludedFromBackups: argResult("--sentinel-env-excluded-from-backups", "planned"),
    plaintextSecretsAbsentFromLogs: argResult("--plaintext-secrets-absent-from-logs", existsSync(logsDir) ? boolResult(!containsPlaintextSecretMarker(logsDir)) : "planned")
  },
  installerChecks: {
    cleanInstall: argResult("--clean-install", "not-run", allowedCheckResults),
    upgradeBackupCreated: argResult("--upgrade-backup-created", "not-run", allowedCheckResults),
    rollbackRestoresPreviousVersion: argResult("--rollback-restores-previous-version", "not-run", allowedCheckResults),
    uninstallRemovesScheduledTask: argResult("--uninstall-removes-scheduled-task", "not-run", allowedCheckResults),
    healthCheckPassed: argResult("--health-check-passed", "not-run", allowedCheckResults),
    iisReverseProxyValidated: argResult("--iis-reverse-proxy-validated", iisFrontend ? "not-run" : "not-applicable", allowedCheckResults)
  },
  approvals: {
    windowsOwner: args.get("--windows-owner") || "replace-with-owner",
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    operationsReviewer: args.get("--operations-reviewer") || "replace-with-reviewer",
    changeTicket: args.get("--change-ticket") || "replace-with-ticket"
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Windows install hardening evidence written: ${outputPath}`);
