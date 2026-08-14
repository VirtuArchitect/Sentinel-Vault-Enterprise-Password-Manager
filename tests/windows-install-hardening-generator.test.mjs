import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-windows-install-hardening-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-windows-install-hardening-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

test("windows install hardening generator records local install facts", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-hardening-generator-"));
  try {
    const installDir = path.join(dir, "Sentinel Vault");
    const dataDir = path.join(installDir, "data");
    const logsDir = path.join(installDir, "logs");
    const rollbackDir = path.join(dir, "rollbacks");
    mkdirSync(dataDir, { recursive: true });
    mkdirSync(logsDir, { recursive: true });
    mkdirSync(rollbackDir, { recursive: true });
    writeFileSync(path.join(installDir, "sentinel.env"), [
      "HOST=127.0.0.1",
      "PORT=5173",
      "VAULT_ROOT_KEY=local-production-like-key"
    ].join("\n"));
    writeFileSync(path.join(logsDir, "server.log"), "health check ok\n");

    const evidencePath = path.join(dir, "windows-hardening.json");
    assert.match(runGenerator([
      "--install-path", installDir,
      "--data-dir", dataDir,
      "--logs-dir", logsDir,
      "--rollback-dir", rollbackDir,
      "--environment", "lab",
      "--sentinel-env", path.join(installDir, "sentinel.env"),
      "--out", evidencePath
    ]), /Windows install hardening evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.environment, "lab");
    assert.equal(evidence.nodeBinding.host, "127.0.0.1");
    assert.equal(evidence.nodeBinding.port, 5173);
    assert.equal(evidence.targetPreflight.result, "planned");
    assert.equal(evidence.targetPreflight.format, "sentinel-windows-target-preflight-v1");
    assert.equal(evidence.runtimeSecrets.vaultRootKeyNotDemo, "passed");
    assert.equal(evidence.runtimeSecrets.plaintextSecretsAbsentFromLogs, "passed");
    assert.equal(evidence.installerChecks.cleanInstall, "not-run");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("windows install hardening generator flags demo root keys and secret-like logs", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-hardening-generator-fail-"));
  try {
    const installDir = "C:\\Program Files\\Sentinel Vault";
    const localInstallDir = path.join(dir, "Sentinel Vault");
    const logsDir = path.join(localInstallDir, "logs");
    mkdirSync(logsDir, { recursive: true });
    const sentinelEnvPath = path.join(localInstallDir, "sentinel.env");
    writeFileSync(sentinelEnvPath, "VAULT_ROOT_KEY=replace-with-production-secret\n");
    writeFileSync(path.join(logsDir, "server.log"), "VAULT_ROOT_KEY=replace-with-production-secret\n");

    const evidencePath = path.join(dir, "windows-hardening.json");
    runGenerator([
      "--install-path", installDir,
      "--logs-dir", logsDir,
      "--sentinel-env", sentinelEnvPath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.runtimeSecrets.vaultRootKeyNotDemo, "failed");
    assert.equal(evidence.runtimeSecrets.plaintextSecretsAbsentFromLogs, "failed");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("windows install hardening generator can create validated completed evidence from supplied checks", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-hardening-generator-prod-"));
  try {
    const evidencePath = path.join(dir, "windows-hardening.json");
    const preflightPath = path.join(dir, "windows-target-preflight.json");
    writeFileSync(preflightPath, JSON.stringify({
      format: "sentinel-windows-target-preflight-v1",
      generatedAt: "2026-07-01T08:00:00.000Z",
      ready: true,
      failedCount: 0,
      warningCount: 0,
      checks: []
    }, null, 2));
    runGenerator([
      "--status", "production",
      "--environment", "prod",
      "--install-host", "sentinel-prod-01",
      "--install-path", "C:\\Program Files\\Sentinel Vault",
      "--review-date", "2026-07-01",
      "--target-preflight-report", preflightPath,
      "--least-privilege-review", "passed",
      "--install-dir-restricted", "passed",
      "--sentinel-env-restricted", "passed",
      "--data-dir-restricted", "passed",
      "--logs-dir-writable-by-service-only", "passed",
      "--rollback-dir-restricted", "passed",
      "--vault-root-key-not-demo", "passed",
      "--sentinel-env-excluded-from-backups", "passed",
      "--plaintext-secrets-absent-from-logs", "passed",
      "--clean-install", "passed",
      "--upgrade-backup-created", "passed",
      "--rollback-restores-previous-version", "passed",
      "--uninstall-removes-scheduled-task", "passed",
      "--health-check-passed", "passed",
      "--windows-owner", "Windows Owner",
      "--security-reviewer", "Security Reviewer",
      "--operations-reviewer", "Operations Reviewer",
      "--change-ticket", "CHG-67890",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
