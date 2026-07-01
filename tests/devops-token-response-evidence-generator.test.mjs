import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");
const tokenA = "a".repeat(43);
const tokenB = "b".repeat(43);
const valueHash = "c".repeat(43);

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-devops-token-response-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-devops-token-response-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const writePreflight = (filePath, extra = {}) => {
  writeFileSync(filePath, JSON.stringify({
    format: "sentinel-devops-token-response-preflight-v1",
    checkedAt: "2026-07-01T10:00:00Z",
    target: {
      endpointHost: "sentinel.example.test",
      secretId: "secret-prod-db",
      blockedSecretId: "secret-other-tenant"
    },
    tokenFingerprints: {
      revokedTokenSha256: tokenA,
      replacementTokenSha256: tokenB
    },
    checks: {
      revokedTokenRejected: true,
      replacementTokenAccepted: true,
      replacementScopeEnforced: true,
      redactedOutput: true
    },
    results: {
      revokedTokenStatus: 403,
      replacementTokenStatus: 200,
      blockedScopeStatus: 404,
      replacementReturnedValueSha256: valueHash
    },
    ...extra
  }, null, 2));
};

test("devops token response generator enriches planned preflight evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-devops-token-generator-"));
  try {
    const preflightPath = path.join(dir, "devops-token-response.json");
    const evidencePath = path.join(dir, "devops-token-response-evidence.json");
    writePreflight(preflightPath);

    assert.match(runGenerator([
      "--preflight", preflightPath,
      "--environment", "lab",
      "--out", evidencePath
    ]), /DevOps token response evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.environment, "lab");
    assert.equal(evidence.target.endpointHost, "sentinel.example.test");
    assert.equal(evidence.checks.revokedTokenRejected, true);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("devops token response generator reflects failed replacement checks", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-devops-token-failed-generator-"));
  try {
    const preflightPath = path.join(dir, "devops-token-response.json");
    const evidencePath = path.join(dir, "devops-token-response-evidence.json");
    writePreflight(preflightPath, { checks: { revokedTokenRejected: true, replacementTokenAccepted: false, replacementScopeEnforced: true, redactedOutput: true } });

    runGenerator([
      "--preflight", preflightPath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.checks.replacementTokenAccepted, false);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("devops token response generator creates production evidence with approvals", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-devops-token-production-generator-"));
  try {
    const preflightPath = path.join(dir, "devops-token-response.json");
    const evidencePath = path.join(dir, "devops-token-response-evidence.json");
    writePreflight(preflightPath);

    runGenerator([
      "--status", "production",
      "--preflight", preflightPath,
      "--environment", "prod",
      "--owner", "DevOps Owner",
      "--security-reviewer", "Security Reviewer",
      "--devops-owner", "DevOps Owner",
      "--operations-owner", "Operations Owner",
      "--incident-or-change-ticket", "INC-99001",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
