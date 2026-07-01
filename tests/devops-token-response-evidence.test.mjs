import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");
const hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const hashC = "ccccccccccccccccccccccccccccccccccccccccccc";

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-devops-token-response-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "devops-token-response-evidence.json"), "utf8"));

const productionEvidence = () => {
  const evidence = template();
  evidence.status = "production";
  evidence.environment = "prod";
  evidence.owner = "DevOps Platform";
  evidence.checkedAt = "2026-07-01T10:00:00Z";
  evidence.target = {
    endpointHost: "sentinel.example.test",
    secretId: "deploy-secret",
    blockedSecretId: "finance-root"
  };
  evidence.tokenFingerprints = {
    revokedTokenSha256: hashA,
    replacementTokenSha256: hashB
  };
  evidence.checks = {
    revokedTokenRejected: true,
    replacementTokenAccepted: true,
    replacementScopeEnforced: true,
    redactedOutput: true
  };
  evidence.results = {
    revokedTokenStatus: 401,
    replacementTokenStatus: 200,
    blockedScopeStatus: 403,
    replacementReturnedValueSha256: hashC
  };
  evidence.approvals = {
    securityReviewer: "Security Reviewer",
    devopsOwner: "DevOps Owner",
    operationsOwner: "Operations Owner",
    incidentOrChangeTicket: "INC-90005"
  };
  return evidence;
};

test("devops token response evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "devops-token-response-evidence.json")), /validated/);
});

test("production devops token response evidence validates token replacement controls", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-devops-token-evidence-"));
  try {
    const evidencePath = path.join(dir, "devops-token-response.json");
    writeFileSync(evidencePath, JSON.stringify(productionEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production devops token response evidence rejects accepted revoked tokens", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-devops-token-revoked-"));
  try {
    const evidence = productionEvidence();
    evidence.checks.revokedTokenRejected = false;
    const evidencePath = path.join(dir, "devops-token-response.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /revoked token/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production devops token response evidence rejects unredacted output", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-devops-token-redaction-"));
  try {
    const evidence = productionEvidence();
    evidence.checks.redactedOutput = false;
    const evidencePath = path.join(dir, "devops-token-response.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /redacted/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
