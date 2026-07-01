import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-sast-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "sast-evidence.json"), "utf8"));

const completedEvidence = () => {
  const evidence = template();
  evidence.status = "completed";
  evidence.environment = "prod";
  evidence.scan = {
    tool: "Approved SAST",
    toolVersion: "2026.7.1",
    profile: "Sentinel production rules",
    startedAt: "2026-07-01T10:00:00Z",
    completedAt: "2026-07-01T10:30:00Z",
    reportPath: "artifacts/security/sast-prod.json"
  };
  evidence.source = {
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    branch: "main",
    dirty: false
  };
  evidence.results = {
    critical: 0,
    high: 0,
    medium: 2,
    low: 4,
    informational: 8,
    suppressed: 1
  };
  evidence.remediation = {
    trackingProject: "SEC-SAST",
    owner: "Security Engineering",
    criticalDueDays: 7,
    highDueDays: 14,
    mediumDueDays: 30,
    retestStatus: "passed"
  };
  evidence.redaction = {
    secretValuesFound: false,
    tokensFound: false,
    privateKeysFound: false
  };
  evidence.approvals = {
    securityReviewer: "Security Reviewer",
    engineeringOwner: "Engineering Owner",
    releaseOwner: "Release Owner"
  };
  return evidence;
};

test("sast evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "sast-evidence.json")), /validated/);
});

test("completed sast evidence validates scan coverage and remediation", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-sast-"));
  try {
    const evidencePath = path.join(dir, "sast.json");
    writeFileSync(evidencePath, JSON.stringify(completedEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("completed sast evidence rejects open high findings", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-sast-high-"));
  try {
    const evidence = completedEvidence();
    evidence.results.high = 1;
    const evidencePath = path.join(dir, "sast.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /open high findings/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("completed sast evidence rejects leaked private keys", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-sast-key-"));
  try {
    const evidence = completedEvidence();
    evidence.redaction.privateKeysFound = true;
    const evidencePath = path.join(dir, "sast.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /private keys/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
