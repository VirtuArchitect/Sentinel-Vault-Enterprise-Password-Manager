import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-brute-force-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-brute-force-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

const writeReport = (filePath, extra = {}) => {
  writeFileSync(filePath, JSON.stringify({
    testedAt: "2026-07-01T10:00:00Z",
    policy: {
      failedLoginLimit: 5,
      lockoutMinutes: 15
    },
    events: [
      { user: "ada", sourceBucket: "iphash-1", outcome: "failed-login" },
      { user: "ada", sourceBucket: "iphash-1", outcome: "failed-login" },
      { user: "ada", sourceBucket: "iphash-1", outcome: "failed-login" },
      { user: "ada", sourceBucket: "iphash-2", outcome: "failed-login" },
      { user: "ada", sourceBucket: "iphash-2", outcome: "account-locked", locked: true },
      { user: "ada", sourceBucket: "iphash-2", outcome: "siem-alert", alert: true }
    ],
    ...extra
  }, null, 2));
};

test("brute-force generator summarizes planned drill report evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-brute-force-generator-"));
  try {
    const reportPath = path.join(dir, "brute-force-drill.json");
    const evidencePath = path.join(dir, "brute-force.json");
    writeReport(reportPath);

    assert.match(runGenerator([
      "--report", reportPath,
      "--environment", "lab",
      "--out", evidencePath
    ]), /Brute-force evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.environment, "lab");
    assert.equal(evidence.testedAt, "2026-07-01T10:00:00Z");
    assert.equal(evidence.samples.failedAttempts, 4);
    assert.equal(evidence.samples.distinctSourceIps, 2);
    assert.equal(evidence.samples.lockedAccounts, 1);
    assert.equal(evidence.samples.alertsGenerated, 1);
    assert.equal(evidence.redaction.passwordsFound, false);
    assert.equal(evidence.redaction.tokensFound, false);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("brute-force generator flags leaked passwords and tokens in samples", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-brute-force-leak-generator-"));
  try {
    const reportPath = path.join(dir, "brute-force-drill.json");
    const samplesPath = path.join(dir, "samples.log");
    const evidencePath = path.join(dir, "brute-force.json");
    writeReport(reportPath);
    writeFileSync(samplesPath, [
      "password=",
      "sampleCleartext1",
      "\ntoken=",
      "sampleTokenValue12345"
    ].join(""));

    runGenerator([
      "--report", reportPath,
      "--samples", samplesPath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.redaction.passwordsFound, true);
    assert.equal(evidence.redaction.tokensFound, true);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("brute-force generator creates production evidence from supplied controls", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-brute-force-production-generator-"));
  try {
    const reportPath = path.join(dir, "brute-force-drill.json");
    const evidencePath = path.join(dir, "brute-force.json");
    writeReport(reportPath, {
      samples: {
        failedAttempts: 12,
        distinctSourceIps: 3,
        lockedAccounts: 1,
        alertsGenerated: 2
      }
    });

    runGenerator([
      "--status", "production",
      "--environment", "prod",
      "--report", reportPath,
      "--temporary-account-lockout", "passed",
      "--session-invalidation-after-logout", "passed",
      "--mfa-claim-required", "passed",
      "--identity-provider-preflight", "passed",
      "--edge-name", "IIS/WAF edge",
      "--source-ip-preserved", "passed",
      "--trusted-proxy-configured", "passed",
      "--per-ip-rate-limit", "passed",
      "--distributed-attack-detection", "passed",
      "--geo-or-asn-policy", "not-applicable",
      "--waf-or-reverse-proxy-logging", "passed",
      "--single-account-lockout", "passed",
      "--single-ip-spray", "passed",
      "--distributed-spray", "passed",
      "--valid-user-after-lockout", "passed",
      "--mfa-required-after-new-device", "passed",
      "--siem-alert-created", "passed",
      "--ticket-or-incident-created", "passed",
      "--dashboard-reviewed", "passed",
      "--false-positive-disposition", "passed",
      "--source-ips-scoped-or-hashed", "passed",
      "--identity-owner", "Identity Owner",
      "--security-reviewer", "Security Reviewer",
      "--operations-owner", "Operations Owner",
      "--change-ticket", "CHG-92001",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
