import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-siem-receiver-rotation-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-siem-receiver-rotation-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const checkNames = [
  "activeKeyAccepted",
  "previousKeyAcceptedDuringWindow",
  "previousKeyRejectedAfterWindow",
  "signatureVerified",
  "timestampRejectedOutsideReplayWindow",
  "nonceReplayRejected",
  "deliveryIdStored",
  "redactedLogsReviewed",
  "receiverAlertingConfirmed"
];

const writeReport = (filePath, extra = {}) => {
  writeFileSync(filePath, JSON.stringify({
    receiver: {
      system: "Sentinel SIEM",
      endpointHost: "siem.example.test",
      owner: "SIEM Owner",
      supportQueue: "SOC Platform"
    },
    rotation: {
      activeKeyId: "siem-key-2026-07",
      previousKeyId: "siem-key-2026-06",
      rotatedAt: "2026-07-01T10:00:00Z",
      previousKeyRetireAfter: "2026-07-08T10:00:00Z",
      changeTicket: "CHG-95001"
    },
    checks: Object.fromEntries(checkNames.map((name) => [name, "passed"])),
    samples: {
      activeDeliveryId: "delivery-active-1",
      previousKeyDeliveryId: "delivery-previous-1",
      replayAttemptId: "replay-test-1",
      receiverEvidencePath: "artifacts/integrations/siem-rotation-prod.json"
    },
    ...extra
  }, null, 2));
};

test("siem receiver rotation generator summarizes planned receiver evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-siem-rotation-generator-"));
  try {
    const reportPath = path.join(dir, "siem-rotation.json");
    const evidencePath = path.join(dir, "siem-rotation-evidence.json");
    writeReport(reportPath);

    assert.match(runGenerator([
      "--report", reportPath,
      "--environment", "lab",
      "--out", evidencePath
    ]), /SIEM receiver rotation evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.environment, "lab");
    assert.equal(evidence.receiver.system, "Sentinel SIEM");
    assert.equal(evidence.rotation.activeKeyId, "siem-key-2026-07");
    assert.equal(evidence.checks.signatureVerified, "passed");
    assert.equal(evidence.receiverReport.validated, true);
    assert.equal(evidence.receiverReport.receiverEndpointHost, "siem.example.test");
    assert.equal(evidence.receiverReport.activeDeliveryId, "delivery-active-1");
    assert.equal(evidence.redaction.signingSecretsFound, false);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("siem receiver rotation validator rejects certified evidence with failed receiver report checks", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-siem-rotation-certified-report-fail-"));
  try {
    const reportPath = path.join(dir, "siem-rotation.json");
    const evidencePath = path.join(dir, "siem-rotation-evidence.json");
    writeReport(reportPath);

    runGenerator([
      "--status", "certified",
      "--environment", "prod",
      "--report", reportPath,
      "--siem-owner", "SIEM Owner",
      "--security-reviewer", "Security Reviewer",
      "--operations-owner", "Operations Owner",
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    evidence.receiverReport.checks.signatureVerified = "failed";
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /receiverReport\.checks\.signatureVerified must pass/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("siem receiver rotation generator flags leaked signing secrets and tokens", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-siem-rotation-leak-generator-"));
  try {
    const reportPath = path.join(dir, "siem-rotation.json");
    const samplesPath = path.join(dir, "samples.log");
    const evidencePath = path.join(dir, "siem-rotation-evidence.json");
    writeReport(reportPath);
    writeFileSync(samplesPath, [
      "signingSecret=",
      "sampleSigningSecret12345",
      "\ntoken=",
      "sampleTokenValue67890"
    ].join(""));

    runGenerator([
      "--report", reportPath,
      "--samples", samplesPath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.redaction.signingSecretsFound, true);
    assert.equal(evidence.redaction.tokenValuesFound, true);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("siem receiver rotation generator creates certified evidence with approvals", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-siem-rotation-certified-generator-"));
  try {
    const reportPath = path.join(dir, "siem-rotation.json");
    const evidencePath = path.join(dir, "siem-rotation-evidence.json");
    writeReport(reportPath);

    runGenerator([
      "--status", "certified",
      "--environment", "prod",
      "--report", reportPath,
      "--siem-owner", "SIEM Owner",
      "--security-reviewer", "Security Reviewer",
      "--operations-owner", "Operations Owner",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
