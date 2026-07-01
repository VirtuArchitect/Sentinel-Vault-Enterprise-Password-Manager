import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-siem-receiver-rotation-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "siem-receiver-rotation-evidence.json"), "utf8"));

const certifiedEvidence = () => {
  const evidence = template();
  evidence.status = "certified";
  evidence.environment = "prod";
  evidence.receiver = {
    system: "Sentinel SIEM",
    endpointHost: "siem.example.test",
    owner: "SIEM Owner",
    supportQueue: "SOC Platform"
  };
  evidence.rotation = {
    activeKeyId: "siem-key-2026-07",
    previousKeyId: "siem-key-2026-06",
    rotatedAt: "2026-07-01T10:00:00Z",
    previousKeyRetireAfter: "2026-07-08T10:00:00Z",
    changeTicket: "CHG-95001"
  };
  evidence.checks = Object.fromEntries(Object.keys(evidence.checks).map((name) => [name, "passed"]));
  evidence.samples = {
    activeDeliveryId: "delivery-active-1",
    previousKeyDeliveryId: "delivery-previous-1",
    replayAttemptId: "replay-test-1",
    receiverEvidencePath: "artifacts/integrations/siem-rotation-prod.json"
  };
  evidence.redaction = {
    signingSecretsFound: false,
    payloadSecretValuesFound: false,
    tokenValuesFound: false
  };
  evidence.approvals = {
    siemOwner: "SIEM Owner",
    securityReviewer: "Security Reviewer",
    operationsOwner: "Operations Owner"
  };
  return evidence;
};

test("siem receiver rotation evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "siem-receiver-rotation-evidence.json")), /validated/);
});

test("certified siem receiver rotation evidence validates replay and key checks", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-siem-rotation-"));
  try {
    const evidencePath = path.join(dir, "siem-rotation.json");
    writeFileSync(evidencePath, JSON.stringify(certifiedEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("certified siem receiver rotation evidence rejects reused key ids", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-siem-rotation-key-fail-"));
  try {
    const evidence = certifiedEvidence();
    evidence.rotation.previousKeyId = evidence.rotation.activeKeyId;
    const evidencePath = path.join(dir, "siem-rotation.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /key IDs must differ/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("certified siem receiver rotation evidence rejects leaked signing secrets", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-siem-rotation-secret-fail-"));
  try {
    const evidence = certifiedEvidence();
    evidence.redaction.signingSecretsFound = true;
    const evidencePath = path.join(dir, "siem-rotation.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /signing secrets/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
