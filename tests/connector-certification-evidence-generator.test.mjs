import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-connector-certification-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-connector-evidence.mjs",
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
    format: "sentinel-enterprise-connector-live-preflight-v1",
    checkedAt: "2026-07-01T10:00:00Z",
    connectors: {
      siem: {
        endpointHost: "siem.example.test",
        ok: true,
        signed: true,
        replayWindowSeconds: 300,
        receiver: {
          accepted: true,
          replayStored: true
        }
      }
    },
    checks: {
      siemDeliveryAccepted: true,
      siemReplayEvidencePresent: true,
      redactedOutput: true
    },
    ...extra
  }, null, 2));
};

test("connector certification generator creates pilot evidence from preflight", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-connector-generator-"));
  try {
    const preflightPath = path.join(dir, "connector-live-preflight.json");
    const evidencePath = path.join(dir, "connector-evidence.json");
    writePreflight(preflightPath);

    assert.match(runGenerator([
      "--connector", "siem",
      "--preflight", preflightPath,
      "--environment", "lab",
      "--out", evidencePath
    ]), /Connector certification evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.connector, "siem");
    assert.equal(evidence.targetSystem, "siem.example.test");
    assert.equal(evidence.livePreflight.validated, true);
    assert.equal(evidence.livePreflight.selectedEndpointHost, "siem.example.test");
    assert.deepEqual(evidence.livePreflight.connectorTypes, ["siem"]);
    assert.equal(evidence.replayProtection.implemented, true);
    assert.equal(evidence.testResults.deliveryTest, "passed");
    assert.equal(evidence.testResults.replayTest, "passed");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("connector certification generator reflects unredacted preflight output", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-connector-redaction-generator-"));
  try {
    const preflightPath = path.join(dir, "connector-live-preflight.json");
    const evidencePath = path.join(dir, "connector-evidence.json");
    writePreflight(preflightPath, { checks: { siemDeliveryAccepted: true, siemReplayEvidencePresent: true, redactedOutput: false } });

    runGenerator([
      "--connector", "siem",
      "--preflight", preflightPath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.redactionEvidence.secretValuesFound, true);
    assert.equal(evidence.livePreflight.validated, false);
    assert.equal(evidence.testResults.redactionTest, "failed");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("connector certification validator rejects certified evidence without validated live preflight", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-connector-certified-preflight-fail-"));
  try {
    const preflightPath = path.join(dir, "connector-live-preflight.json");
    const evidencePath = path.join(dir, "connector-evidence.json");
    writePreflight(preflightPath);

    runGenerator([
      "--connector", "siem",
      "--status", "certified",
      "--preflight", preflightPath,
      "--environment", "prod",
      "--owner", "Connector Owner",
      "--support-contact", "SOC Platform",
      "--classification", "confidential",
      "--network-path", "private endpoint",
      "--credential-storage", "Windows DPAPI protected secret",
      "--least-privilege-scopes", "audit.write,health.read",
      "--dedupe-store", "SIEM delivery ID store",
      "--receiver-outage", "bounded retry with alert",
      "--rate-limit", "backoff and alert",
      "--malformed-payload", "reject and alert",
      "--dashboards-reviewed", "true",
      "--tickets-reviewed", "true",
      "--auth-failure-test", "passed",
      "--retry-test", "passed",
      "--disable-procedure", "Disable connector in Sentinel Vault integration settings",
      "--rollback-tested", "true",
      "--connector-owner", "Connector Owner",
      "--security-reviewer", "Security Reviewer",
      "--operations-reviewer", "Operations Reviewer",
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    evidence.livePreflight.checks.siemDeliveryAccepted = false;
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /livePreflight\.checks\.siemDeliveryAccepted must pass/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("connector certification generator creates certified evidence with supplied controls", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-connector-certified-generator-"));
  try {
    const preflightPath = path.join(dir, "connector-live-preflight.json");
    const evidencePath = path.join(dir, "connector-evidence.json");
    writePreflight(preflightPath);

    runGenerator([
      "--connector", "siem",
      "--status", "certified",
      "--preflight", preflightPath,
      "--environment", "prod",
      "--owner", "Connector Owner",
      "--support-contact", "SOC Platform",
      "--classification", "confidential",
      "--network-path", "private endpoint",
      "--credential-storage", "Windows DPAPI protected secret",
      "--least-privilege-scopes", "audit.write,health.read",
      "--dedupe-store", "SIEM delivery ID store",
      "--receiver-outage", "bounded retry with alert",
      "--rate-limit", "backoff and alert",
      "--malformed-payload", "reject and alert",
      "--dashboards-reviewed", "true",
      "--tickets-reviewed", "true",
      "--auth-failure-test", "passed",
      "--retry-test", "passed",
      "--disable-procedure", "Disable connector in Sentinel Vault integration settings",
      "--rollback-tested", "true",
      "--connector-owner", "Connector Owner",
      "--security-reviewer", "Security Reviewer",
      "--operations-reviewer", "Operations Reviewer",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
