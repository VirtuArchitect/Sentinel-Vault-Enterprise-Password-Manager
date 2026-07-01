import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-log-redaction-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-log-redaction-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

test("log redaction evidence generator summarizes planned sample logs", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-log-redaction-generator-"));
  try {
    const samplesDir = path.join(dir, "samples");
    mkdirSync(samplesDir);
    writeFileSync(path.join(samplesDir, "api.log"), [
      "{\"event\":\"synthetic-secret\",\"message\":\"secret-redaction-test [REDACTED]\"}",
      "{\"event\":\"synthetic-token\",\"message\":\"token-redaction-test [REDACTED]\"}",
      "{\"event\":\"audit\",\"deliveryId\":\"abc\"}"
    ].join("\n"));
    const evidencePath = path.join(dir, "log-redaction.json");

    assert.match(runGenerator([
      "--samples", samplesDir,
      "--environment", "lab",
      "--out", evidencePath
    ]), /Log redaction evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.environment, "lab");
    assert.equal(evidence.samples.syntheticSecretEvents, 1);
    assert.equal(evidence.samples.syntheticTokenEvents, 1);
    assert.equal(evidence.findings.tokensFound, false);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("log redaction evidence generator flags leaked values in samples", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-log-redaction-generator-leak-"));
  try {
    const samplePath = path.join(dir, "leak.log");
    const evidencePath = path.join(dir, "log-redaction.json");
    writeFileSync(samplePath, [
      "bearer abcdefghijklmnopqrstuvwxyz",
      "password=PlaintextPassword123",
      "-----BEGIN PRIVATE KEY-----"
    ].join("\n"));

    runGenerator([
      "--samples", samplePath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.findings.tokensFound, true);
    assert.equal(evidence.findings.plaintextPasswordsFound, true);
    assert.equal(evidence.findings.privateKeysFound, true);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("log redaction evidence generator can create validated production evidence from supplied controls", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-log-redaction-generator-prod-"));
  try {
    const samplePath = path.join(dir, "receiver.log");
    const evidencePath = path.join(dir, "log-redaction.json");
    writeFileSync(samplePath, [
      "{\"event\":\"synthetic-secret\",\"message\":\"secret-redaction-test [REDACTED]\"}",
      "{\"event\":\"synthetic-token\",\"message\":\"token-redaction-test [REDACTED]\"}",
      "{\"event\":\"audit\",\"deliveryId\":\"abc\"}"
    ].join("\n"));

    runGenerator([
      "--status", "production",
      "--environment", "prod",
      "--collected-at", "2026-07-01T10:00:00Z",
      "--sink-name", "Sentinel SIEM",
      "--sink-environment", "prod-log",
      "--retention-days", "365",
      "--samples", samplePath,
      "--source-api", "passed",
      "--source-siem-webhook", "passed",
      "--source-windows-installer", "passed",
      "--source-browser-extension", "passed",
      "--source-native-companion", "not-applicable",
      "--events-shipped", "3",
      "--synthetic-secret-events", "1",
      "--synthetic-token-events", "1",
      "--recursive-sensitive-fields", "passed",
      "--bearer-tokens", "passed",
      "--sentinel-service-tokens", "passed",
      "--private-keys", "passed",
      "--password-values", "passed",
      "--error-stacks", "passed",
      "--ticket-work-notes", "passed",
      "--audit-ledger-exports", "passed",
      "--schema-validated", "passed",
      "--receiver-search-completed", "passed",
      "--alerting-configured", "passed",
      "--retention-policy-verified", "passed",
      "--access-review-completed", "passed",
      "--security-reviewer", "Security Reviewer",
      "--siem-owner", "SIEM Owner",
      "--operations-owner", "Operations Owner",
      "--change-ticket", "CHG-90003",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
