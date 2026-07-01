import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-log-redaction-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "log-redaction-evidence.json"), "utf8"));

const productionEvidence = () => {
  const evidence = template();
  evidence.status = "production";
  evidence.environment = "prod";
  evidence.collectedAt = "2026-07-01T10:00:00Z";
  evidence.sink = {
    name: "Sentinel SIEM",
    type: "siem",
    environment: "prod-log",
    retentionDays: 365
  };
  evidence.sources = {
    api: "passed",
    siemWebhook: "passed",
    windowsInstaller: "passed",
    browserExtension: "passed",
    nativeCompanion: "not-applicable"
  };
  evidence.samples = {
    eventsShipped: 120,
    syntheticSecretEvents: 8,
    syntheticTokenEvents: 8,
    parserFailures: 0
  };
  evidence.redaction = {
    recursiveSensitiveFields: "passed",
    bearerTokens: "passed",
    sentinelServiceTokens: "passed",
    privateKeys: "passed",
    passwordValues: "passed",
    errorStacks: "passed",
    ticketWorkNotes: "passed",
    auditLedgerExports: "passed"
  };
  evidence.controls = {
    schemaValidated: "passed",
    receiverSearchCompleted: "passed",
    alertingConfigured: "passed",
    retentionPolicyVerified: "passed",
    accessReviewCompleted: "passed"
  };
  evidence.findings = {
    secretValuesFound: false,
    tokensFound: false,
    privateKeysFound: false,
    plaintextPasswordsFound: false
  };
  evidence.approvals = {
    securityReviewer: "Security Reviewer",
    siemOwner: "SIEM Owner",
    operationsOwner: "Operations Owner",
    changeTicket: "CHG-90003"
  };
  return evidence;
};

test("log redaction evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "log-redaction-evidence.json")), /validated/);
});

test("production log redaction evidence validates shipped samples and controls", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-log-redaction-"));
  try {
    const evidencePath = path.join(dir, "log-redaction.json");
    writeFileSync(evidencePath, JSON.stringify(productionEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production log redaction evidence rejects leaked tokens", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-log-redaction-token-"));
  try {
    const evidence = productionEvidence();
    evidence.findings.tokensFound = true;
    const evidencePath = path.join(dir, "log-redaction.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /tokens/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production log redaction evidence rejects parser failures", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-log-redaction-parser-"));
  try {
    const evidence = productionEvidence();
    evidence.samples.parserFailures = 1;
    const evidencePath = path.join(dir, "log-redaction.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /parser failures/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
