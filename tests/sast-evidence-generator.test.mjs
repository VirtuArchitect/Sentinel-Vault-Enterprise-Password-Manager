import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-sast-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-sast-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const sourceCommit = "a".repeat(40);

test("sast evidence generator creates planned evidence from a scan report", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-sast-generator-"));
  try {
    const reportPath = path.join(dir, "scan.json");
    const evidencePath = path.join(dir, "sast-evidence.json");
    writeFileSync(reportPath, JSON.stringify({
      results: {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        informational: 4,
        suppressed: 1
      }
    }));

    assert.match(runGenerator([
      "--report", reportPath,
      "--environment", "lab",
      "--tool", "Local SAST",
      "--tool-version", "1.2.3",
      "--profile", "sentinel-local",
      "--out", evidencePath
    ]), /SAST evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.status, "planned");
    assert.equal(evidence.environment, "lab");
    assert.equal(evidence.results.high, 1);
    assert.equal(evidence.results.suppressed, 1);
    assert.equal(evidence.redaction.privateKeysFound, false);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sast evidence generator creates completed evidence when approvals are supplied", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-sast-generator-completed-"));
  try {
    const reportPath = path.join(dir, "scan.json");
    const evidencePath = path.join(dir, "sast-evidence.json");
    writeFileSync(reportPath, JSON.stringify({
      findings: [
        { severity: "medium" },
        { severity: "low" }
      ]
    }));

    runGenerator([
      "--status", "completed",
      "--environment", "prod",
      "--tool", "Approved SAST",
      "--tool-version", "2026.7.1",
      "--profile", "Sentinel production rules",
      "--started-at", "2026-07-01T10:00:00Z",
      "--completed-at", "2026-07-01T10:30:00Z",
      "--source-commit", sourceCommit,
      "--dirty", "false",
      "--report", reportPath,
      "--tracking-project", "SEC-SAST",
      "--owner", "Security Engineering",
      "--retest-status", "passed",
      "--security-reviewer", "Security Reviewer",
      "--engineering-owner", "Engineering Owner",
      "--release-owner", "Release Owner",
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.status, "completed");
    assert.equal(evidence.results.critical, 0);
    assert.equal(evidence.results.high, 0);
    assert.equal(evidence.results.medium, 1);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sast evidence generator surfaces private key markers from reports", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-sast-generator-key-"));
  try {
    const reportPath = path.join(dir, "scan.txt");
    const evidencePath = path.join(dir, "sast-evidence.json");
    writeFileSync(reportPath, ["finding includes -----BEGIN ", "PRIVATE KEY----- marker"].join(""));

    runGenerator([
      "--report", reportPath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.redaction.privateKeysFound, true);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
