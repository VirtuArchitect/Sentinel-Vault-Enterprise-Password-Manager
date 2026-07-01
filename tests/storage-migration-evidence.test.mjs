import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-storage-migration-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "storage-migration-evidence.json"), "utf8"));
const completedEvidence = () => {
  const evidence = template();
  evidence.inspectedAt = "2026-07-01T10:00:00Z";
  evidence.stateFile = "C:/sentinel/data/sentinel-state.json";
  evidence.stateSha256 = "a".repeat(43);
  evidence.stateVersion = 3;
  evidence.counts = Object.fromEntries(Object.keys(evidence.counts).map((name) => [name, 1]));
  evidence.checks = Object.fromEntries(Object.keys(evidence.checks).map((name) => [name, true]));
  evidence.findings = Object.fromEntries(Object.keys(evidence.findings).map((name) => [name, []]));
  return evidence;
};

test("storage migration evidence template validates", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "storage-migration-evidence.json")), /validated/);
});

test("completed storage migration evidence validates clean checks", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-storage-migration-evidence-"));
  try {
    const evidencePath = path.join(dir, "storage-migration-evidence.json");
    writeFileSync(evidencePath, JSON.stringify(completedEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("completed storage migration evidence rejects plaintext findings", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-storage-migration-evidence-plaintext-"));
  try {
    const evidence = completedEvidence();
    evidence.checks.plaintextSecretsAbsent = false;
    evidence.findings.plaintextSecretFields = [{ id: "secret-1", field: "password" }];
    const evidencePath = path.join(dir, "storage-migration-evidence.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /plaintextSecretsAbsent/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
