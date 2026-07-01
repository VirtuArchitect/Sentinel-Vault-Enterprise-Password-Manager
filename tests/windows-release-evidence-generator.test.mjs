import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-windows-release-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-windows-release-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("windows release evidence generator writes valid planned evidence from artifacts", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-release-generator-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault-Windows.zip");
    const evidencePath = path.join(dir, "windows-release-evidence.json");
    writeFileSync(artifactPath, "sentinel release artifact fixture");

    runGenerator([
      "--artifact", artifactPath,
      "--version", "1.2.3",
      "--release-date", "2026-07-01",
      "--build-host", "release-host-01",
      "--source-commit", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "--pnpm-verify", "passed",
      "--secret-scan", "passed",
      "--dependency-audit", "passed",
      "--out", evidencePath
    ]);

    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.format, "sentinel-windows-release-evidence-v1");
    assert.equal(evidence.releaseVersion, "1.2.3");
    assert.equal(evidence.artifacts[0].name, "SentinelVault-Windows.zip");
    assert.equal(evidence.artifacts[0].sha256, crypto.createHash("sha256").update("sentinel release artifact fixture").digest("hex"));
    assert.equal(evidence.artifacts[0].authenticodeStatus, "not-signed");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("windows release evidence generator rejects missing artifact paths", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-release-generator-fail-"));
  try {
    assert.throws(() => runGenerator([
      "--artifact", path.join(dir, "missing.msi"),
      "--out", path.join(dir, "windows-release-evidence.json")
    ]), /artifact not found/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
