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
    const validationPath = path.join(dir, "windows-package-validation.json");
    const evidencePath = path.join(dir, "windows-release-evidence.json");
    const fixture = "sentinel release artifact fixture";
    const artifactSha256 = crypto.createHash("sha256").update(fixture).digest("hex");
    writeFileSync(artifactPath, fixture);
    writeFileSync(validationPath, JSON.stringify({
      format: "sentinel-windows-package-validation-v1",
      packagePath: artifactPath,
      packageSha256: artifactSha256,
      runtimeSmoke: "passed",
      requiredFileCount: 15,
      validated: true
    }, null, 2));

    runGenerator([
      "--artifact", artifactPath,
      "--package-validation", validationPath,
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
    assert.equal(evidence.artifacts[0].sha256, artifactSha256);
    assert.equal(evidence.packageValidation.packageSha256, artifactSha256);
    assert.equal(evidence.packageValidation.validated, true);
    assert.equal(evidence.artifacts[0].authenticodeStatus, "not-signed");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("windows release evidence generator rejects package validation hash mismatches", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-release-validation-fail-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault-Windows.zip");
    const validationPath = path.join(dir, "windows-package-validation.json");
    writeFileSync(artifactPath, "sentinel release artifact fixture");
    writeFileSync(validationPath, JSON.stringify({
      format: "sentinel-windows-package-validation-v1",
      packagePath: artifactPath,
      packageSha256: "f".repeat(64),
      runtimeSmoke: "passed",
      requiredFileCount: 15,
      validated: true
    }, null, 2));

    assert.throws(() => runGenerator([
      "--artifact", artifactPath,
      "--package-validation", validationPath,
      "--out", path.join(dir, "windows-release-evidence.json")
    ]), /package validation hash must match release artifact hash/);
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
