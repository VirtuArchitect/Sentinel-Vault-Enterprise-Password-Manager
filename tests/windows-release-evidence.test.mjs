import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-windows-release-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "windows-release-evidence.json"), "utf8"));
const hex = (char, length) => char.repeat(length);

test("windows release evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "windows-release-evidence.json")), /validated/);
});

test("signed windows release evidence requires real signatures and hashes", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-evidence-"));
  try {
    const evidence = template();
    evidence.releaseVersion = "1.0.0";
    evidence.releaseDate = "2026-07-01";
    evidence.buildHost = "release-host-01";
    evidence.sourceCommit = hex("a", 40);
    evidence.checks.signatureVerification = "valid";
    evidence.packageValidation = {
      reportPath: "C:\\Release\\windows-package-validation.json",
      format: "sentinel-windows-package-validation-v1",
      validated: true,
      packagePath: "C:\\Release\\SentinelVault-Windows.zip",
      packageSha256: hex("b", 64),
      runtimeSmoke: "passed",
      requiredFileCount: 15
    };
    evidence.rollback.tested = true;
    evidence.approvals = {
      releaseOwner: "Release Owner",
      securityReviewer: "Security Reviewer",
      operationsReviewer: "Operations Reviewer"
    };
    evidence.artifacts = [
      {
        name: "SentinelVault-Windows-Setup.exe",
        sha256: hex("b", 64),
        authenticodeStatus: "Valid",
        signerThumbprint: hex("c", 40)
      },
      {
        name: "SentinelVault-Windows.msi",
        sha256: hex("d", 64),
        authenticodeStatus: "Valid",
        signerThumbprint: hex("e", 40)
      }
    ];
    const evidencePath = path.join(dir, "windows-release.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("signed windows release evidence rejects unsigned installer artifacts", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-evidence-fail-"));
  try {
    const evidence = template();
    evidence.releaseVersion = "1.0.0";
    evidence.releaseDate = "2026-07-01";
    evidence.buildHost = "release-host-01";
    evidence.sourceCommit = hex("a", 40);
    evidence.checks.signatureVerification = "valid";
    evidence.packageValidation = {
      reportPath: "C:\\Release\\windows-package-validation.json",
      format: "sentinel-windows-package-validation-v1",
      validated: true,
      packagePath: "C:\\Release\\SentinelVault-Windows.zip",
      packageSha256: hex("b", 64),
      runtimeSmoke: "passed",
      requiredFileCount: 15
    };
    evidence.rollback.tested = true;
    evidence.approvals = {
      releaseOwner: "Release Owner",
      securityReviewer: "Security Reviewer",
      operationsReviewer: "Operations Reviewer"
    };
    evidence.artifacts = [{
      name: "SentinelVault-Windows.msix",
      sha256: hex("b", 64),
      authenticodeStatus: "NotSigned",
      signerThumbprint: hex("c", 40)
    }];
    const evidencePath = path.join(dir, "windows-release.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /must have a valid Authenticode signature/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("signed windows release evidence rejects missing package validation binding", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-package-binding-fail-"));
  try {
    const evidence = template();
    evidence.releaseVersion = "1.0.0";
    evidence.releaseDate = "2026-07-01";
    evidence.buildHost = "release-host-01";
    evidence.sourceCommit = hex("a", 40);
    evidence.checks.signatureVerification = "valid";
    evidence.packageValidation = {
      reportPath: "C:\\Release\\windows-package-validation.json",
      format: "sentinel-windows-package-validation-v1",
      validated: false,
      packagePath: "C:\\Release\\SentinelVault-Windows.zip",
      packageSha256: hex("b", 64),
      runtimeSmoke: "passed",
      requiredFileCount: 15
    };
    evidence.rollback.tested = true;
    evidence.approvals = {
      releaseOwner: "Release Owner",
      securityReviewer: "Security Reviewer",
      operationsReviewer: "Operations Reviewer"
    };
    evidence.artifacts = [{
      name: "SentinelVault-Windows-Setup.exe",
      sha256: hex("b", 64),
      authenticodeStatus: "Valid",
      signerThumbprint: hex("c", 40)
    }];
    const evidencePath = path.join(dir, "windows-release.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /packageValidation.validated must be true/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
