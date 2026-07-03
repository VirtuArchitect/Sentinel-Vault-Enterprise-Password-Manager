import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runValidator = (args) => execFileSync(process.execPath, [
  "scripts/validate-native-release-artifacts.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

test("native release artifact validator records hashes and artifact metadata", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-native-artifact-validator-"));
  try {
    const artifactPath = path.join(dir, "sentinel-tray-helper.ps1");
    const reportPath = path.join(dir, "native-artifact-validation.json");
    const fixture = "Write-Host 'Sentinel fixture'\n";
    writeFileSync(artifactPath, fixture);

    const output = runValidator([
      "--artifact", artifactPath,
      "--out", reportPath
    ]);
    const result = JSON.parse(output);
    const saved = JSON.parse(readFileSync(reportPath, "utf8"));

    assert.equal(result.format, "sentinel-native-release-artifact-validation-v1");
    assert.equal(result.artifactCount, 1);
    assert.equal(result.validated, true);
    assert.equal(result.artifacts[0].name, "sentinel-tray-helper.ps1");
    assert.equal(result.artifacts[0].type, "script");
    assert.equal(result.artifacts[0].sha256, sha256(fixture));
    assert.equal(result.artifacts[0].authenticodeStatus, "not-applicable");
    assert.deepEqual(saved, result);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("native release artifact validator requires signatures when requested", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-native-artifact-validator-signature-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault.CredentialProvider.dll");
    writeFileSync(artifactPath, "unsigned dll fixture");

    assert.throws(() => runValidator([
      "--artifact", artifactPath,
      "--require-signature"
    ]), /must have a valid Authenticode signature/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
