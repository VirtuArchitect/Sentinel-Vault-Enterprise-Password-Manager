import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-native-companion-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-native-companion-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const sourceCommit = "a".repeat(40);

test("native companion evidence generator creates planned companion evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-native-generator-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault.Companion.exe");
    const evidencePath = path.join(dir, "native-companion-evidence.json");
    const fixture = "sentinel companion fixture";
    writeFileSync(artifactPath, fixture);

    assert.match(runGenerator([
      "--artifact", artifactPath,
      "--version", "1.2.3",
      "--release-date", "2026-07-01",
      "--build-host", "release-host-01",
      "--source-commit", sourceCommit,
      "--out", evidencePath
    ]), /Native companion evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.format, "sentinel-native-companion-evidence-v1");
    assert.equal(evidence.releaseVersion, "1.2.3");
    assert.equal(evidence.buildHost, "release-host-01");
    assert.equal(evidence.sourceCommit, sourceCommit);
    assert.equal(evidence.artifacts[0].name, "SentinelVault.Companion.exe");
    assert.equal(evidence.artifacts[0].type, "companion-exe");
    assert.equal(evidence.artifacts[0].sha256, sha256(fixture));
    assert.equal(evidence.artifacts[0].authenticodeStatus, "not-signed");
    assert.equal(evidence.credentialProvider.enabled, false);
    assert.equal(evidence.testResults.credentialProviderReview, "not-applicable");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("native companion evidence generator records credential provider planned evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-native-generator-cp-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault.CredentialProvider.dll");
    const evidencePath = path.join(dir, "native-companion-evidence.json");
    writeFileSync(artifactPath, "credential provider fixture");

    runGenerator([
      "--artifact", artifactPath,
      "--credential-provider-enabled", "true",
      "--source-commit", sourceCommit,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.artifacts[0].type, "credential-provider-dll");
    assert.equal(evidence.credentialProvider.enabled, true);
    assert.equal(evidence.testResults.credentialProviderReview, "not-run");
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("native companion evidence generator rejects missing artifacts", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-native-generator-missing-"));
  try {
    const missingArtifactPath = path.join(dir, "missing.exe");
    const evidencePath = path.join(dir, "native-companion-evidence.json");

    assert.throws(() => runGenerator([
      "--artifact", missingArtifactPath,
      "--out", evidencePath
    ]), /Native companion artifact not found/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
