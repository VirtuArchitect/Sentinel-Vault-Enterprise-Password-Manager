import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-release-attestation-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-release-attestation-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

const writeProvenance = (filePath, artifactPath) => {
  writeFileSync(filePath, JSON.stringify({
    format: "sentinel-release-provenance-v1",
    generatedAt: "2026-07-01T10:00:00Z",
    source: {
      commit: "abcdef1234567890abcdef1234567890abcdef12",
      branch: "main",
      dirty: false,
      remote: "https://github.com/VirtuArchitect/Sentinel-Vault-Enterprise-Password-Manager.git"
    },
    package: {
      name: "sentinel-vault-console",
      version: "1.0.0"
    },
    lockfile: {
      path: "pnpm-lock.yaml",
      exists: true,
      sha256: "base64url-not-used-by-attestation"
    },
    artifacts: [
      {
        path: artifactPath,
        exists: true,
        sha256: "base64url-not-used-by-attestation",
        size: 12
      }
    ]
  }, null, 2));
};

test("release attestation generator creates planned evidence from provenance", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-release-attestation-generator-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault-Windows.zip");
    const provenancePath = path.join(dir, "release-provenance.json");
    const evidencePath = path.join(dir, "release-attestation.json");
    writeFileSync(artifactPath, "artifact-data");
    writeProvenance(provenancePath, artifactPath);

    assert.match(runGenerator([
      "--provenance", provenancePath,
      "--out", evidencePath
    ]), /Release attestation evidence written/);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.releaseVersion, "1.0.0");
    assert.equal(evidence.source.commit, "abcdef1234567890abcdef1234567890abcdef12");
    assert.equal(evidence.artifacts[0].name, "SentinelVault-Windows.zip");
    assert.match(evidence.artifacts[0].sha256, /^[a-f0-9]{64}$/);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("release attestation generator flags leaked keys and tokens in statements", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-release-attestation-leak-generator-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault-Windows.zip");
    const provenancePath = path.join(dir, "release-provenance.json");
    const statementPath = path.join(dir, "statement.jsonl");
    const signaturePath = path.join(dir, "statement.sig");
    const evidencePath = path.join(dir, "release-attestation.json");
    writeFileSync(artifactPath, "artifact-data");
    writeProvenance(provenancePath, artifactPath);
    writeFileSync(statementPath, [
      "-----BEGIN ",
      "PRIVATE KEY-----\n",
      "token=",
      "sampleTokenValue12345"
    ].join(""));
    writeFileSync(signaturePath, "signature-data");

    runGenerator([
      "--provenance", provenancePath,
      "--statement", statementPath,
      "--signature", signaturePath,
      "--out", evidencePath
    ]);

    const evidence = readJson(evidencePath);
    assert.equal(evidence.redaction.privateKeysFound, true);
    assert.equal(evidence.redaction.tokensFound, true);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("release attestation generator creates verified evidence with approvals", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-release-attestation-verified-generator-"));
  try {
    const artifactPath = path.join(dir, "SentinelVault-Windows.zip");
    const provenancePath = path.join(dir, "release-provenance.json");
    const statementPath = path.join(dir, "statement.jsonl");
    const signaturePath = path.join(dir, "statement.sig");
    const evidencePath = path.join(dir, "release-attestation.json");
    writeFileSync(artifactPath, "artifact-data");
    writeProvenance(provenancePath, artifactPath);
    writeFileSync(statementPath, JSON.stringify({ subject: "SentinelVault-Windows.zip" }));
    writeFileSync(signaturePath, "signature-data");

    runGenerator([
      "--status", "verified",
      "--provenance", provenancePath,
      "--statement", statementPath,
      "--signature", signaturePath,
      "--attestation-type", "sigstore",
      "--signer-identity", "release@example.test",
      "--certificate-thumbprint", "e".repeat(40),
      "--transparency-log-url", "https://rekor.example.test/entry/123",
      "--pnpm-verify", "passed",
      "--secret-scan", "passed",
      "--dependency-audit", "passed",
      "--windows-signature-verification", "passed",
      "--provenance-matches-artifacts", "passed",
      "--release-owner", "Release Owner",
      "--security-reviewer", "Security Reviewer",
      "--operations-reviewer", "Operations Reviewer",
      "--out", evidencePath
    ]);

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
