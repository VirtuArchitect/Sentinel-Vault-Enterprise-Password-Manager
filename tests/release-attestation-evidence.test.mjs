import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");
const shaA = "a".repeat(64);
const shaB = "b".repeat(64);
const shaC = "c".repeat(64);
const shaD = "d".repeat(64);
const thumb = "e".repeat(40);

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-release-attestation-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const template = () => JSON.parse(readFileSync(path.join(rootDir, "docs", "templates", "release-attestation-evidence.json"), "utf8"));

const verifiedEvidence = () => {
  const evidence = template();
  evidence.status = "verified";
  evidence.releaseVersion = "1.0.0";
  evidence.generatedAt = "2026-07-01T10:00:00Z";
  evidence.source = {
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    branch: "main",
    remote: "https://github.com/VirtuArchitect/Sentinel-Vault-Enterprise-Password-Manager.git",
    dirty: false
  };
  evidence.provenance = {
    path: "artifacts/release/release-provenance.json",
    sha256: shaA,
    lockfileSha256: shaB
  };
  evidence.checks = Object.fromEntries(Object.keys(evidence.checks).map((name) => [name, "passed"]));
  evidence.attestation = {
    type: "sigstore",
    statementPath: "artifacts/release/sentinel-vault.intoto.jsonl",
    statementSha256: shaC,
    signaturePath: "artifacts/release/sentinel-vault.intoto.sig",
    signatureSha256: shaD,
    signerIdentity: "release@example.test",
    certificateThumbprint: thumb,
    transparencyLogUrl: "https://rekor.example.test/entry/123"
  };
  evidence.artifacts = [
    {
      name: "SentinelVault-Windows-Setup.exe",
      sha256: shaA,
      size: 1024
    }
  ];
  evidence.redaction = {
    privateKeysFound: false,
    tokensFound: false,
    secretValuesFound: false
  };
  evidence.approvals = {
    releaseOwner: "Release Owner",
    securityReviewer: "Security Reviewer",
    operationsReviewer: "Operations Reviewer"
  };
  return evidence;
};

test("release attestation evidence template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "release-attestation-evidence.json")), /validated/);
});

test("verified release attestation evidence validates provenance and signer metadata", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-release-attestation-"));
  try {
    const evidencePath = path.join(dir, "release-attestation.json");
    writeFileSync(evidencePath, JSON.stringify(verifiedEvidence(), null, 2));

    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verified release attestation evidence rejects dirty source trees", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-release-attestation-dirty-"));
  try {
    const evidence = verifiedEvidence();
    evidence.source.dirty = true;
    const evidencePath = path.join(dir, "release-attestation.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /clean worktree/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verified release attestation evidence rejects leaked private keys", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-release-attestation-key-"));
  try {
    const evidence = verifiedEvidence();
    evidence.redaction.privateKeysFound = true;
    const evidencePath = path.join(dir, "release-attestation.json");
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /private keys/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
