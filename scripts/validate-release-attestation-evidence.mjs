import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/release-attestation-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "signed", "verified", "expired"]);
const strictStatuses = new Set(["signed", "verified"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const attestationTypes = new Set(["sigstore", "gpg", "certificate", "notary", "replace-with-sigstore-gpg-or-certificate"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const sha256Pattern = /^[a-f0-9]{64}$/i;
const gitShaPattern = /^[a-f0-9]{7,40}$/i;
const thumbprintPattern = /^[a-f0-9]{40,64}$/i;

assert.equal(evidence.format, "sentinel-release-attestation-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported release attestation evidence status");
assert.ok(evidence.releaseVersion, "releaseVersion is required");
assert.ok(evidence.generatedAt, "generatedAt is required");
assert.ok(evidence.source?.commit, "source.commit is required");
assert.ok(evidence.source?.branch, "source.branch is required");
assert.ok(evidence.source?.remote, "source.remote is required");
assert.equal(typeof evidence.source?.dirty, "boolean", "source.dirty must be boolean");

assert.ok(evidence.provenance?.path, "provenance.path is required");
assert.ok(evidence.provenance?.sha256, "provenance.sha256 is required");
assert.ok(evidence.provenance?.lockfileSha256, "provenance.lockfileSha256 is required");

for (const name of ["pnpmVerify", "secretScan", "dependencyAudit", "windowsSignatureVerification", "provenanceMatchesArtifacts"]) {
  assert.ok(checkStatuses.has(evidence.checks?.[name]), `Unsupported check result for ${name}`);
}

assert.ok(attestationTypes.has(evidence.attestation?.type), "Unsupported attestation.type");
assert.ok(evidence.attestation?.statementPath, "attestation.statementPath is required");
assert.ok(evidence.attestation?.statementSha256, "attestation.statementSha256 is required");
assert.ok(evidence.attestation?.signaturePath, "attestation.signaturePath is required");
assert.ok(evidence.attestation?.signatureSha256, "attestation.signatureSha256 is required");
assert.ok(evidence.attestation?.signerIdentity, "attestation.signerIdentity is required");
assert.ok(evidence.attestation?.certificateThumbprint, "attestation.certificateThumbprint is required");
assert.ok(evidence.attestation?.transparencyLogUrl, "attestation.transparencyLogUrl is required");
assert.ok(Array.isArray(evidence.artifacts), "artifacts must be an array");
assert.ok(evidence.artifacts.length > 0, "at least one release artifact is required");

for (const artifact of evidence.artifacts) {
  assert.ok(artifact.name, "artifact.name is required");
  assert.ok(artifact.sha256, `${artifact.name || "artifact"}.sha256 is required`);
  assert.ok(Number.isInteger(artifact.size) && artifact.size >= 0, `${artifact.name || "artifact"}.size must be a non-negative integer`);
}

assert.equal(typeof evidence.redaction?.privateKeysFound, "boolean", "redaction.privateKeysFound must be boolean");
assert.equal(typeof evidence.redaction?.tokensFound, "boolean", "redaction.tokensFound must be boolean");
assert.equal(typeof evidence.redaction?.secretValuesFound, "boolean", "redaction.secretValuesFound must be boolean");
assert.ok(evidence.approvals?.releaseOwner, "approvals.releaseOwner is required");
assert.ok(evidence.approvals?.securityReviewer, "approvals.securityReviewer is required");
assert.ok(evidence.approvals?.operationsReviewer, "approvals.operationsReviewer is required");

if (strictStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "strict release attestation evidence cannot contain placeholders");
  assert.ok(isoTimestamp.test(evidence.generatedAt), "generatedAt must be an ISO timestamp");
  assert.ok(gitShaPattern.test(evidence.source.commit), "source.commit must be a Git SHA");
  assert.equal(evidence.source.dirty, false, "attested releases must be built from a clean worktree");
  assert.ok(sha256Pattern.test(evidence.provenance.sha256), "provenance.sha256 must be a SHA-256 hex digest");
  assert.ok(sha256Pattern.test(evidence.provenance.lockfileSha256), "provenance.lockfileSha256 must be a SHA-256 hex digest");
  for (const [name, result] of Object.entries(evidence.checks)) {
    assert.equal(result, "passed", `${name} must pass for strict release attestation evidence`);
  }
  assert.notEqual(evidence.attestation.type, "replace-with-sigstore-gpg-or-certificate", "attestation.type must be concrete");
  assert.ok(sha256Pattern.test(evidence.attestation.statementSha256), "attestation.statementSha256 must be a SHA-256 hex digest");
  assert.ok(sha256Pattern.test(evidence.attestation.signatureSha256), "attestation.signatureSha256 must be a SHA-256 hex digest");
  assert.ok(thumbprintPattern.test(evidence.attestation.certificateThumbprint), "certificateThumbprint must be a certificate thumbprint");
  for (const artifact of evidence.artifacts) {
    assert.ok(sha256Pattern.test(artifact.sha256), `${artifact.name}.sha256 must be a SHA-256 hex digest`);
    assert.ok(artifact.size > 0, `${artifact.name}.size must be greater than zero`);
  }
  assert.equal(evidence.redaction.privateKeysFound, false, "attestation evidence cannot contain private keys");
  assert.equal(evidence.redaction.tokensFound, false, "attestation evidence cannot contain tokens");
  assert.equal(evidence.redaction.secretValuesFound, false, "attestation evidence cannot contain secret values");
}

console.log(`Release attestation evidence validated: ${evidencePath}`);
