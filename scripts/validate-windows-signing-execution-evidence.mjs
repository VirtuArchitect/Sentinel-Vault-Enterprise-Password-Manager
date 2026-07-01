import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/windows-signing-execution-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const isoDate = /^\d{4}-\d{2}-\d{2}$/;
const sha256Pattern = /^[a-f0-9]{64}$/i;
const thumbprintPattern = /^[a-f0-9]{40,64}$/i;
const allowedStatuses = new Set(["planned", "signed", "retired"]);
const validArtifactTypes = new Set(["msi", "msix", "exe"]);
const passValues = new Set(["passed", "valid", "signed", true]);
const failValues = new Set(["failed", "invalid", "not-signed", "planned", false]);

const sha256FileHex = (filePath) => crypto.createHash("sha256").update(readFileSync(filePath)).digest("hex");
const assertPassed = (value, message) => assert.ok(passValues.has(value), message);
const assertFalse = (value, message) => assert.equal(value, false, message);

assert.equal(evidence.format, "sentinel-windows-signing-execution-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported signing evidence status");
assert.ok(evidence.environment, "environment is required");
assert.ok(evidence.releaseVersion, "releaseVersion is required");
assert.ok(evidence.signedAt, "signedAt is required");
assert.ok(evidence.releaseHost?.hostnameHash, "releaseHost.hostnameHash is required");
assert.ok(evidence.releaseHost?.osBuild, "releaseHost.osBuild is required");
assert.ok(evidence.releaseHost?.runnerIdentity, "releaseHost.runnerIdentity is required");
assert.ok(evidence.releaseHost?.certificateSource, "releaseHost.certificateSource is required");
assert.ok(evidence.certificate?.subject, "certificate.subject is required");
assert.ok(evidence.certificate?.thumbprint, "certificate.thumbprint is required");
assert.ok(evidence.certificate?.issuer, "certificate.issuer is required");
assert.ok(evidence.certificate?.validFrom, "certificate.validFrom is required");
assert.ok(evidence.certificate?.validTo, "certificate.validTo is required");
assert.ok(evidence.certificate?.timestampAuthority, "certificate.timestampAuthority is required");
assert.ok(Array.isArray(evidence.artifacts), "artifacts must be an array");
assert.ok(evidence.artifacts.length > 0, "at least one signed artifact is required");
assert.ok(evidence.checks && typeof evidence.checks === "object", "checks are required");
assert.ok(evidence.approvals?.releaseOwner, "approvals.releaseOwner is required");
assert.ok(evidence.approvals?.securityReviewer, "approvals.securityReviewer is required");
assert.ok(evidence.approvals?.operationsOwner, "approvals.operationsOwner is required");
assert.ok(evidence.approvals?.changeTicket, "approvals.changeTicket is required");
assert.ok(evidence.redaction && typeof evidence.redaction === "object", "redaction is required");

for (const artifact of evidence.artifacts) {
  assert.ok(validArtifactTypes.has(artifact.type), `Unsupported artifact type: ${artifact.type}`);
  assert.ok(artifact.path, "artifact.path is required");
  assert.ok(artifact.sha256, `${artifact.path}.sha256 is required`);
  assert.ok(artifact.signatureStatus, `${artifact.path}.signatureStatus is required`);
  assert.ok(artifact.timestampStatus, `${artifact.path}.timestampStatus is required`);
  assert.ok(artifact.authenticodeStatus, `${artifact.path}.authenticodeStatus is required`);
}

if (evidence.status === "signed") {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "signed Windows signing evidence cannot contain placeholders");
  assert.ok(isoTimestamp.test(evidence.signedAt), "signedAt must be an ISO timestamp for signed evidence");
  assert.ok(sha256Pattern.test(evidence.releaseHost.hostnameHash), "releaseHost.hostnameHash must be a SHA-256 hex digest");
  assert.ok(thumbprintPattern.test(evidence.certificate.thumbprint), "certificate.thumbprint must be a certificate thumbprint");
  assert.ok(isoDate.test(evidence.certificate.validFrom), "certificate.validFrom must be YYYY-MM-DD");
  assert.ok(isoDate.test(evidence.certificate.validTo), "certificate.validTo must be YYYY-MM-DD");
  assert.ok(Date.parse(evidence.certificate.validTo) > Date.parse(evidence.signedAt), "certificate.validTo must be after signedAt");
  assertPassed(evidence.releaseHost.approvedHost, "releaseHost.approvedHost must be passed for signed evidence");

  for (const [name, result] of Object.entries(evidence.checks)) {
    assertPassed(result, `checks.${name} must be passed for signed evidence`);
  }

  assertFalse(evidence.redaction.containsPfxPassword, "signed evidence cannot contain a PFX password");
  assertFalse(evidence.redaction.containsPrivateKeyMaterial, "signed evidence cannot contain private key material");
  assertFalse(evidence.redaction.containsSigningToken, "signed evidence cannot contain signing tokens");

  for (const artifact of evidence.artifacts) {
    assert.ok(existsSync(artifact.path), `signed artifact does not exist: ${artifact.path}`);
    assert.ok(statSync(artifact.path).isFile(), `signed artifact must be a file: ${artifact.path}`);
    assert.ok(sha256Pattern.test(artifact.sha256), `${artifact.path}.sha256 must be a SHA-256 hex digest`);
    assert.equal(artifact.sha256, sha256FileHex(artifact.path), `${artifact.path}.sha256 does not match the artifact`);
    assertPassed(artifact.signatureStatus, `${artifact.path}.signatureStatus must be passed`);
    assertPassed(artifact.timestampStatus, `${artifact.path}.timestampStatus must be passed`);
    assertPassed(artifact.authenticodeStatus, `${artifact.path}.authenticodeStatus must be valid`);
  }
} else {
  for (const value of Object.values(evidence.checks)) {
    assert.ok(passValues.has(value) || failValues.has(value), `Unsupported signing check value: ${value}`);
  }
}

console.log(`Windows signing execution evidence validated: ${evidencePath}`);
