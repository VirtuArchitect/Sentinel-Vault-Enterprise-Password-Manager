import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/windows-release-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
const allowedCheckResults = new Set(["passed", "failed", "not-run", "not-applicable", "valid", "not-signed"]);
const strictSignatureResults = new Set(["valid", "passed"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoDate = /^\d{4}-\d{2}-\d{2}$/;
const sha256Pattern = /^[a-f0-9]{64}$/i;
const gitShaPattern = /^[a-f0-9]{7,40}$/i;
const thumbprintPattern = /^[a-f0-9]{40,64}$/i;
const signedExtensions = /\.(exe|msi|msix)$/i;
const signedRelease = strictSignatureResults.has(evidence.checks?.signatureVerification);
const plannedPlaceholder = (value) => placeholder.test(String(value || ""));

assert.equal(evidence.format, "sentinel-windows-release-evidence-v1");
assert.ok(evidence.releaseVersion, "releaseVersion is required");
assert.ok(evidence.releaseDate, "releaseDate is required");
assert.ok(evidence.buildHost, "buildHost is required");
assert.ok(evidence.sourceCommit, "sourceCommit is required");
assert.ok(evidence.checks && typeof evidence.checks === "object", "checks are required");
assert.ok(evidence.packageValidation && typeof evidence.packageValidation === "object", "packageValidation is required");
assert.equal(evidence.packageValidation.format, "sentinel-windows-package-validation-v1", "packageValidation.format must be sentinel-windows-package-validation-v1");
assert.ok(Array.isArray(evidence.artifacts), "artifacts must be an array");
assert.ok(evidence.artifacts.length > 0, "at least one artifact is required");
assert.ok(evidence.approvals?.releaseOwner, "releaseOwner approval is required");
assert.ok(evidence.approvals?.securityReviewer, "securityReviewer approval is required");
assert.ok(evidence.approvals?.operationsReviewer, "operationsReviewer approval is required");
assert.ok(evidence.rollback?.procedure, "rollback.procedure is required");

for (const [name, result] of Object.entries(evidence.checks)) {
  if (!signedRelease && plannedPlaceholder(result)) continue;
  assert.ok(allowedCheckResults.has(result), `Unsupported check result for ${name}`);
}

for (const artifact of evidence.artifacts) {
  assert.ok(artifact.name, "artifact.name is required");
  assert.ok(artifact.sha256, `${artifact.name}.sha256 is required`);
  assert.ok(artifact.authenticodeStatus, `${artifact.name}.authenticodeStatus is required`);
  assert.ok(artifact.signerThumbprint, `${artifact.name}.signerThumbprint is required`);
}

if (signedRelease) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "signed release evidence cannot contain placeholders");
  assert.ok(isoDate.test(evidence.releaseDate), "releaseDate must be YYYY-MM-DD for signed releases");
  assert.ok(gitShaPattern.test(evidence.sourceCommit), "sourceCommit must be a Git SHA for signed releases");
  assert.equal(evidence.checks.pnpmVerify, "passed", "pnpmVerify must pass for signed releases");
  assert.equal(evidence.checks.secretScan, "passed", "secretScan must pass for signed releases");
  assert.equal(evidence.checks.dependencyAudit, "passed", "dependencyAudit must pass for signed releases");
  assert.equal(evidence.checks.windowsPackage, "passed", "windowsPackage must pass for signed releases");
  assert.equal(evidence.packageValidation.validated, true, "packageValidation.validated must be true for signed releases");
  assert.ok(sha256Pattern.test(evidence.packageValidation.packageSha256 || ""), "packageValidation.packageSha256 must be a SHA-256 hex digest");
  assert.ok(["passed", "skipped"].includes(evidence.packageValidation.runtimeSmoke), "packageValidation.runtimeSmoke must be passed or skipped for signed releases");
  assert.ok(evidence.packageValidation.requiredFileCount >= 15, "packageValidation.requiredFileCount must cover the Windows package manifest");
  assert.equal(evidence.rollback.tested, true, "rollback must be tested for signed releases");

  const validatedPackageArtifact = evidence.artifacts.find((artifact) => artifact.sha256 === evidence.packageValidation.packageSha256);
  assert.ok(validatedPackageArtifact, "packageValidation.packageSha256 must match a release artifact");

  for (const artifact of evidence.artifacts) {
    assert.ok(sha256Pattern.test(artifact.sha256), `${artifact.name}.sha256 must be a SHA-256 hex digest`);
    if (signedExtensions.test(artifact.name)) {
      assert.equal(artifact.authenticodeStatus, "Valid", `${artifact.name} must have a valid Authenticode signature`);
      assert.ok(thumbprintPattern.test(artifact.signerThumbprint), `${artifact.name}.signerThumbprint must be a certificate thumbprint`);
    }
  }
}

console.log(`Windows release evidence validated: ${evidencePath}`);
