import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/native-companion-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

const allowedStatuses = new Set(["planned", "pilot", "production", "suspended"]);
const deployedStatuses = new Set(["pilot", "production"]);
const allowedArchitectures = new Set(["x64", "arm64"]);
const allowedArtifactTypes = new Set(["companion-exe", "native-messaging-host", "credential-provider-dll", "installer"]);
const allowedResultValues = new Set(["passed", "failed", "not-run", "not-applicable"]);
const allowedControlValues = new Set(["passed", "failed", "planned", "not-applicable"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoDate = /^\d{4}-\d{2}-\d{2}$/;
const sha256Pattern = /^[a-f0-9]{64}$/i;
const gitShaPattern = /^[a-f0-9]{7,40}$/i;
const thumbprintPattern = /^[a-f0-9]{40,64}$/i;
const extensionIdPattern = /^[a-p]{32}$/;
const clsidPattern = /^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$/i;
const signedNativeArtifact = /\.(exe|dll|msi|msix)$/i;

assert.equal(evidence.format, "sentinel-native-companion-evidence-v1");
assert.equal(evidence.component, "windows-companion");
assert.ok(allowedStatuses.has(evidence.releaseStatus), "Unsupported releaseStatus");
assert.ok(evidence.releaseVersion, "releaseVersion is required");
assert.ok(evidence.releaseDate, "releaseDate is required");
assert.ok(evidence.buildHost, "buildHost is required");
assert.ok(evidence.sourceCommit, "sourceCommit is required");
assert.ok(Array.isArray(evidence.architectures), "architectures must be an array");
assert.ok(evidence.architectures.length > 0, "at least one architecture is required");
assert.ok(Array.isArray(evidence.artifacts), "artifacts must be an array");
assert.ok(evidence.artifacts.length > 0, "at least one native artifact is required");
assert.ok(evidence.artifactValidation && typeof evidence.artifactValidation === "object", "artifactValidation is required");
assert.equal(
  evidence.artifactValidation.format,
  "sentinel-native-release-artifact-validation-v1",
  "artifactValidation.format must be sentinel-native-release-artifact-validation-v1"
);
assert.ok(Array.isArray(evidence.artifactValidation.artifacts), "artifactValidation.artifacts must be an array");
assert.ok(evidence.securityControls && typeof evidence.securityControls === "object", "securityControls are required");
assert.ok(evidence.testResults && typeof evidence.testResults === "object", "testResults are required");
assert.ok(evidence.rollback?.disableProcedure, "rollback.disableProcedure is required");
assert.ok(evidence.approvals?.securityReviewer, "securityReviewer approval is required");
assert.ok(evidence.approvals?.desktopEngineering, "desktopEngineering approval is required");
assert.ok(evidence.approvals?.releaseOwner, "releaseOwner approval is required");
assert.ok(evidence.approvals?.changeTicket, "changeTicket approval is required");

for (const architecture of evidence.architectures) {
  assert.ok(allowedArchitectures.has(architecture), `Unsupported architecture: ${architecture}`);
}

for (const artifact of evidence.artifacts) {
  assert.ok(artifact.name, "artifact.name is required");
  assert.ok(allowedArtifactTypes.has(artifact.type), `Unsupported artifact type: ${artifact.type}`);
  assert.ok(artifact.sha256, `${artifact.name}.sha256 is required`);
  assert.ok(artifact.authenticodeStatus, `${artifact.name}.authenticodeStatus is required`);
  assert.ok(artifact.signerThumbprint, `${artifact.name}.signerThumbprint is required`);
}

for (const [name, result] of Object.entries(evidence.securityControls)) {
  assert.ok(allowedControlValues.has(result), `Unsupported security control result for ${name}`);
}

for (const [name, result] of Object.entries(evidence.testResults)) {
  assert.ok(allowedResultValues.has(result), `Unsupported test result for ${name}`);
}

if (evidence.nativeMessaging?.enabled) {
  assert.ok(evidence.nativeMessaging.manifestPath, "nativeMessaging.manifestPath is required when native messaging is enabled");
  assert.ok(evidence.nativeMessaging.hostPath, "nativeMessaging.hostPath is required when native messaging is enabled");
  assert.ok(Array.isArray(evidence.nativeMessaging.allowedExtensionIds), "nativeMessaging.allowedExtensionIds must be an array");
  assert.ok(evidence.nativeMessaging.allowedExtensionIds.length > 0, "native messaging requires at least one allowed extension ID");
}

if (evidence.credentialProvider?.enabled) {
  assert.ok(evidence.credentialProvider.clsid, "credentialProvider.clsid is required when enabled");
  assert.ok(evidence.credentialProvider.registrationPath, "credentialProvider.registrationPath is required when enabled");
  assert.equal(evidence.credentialProvider.allowListedVaultEntriesOnly, true, "credential provider must only allow listed vault entries");
}

if (deployedStatuses.has(evidence.releaseStatus)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "deployed native companion evidence cannot contain placeholders");
  assert.ok(isoDate.test(evidence.releaseDate), "releaseDate must be YYYY-MM-DD for deployed evidence");
  assert.ok(gitShaPattern.test(evidence.sourceCommit), "sourceCommit must be a Git SHA for deployed evidence");
  assert.equal(evidence.rollback.tested, true, "rollback must be tested for deployed native companion evidence");

  for (const artifact of evidence.artifacts) {
    assert.ok(sha256Pattern.test(artifact.sha256), `${artifact.name}.sha256 must be a SHA-256 hex digest`);
    const validatedArtifact = evidence.artifactValidation.artifacts.find((candidate) => candidate.name === artifact.name);
    assert.ok(validatedArtifact, `${artifact.name} must be present in artifactValidation.artifacts`);
    assert.equal(validatedArtifact.type, artifact.type, `${artifact.name}.type must match artifact validation`);
    assert.equal(validatedArtifact.sha256, artifact.sha256, `${artifact.name}.sha256 must match artifact validation`);
    if (signedNativeArtifact.test(artifact.name)) {
      assert.equal(artifact.authenticodeStatus, "Valid", `${artifact.name} must have a valid Authenticode signature`);
      assert.ok(thumbprintPattern.test(artifact.signerThumbprint), `${artifact.name}.signerThumbprint must be a certificate thumbprint`);
      assert.equal(validatedArtifact.authenticodeStatus, "Valid", `${artifact.name} artifact validation must have a valid Authenticode signature`);
    }
  }

  assert.ok(evidence.artifactValidation.reportPath, "artifactValidation.reportPath is required for deployed evidence");
  assert.equal(evidence.artifactValidation.validated, true, "artifactValidation.validated must be true for deployed evidence");
  assert.equal(evidence.artifactValidation.requireSignature, true, "artifactValidation.requireSignature must be true for deployed evidence");
  assert.ok(evidence.artifactValidation.artifactCount >= evidence.artifacts.length, "artifactValidation.artifactCount must cover native artifacts");

  if (evidence.nativeMessaging?.enabled) {
    for (const extensionId of evidence.nativeMessaging.allowedExtensionIds) {
      assert.ok(extensionIdPattern.test(extensionId), `nativeMessaging.allowedExtensionIds contains an invalid extension ID: ${extensionId}`);
    }
  }

  if (evidence.credentialProvider?.enabled) {
    assert.ok(clsidPattern.test(evidence.credentialProvider.clsid), "credentialProvider.clsid must be a CLSID");
    assert.equal(evidence.credentialProvider.offlineLogonDocumented, true, "credential-provider offline logon behavior must be documented");
  }

  for (const [name, result] of Object.entries(evidence.securityControls)) {
    assert.ok(["passed", "not-applicable"].includes(result), `${name} must be passed or not-applicable for deployed evidence`);
  }

  assert.equal(evidence.testResults.cleanInstall, "passed", "cleanInstall must pass for deployed evidence");
  assert.equal(evidence.testResults.cleanUninstall, "passed", "cleanUninstall must pass for deployed evidence");
  assert.equal(evidence.testResults.abuseCaseSuite, "passed", "abuseCaseSuite must pass for deployed evidence");
  assert.equal(evidence.testResults.autotypeReview, "passed", "autotypeReview must pass for deployed evidence");
  assert.equal(evidence.testResults.offlineCacheExpiry, "passed", "offlineCacheExpiry must pass for deployed evidence");
  assert.equal(evidence.testResults.rollbackDisable, "passed", "rollbackDisable must pass for deployed evidence");
}

console.log(`Native companion evidence validated: ${evidencePath}`);
