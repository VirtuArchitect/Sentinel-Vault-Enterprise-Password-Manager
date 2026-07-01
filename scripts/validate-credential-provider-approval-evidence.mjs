import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/credential-provider-approval-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
const allowedStatuses = new Set(["planned", "approved", "retired"]);
const allowedArchitectures = new Set(["x64", "arm64"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const clsidPattern = /^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$/i;
const sha256Pattern = /^[a-f0-9]{64}$/i;
const thumbprintPattern = /^[a-f0-9]{40,64}$/i;
const passValues = new Set(["passed", "approved", true]);
const plannedValues = new Set(["planned", "pending", "not-applicable", false]);
const sha256FileHex = (filePath) => crypto.createHash("sha256").update(readFileSync(filePath)).digest("hex");
const assertPassed = (value, message) => assert.ok(passValues.has(value), message);
const assertFalse = (value, message) => assert.equal(value, false, message);

assert.equal(evidence.format, "sentinel-credential-provider-approval-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported credential provider approval status");
assert.ok(evidence.environment, "environment is required");
assert.equal(evidence.component, "windows-credential-provider");
assert.ok(evidence.implementation?.approvalReference, "implementation.approvalReference is required");
assert.ok(allowedArchitectures.has(evidence.implementation?.architecture), "Unsupported credential provider architecture");
assert.ok(evidence.implementation?.clsid, "implementation.clsid is required");
assert.ok(evidence.implementation?.registrationPath, "implementation.registrationPath is required");
assert.ok(evidence.releaseEvidence?.nativeCompanionEvidencePath, "releaseEvidence.nativeCompanionEvidencePath is required");
assert.ok(evidence.releaseEvidence?.signedCredentialProviderArtifact, "releaseEvidence.signedCredentialProviderArtifact is required");
assert.ok(evidence.releaseEvidence?.artifactSha256, "releaseEvidence.artifactSha256 is required");
assert.ok(evidence.releaseEvidence?.authenticodeStatus, "releaseEvidence.authenticodeStatus is required");
assert.ok(evidence.releaseEvidence?.signerThumbprint, "releaseEvidence.signerThumbprint is required");
assert.ok(evidence.approvals?.windowsEndpointSecurityOwner, "approvals.windowsEndpointSecurityOwner is required");
assert.ok(evidence.approvals?.securityReviewer, "approvals.securityReviewer is required");
assert.ok(evidence.approvals?.desktopEngineeringOwner, "approvals.desktopEngineeringOwner is required");
assert.ok(evidence.approvals?.releaseOwner, "approvals.releaseOwner is required");
assert.ok(evidence.approvals?.changeTicket, "approvals.changeTicket is required");

const reviewedValues = [
  ...Object.values(evidence.implementation || {}).filter((value) => typeof value !== "string" || ["planned", "pending", "not-applicable", "passed", "approved"].includes(value)),
  ...Object.values(evidence.riskReview || {}),
  evidence.releaseEvidence.cleanInstall,
  evidence.releaseEvidence.cleanUninstall,
  evidence.releaseEvidence.rollbackDisable
];
for (const value of reviewedValues) {
  assert.ok(passValues.has(value) || plannedValues.has(value), `Unsupported credential provider approval value: ${value}`);
}

if (evidence.status === "approved") {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "approved credential provider evidence cannot contain placeholders");
  assert.ok(clsidPattern.test(evidence.implementation.clsid), "implementation.clsid must be a CLSID");
  assert.ok(evidence.implementation.registrationPath.includes(evidence.implementation.clsid), "registrationPath must include the credential provider CLSID");
  assert.ok(existsSync(evidence.releaseEvidence.nativeCompanionEvidencePath), "native companion evidence path must exist");
  assert.ok(existsSync(evidence.releaseEvidence.signedCredentialProviderArtifact), "signed credential provider artifact must exist");
  assert.ok(statSync(evidence.releaseEvidence.signedCredentialProviderArtifact).isFile(), "signed credential provider artifact must be a file");
  assert.ok(sha256Pattern.test(evidence.releaseEvidence.artifactSha256), "artifactSha256 must be a SHA-256 hex digest");
  assert.equal(evidence.releaseEvidence.artifactSha256, sha256FileHex(evidence.releaseEvidence.signedCredentialProviderArtifact), "artifactSha256 does not match artifact bytes");
  assert.equal(evidence.releaseEvidence.authenticodeStatus, "Valid", "credential provider artifact must have a valid Authenticode signature");
  assert.ok(thumbprintPattern.test(evidence.releaseEvidence.signerThumbprint), "signerThumbprint must be a certificate thumbprint");

  for (const [name, value] of Object.entries(evidence.implementation)) {
    if (["approvalReference", "architecture", "clsid", "registrationPath"].includes(name)) continue;
    assertPassed(value, `implementation.${name} must be passed`);
  }
  for (const [name, value] of Object.entries(evidence.riskReview || {})) {
    assertPassed(value, `riskReview.${name} must be passed`);
  }
  assertPassed(evidence.releaseEvidence.cleanInstall, "releaseEvidence.cleanInstall must be passed");
  assertPassed(evidence.releaseEvidence.cleanUninstall, "releaseEvidence.cleanUninstall must be passed");
  assertPassed(evidence.releaseEvidence.rollbackDisable, "releaseEvidence.rollbackDisable must be passed");
  assertFalse(evidence.redaction.containsCredentialMaterial, "approved evidence cannot contain credential material");
  assertFalse(evidence.redaction.containsSessionTokens, "approved evidence cannot contain session tokens");
  assertFalse(evidence.redaction.containsCustomerData, "approved evidence cannot contain customer data");
  assertFalse(evidence.redaction.containsPrivateKeyMaterial, "approved evidence cannot contain private key material");
}

console.log(`Credential provider approval evidence validated: ${evidencePath}`);
