import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
const args = new Map();
for (let index = 0; index < cliArgs.length; index += 1) {
  const arg = cliArgs[index];
  if (arg.startsWith("--")) {
    const next = cliArgs[index + 1];
    if (!next || next.startsWith("--")) {
      args.set(arg, true);
    } else {
      args.set(arg, next);
      index += 1;
    }
  }
}

const manifestPath = path.resolve(args.get("--manifest") || "artifacts/deployment/pilot/phase-review-bundle-manifest.json");
const requiredArtifactNames = [
  "phaseEvidenceManifest",
  "phaseGateValidation",
  "phaseGateValidationMarkdown",
  "phaseActionRegister",
  "phaseActionRegisterMarkdown",
  "phaseGapMatrix",
  "phaseGapMatrixMarkdown",
  "phaseDecisionRecord",
  "phaseDecisionRecordMarkdown",
  "phaseSignoffMatrix",
  "phaseSignoffMatrixMarkdown",
  "phaseEvidenceIntake",
  "phaseEvidenceIntakeMarkdown",
  "phaseAttachmentInventory",
  "phaseAttachmentInventoryMarkdown"
];

const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex")
  };
};

assert.ok(existsSync(manifestPath), `Phase review bundle manifest not found: ${manifestPath}`);
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

assert.equal(manifest.format, "sentinel-phase-review-bundle-manifest-v1");
assert.ok(!Number.isNaN(Date.parse(manifest.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.ok(manifest.artifacts && typeof manifest.artifacts === "object", "artifacts map is required");

for (const artifactName of requiredArtifactNames) {
  const artifact = manifest.artifacts[artifactName];
  assert.ok(artifact, `missing artifact entry: ${artifactName}`);
  assert.ok(artifact.path && typeof artifact.path === "string", `${artifactName}.path is required`);
  assert.match(artifact.sha256, /^[a-f0-9]{64}$/, `${artifactName}.sha256 must be a SHA-256 hex digest`);
  assert.ok(Number.isInteger(artifact.bytes) && artifact.bytes > 0, `${artifactName}.bytes must be a positive integer`);
  assert.ok(existsSync(artifact.path), `artifact file not found: ${artifactName}: ${artifact.path}`);

  const actual = hashFile(artifact.path);
  assert.equal(actual.bytes, artifact.bytes, `${artifactName} byte length changed`);
  assert.equal(actual.sha256, artifact.sha256, `${artifactName} SHA-256 changed`);
}

const phaseEvidence = JSON.parse(readFileSync(manifest.artifacts.phaseEvidenceManifest.path, "utf8"));
const phaseGate = JSON.parse(readFileSync(manifest.artifacts.phaseGateValidation.path, "utf8"));
const phaseActions = JSON.parse(readFileSync(manifest.artifacts.phaseActionRegister.path, "utf8"));
const phaseGaps = JSON.parse(readFileSync(manifest.artifacts.phaseGapMatrix.path, "utf8"));
const phaseDecision = JSON.parse(readFileSync(manifest.artifacts.phaseDecisionRecord.path, "utf8"));
const phaseSignoffs = JSON.parse(readFileSync(manifest.artifacts.phaseSignoffMatrix.path, "utf8"));
const phaseIntake = JSON.parse(readFileSync(manifest.artifacts.phaseEvidenceIntake.path, "utf8"));
const phaseAttachments = JSON.parse(readFileSync(manifest.artifacts.phaseAttachmentInventory.path, "utf8"));

assert.equal(phaseEvidence.format, "sentinel-phase-evidence-pack-manifest-v1");
assert.equal(phaseGate.format, "sentinel-phase-gate-validation-v1");
assert.equal(phaseActions.format, "sentinel-phase-action-register-v1");
assert.equal(phaseGaps.format, "sentinel-phase-gap-matrix-v1");
assert.equal(phaseDecision.format, "sentinel-phase-decision-record-v1");
assert.equal(phaseSignoffs.format, "sentinel-phase-signoff-matrix-v1");
assert.equal(phaseIntake.format, "sentinel-phase-evidence-intake-v1");
assert.equal(phaseAttachments.format, "sentinel-phase-attachment-inventory-v1");
assert.equal(phaseGate.paths.phaseEvidenceManifest, manifest.artifacts.phaseEvidenceManifest.path, "phase gate does not reference phase evidence manifest");
assert.equal(phaseActions.phaseGatePath, manifest.artifacts.phaseGateValidation.path, "phase action register does not reference phase gate report");
assert.equal(phaseGaps.summary.phaseCount, phaseActions.actions.length, "phase gap matrix action count does not match phase action register");
assert.equal(phaseDecision.phaseGatePath, manifest.artifacts.phaseGateValidation.path, "phase decision record does not reference phase gate report");
assert.equal(phaseDecision.actionRegisterPath, manifest.artifacts.phaseActionRegister.path, "phase decision record does not reference phase action register");
assert.equal(phaseDecision.gapMatrixPath, manifest.artifacts.phaseGapMatrix.path, "phase decision record does not reference phase gap matrix");
assert.equal(phaseSignoffs.decisionPath, manifest.artifacts.phaseDecisionRecord.path, "phase signoff matrix does not reference phase decision record");
assert.equal(phaseSignoffs.actionRegisterPath, manifest.artifacts.phaseActionRegister.path, "phase signoff matrix does not reference phase action register");
assert.equal(phaseIntake.signoffMatrixPath, manifest.artifacts.phaseSignoffMatrix.path, "phase evidence intake does not reference phase signoff matrix");
assert.equal(phaseIntake.gapMatrixPath, manifest.artifacts.phaseGapMatrix.path, "phase evidence intake does not reference phase gap matrix");
assert.equal(phaseAttachments.intakePath, manifest.artifacts.phaseEvidenceIntake.path, "phase attachment inventory does not reference phase evidence intake");
assert.equal(manifest.environment, phaseEvidence.environment, "manifest environment does not match phase evidence");
assert.equal(manifest.target, phaseEvidence.target, "manifest target does not match phase evidence");
assert.equal(manifest.ready, phaseGate.ready, "manifest ready flag does not match phase gate");
assert.equal(manifest.validated, phaseGate.validated, "manifest validated flag does not match phase gate");
assert.equal(manifest.decision, phaseDecision.decision, "manifest decision does not match phase decision record");
assert.equal(manifest.blockerCount, phaseGate.blockerCount, "manifest blocker count does not match phase gate");
assert.equal(manifest.warningCount, phaseGate.warningCount, "manifest warning count does not match phase gate");
assert.equal(manifest.remainingPhaseCount, phaseGate.remainingPhaseCount, "manifest remaining phase count does not match phase gate");
assert.equal(manifest.remainingItemCount, phaseGate.remainingItemCount, "manifest remaining item count does not match phase gate");

console.log(JSON.stringify({
  format: "sentinel-phase-review-bundle-validation-v1",
  manifestPath,
  artifactCount: requiredArtifactNames.length,
  ready: manifest.ready,
  validated: true,
  blockerCount: manifest.blockerCount
}, null, 2));
