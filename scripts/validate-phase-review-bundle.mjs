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
const requireApprovedWaivers = args.get("--require-approved-waivers") === true || args.get("--require-approved-waivers") === "true";
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
  "phaseAttachmentInventoryMarkdown",
  "phaseWaiverRegister",
  "phaseWaiverRegisterMarkdown"
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
const phaseWaivers = JSON.parse(readFileSync(manifest.artifacts.phaseWaiverRegister.path, "utf8"));
const placeholder = /replace-with/i;

assert.equal(phaseEvidence.format, "sentinel-phase-evidence-pack-manifest-v1");
assert.equal(phaseGate.format, "sentinel-phase-gate-validation-v1");
assert.equal(phaseActions.format, "sentinel-phase-action-register-v1");
assert.equal(phaseGaps.format, "sentinel-phase-gap-matrix-v1");
assert.equal(phaseDecision.format, "sentinel-phase-decision-record-v1");
assert.equal(phaseSignoffs.format, "sentinel-phase-signoff-matrix-v1");
assert.equal(phaseIntake.format, "sentinel-phase-evidence-intake-v1");
assert.equal(phaseAttachments.format, "sentinel-phase-attachment-inventory-v1");
assert.equal(phaseWaivers.format, "sentinel-phase-waiver-register-v1");
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
assert.equal(phaseWaivers.inventoryPath, manifest.artifacts.phaseAttachmentInventory.path, "phase waiver register does not reference phase attachment inventory");
assert.equal(phaseWaivers.decisionPath, manifest.artifacts.phaseDecisionRecord.path, "phase waiver register does not reference phase decision record");
assert.equal(manifest.environment, phaseEvidence.environment, "manifest environment does not match phase evidence");
assert.equal(manifest.target, phaseEvidence.target, "manifest target does not match phase evidence");
assert.equal(manifest.ready, phaseGate.ready, "manifest ready flag does not match phase gate");
assert.equal(manifest.validated, phaseGate.validated, "manifest validated flag does not match phase gate");
assert.equal(manifest.decision, phaseDecision.decision, "manifest decision does not match phase decision record");
assert.equal(manifest.blockerCount, phaseGate.blockerCount, "manifest blocker count does not match phase gate");
assert.equal(manifest.warningCount, phaseGate.warningCount, "manifest warning count does not match phase gate");
assert.equal(manifest.remainingPhaseCount, phaseGate.remainingPhaseCount, "manifest remaining phase count does not match phase gate");
assert.equal(manifest.remainingItemCount, phaseGate.remainingItemCount, "manifest remaining item count does not match phase gate");

const today = new Date().toISOString().slice(0, 10);
const waiverSummary = {
  waiverCount: phaseWaivers.waivers.length,
  proposedCount: phaseWaivers.waivers.filter((waiver) => waiver.status === "proposed").length,
  approvedCount: phaseWaivers.waivers.filter((waiver) => waiver.status === "approved").length,
  expiredCount: phaseWaivers.waivers.filter((waiver) => waiver.expiresAt <= today).length
};
const evidenceKeySummary = {
  decisionActionEvidenceKeyCount: phaseDecision.evidenceKeySummary.actionEvidenceKeyCount,
  decisionGapEvidenceKeyCount: phaseDecision.evidenceKeySummary.gapEvidenceKeyCount,
  decisionActionEvidenceKeys: phaseDecision.evidenceKeySummary.actionEvidenceKeys,
  decisionGapEvidenceKeys: phaseDecision.evidenceKeySummary.gapEvidenceKeys,
  signoffEvidenceKeyCount: phaseSignoffs.summary.evidenceKeyCount,
  signoffEvidenceKeys: phaseSignoffs.summary.evidenceKeys,
  intakeEvidenceKeyCount: new Set(phaseIntake.intakeItems.flatMap((item) => item.evidenceKeys || [])).size,
  attachmentEvidenceKeyCount: new Set(phaseAttachments.attachments.flatMap((item) => item.evidenceKeys || [])).size,
  waivedEvidenceKeyCount: new Set(phaseWaivers.waivers.map((waiver) => waiver.evidenceKey).filter(Boolean)).size,
  waivedEvidenceKeys: [...new Set(phaseWaivers.waivers.map((waiver) => waiver.evidenceKey).filter(Boolean))].sort()
};
assert.deepEqual(evidenceKeySummary.decisionActionEvidenceKeys, evidenceKeySummary.signoffEvidenceKeys, "decision and signoff evidence keys do not match");

const commandCoverageSummary = {
  decisionActionCommandScriptCount: phaseDecision.commandCoverageSummary.actionCommandScriptCount,
  decisionGapCommandScriptCount: phaseDecision.commandCoverageSummary.gapCommandScriptCount,
  decisionValidatorCommandCount: phaseDecision.commandCoverageSummary.validatorCommandCount,
  decisionActionCommandScripts: phaseDecision.commandCoverageSummary.actionCommandScripts,
  decisionGapCommandScripts: phaseDecision.commandCoverageSummary.gapCommandScripts,
  signoffCommandScriptCount: phaseSignoffs.summary.commandScriptCount,
  signoffValidatorCommandCount: phaseSignoffs.summary.validatorCommandCount,
  signoffCommandScripts: phaseSignoffs.summary.commandScripts,
  waiverCommandScriptCount: phaseWaivers.summary.commandScriptCount,
  waiverValidatorCommandCount: phaseWaivers.summary.validatorCommandCount,
  waiverCommandScripts: phaseWaivers.summary.commandScripts
};
assert.deepEqual(commandCoverageSummary.decisionActionCommandScripts, commandCoverageSummary.signoffCommandScripts, "decision and signoff command scripts do not match");
assert.equal(commandCoverageSummary.decisionActionCommandScriptCount, commandCoverageSummary.signoffCommandScriptCount, "decision and signoff command script counts do not match");
assert.equal(commandCoverageSummary.decisionValidatorCommandCount, commandCoverageSummary.signoffValidatorCommandCount, "decision and signoff validator command counts do not match");
assert.deepEqual(commandCoverageSummary.signoffCommandScripts, commandCoverageSummary.waiverCommandScripts, "signoff and waiver command scripts do not match");
assert.equal(commandCoverageSummary.signoffCommandScriptCount, commandCoverageSummary.waiverCommandScriptCount, "signoff and waiver command script counts do not match");
assert.equal(commandCoverageSummary.signoffValidatorCommandCount, commandCoverageSummary.waiverValidatorCommandCount, "signoff and waiver validator command counts do not match");

const commandCoverageMarkdownArtifacts = [
  "phaseActionRegisterMarkdown",
  "phaseGapMatrixMarkdown",
  "phaseDecisionRecordMarkdown",
  "phaseSignoffMatrixMarkdown",
  "phaseEvidenceIntakeMarkdown",
  "phaseAttachmentInventoryMarkdown",
  "phaseWaiverRegisterMarkdown"
];
const markdownCoverageSummary = {
  artifactCount: commandCoverageMarkdownArtifacts.length,
  artifactNames: commandCoverageMarkdownArtifacts,
  commandScriptCount: commandCoverageSummary.signoffCommandScriptCount,
  validatorCommandCount: commandCoverageSummary.signoffValidatorCommandCount
};
for (const artifactName of commandCoverageMarkdownArtifacts) {
  const markdown = readFileSync(manifest.artifacts[artifactName].path, "utf8");
  assert.ok(markdown.includes("## Command Coverage Summary"), `${artifactName} must include command coverage summary`);
  for (const script of commandCoverageSummary.signoffCommandScripts) {
    assert.ok(markdown.includes(`- \`pnpm ${script}\``), `${artifactName} missing command script coverage: ${script}`);
  }
}

assert.deepEqual(manifest.waiverSummary, waiverSummary, "manifest waiver summary does not match waiver register");
assert.deepEqual(manifest.evidenceKeySummary, evidenceKeySummary, "manifest evidence key summary does not match review artifacts");
assert.deepEqual(manifest.commandCoverageSummary, commandCoverageSummary, "manifest command coverage summary does not match review artifacts");
assert.deepEqual(manifest.markdownCoverageSummary, markdownCoverageSummary, "manifest markdown coverage summary does not match review artifacts");

if (requireApprovedWaivers) {
  for (const [index, waiver] of phaseWaivers.waivers.entries()) {
    assert.equal(waiver.status, "approved", `waiver ${index + 1} must be approved for release review`);
    assert.match(waiver.expiresAt || "", /^\d{4}-\d{2}-\d{2}$/, `waiver ${index + 1} expiry must be YYYY-MM-DD`);
    assert.ok(waiver.expiresAt > today, `waiver ${index + 1} approval is expired`);
    assert.ok(waiver.approvalReference && !placeholder.test(waiver.approvalReference), `waiver ${index + 1} approval reference is required`);
    assert.ok(waiver.compensatingControl && !placeholder.test(waiver.compensatingControl), `waiver ${index + 1} compensating control is required`);
  }
}

console.log(JSON.stringify({
  format: "sentinel-phase-review-bundle-validation-v1",
  manifestPath,
  artifactCount: requiredArtifactNames.length,
  ready: manifest.ready,
  validated: true,
  blockerCount: manifest.blockerCount,
  waiverCount: waiverSummary.waiverCount,
  approvedWaiverCount: waiverSummary.approvedCount,
  decisionEvidenceKeyCount: evidenceKeySummary.decisionActionEvidenceKeyCount,
  signoffEvidenceKeyCount: evidenceKeySummary.signoffEvidenceKeyCount,
  waivedEvidenceKeyCount: evidenceKeySummary.waivedEvidenceKeyCount,
  commandScriptCount: commandCoverageSummary.signoffCommandScriptCount,
  validatorCommandCount: commandCoverageSummary.signoffValidatorCommandCount,
  commandCoverageMarkdownArtifactCount: markdownCoverageSummary.artifactCount
}, null, 2));
