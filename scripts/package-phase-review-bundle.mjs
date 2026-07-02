import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

const evidenceDir = path.resolve(args.get("--dir") || "artifacts/deployment/pilot");
const outputPath = path.resolve(args.get("--out") || path.join(evidenceDir, "phase-review-bundle-manifest.json"));
const requireApprovedWaivers = args.get("--require-approved-waivers") === true || args.get("--require-approved-waivers") === "true";

const artifactMap = {
  phaseEvidenceManifest: args.get("--phase-evidence") || path.join(evidenceDir, "phase-evidence-pack-manifest.json"),
  phaseGateValidation: args.get("--phase-gate") || path.join(evidenceDir, "phase-gate-validation.json"),
  phaseGateValidationMarkdown: args.get("--phase-gate-markdown") || path.join(evidenceDir, "phase-gate-validation.md"),
  phaseActionRegister: args.get("--phase-actions") || path.join(evidenceDir, "phase-action-register.json"),
  phaseActionRegisterMarkdown: args.get("--phase-actions-markdown") || path.join(evidenceDir, "phase-action-register.md"),
  phaseGapMatrix: args.get("--phase-gaps") || path.join(evidenceDir, "phase-gap-matrix.json"),
  phaseGapMatrixMarkdown: args.get("--phase-gaps-markdown") || path.join(evidenceDir, "phase-gap-matrix.md"),
  phaseDecisionRecord: args.get("--phase-decision") || path.join(evidenceDir, "phase-decision-record.json"),
  phaseDecisionRecordMarkdown: args.get("--phase-decision-markdown") || path.join(evidenceDir, "phase-decision-record.md"),
  phaseSignoffMatrix: args.get("--phase-signoffs") || path.join(evidenceDir, "phase-signoff-matrix.json"),
  phaseSignoffMatrixMarkdown: args.get("--phase-signoffs-markdown") || path.join(evidenceDir, "phase-signoff-matrix.md"),
  phaseEvidenceIntake: args.get("--phase-intake") || path.join(evidenceDir, "phase-evidence-intake.json"),
  phaseEvidenceIntakeMarkdown: args.get("--phase-intake-markdown") || path.join(evidenceDir, "phase-evidence-intake.md"),
  phaseAttachmentInventory: args.get("--phase-attachments") || path.join(evidenceDir, "phase-attachment-inventory.json"),
  phaseAttachmentInventoryMarkdown: args.get("--phase-attachments-markdown") || path.join(evidenceDir, "phase-attachment-inventory.md"),
  phaseWaiverRegister: args.get("--phase-waivers") || path.join(evidenceDir, "phase-waiver-register.json"),
  phaseWaiverRegisterMarkdown: args.get("--phase-waivers-markdown") || path.join(evidenceDir, "phase-waiver-register.md")
};

const hashFile = (filePath) => {
  const buffer = readFileSync(filePath);
  return {
    path: path.resolve(filePath),
    bytes: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex")
  };
};

for (const [name, filePath] of Object.entries(artifactMap)) {
  assert.ok(existsSync(filePath), `Missing phase review artifact ${name}: ${filePath}`);
}

const phaseEvidence = JSON.parse(readFileSync(artifactMap.phaseEvidenceManifest, "utf8"));
const phaseGate = JSON.parse(readFileSync(artifactMap.phaseGateValidation, "utf8"));
const phaseActions = JSON.parse(readFileSync(artifactMap.phaseActionRegister, "utf8"));
const phaseGaps = JSON.parse(readFileSync(artifactMap.phaseGapMatrix, "utf8"));
const phaseDecision = JSON.parse(readFileSync(artifactMap.phaseDecisionRecord, "utf8"));
const phaseSignoffs = JSON.parse(readFileSync(artifactMap.phaseSignoffMatrix, "utf8"));
const phaseIntake = JSON.parse(readFileSync(artifactMap.phaseEvidenceIntake, "utf8"));
const phaseAttachments = JSON.parse(readFileSync(artifactMap.phaseAttachmentInventory, "utf8"));
const phaseWaivers = JSON.parse(readFileSync(artifactMap.phaseWaiverRegister, "utf8"));
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
assert.equal(phaseGate.paths.phaseEvidenceManifest, path.resolve(artifactMap.phaseEvidenceManifest), "phase gate does not reference selected phase evidence manifest");
assert.equal(phaseActions.phaseGatePath, path.resolve(artifactMap.phaseGateValidation), "phase action register does not reference selected phase gate report");
assert.equal(phaseGaps.summary.phaseCount, phaseActions.actions.length, "phase gap matrix action count does not match phase action register");
assert.equal(phaseDecision.phaseGatePath, path.resolve(artifactMap.phaseGateValidation), "phase decision record does not reference selected phase gate report");
assert.equal(phaseDecision.actionRegisterPath, path.resolve(artifactMap.phaseActionRegister), "phase decision record does not reference selected phase action register");
assert.equal(phaseDecision.gapMatrixPath, path.resolve(artifactMap.phaseGapMatrix), "phase decision record does not reference selected phase gap matrix");
assert.equal(phaseSignoffs.decisionPath, path.resolve(artifactMap.phaseDecisionRecord), "phase signoff matrix does not reference selected phase decision record");
assert.equal(phaseSignoffs.actionRegisterPath, path.resolve(artifactMap.phaseActionRegister), "phase signoff matrix does not reference selected phase action register");
assert.equal(phaseIntake.signoffMatrixPath, path.resolve(artifactMap.phaseSignoffMatrix), "phase evidence intake does not reference selected phase signoff matrix");
assert.equal(phaseIntake.gapMatrixPath, path.resolve(artifactMap.phaseGapMatrix), "phase evidence intake does not reference selected phase gap matrix");
assert.equal(phaseAttachments.intakePath, path.resolve(artifactMap.phaseEvidenceIntake), "phase attachment inventory does not reference selected phase evidence intake");
assert.equal(phaseWaivers.inventoryPath, path.resolve(artifactMap.phaseAttachmentInventory), "phase waiver register does not reference selected phase attachment inventory");
assert.equal(phaseWaivers.decisionPath, path.resolve(artifactMap.phaseDecisionRecord), "phase waiver register does not reference selected phase decision record");

const today = new Date().toISOString().slice(0, 10);
const waiverSummary = {
  waiverCount: phaseWaivers.waivers.length,
  proposedCount: phaseWaivers.waivers.filter((waiver) => waiver.status === "proposed").length,
  approvedCount: phaseWaivers.waivers.filter((waiver) => waiver.status === "approved").length,
  expiredCount: phaseWaivers.waivers.filter((waiver) => waiver.expiresAt <= today).length
};
const evidenceKeySummary = {
  intakeEvidenceKeyCount: new Set(phaseIntake.intakeItems.flatMap((item) => item.evidenceKeys || [])).size,
  attachmentEvidenceKeyCount: new Set(phaseAttachments.attachments.flatMap((item) => item.evidenceKeys || [])).size,
  waivedEvidenceKeyCount: new Set(phaseWaivers.waivers.map((waiver) => waiver.evidenceKey).filter(Boolean)).size,
  waivedEvidenceKeys: [...new Set(phaseWaivers.waivers.map((waiver) => waiver.evidenceKey).filter(Boolean))].sort()
};

if (requireApprovedWaivers) {
  for (const [index, waiver] of phaseWaivers.waivers.entries()) {
    assert.equal(waiver.status, "approved", `waiver ${index + 1} must be approved for release review`);
    assert.match(waiver.expiresAt || "", /^\d{4}-\d{2}-\d{2}$/, `waiver ${index + 1} expiry must be YYYY-MM-DD`);
    assert.ok(waiver.expiresAt > today, `waiver ${index + 1} approval is expired`);
    assert.ok(waiver.approvalReference && !placeholder.test(waiver.approvalReference), `waiver ${index + 1} approval reference is required`);
    assert.ok(waiver.compensatingControl && !placeholder.test(waiver.compensatingControl), `waiver ${index + 1} compensating control is required`);
  }
}

const artifacts = Object.fromEntries(Object.entries(artifactMap).map(([name, filePath]) => [name, hashFile(filePath)]));
const manifest = {
  format: "sentinel-phase-review-bundle-manifest-v1",
  generatedAt: new Date().toISOString(),
  evidenceDir,
  environment: phaseEvidence.environment,
  target: phaseEvidence.target,
  ready: phaseGate.ready,
  validated: phaseGate.validated,
  decision: phaseDecision.decision,
  blockerCount: phaseGate.blockerCount,
  warningCount: phaseGate.warningCount,
  remainingPhaseCount: phaseGate.remainingPhaseCount,
  remainingItemCount: phaseGate.remainingItemCount,
  waiverPolicy: {
    requireApprovedWaivers
  },
  waiverSummary,
  evidenceKeySummary,
  artifacts
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(manifest, null, 2));

console.log(JSON.stringify({
  format: "sentinel-phase-review-bundle-result-v1",
  outputPath,
  artifactCount: Object.keys(artifacts).length,
  ready: manifest.ready,
  validated: manifest.validated,
  blockerCount: manifest.blockerCount,
  waiverCount: manifest.waiverSummary.waiverCount,
  approvedWaiverCount: manifest.waiverSummary.approvedCount,
  waivedEvidenceKeyCount: manifest.evidenceKeySummary.waivedEvidenceKeyCount
}, null, 2));
