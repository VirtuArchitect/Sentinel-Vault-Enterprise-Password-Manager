import assert from "node:assert/strict";
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
const phaseGatePath = path.resolve(args.get("--phase-gate") || path.join(evidenceDir, "phase-gate-validation.json"));
const actionRegisterPath = path.resolve(args.get("--phase-actions") || path.join(evidenceDir, "phase-action-register.json"));
const gapMatrixPath = path.resolve(args.get("--phase-gaps") || path.join(evidenceDir, "phase-gap-matrix.json"));
const outputPath = path.resolve(args.get("--out") || path.join(evidenceDir, "phase-decision-record.json"));
const markdownPath = path.resolve(args.get("--markdown-out") || path.join(evidenceDir, "phase-decision-record.md"));

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

assert.ok(existsSync(phaseGatePath), `Phase gate report not found: ${phaseGatePath}`);
assert.ok(existsSync(actionRegisterPath), `Phase action register not found: ${actionRegisterPath}`);
assert.ok(existsSync(gapMatrixPath), `Phase gap matrix not found: ${gapMatrixPath}`);

const phaseGate = readJson(phaseGatePath);
const actionRegister = readJson(actionRegisterPath);
const gapMatrix = readJson(gapMatrixPath);

assert.equal(phaseGate.format, "sentinel-phase-gate-validation-v1");
assert.equal(actionRegister.format, "sentinel-phase-action-register-v1");
assert.equal(gapMatrix.format, "sentinel-phase-gap-matrix-v1");
assert.equal(actionRegister.phaseGatePath, phaseGatePath, "phase action register does not reference selected phase gate report");
assert.equal(gapMatrix.summary.phaseCount, actionRegister.actions.length, "phase gap matrix action count does not match phase action register");

const pendingActions = actionRegister.actions.filter((action) => action.status !== "complete");
const actionEvidenceKeys = [...new Set(actionRegister.actions.flatMap((action) => action.evidenceKeys || []))].sort();
const gapEvidenceKeys = [...new Set(gapMatrix.phases.flatMap((phase) => phase.evidenceKeys || []))].sort();
const missingArtifacts = gapMatrix.phases.flatMap((phase) => (
  phase.templateMappings
    .filter((mapping) => !mapping.exists)
    .map((mapping) => ({
      phase: phase.phase,
      title: phase.title,
      templatePath: mapping.templatePath,
      evidenceKey: mapping.evidenceKey || null,
      phaseEvidenceKeys: phase.evidenceKeys || []
    }))
));
const ownerRoles = [...new Set(actionRegister.actions.map((action) => action.ownerRole))];
const decision = phaseGate.ready && pendingActions.length === 0 && missingArtifacts.length === 0
  ? "approve-phase-closure"
  : "hold-phase-closure";

const record = {
  format: "sentinel-phase-decision-record-v1",
  generatedAt: new Date().toISOString(),
  evidenceDir,
  phaseGatePath,
  actionRegisterPath,
  gapMatrixPath,
  environment: gapMatrix.environment,
  owner: gapMatrix.owner,
  status: gapMatrix.status,
  target: phaseGate.target || gapMatrix.status,
  decision,
  ready: phaseGate.ready,
  validated: phaseGate.validated,
  blockerCount: phaseGate.blockerCount,
  warningCount: phaseGate.warningCount,
  remainingPhaseCount: phaseGate.remainingPhaseCount,
  remainingItemCount: phaseGate.remainingItemCount,
  pendingActionCount: pendingActions.length,
  missingArtifactCount: missingArtifacts.length,
  evidenceKeySummary: {
    actionEvidenceKeyCount: actionEvidenceKeys.length,
    gapEvidenceKeyCount: gapEvidenceKeys.length,
    actionEvidenceKeys,
    gapEvidenceKeys
  },
  ownerRoles,
  requiredApprovals: ownerRoles.map((ownerRole) => {
    const actions = actionRegister.actions.filter((action) => action.ownerRole === ownerRole);
    return {
      ownerRole,
      status: decision === "approve-phase-closure" ? "required-before-release" : "blocked-until-evidence-complete",
      evidenceKeys: [...new Set(actions.flatMap((action) => action.evidenceKeys || []))].sort()
    };
  }),
  pendingActions: pendingActions.map((action) => ({
    id: action.id,
    phase: action.phase,
    title: action.title,
    ownerRole: action.ownerRole,
    blockerType: action.blockerType,
    status: action.status,
    evidenceKeys: action.evidenceKeys || []
  })),
  missingArtifacts
};

const renderMarkdown = () => `# Sentinel Vault Phase Decision Record

Environment: ${record.environment}
Target: ${record.target}
Decision: ${record.decision}
Generated: ${record.generatedAt}

Readiness:
- Gate ready: ${record.ready}
- Gate validated: ${record.validated}
- Blockers: ${record.blockerCount}
- Warnings: ${record.warningCount}
- Remaining phases: ${record.remainingPhaseCount}
- Remaining items: ${record.remainingItemCount}
- Pending owner actions: ${record.pendingActionCount}
- Missing mapped artifacts: ${record.missingArtifactCount}
- Action evidence keys: ${record.evidenceKeySummary.actionEvidenceKeyCount}
- Gap evidence keys: ${record.evidenceKeySummary.gapEvidenceKeyCount}

Required approvals:
${record.requiredApprovals.map((approval) => `- ${approval.ownerRole}: ${approval.status} (${approval.evidenceKeys.join(", ")})`).join("\n")}

Pending actions:
${record.pendingActions.length > 0 ? record.pendingActions.map((action) => `- ${action.id}: ${action.phase} - ${action.title} (${action.ownerRole}; ${action.evidenceKeys.join(", ")})`).join("\n") : "- none"}
`;

mkdirSync(path.dirname(outputPath), { recursive: true });
mkdirSync(path.dirname(markdownPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(record, null, 2));
writeFileSync(markdownPath, renderMarkdown());

console.log(JSON.stringify({
  format: "sentinel-phase-decision-record-result-v1",
  outputPath,
  markdownPath,
  decision,
  ready: record.ready,
  pendingActionCount: record.pendingActionCount,
  blockerCount: record.blockerCount
}, null, 2));
