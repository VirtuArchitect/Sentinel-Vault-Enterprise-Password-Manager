import assert from "node:assert/strict";
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

const recordPath = path.resolve(args.get("--record") || "artifacts/deployment/pilot/phase-decision-record.json");
const markdownPath = args.get("--markdown") ? path.resolve(args.get("--markdown")) : null;
const phaseGatePath = args.get("--phase-gate") ? path.resolve(args.get("--phase-gate")) : null;
const actionRegisterPath = args.get("--phase-actions") ? path.resolve(args.get("--phase-actions")) : null;
const gapMatrixPath = args.get("--phase-gaps") ? path.resolve(args.get("--phase-gaps")) : null;

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

assert.ok(existsSync(recordPath), `Phase decision record not found: ${recordPath}`);
const record = readJson(recordPath);

assert.equal(record.format, "sentinel-phase-decision-record-v1");
assert.ok(!Number.isNaN(Date.parse(record.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.ok(record.environment, "environment is required");
assert.ok(record.owner, "owner is required");
assert.ok(record.status, "status is required");
assert.ok(record.target, "target is required");
assert.ok(["approve-phase-closure", "hold-phase-closure"].includes(record.decision), "unsupported decision");
assert.ok(Array.isArray(record.requiredApprovals), "requiredApprovals must be an array");
assert.ok(Array.isArray(record.pendingActions), "pendingActions must be an array");
assert.ok(Array.isArray(record.missingArtifacts), "missingArtifacts must be an array");

const gatePath = phaseGatePath || record.phaseGatePath;
const actionsPath = actionRegisterPath || record.actionRegisterPath;
const gapsPath = gapMatrixPath || record.gapMatrixPath;

const phaseGate = readJson(gatePath);
const actionRegister = readJson(actionsPath);
const gapMatrix = readJson(gapsPath);

assert.equal(phaseGate.format, "sentinel-phase-gate-validation-v1");
assert.equal(actionRegister.format, "sentinel-phase-action-register-v1");
assert.equal(gapMatrix.format, "sentinel-phase-gap-matrix-v1");
assert.equal(record.phaseGatePath, gatePath, "record phase gate path mismatch");
assert.equal(record.actionRegisterPath, actionsPath, "record action register path mismatch");
assert.equal(record.gapMatrixPath, gapsPath, "record gap matrix path mismatch");
assert.equal(actionRegister.phaseGatePath, gatePath, "phase action register does not reference selected phase gate report");
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
const expectedDecision = phaseGate.ready && pendingActions.length === 0 && missingArtifacts.length === 0
  ? "approve-phase-closure"
  : "hold-phase-closure";

assert.equal(record.environment, gapMatrix.environment, "environment mismatch");
assert.equal(record.owner, gapMatrix.owner, "owner mismatch");
assert.equal(record.status, gapMatrix.status, "status mismatch");
assert.equal(record.target, phaseGate.target || gapMatrix.status, "target mismatch");
assert.equal(record.decision, expectedDecision, "decision does not match gate and action state");
assert.equal(record.ready, phaseGate.ready, "ready flag mismatch");
assert.equal(record.validated, phaseGate.validated, "validated flag mismatch");
assert.equal(record.blockerCount, phaseGate.blockerCount, "blocker count mismatch");
assert.equal(record.warningCount, phaseGate.warningCount, "warning count mismatch");
assert.equal(record.remainingPhaseCount, phaseGate.remainingPhaseCount, "remaining phase count mismatch");
assert.equal(record.remainingItemCount, phaseGate.remainingItemCount, "remaining item count mismatch");
assert.equal(record.pendingActionCount, pendingActions.length, "pending action count mismatch");
assert.equal(record.missingArtifactCount, missingArtifacts.length, "missing artifact count mismatch");
assert.deepEqual(record.evidenceKeySummary, {
  actionEvidenceKeyCount: actionEvidenceKeys.length,
  gapEvidenceKeyCount: gapEvidenceKeys.length,
  actionEvidenceKeys,
  gapEvidenceKeys
}, "evidence key summary mismatch");
assert.deepEqual(record.commandCoverageSummary, {
  actionCommandScriptCount: actionRegister.summary.commandScriptCount || 0,
  gapCommandScriptCount: gapMatrix.summary.commandScriptCount || 0,
  validatorCommandCount: gapMatrix.summary.validatorCommandCount || actionRegister.summary.validatorCommandCount || 0,
  actionCommandScripts: actionRegister.summary.commandScripts || [],
  gapCommandScripts: gapMatrix.summary.commandScripts || []
}, "command coverage summary mismatch");
assert.deepEqual(record.commandCoverageSummary.actionCommandScripts, record.commandCoverageSummary.gapCommandScripts, "action and gap command scripts mismatch");

if (markdownPath) {
  assert.ok(existsSync(markdownPath), `Phase decision record markdown not found: ${markdownPath}`);
  const markdown = readFileSync(markdownPath, "utf8");
  assert.ok(markdown.includes("## Command Coverage Summary"), "markdown must include command coverage summary");
  assert.ok(markdown.includes(`- Action command scripts: ${record.commandCoverageSummary.actionCommandScriptCount}`), "markdown action command script count mismatch");
  assert.ok(markdown.includes(`- Gap command scripts: ${record.commandCoverageSummary.gapCommandScriptCount}`), "markdown gap command script count mismatch");
  assert.ok(markdown.includes(`- Validator commands: ${record.commandCoverageSummary.validatorCommandCount}`), "markdown validator command count mismatch");
  for (const script of record.commandCoverageSummary.actionCommandScripts) {
    assert.ok(markdown.includes(`- \`pnpm ${script}\``), `markdown missing action command script coverage: ${script}`);
  }
  for (const script of record.commandCoverageSummary.gapCommandScripts) {
    assert.ok(markdown.includes(`- \`pnpm ${script}\``), `markdown missing gap command script coverage: ${script}`);
  }
}

assert.deepEqual(record.ownerRoles, ownerRoles, "owner roles mismatch");
assert.equal(record.requiredApprovals.length, ownerRoles.length, "required approval count mismatch");

record.requiredApprovals.forEach((approval, index) => {
  const ownerRole = ownerRoles[index];
  const actions = actionRegister.actions.filter((action) => action.ownerRole === ownerRole);
  assert.equal(approval.ownerRole, ownerRole, `required approval ${index + 1} owner role mismatch`);
  assert.deepEqual(approval.evidenceKeys, [...new Set(actions.flatMap((action) => action.evidenceKeys || []))].sort(), `required approval ${index + 1} evidence key mismatch`);
});

record.pendingActions.forEach((pendingAction, index) => {
  const action = pendingActions[index];
  assert.ok(action, `pending action ${index + 1} is stale`);
  assert.equal(pendingAction.id, action.id, `pending action ${index + 1} id mismatch`);
  assert.equal(pendingAction.title, action.title, `pending action ${index + 1} title mismatch`);
  assert.equal(pendingAction.status, action.status, `pending action ${index + 1} status mismatch`);
  assert.deepEqual(pendingAction.evidenceKeys, action.evidenceKeys || [], `pending action ${index + 1} evidence key mismatch`);
});
assert.deepEqual(record.missingArtifacts, missingArtifacts, "missing artifacts mismatch");

console.log(JSON.stringify({
  format: "sentinel-phase-decision-record-validation-v1",
  recordPath,
  decision: record.decision,
  ready: record.ready,
  pendingActionCount: record.pendingActionCount,
  blockerCount: record.blockerCount,
  evidenceKeyCount: record.evidenceKeySummary.actionEvidenceKeyCount,
  commandScriptCount: record.commandCoverageSummary.actionCommandScriptCount,
  gapCommandScriptCount: record.commandCoverageSummary.gapCommandScriptCount,
  validatorCommandCount: record.commandCoverageSummary.validatorCommandCount,
  validated: true
}, null, 2));
