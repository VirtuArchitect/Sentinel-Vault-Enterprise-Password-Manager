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

const matrixPath = path.resolve(args.get("--matrix") || "artifacts/deployment/pilot/phase-signoff-matrix.json");
const decisionPath = args.get("--phase-decision") ? path.resolve(args.get("--phase-decision")) : null;
const actionRegisterPath = args.get("--phase-actions") ? path.resolve(args.get("--phase-actions")) : null;
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

assert.ok(existsSync(matrixPath), `Phase signoff matrix not found: ${matrixPath}`);
const matrix = readJson(matrixPath);

assert.equal(matrix.format, "sentinel-phase-signoff-matrix-v1");
assert.ok(!Number.isNaN(Date.parse(matrix.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.ok(Array.isArray(matrix.approvals), "approvals must be an array");

const decision = readJson(decisionPath || matrix.decisionPath);
const actionRegister = readJson(actionRegisterPath || matrix.actionRegisterPath);
assert.equal(decision.format, "sentinel-phase-decision-record-v1");
assert.equal(actionRegister.format, "sentinel-phase-action-register-v1");
assert.equal(matrix.decisionPath, decisionPath || matrix.decisionPath, "decision path mismatch");
assert.equal(matrix.actionRegisterPath, actionRegisterPath || matrix.actionRegisterPath, "action register path mismatch");
assert.equal(decision.actionRegisterPath, matrix.actionRegisterPath, "decision record does not reference action register");
assert.equal(matrix.environment, decision.environment, "environment mismatch");
assert.equal(matrix.owner, decision.owner, "owner mismatch");
assert.equal(matrix.status, decision.status, "status mismatch");
assert.equal(matrix.decision, decision.decision, "decision mismatch");
assert.equal(matrix.ready, decision.ready, "ready flag mismatch");

const ownerRoles = [...new Set(actionRegister.actions.map((action) => action.ownerRole))];
assert.equal(matrix.approvals.length, ownerRoles.length, "approval count mismatch");
assert.equal(matrix.summary.approvalCount, matrix.approvals.length, "summary approval count mismatch");
assert.equal(matrix.summary.blockedApprovalCount, matrix.approvals.filter((approval) => approval.status === "blocked-pending-evidence").length, "summary blocked approval count mismatch");
assert.equal(matrix.summary.readyApprovalCount, matrix.approvals.filter((approval) => approval.status === "ready-for-signoff").length, "summary ready approval count mismatch");
assert.equal(matrix.summary.pendingActionCount, matrix.approvals.reduce((total, approval) => total + approval.pendingActionCount, 0), "summary pending action count mismatch");

matrix.approvals.forEach((approval, index) => {
  const ownerRole = ownerRoles[index];
  const actions = actionRegister.actions.filter((action) => action.ownerRole === ownerRole);
  const pendingActions = actions.filter((action) => action.status !== "complete");
  const expectedStatus = pendingActions.length === 0 && decision.decision === "approve-phase-closure"
    ? "ready-for-signoff"
    : "blocked-pending-evidence";

  assert.equal(approval.id, `SIGN-${String(index + 1).padStart(2, "0")}`, `approval ${index + 1} id mismatch`);
  assert.equal(approval.ownerRole, ownerRole, `approval ${index + 1} owner role mismatch`);
  assert.equal(approval.status, expectedStatus, `approval ${index + 1} status mismatch`);
  assert.equal(approval.actionCount, actions.length, `approval ${index + 1} action count mismatch`);
  assert.equal(approval.pendingActionCount, pendingActions.length, `approval ${index + 1} pending action count mismatch`);
  assert.deepEqual(approval.blockerTypes, [...new Set(actions.map((action) => action.blockerType))], `approval ${index + 1} blocker types mismatch`);
  assert.equal(approval.actions.length, actions.length, `approval ${index + 1} action list mismatch`);
  assert.ok(approval.requiredSignoffEvidence.length >= 4, `approval ${index + 1} signoff evidence is incomplete`);

  approval.actions.forEach((approvalAction, actionIndex) => {
    const action = actions[actionIndex];
    assert.equal(approvalAction.id, action.id, `approval ${index + 1} action ${actionIndex + 1} id mismatch`);
    assert.equal(approvalAction.title, action.title, `approval ${index + 1} action ${actionIndex + 1} title mismatch`);
    assert.equal(approvalAction.status, action.status, `approval ${index + 1} action ${actionIndex + 1} status mismatch`);
  });
});

console.log(JSON.stringify({
  format: "sentinel-phase-signoff-matrix-validation-v1",
  matrixPath,
  approvalCount: matrix.summary.approvalCount,
  blockedApprovalCount: matrix.summary.blockedApprovalCount,
  pendingActionCount: matrix.summary.pendingActionCount,
  validated: true
}, null, 2));
