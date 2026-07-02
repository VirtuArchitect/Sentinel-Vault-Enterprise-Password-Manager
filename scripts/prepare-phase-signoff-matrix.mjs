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
const decisionPath = path.resolve(args.get("--phase-decision") || path.join(evidenceDir, "phase-decision-record.json"));
const actionRegisterPath = path.resolve(args.get("--phase-actions") || path.join(evidenceDir, "phase-action-register.json"));
const outputPath = path.resolve(args.get("--out") || path.join(evidenceDir, "phase-signoff-matrix.json"));
const markdownPath = path.resolve(args.get("--markdown-out") || path.join(evidenceDir, "phase-signoff-matrix.md"));

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

assert.ok(existsSync(decisionPath), `Phase decision record not found: ${decisionPath}`);
assert.ok(existsSync(actionRegisterPath), `Phase action register not found: ${actionRegisterPath}`);

const decision = readJson(decisionPath);
const actionRegister = readJson(actionRegisterPath);

assert.equal(decision.format, "sentinel-phase-decision-record-v1");
assert.equal(actionRegister.format, "sentinel-phase-action-register-v1");
assert.equal(decision.actionRegisterPath, actionRegisterPath, "phase decision record does not reference selected action register");

const ownerRoles = [...new Set(actionRegister.actions.map((action) => action.ownerRole))];
const evidenceKeys = [...new Set(actionRegister.actions.flatMap((action) => action.evidenceKeys || []))].sort();
const approvals = ownerRoles.map((ownerRole, index) => {
  const actions = actionRegister.actions.filter((action) => action.ownerRole === ownerRole);
  const pendingActions = actions.filter((action) => action.status !== "complete");
  const approvalEvidenceKeys = [...new Set(actions.flatMap((action) => action.evidenceKeys || []))].sort();
  return {
    id: `SIGN-${String(index + 1).padStart(2, "0")}`,
    ownerRole,
    status: pendingActions.length === 0 && decision.decision === "approve-phase-closure"
      ? "ready-for-signoff"
      : "blocked-pending-evidence",
    actionCount: actions.length,
    pendingActionCount: pendingActions.length,
    blockerTypes: [...new Set(actions.map((action) => action.blockerType))],
    evidenceKeys: approvalEvidenceKeys,
    actions: actions.map((action) => ({
      id: action.id,
      phase: action.phase,
      title: action.title,
      blockerType: action.blockerType,
      status: action.status,
      evidenceKeys: action.evidenceKeys || []
    })),
    requiredSignoffEvidence: [
      "Named owner approval",
      "Change, incident, release, or architecture reference",
      "Evidence files attached to the deployment evidence workspace",
      "Validation commands passing after owner evidence is attached"
    ]
  };
});

const matrix = {
  format: "sentinel-phase-signoff-matrix-v1",
  generatedAt: new Date().toISOString(),
  evidenceDir,
  decisionPath,
  actionRegisterPath,
  environment: decision.environment,
  owner: decision.owner,
  status: decision.status,
  decision: decision.decision,
  ready: decision.ready,
  summary: {
    approvalCount: approvals.length,
    blockedApprovalCount: approvals.filter((approval) => approval.status === "blocked-pending-evidence").length,
    readyApprovalCount: approvals.filter((approval) => approval.status === "ready-for-signoff").length,
    pendingActionCount: approvals.reduce((total, approval) => total + approval.pendingActionCount, 0),
    evidenceKeyCount: evidenceKeys.length,
    evidenceKeys
  },
  approvals
};

const renderMarkdown = () => `# Sentinel Vault Phase Signoff Matrix

Environment: ${matrix.environment}
Owner: ${matrix.owner}
Decision: ${matrix.decision}
Generated: ${matrix.generatedAt}

Summary:
- Approval owners: ${matrix.summary.approvalCount}
- Blocked approvals: ${matrix.summary.blockedApprovalCount}
- Ready approvals: ${matrix.summary.readyApprovalCount}
- Pending actions: ${matrix.summary.pendingActionCount}
- Evidence keys: ${matrix.summary.evidenceKeyCount}

${approvals.map((approval) => `## ${approval.id}: ${approval.ownerRole}

Status: ${approval.status}
Pending actions: ${approval.pendingActionCount}
Blocker types: ${approval.blockerTypes.join(", ")}
Evidence keys: ${approval.evidenceKeys.join(", ")}

Actions:
${approval.actions.map((action) => `- ${action.id}: ${action.phase} - ${action.title} (${action.status}; ${action.evidenceKeys.join(", ")})`).join("\n")}

Required signoff evidence:
${approval.requiredSignoffEvidence.map((item) => `- [ ] ${item}`).join("\n")}`).join("\n\n")}
`;

mkdirSync(path.dirname(outputPath), { recursive: true });
mkdirSync(path.dirname(markdownPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(matrix, null, 2));
writeFileSync(markdownPath, renderMarkdown());

console.log(JSON.stringify({
  format: "sentinel-phase-signoff-matrix-result-v1",
  outputPath,
  markdownPath,
  approvalCount: matrix.summary.approvalCount,
  blockedApprovalCount: matrix.summary.blockedApprovalCount,
  pendingActionCount: matrix.summary.pendingActionCount
}, null, 2));
