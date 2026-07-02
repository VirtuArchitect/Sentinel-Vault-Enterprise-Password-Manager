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
const externalRequestsPath = path.resolve(args.get("--external-requests") || path.join(evidenceDir, "external-evidence-requests.json"));
const completionAuditPath = path.resolve(args.get("--completion-audit") || path.join(evidenceDir, "phase-completion-audit.json"));
const outputPath = path.resolve(args.get("--out") || path.join(evidenceDir, "phase-action-register.json"));
const markdownPath = path.resolve(args.get("--markdown-out") || path.join(evidenceDir, "phase-action-register.md"));

assert.ok(existsSync(phaseGatePath), `Phase gate validation report not found: ${phaseGatePath}`);
assert.ok(existsSync(externalRequestsPath), `External evidence request pack not found: ${externalRequestsPath}`);
assert.ok(existsSync(completionAuditPath), `Phase completion audit not found: ${completionAuditPath}`);

const phaseGate = JSON.parse(readFileSync(phaseGatePath, "utf8"));
const externalRequests = JSON.parse(readFileSync(externalRequestsPath, "utf8"));
const completionAudit = JSON.parse(readFileSync(completionAuditPath, "utf8"));

assert.equal(phaseGate.format, "sentinel-phase-gate-validation-v1");
assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");
assert.equal(completionAudit.format, "sentinel-phase-completion-audit-v1");

const phaseRemaining = new Map(completionAudit.phases.map((phase) => [
  `Phase ${phase.number}`,
  {
    phase: `Phase ${phase.number}`,
    title: phase.title,
    status: phase.status,
    remaining: phase.remaining
  }
]));

const actions = externalRequests.requests.map((request, index) => {
  const remaining = phaseRemaining.get(request.phase);
  return {
    id: `ACT-${String(index + 1).padStart(2, "0")}`,
    phase: request.phase,
    title: request.title,
    ownerRole: request.ownerRole,
    blockerType: request.blockerType,
    status: phaseGate.ready ? "complete" : "pending-external-evidence",
    phaseRemaining: remaining?.remaining || [],
    evidenceKeys: request.evidenceKeys || [],
    requiredInputs: request.requiredInputs,
    evidenceTemplates: request.evidenceTemplates,
    commands: request.commands,
    acceptanceCriteria: request.acceptanceCriteria
  };
});

const report = {
  format: "sentinel-phase-action-register-v1",
  generatedAt: new Date().toISOString(),
  evidenceDir,
  phaseGatePath,
  externalRequestsPath,
  completionAuditPath,
  gate: {
    validated: phaseGate.validated,
    ready: phaseGate.ready,
    blockerCount: phaseGate.blockerCount,
    warningCount: phaseGate.warningCount,
    remainingPhaseCount: phaseGate.remainingPhaseCount,
    remainingItemCount: phaseGate.remainingItemCount
  },
  summary: {
    actionCount: actions.length,
    evidenceKeyCount: new Set(actions.flatMap((action) => action.evidenceKeys)).size,
    ownerRoles: [...new Set(actions.map((action) => action.ownerRole))],
    blockerTypes: [...new Set(actions.map((action) => action.blockerType))]
  },
  actions
};

const renderMarkdown = () => `# Sentinel Vault Phase Action Register

Gate validated: ${report.gate.validated ? "yes" : "no"}
Gate ready: ${report.gate.ready ? "yes" : "no"}
Blockers: ${report.gate.blockerCount}
Remaining phases: ${report.gate.remainingPhaseCount}
Remaining items: ${report.gate.remainingItemCount}

${actions.map((action) => `## ${action.id}: ${action.phase}: ${action.title}

Owner role: ${action.ownerRole}
Blocker type: ${action.blockerType}
Status: ${action.status}

Required inputs:
${action.requiredInputs.map((input) => `- [ ] ${input}`).join("\n")}

Deployment bundle evidence keys:
${action.evidenceKeys.map((key) => `- \`${key}\``).join("\n")}

Evidence templates:
${action.evidenceTemplates.map((template) => `- \`${template}\``).join("\n")}

Commands:
${action.commands.map((command) => `- \`${command}\``).join("\n")}

Acceptance criteria:
${action.acceptanceCriteria.map((criterion) => `- [ ] ${criterion}`).join("\n")}`).join("\n\n")}
`;

mkdirSync(path.dirname(outputPath), { recursive: true });
mkdirSync(path.dirname(markdownPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(report, null, 2));
writeFileSync(markdownPath, renderMarkdown());

console.log(JSON.stringify({
  format: "sentinel-phase-action-register-result-v1",
  outputPath,
  markdownPath,
  actionCount: actions.length,
  ready: report.gate.ready,
  blockerCount: report.gate.blockerCount
}, null, 2));
