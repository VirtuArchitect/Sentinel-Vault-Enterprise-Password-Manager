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

const registerPath = path.resolve(args.get("--register") || "artifacts/deployment/pilot/phase-action-register.json");
const markdownPath = args.get("--markdown") ? path.resolve(args.get("--markdown")) : null;
const phaseGatePath = args.get("--phase-gate") ? path.resolve(args.get("--phase-gate")) : null;
const externalRequestsPath = args.get("--external-requests") ? path.resolve(args.get("--external-requests")) : null;

assert.ok(existsSync(registerPath), `Phase action register not found: ${registerPath}`);
const register = JSON.parse(readFileSync(registerPath, "utf8"));

assert.equal(register.format, "sentinel-phase-action-register-v1");
assert.ok(!Number.isNaN(Date.parse(register.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.ok(existsSync(register.phaseGatePath), `phaseGatePath does not exist: ${register.phaseGatePath}`);
assert.ok(existsSync(register.externalRequestsPath), `externalRequestsPath does not exist: ${register.externalRequestsPath}`);
assert.ok(existsSync(register.completionAuditPath), `completionAuditPath does not exist: ${register.completionAuditPath}`);

if (phaseGatePath) assert.equal(path.resolve(register.phaseGatePath), phaseGatePath, "phase gate path does not match");
if (externalRequestsPath) assert.equal(path.resolve(register.externalRequestsPath), externalRequestsPath, "external requests path does not match");
if (markdownPath) assert.ok(existsSync(markdownPath), `Phase action register markdown not found: ${markdownPath}`);

const phaseGate = JSON.parse(readFileSync(register.phaseGatePath, "utf8"));
const externalRequests = JSON.parse(readFileSync(register.externalRequestsPath, "utf8"));
const completionAudit = JSON.parse(readFileSync(register.completionAuditPath, "utf8"));

assert.equal(phaseGate.format, "sentinel-phase-gate-validation-v1");
assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");
assert.equal(completionAudit.format, "sentinel-phase-completion-audit-v1");
assert.equal(register.gate.validated, phaseGate.validated, "gate validated flag is stale");
assert.equal(register.gate.ready, phaseGate.ready, "gate ready flag is stale");
assert.equal(register.gate.blockerCount, phaseGate.blockerCount, "gate blocker count is stale");
assert.equal(register.gate.remainingPhaseCount, phaseGate.remainingPhaseCount, "gate remaining phase count is stale");
assert.equal(register.gate.remainingItemCount, phaseGate.remainingItemCount, "gate remaining item count is stale");
assert.deepEqual(register.gate.externalRequestSummary, phaseGate.externalRequestSummary, "gate external request summary is stale");
assert.ok(Array.isArray(register.actions), "actions must be an array");
assert.equal(register.actions.length, externalRequests.requests.length, "action count does not match external requests");
assert.equal(register.summary.evidenceKeyCount, new Set(register.actions.flatMap((action) => action.evidenceKeys || [])).size, "summary evidence key count mismatch");
assert.equal(register.summary.commandScriptCount, externalRequests.summary?.commandScriptCount || 0, "summary command script count mismatch");
assert.equal(register.summary.validatorCommandCount, phaseGate.externalRequestSummary?.validatorCommandCount || 0, "summary validator command count mismatch");
assert.deepEqual(register.summary.commandScripts, externalRequests.summary?.commandScripts || [], "summary command scripts mismatch");

if (markdownPath) {
  const markdown = readFileSync(markdownPath, "utf8");
  assert.ok(markdown.includes("## Command Coverage Summary"), "markdown must include command coverage summary");
  assert.ok(markdown.includes(`- Command scripts: ${register.summary.commandScriptCount}`), "markdown command script count mismatch");
  assert.ok(markdown.includes(`- Validator commands: ${register.summary.validatorCommandCount}`), "markdown validator command count mismatch");
  for (const script of register.summary.commandScripts) {
    assert.ok(markdown.includes(`- \`pnpm ${script}\``), `markdown missing command script coverage: ${script}`);
  }
}

for (const [index, request] of externalRequests.requests.entries()) {
  const action = register.actions[index];
  assert.ok(action, `missing action ${index + 1}`);
  assert.equal(action.phase, request.phase, `action ${index + 1} phase mismatch`);
  assert.equal(action.title, request.title, `action ${index + 1} title mismatch`);
  assert.equal(action.ownerRole, request.ownerRole, `action ${index + 1} ownerRole mismatch`);
  assert.equal(action.blockerType, request.blockerType, `action ${index + 1} blockerType mismatch`);
  assert.deepEqual(action.evidenceKeys, request.evidenceKeys || [], `action ${index + 1} evidence key mismatch`);
  assert.deepEqual(action.requiredInputs, request.requiredInputs, `action ${index + 1} required inputs mismatch`);
  assert.deepEqual(action.evidenceTemplates, request.evidenceTemplates, `action ${index + 1} evidence templates mismatch`);
  assert.deepEqual(action.commands, request.commands, `action ${index + 1} commands mismatch`);
  assert.deepEqual(action.acceptanceCriteria, request.acceptanceCriteria, `action ${index + 1} acceptance criteria mismatch`);
}

console.log(JSON.stringify({
  format: "sentinel-phase-action-register-validation-v1",
  registerPath,
  actionCount: register.actions.length,
  evidenceKeyCount: register.summary.evidenceKeyCount,
  commandScriptCount: register.summary.commandScriptCount,
  validatorCommandCount: register.summary.validatorCommandCount,
  ready: register.gate.ready,
  validated: true
}, null, 2));
