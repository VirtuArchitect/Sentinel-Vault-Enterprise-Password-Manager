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

const registerPath = path.resolve(args.get("--register") || "artifacts/deployment/pilot/phase-waiver-register.json");
const inventoryPath = args.get("--attachments") ? path.resolve(args.get("--attachments")) : null;
const decisionPath = args.get("--phase-decision") ? path.resolve(args.get("--phase-decision")) : null;
const requireApproved = args.get("--require-approved") === true || args.get("--require-approved") === "true";

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const placeholder = /replace-with/i;
const isoDate = /^\d{4}-\d{2}-\d{2}$/;

assert.ok(existsSync(registerPath), `Phase waiver register not found: ${registerPath}`);
const register = readJson(registerPath);
assert.equal(register.format, "sentinel-phase-waiver-register-v1");
assert.ok(!Number.isNaN(Date.parse(register.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.ok(Array.isArray(register.waivers), "waivers must be an array");

const inventory = readJson(inventoryPath || register.inventoryPath);
const decision = readJson(decisionPath || register.decisionPath);
assert.equal(inventory.format, "sentinel-phase-attachment-inventory-v1");
assert.equal(decision.format, "sentinel-phase-decision-record-v1");
assert.equal(register.inventoryPath, inventoryPath || register.inventoryPath, "inventory path mismatch");
assert.equal(register.decisionPath, decisionPath || register.decisionPath, "decision path mismatch");
assert.equal(register.environment, inventory.environment, "environment mismatch");
assert.equal(register.owner, inventory.owner, "owner mismatch");
assert.equal(register.decision, decision.decision, "decision mismatch");

const expectedWaivers = [];
for (const attachment of inventory.attachments) {
  for (const file of attachment.files) {
    if (file.status === "missing") {
      expectedWaivers.push({
        phase: attachment.phase,
        title: attachment.title,
        ownerRole: attachment.ownerRole,
        blockerType: attachment.blockerType,
        evidenceKey: file.evidenceKey || null,
        evidenceKeys: attachment.evidenceKeys || [],
        commandScripts: attachment.commandScripts || [],
        waiverType: "missing-evidence",
        targetPath: file.targetPath
      });
    }

    for (const finding of file.redactionFindings) {
      expectedWaivers.push({
        phase: attachment.phase,
        title: attachment.title,
        ownerRole: attachment.ownerRole,
        blockerType: attachment.blockerType,
        evidenceKey: file.evidenceKey || null,
        evidenceKeys: attachment.evidenceKeys || [],
        commandScripts: attachment.commandScripts || [],
        waiverType: "redaction-finding",
        targetPath: file.targetPath,
        finding
      });
    }
  }
}

assert.equal(register.waivers.length, expectedWaivers.length, "waiver count mismatch");
assert.equal(register.summary.waiverCount, register.waivers.length, "summary waiver count mismatch");
assert.equal(register.summary.proposedCount, register.waivers.filter((waiver) => waiver.status === "proposed").length, "summary proposed count mismatch");
assert.equal(register.summary.approvedCount, register.waivers.filter((waiver) => waiver.status === "approved").length, "summary approved count mismatch");
assert.equal(register.summary.rejectedCount, register.waivers.filter((waiver) => waiver.status === "rejected").length, "summary rejected count mismatch");
assert.equal(register.summary.missingEvidenceCount, register.waivers.filter((waiver) => waiver.waiverType === "missing-evidence").length, "summary missing evidence count mismatch");
assert.equal(register.summary.redactionFindingCount, register.waivers.filter((waiver) => waiver.waiverType === "redaction-finding").length, "summary redaction finding count mismatch");
assert.equal(register.summary.commandScriptCount, inventory.summary.commandScriptCount || 0, "summary command script count mismatch");
assert.equal(register.summary.validatorCommandCount, inventory.summary.validatorCommandCount || 0, "summary validator command count mismatch");
assert.deepEqual(register.summary.commandScripts, inventory.summary.commandScripts || [], "summary command scripts mismatch");

register.waivers.forEach((waiver, index) => {
  const expected = expectedWaivers[index];
  assert.equal(waiver.id, `WVR-${String(index + 1).padStart(2, "0")}`, `waiver ${index + 1} id mismatch`);
  assert.equal(waiver.phase, expected.phase, `waiver ${index + 1} phase mismatch`);
  assert.equal(waiver.title, expected.title, `waiver ${index + 1} title mismatch`);
  assert.equal(waiver.ownerRole, expected.ownerRole, `waiver ${index + 1} owner mismatch`);
  assert.equal(waiver.blockerType, expected.blockerType, `waiver ${index + 1} blocker mismatch`);
  assert.equal(waiver.evidenceKey, expected.evidenceKey, `waiver ${index + 1} evidence key mismatch`);
  assert.deepEqual(waiver.evidenceKeys, expected.evidenceKeys, `waiver ${index + 1} evidence keys mismatch`);
  assert.deepEqual(waiver.commandScripts, expected.commandScripts, `waiver ${index + 1} command scripts mismatch`);
  assert.equal(waiver.waiverType, expected.waiverType, `waiver ${index + 1} type mismatch`);
  assert.equal(waiver.targetPath, expected.targetPath, `waiver ${index + 1} target mismatch`);
  assert.ok(["proposed", "approved", "rejected"].includes(waiver.status), `waiver ${index + 1} status invalid`);
  assert.ok(waiver.reason, `waiver ${index + 1} reason is required`);
  assert.ok(waiver.requiredApproval, `waiver ${index + 1} required approval is required`);

  if (requireApproved) {
    assert.equal(waiver.status, "approved", `waiver ${index + 1} must be approved`);
    assert.ok(!placeholder.test(waiver.approvalReference), `waiver ${index + 1} approval reference is still a placeholder`);
    assert.ok(!placeholder.test(waiver.compensatingControl), `waiver ${index + 1} compensating control is still a placeholder`);
    assert.match(waiver.expiresAt, isoDate, `waiver ${index + 1} expiry must be YYYY-MM-DD`);
    assert.ok(Date.parse(waiver.expiresAt) > Date.now(), `waiver ${index + 1} expiry must be in the future`);
  }
});

console.log(JSON.stringify({
  format: "sentinel-phase-waiver-register-validation-v1",
  registerPath,
  waiverCount: register.summary.waiverCount,
  proposedCount: register.summary.proposedCount,
  approvedCount: register.summary.approvedCount,
  commandScriptCount: register.summary.commandScriptCount,
  validatorCommandCount: register.summary.validatorCommandCount,
  validated: true
}, null, 2));
