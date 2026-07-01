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

const checklistPath = path.resolve(args.get("--checklist") || "artifacts/deployment/pilot/phase-handoff-checklist.md");
const readinessPath = path.resolve(args.get("--readiness") || "artifacts/deployment/pilot/phase-readiness.json");
const externalRequestsPath = path.resolve(args.get("--external-requests") || "artifacts/deployment/pilot/external-evidence-requests.json");

assert.ok(existsSync(checklistPath), `Phase handoff checklist not found: ${checklistPath}`);
assert.ok(existsSync(readinessPath), `Phase readiness report not found: ${readinessPath}`);
assert.ok(existsSync(externalRequestsPath), `External evidence request pack not found: ${externalRequestsPath}`);

const checklist = readFileSync(checklistPath, "utf8");
const readiness = JSON.parse(readFileSync(readinessPath, "utf8"));
const externalRequests = JSON.parse(readFileSync(externalRequestsPath, "utf8"));

assert.equal(readiness.format, "sentinel-phase-readiness-report-v1");
assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");
assert.match(checklist, /^# Sentinel Vault Phase Handoff Checklist/m);
assert.ok(checklist.includes(`Environment: ${readiness.bundle.environment}`), "checklist environment does not match readiness report");
assert.ok(checklist.includes(`Target: ${readiness.target}`), "checklist target does not match readiness report");
assert.ok(checklist.includes(`Bundle status: ${readiness.bundle.status}`), "checklist bundle status does not match readiness report");
assert.ok(checklist.includes(`Bundle owner: ${readiness.bundle.owner}`), "checklist bundle owner does not match readiness report");
assert.ok(checklist.includes(`Readiness: ${readiness.ready ? "ready" : "blocked"}`), "checklist readiness does not match readiness report");
assert.ok(checklist.includes(`Generated from: \`${readinessPath}\``), "checklist source readiness path does not match");
assert.ok(checklist.includes("pnpm report:phase-readiness"), "checklist must include the readiness rerun command");

const blockerSummary = (readiness.blockers || []).reduce((summary, blocker) => {
  const key = blocker.gate.startsWith("evidence.") ? "evidence-items" : blocker.gate;
  summary.set(key, (summary.get(key) || 0) + 1);
  return summary;
}, new Map());

for (const [gate, count] of blockerSummary.entries()) {
  assert.ok(checklist.includes(`- ${gate}: ${count}`), `checklist missing blocker summary: ${gate}`);
}

if (!blockerSummary.size) assert.ok(checklist.includes("- None"), "checklist should record no blockers");

for (const [index, request] of externalRequests.requests.entries()) {
  assert.ok(checklist.includes(`## ${index + 1}. ${request.phase}: ${request.title}`), `missing request section: ${request.title}`);
  assert.ok(checklist.includes(`Owner role: ${request.ownerRole}`), `missing owner role: ${request.ownerRole}`);
  assert.ok(checklist.includes(`Blocker type: ${request.blockerType}`), `missing blocker type: ${request.blockerType}`);

  for (const input of request.requiredInputs) {
    assert.ok(checklist.includes(`- [ ] ${input}`), `missing required input: ${input}`);
  }
  for (const template of request.evidenceTemplates) {
    assert.ok(checklist.includes(`- [ ] \`${template}\``), `missing evidence template: ${template}`);
  }
  for (const command of request.commands) {
    assert.ok(checklist.includes(`- [ ] \`${command}\``), `missing command: ${command}`);
  }
  for (const criterion of request.acceptanceCriteria) {
    assert.ok(checklist.includes(`- [ ] ${criterion}`), `missing acceptance criterion: ${criterion}`);
  }
}

console.log(JSON.stringify({
  format: "sentinel-phase-handoff-checklist-validation-v1",
  checklistPath,
  readinessPath,
  externalRequestsPath,
  requestCount: externalRequests.requests.length,
  blockerSummaryCount: blockerSummary.size,
  validated: true
}, null, 2));
