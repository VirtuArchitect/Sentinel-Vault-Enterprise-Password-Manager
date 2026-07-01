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

const auditPath = path.resolve(args.get("--audit") || "artifacts/deployment/pilot/phase-completion-audit.json");
const roadmapPath = args.get("--roadmap") ? path.resolve(args.get("--roadmap")) : null;
const externalRequestsPath = args.get("--external-requests") ? path.resolve(args.get("--external-requests")) : null;
const failOnRemaining = args.has("--fail-on-remaining");
const allowUncovered = args.has("--allow-uncovered");

assert.ok(existsSync(auditPath), `Phase completion audit not found: ${auditPath}`);
const audit = JSON.parse(readFileSync(auditPath, "utf8"));

assert.equal(audit.format, "sentinel-phase-completion-audit-v1");
assert.ok(!Number.isNaN(Date.parse(audit.generatedAt)), "generatedAt must be an ISO-compatible timestamp");
assert.ok(audit.roadmapPath && typeof audit.roadmapPath === "string", "roadmapPath is required");
assert.ok(audit.externalRequestsPath && typeof audit.externalRequestsPath === "string", "externalRequestsPath is required");
assert.ok(existsSync(audit.roadmapPath), `roadmapPath does not exist: ${audit.roadmapPath}`);
assert.ok(existsSync(audit.externalRequestsPath), `externalRequestsPath does not exist: ${audit.externalRequestsPath}`);

if (roadmapPath) {
  assert.equal(path.resolve(audit.roadmapPath), roadmapPath, "audit roadmapPath does not match expected roadmap");
}
if (externalRequestsPath) {
  assert.equal(path.resolve(audit.externalRequestsPath), externalRequestsPath, "audit externalRequestsPath does not match expected request pack");
}

const roadmap = readFileSync(audit.roadmapPath, "utf8");
const externalRequests = JSON.parse(readFileSync(audit.externalRequestsPath, "utf8"));
assert.equal(externalRequests.format, "sentinel-external-evidence-requests-v1");

const roadmapPhaseHeadings = [...roadmap.matchAll(/^## Phase (\d+): ([^\r\n]+)$/gm)];
assert.ok(roadmapPhaseHeadings.length > 0, "roadmap must include implementation phases");
assert.ok(Array.isArray(audit.phases), "phases must be an array");
assert.equal(audit.phaseCount, roadmapPhaseHeadings.length, "phaseCount does not match roadmap");
assert.equal(audit.phases.length, audit.phaseCount, "phases length does not match phaseCount");

const requestKeys = new Set((externalRequests.requests || []).map((request) => `${request.phase}:${request.blockerType}`));
let implementedPhaseCount = 0;
let remainingPhaseCount = 0;
let remainingItemCount = 0;
const uncoveredRemaining = [];

for (const [index, phase] of audit.phases.entries()) {
  const heading = roadmapPhaseHeadings[index];
  assert.ok(heading, `phase ${index} has no roadmap heading`);
  assert.equal(phase.number, Number.parseInt(heading[1], 10), `phase ${index} number does not match roadmap`);
  assert.equal(phase.title, heading[2].trim(), `phase ${phase.number} title does not match roadmap`);
  assert.ok(phase.status && typeof phase.status === "string", `phase ${phase.number} status is required`);
  assert.ok(Number.isInteger(phase.implementedCount) && phase.implementedCount >= 0, `phase ${phase.number} implementedCount must be non-negative`);
  assert.ok(Array.isArray(phase.remaining), `phase ${phase.number} remaining must be an array`);
  assert.ok(Array.isArray(phase.externalRequests), `phase ${phase.number} externalRequests must be an array`);

  if (phase.remaining.length === 0) implementedPhaseCount += 1;
  if (phase.remaining.length > 0) {
    remainingPhaseCount += 1;
    remainingItemCount += phase.remaining.length;
    if (phase.externalRequests.length === 0) {
      uncoveredRemaining.push({
        phase: `Phase ${phase.number}`,
        title: phase.title,
        remaining: phase.remaining
      });
    }
  }

  for (const request of phase.externalRequests) {
    assert.ok(request.title, `phase ${phase.number} external request title is required`);
    assert.ok(request.blockerType, `phase ${phase.number} external request blockerType is required`);
    assert.ok(request.ownerRole, `phase ${phase.number} external request ownerRole is required`);
    assert.ok(requestKeys.has(`Phase ${phase.number}:${request.blockerType}`), `phase ${phase.number} external request is not present in request pack: ${request.blockerType}`);
  }
}

assert.equal(audit.implementedPhaseCount, implementedPhaseCount, "implementedPhaseCount is stale");
assert.equal(audit.remainingPhaseCount, remainingPhaseCount, "remainingPhaseCount is stale");
assert.equal(audit.remainingItemCount, remainingItemCount, "remainingItemCount is stale");
assert.equal(audit.complete, remainingPhaseCount === 0, "complete flag is stale");
assert.deepEqual(audit.uncoveredRemaining, uncoveredRemaining, "uncoveredRemaining is stale");
assert.equal(audit.externallyCovered, uncoveredRemaining.length === 0, "externallyCovered flag is stale");

if (!allowUncovered) {
  assert.equal(audit.externallyCovered, true, "remaining work must be covered by external handoff requests");
}
if (failOnRemaining) {
  assert.equal(audit.complete, true, "phase completion audit still has remaining work");
}

console.log(JSON.stringify({
  format: "sentinel-phase-completion-audit-validation-v1",
  auditPath,
  phaseCount: audit.phaseCount,
  remainingPhaseCount: audit.remainingPhaseCount,
  remainingItemCount: audit.remainingItemCount,
  externallyCovered: audit.externallyCovered,
  complete: audit.complete,
  validated: true
}, null, 2));
