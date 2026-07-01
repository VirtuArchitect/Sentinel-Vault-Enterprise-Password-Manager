import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/connector-certification-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
const allowedConnectors = new Set(["siem", "itsm", "devops", "siem-or-itsm-or-devops"]);
const allowedStatuses = new Set(["prototype", "pilot", "certified", "suspended"]);

assert.equal(evidence.format, "sentinel-connector-certification-evidence-v1");
assert.ok(allowedConnectors.has(evidence.connector), "Unsupported connector type");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported certification status");
assert.ok(evidence.owner, "owner is required");
assert.ok(evidence.targetSystem, "targetSystem is required");
assert.ok(evidence.tlsPolicy, "tlsPolicy is required");
assert.ok(evidence.authMethod, "authMethod is required");
assert.ok(Array.isArray(evidence.leastPrivilegeScopes), "leastPrivilegeScopes must be an array");
assert.equal(typeof evidence.replayProtection?.implemented, "boolean");
assert.equal(typeof evidence.redactionEvidence?.secretValuesFound, "boolean");
assert.ok(evidence.testResults?.deliveryTest, "deliveryTest result is required");
assert.ok(evidence.rollback?.disableProcedure, "rollback disableProcedure is required");
assert.ok(evidence.approvals?.securityReviewer, "securityReviewer approval field is required");

if (evidence.status === "certified") {
  assert.equal(evidence.redactionEvidence.secretValuesFound, false, "certified connectors must have no secret leakage evidence");
  for (const [name, result] of Object.entries(evidence.testResults)) {
    if (name.endsWith("Date")) continue;
    assert.equal(result, "passed", `${name} must be passed for certified connectors`);
  }
  assert.equal(evidence.rollback.tested, true, "certified connectors require rollback testing");
}

console.log(`Connector certification evidence validated: ${evidencePath}`);
