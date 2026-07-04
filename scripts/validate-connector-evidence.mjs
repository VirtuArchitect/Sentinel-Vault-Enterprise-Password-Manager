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
assert.ok(evidence.livePreflight && typeof evidence.livePreflight === "object", "livePreflight is required");
assert.equal(evidence.livePreflight.format, "sentinel-enterprise-connector-live-preflight-v1", "livePreflight.format must be sentinel-enterprise-connector-live-preflight-v1");
assert.ok(Array.isArray(evidence.livePreflight.connectorTypes), "livePreflight.connectorTypes must be an array");
assert.ok(evidence.livePreflight.checks && typeof evidence.livePreflight.checks === "object", "livePreflight.checks are required");
assert.equal(typeof evidence.replayProtection?.implemented, "boolean");
assert.equal(typeof evidence.redactionEvidence?.secretValuesFound, "boolean");
assert.ok(evidence.testResults?.deliveryTest, "deliveryTest result is required");
assert.ok(evidence.rollback?.disableProcedure, "rollback disableProcedure is required");
assert.ok(evidence.approvals?.securityReviewer, "securityReviewer approval field is required");

if (evidence.status === "certified") {
  assert.ok(evidence.livePreflight.reportPath, "certified connectors require livePreflight.reportPath");
  assert.equal(evidence.livePreflight.validated, true, "certified connectors require validated live preflight evidence");
  assert.ok(evidence.livePreflight.checkCount > 0, "certified connectors require live preflight checks");
  assert.ok(evidence.livePreflight.connectorTypes.includes(evidence.connector), "certified connector type must be present in live preflight evidence");
  assert.equal(evidence.livePreflight.selectedConnector, evidence.connector, "livePreflight.selectedConnector must match connector");
  assert.equal(evidence.livePreflight.selectedEndpointHost, evidence.targetSystem, "targetSystem must match live preflight endpoint host");
  for (const [name, passed] of Object.entries(evidence.livePreflight.checks)) {
    assert.equal(passed, true, `livePreflight.checks.${name} must pass for certified connectors`);
  }
  assert.equal(evidence.redactionEvidence.secretValuesFound, false, "certified connectors must have no secret leakage evidence");
  for (const [name, result] of Object.entries(evidence.testResults)) {
    if (name.endsWith("Date")) continue;
    assert.equal(result, "passed", `${name} must be passed for certified connectors`);
  }
  assert.equal(evidence.rollback.tested, true, "certified connectors require rollback testing");
}

console.log(`Connector certification evidence validated: ${evidencePath}`);
