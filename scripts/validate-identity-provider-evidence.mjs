import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/identity-provider-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
const allowedProviders = new Set(["oidc", "entra"]);
const allowedStatuses = new Set(["planned", "pilot", "production", "suspended"]);
const strictStatuses = new Set(["pilot", "production"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const placeholder = /replace-with|example\.|tenant-id|client-id/i;
const httpsUrl = /^https:\/\//i;
const requiredRoles = ["SECURITY_ADMIN", "VAULT_OPERATOR", "AUDITOR"];

assert.equal(evidence.format, "sentinel-identity-provider-evidence-v1");
assert.ok(allowedStatuses.has(evidence.status), "Unsupported identity evidence status");
assert.ok(allowedProviders.has(evidence.provider), "Unsupported identity provider");
assert.match(evidence.issuer || "", httpsUrl, "issuer must be an HTTPS URL");
assert.ok(evidence.clientId, "clientId is required");
assert.ok(evidence.audience, "audience is required");
assert.match(evidence.jwksUri || "", httpsUrl, "jwksUri must be an HTTPS URL");
assert.ok(evidence.claims?.subject, "subject claim is required");
assert.ok(evidence.claims?.groups, "groups claim is required");
assert.ok(evidence.claims?.mfa, "MFA claim is required");
assert.ok(evidence.claims?.mfaRequiredValue, "MFA required value is required");

if (evidence.provider === "entra") {
  assert.ok(evidence.tenantId, "tenantId is required for Entra ID evidence");
  assert.match(evidence.issuer, /login\.microsoftonline\.com/i, "Entra issuer should use login.microsoftonline.com");
}

for (const role of requiredRoles) {
  assert.ok(evidence.roleMappings?.[role], `${role} role mapping is required`);
}

for (const [name, result] of Object.entries(evidence.checks || {})) {
  assert.ok(checkStatuses.has(result), `Unsupported check result for ${name}`);
}

assert.ok(evidence.rollback?.disableProcedure, "rollback.disableProcedure is required");
assert.ok(evidence.approvals?.identityOwner, "identity owner approval field is required");
assert.ok(evidence.approvals?.securityReviewer, "security reviewer approval field is required");
assert.ok(evidence.approvals?.changeTicket, "change ticket approval field is required");

if (strictStatuses.has(evidence.status)) {
  assert.doesNotMatch(JSON.stringify(evidence), placeholder, "pilot or production identity evidence cannot contain placeholders");
  assert.equal(evidence.rollback.tested, true, "rollback must be tested for pilot or production identity evidence");
  for (const [name, result] of Object.entries(evidence.checks || {})) {
    assert.equal(result, "passed", `${name} must be passed for pilot or production identity evidence`);
  }
}

console.log(`Identity provider evidence validated: ${evidencePath}`);
