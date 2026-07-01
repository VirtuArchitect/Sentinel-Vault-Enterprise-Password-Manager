import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const evidencePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/storage-migration-evidence.json";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8").replace(/^\uFEFF/, ""));
const requiredCounts = [
  "users",
  "deviceInventory",
  "tenants",
  "vaults",
  "secrets",
  "serviceTokens",
  "secretImports",
  "accessRequests",
  "integrationOutbox",
  "audit"
];
const requiredChecks = [
  "requiredCollectionsPresent",
  "transientCollectionsExcluded",
  "plaintextSecretsAbsent",
  "encryptedSecretPayloadsPresent",
  "orphanSecretsAbsent",
  "orphanVaultMembersAbsent"
];
const requiredFindings = [
  "missingCollections",
  "defaultedCollections",
  "transientCollectionsPresent",
  "plaintextSecretFields",
  "legacyEncryptedShape",
  "unencryptedSecretIds",
  "orphanSecrets",
  "orphanVaultMembers"
];
const timestampOrPlaceholder = /^YYYY-MM-DDTHH:mm:ssZ$|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const sha256Base64UrlOrPlaceholder = /^replace-with-sha256$|^[A-Za-z0-9_-]{43}$/;

assert.equal(evidence.format, "sentinel-storage-migration-evidence-v1");
assert.match(evidence.inspectedAt || "", timestampOrPlaceholder, "inspectedAt must be an ISO timestamp or placeholder");
assert.ok(evidence.stateFile, "stateFile is required");
assert.match(evidence.stateSha256 || "", sha256Base64UrlOrPlaceholder, "stateSha256 must be SHA-256 base64url or placeholder");
assert.ok(Number.isInteger(evidence.stateVersion) || evidence.stateVersion === null, "stateVersion must be an integer or null");
assert.ok(Array.isArray(evidence.providerTargets), "providerTargets must be an array");
assert.ok(evidence.providerTargets.includes("sqlite"), "providerTargets must include sqlite");
assert.ok(evidence.providerTargets.includes("postgres"), "providerTargets must include postgres");

for (const name of requiredCounts) {
  assert.ok(Number.isInteger(evidence.counts?.[name]) && evidence.counts[name] >= 0, `counts.${name} must be a non-negative integer`);
}
for (const name of requiredChecks) {
  assert.equal(typeof evidence.checks?.[name], "boolean", `checks.${name} must be boolean`);
}
for (const name of requiredFindings) {
  assert.ok(Array.isArray(evidence.findings?.[name]), `findings.${name} must be an array`);
}
assert.ok(Array.isArray(evidence.migrationTables), "migrationTables must be an array");
for (const table of ["users", "vaults", "secrets", "audit_events", "policies"]) {
  assert.ok(evidence.migrationTables.includes(table), `migrationTables must include ${table}`);
}

const hasPlaceholders = /replace-with|YYYY-MM-DD/i.test(JSON.stringify(evidence));
if (!hasPlaceholders) {
  for (const name of requiredChecks) {
    assert.equal(evidence.checks[name], true, `${name} must pass for completed storage migration evidence`);
  }
  assert.equal(evidence.findings.missingCollections.length, 0, "completed evidence cannot have missing collections");
  assert.equal(evidence.findings.transientCollectionsPresent.length, 0, "completed evidence cannot include transient collections");
  assert.equal(evidence.findings.plaintextSecretFields.length, 0, "completed evidence cannot include plaintext secret fields");
  assert.equal(evidence.findings.unencryptedSecretIds.length, 0, "completed evidence cannot include unencrypted secrets");
  assert.equal(evidence.findings.orphanSecrets.length, 0, "completed evidence cannot include orphan secrets");
  assert.equal(evidence.findings.orphanVaultMembers.length, 0, "completed evidence cannot include orphan vault members");
}

console.log(`Storage migration evidence validated: ${evidencePath}`);
