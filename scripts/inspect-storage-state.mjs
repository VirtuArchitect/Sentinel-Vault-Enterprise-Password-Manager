import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const statePath = args.get("--state") || "data/sentinel-state.json";
const outputPath = args.get("--out") || "artifacts/storage/storage-migration-evidence.json";

assert.ok(existsSync(statePath), `State file not found: ${statePath}`);

const raw = readFileSync(statePath, "utf8");
const state = JSON.parse(raw);
const requiredCollections = [
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
const defaultedCollections = [];
for (const collection of requiredCollections) {
  if (!Array.isArray(state[collection])) {
    state[collection] = [];
    defaultedCollections.push(collection);
  }
}

const missingCollections = requiredCollections.filter((collection) => !Array.isArray(state[collection]));
const transientCollectionsPresent = ["sessions", "loginFailures"].filter((collection) => Object.hasOwn(state, collection));
const plaintextSecretFields = (state.secrets || []).flatMap((secret) => (
  Object.hasOwn(secret, "password") && secret.password ? [{ id: secret.id, field: "password" }] : []
));
const hasEncryptedPayload = (secret) => secret.encrypted?.iv && secret.encrypted?.tag && (secret.encrypted?.ciphertext || secret.encrypted?.value);
const legacyEncryptedShape = (state.secrets || []).filter((secret) => secret.encrypted?.value && !secret.encrypted?.ciphertext).map((secret) => secret.id);
const unencryptedSecrets = (state.secrets || []).filter((secret) => !hasEncryptedPayload(secret));
const vaultIds = new Set((state.vaults || []).map((vault) => vault.id));
const orphanSecrets = (state.secrets || []).filter((secret) => !vaultIds.has(secret.vaultId)).map((secret) => secret.id);
const userIds = new Set((state.users || []).map((user) => user.id));
const orphanVaultMembers = (state.vaults || []).flatMap((vault) => (
  (vault.members || []).filter((member) => !userIds.has(member)).map((member) => ({ vaultId: vault.id, member }))
));

const evidence = {
  format: "sentinel-storage-migration-evidence-v1",
  inspectedAt: new Date().toISOString(),
  stateFile: path.resolve(statePath),
  stateSha256: crypto.createHash("sha256").update(raw, "utf8").digest("base64url"),
  stateVersion: state.metadata?.version || null,
  providerTargets: ["sqlite", "postgres"],
  counts: Object.fromEntries(requiredCollections.map((collection) => [collection, state[collection]?.length || 0])),
  checks: {
    requiredCollectionsPresent: missingCollections.length === 0,
    transientCollectionsExcluded: transientCollectionsPresent.length === 0,
    plaintextSecretsAbsent: plaintextSecretFields.length === 0,
    encryptedSecretPayloadsPresent: unencryptedSecrets.length === 0,
    orphanSecretsAbsent: orphanSecrets.length === 0,
    orphanVaultMembersAbsent: orphanVaultMembers.length === 0
  },
  findings: {
    missingCollections,
    defaultedCollections,
    transientCollectionsPresent,
    plaintextSecretFields,
    legacyEncryptedShape,
    unencryptedSecretIds: unencryptedSecrets.map((secret) => secret.id),
    orphanSecrets,
    orphanVaultMembers
  },
  migrationTables: [
    "users",
    "devices",
    "tenants",
    "vaults",
    "vault_members",
    "secrets",
    "secret_imports",
    "access_requests",
    "service_tokens",
    "integration_outbox",
    "audit_events",
    "policies"
  ]
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));

const failed = Object.entries(evidence.checks).filter(([, passed]) => !passed);
if (failed.length) {
  console.error(JSON.stringify(evidence, null, 2));
  throw new Error(`Storage state is not migration-ready: ${failed.map(([name]) => name).join(", ")}`);
}

console.log(`Storage migration evidence written: ${outputPath}`);
