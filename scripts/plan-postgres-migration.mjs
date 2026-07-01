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
const schemaPath = args.get("--schema") || "docs/architecture/postgres-schema.sql";
const outputPath = args.get("--out") || "artifacts/storage/postgres-migration-plan.json";

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
const migrationTables = [
  "sentinel_state",
  "users",
  "device_inventory",
  "tenants",
  "vaults",
  "secrets",
  "secret_imports",
  "access_requests",
  "service_tokens",
  "integration_outbox",
  "audit_events",
  "policies"
];

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("base64url");
const hasEncryptedPayload = (secret) => secret.encrypted?.iv && secret.encrypted?.tag && (secret.encrypted?.ciphertext || secret.encrypted?.value);

assert.ok(existsSync(statePath), `State file not found: ${statePath}`);
assert.ok(existsSync(schemaPath), `Postgres schema file not found: ${schemaPath}`);

const raw = readFileSync(statePath, "utf8");
const state = JSON.parse(raw);
const schema = readFileSync(schemaPath, "utf8");
const missingCollections = requiredCollections.filter((collection) => !Array.isArray(state[collection]));
const transientCollectionsPresent = ["sessions", "loginFailures"].filter((collection) => Object.hasOwn(state, collection));
const plaintextSecretFields = (state.secrets || []).flatMap((secret) => (
  Object.hasOwn(secret, "password") && secret.password ? [{ id: secret.id, field: "password" }] : []
));
const unencryptedSecretIds = (state.secrets || []).filter((secret) => !hasEncryptedPayload(secret)).map((secret) => secret.id);
const vaultIds = new Set((state.vaults || []).map((vault) => vault.id));
const orphanSecrets = (state.secrets || []).filter((secret) => !vaultIds.has(secret.vaultId)).map((secret) => secret.id);
const userIds = new Set((state.users || []).map((user) => user.id));
const orphanVaultMembers = (state.vaults || []).flatMap((vault) => (
  (vault.members || []).filter((member) => !userIds.has(member)).map((member) => ({ vaultId: vault.id, member }))
));
const schemaTablesPresent = migrationTables.every((table) => new RegExp(`CREATE TABLE IF NOT EXISTS ${table}\\b`, "i").test(schema));
const schemaIndexesPresent = [
  "idx_users_email",
  "idx_vaults_tenant_id",
  "idx_secrets_vault_id",
  "idx_access_requests_secret_status",
  "idx_integration_outbox_target_status",
  "idx_audit_events_ts"
].every((index) => schema.includes(index));

const checks = {
  requiredCollectionsPresent: missingCollections.length === 0,
  transientCollectionsExcluded: transientCollectionsPresent.length === 0,
  plaintextSecretsAbsent: plaintextSecretFields.length === 0,
  encryptedSecretPayloadsPresent: unencryptedSecretIds.length === 0,
  orphanSecretsAbsent: orphanSecrets.length === 0,
  orphanVaultMembersAbsent: orphanVaultMembers.length === 0,
  schemaTablesPresent,
  schemaIndexesPresent,
  driverDependencyDeferred: true
};

const plan = {
  format: "sentinel-postgres-migration-plan-v1",
  plannedAt: new Date().toISOString(),
  sourceStateFile: path.resolve(statePath),
  schemaFile: path.resolve(schemaPath),
  sourceSha256: sha256(raw),
  schemaSha256: sha256(schema),
  stateVersion: state.metadata?.version || null,
  migrationTables,
  counts: Object.fromEntries(requiredCollections.map((collection) => [collection, state[collection]?.length || 0])),
  cutoverSteps: [
    "Freeze JSON/SQLite writes and create an encrypted backup plus restore-drill evidence.",
    "Run storage migration-readiness inspection against the source state.",
    "Apply postgres-schema.sql inside a locked maintenance transaction.",
    "Bulk load sentinel_state and relational JSONB mirror tables from the normalized source state.",
    "Verify row counts, orphan checks, encrypted secret payload presence, and audit hash continuity.",
    "Switch STORAGE_PROVIDER=postgres and DATABASE_URL on the approved deployment target.",
    "Run pnpm test against the Postgres provider after driver approval and implementation."
  ],
  checks,
  findings: {
    missingCollections,
    transientCollectionsPresent,
    plaintextSecretFields,
    unencryptedSecretIds,
    orphanSecrets,
    orphanVaultMembers
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(plan, null, 2));

const failed = Object.entries(checks).filter(([, passed]) => !passed);
if (failed.length) {
  console.error(JSON.stringify(plan, null, 2));
  throw new Error(`Postgres migration plan failed validation: ${failed.map(([name]) => name).join(", ")}`);
}

console.log(`Postgres migration plan written: ${outputPath}`);
