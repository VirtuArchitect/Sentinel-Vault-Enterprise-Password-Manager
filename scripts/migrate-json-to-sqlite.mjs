import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { createSeedState } from "../src/server/data/seedData.mjs";

const require = createRequire(import.meta.url);
const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const statePath = args.get("--state") || "data/sentinel-state.json";
const sqlitePath = args.get("--sqlite") || "data/sentinel-vault.sqlite";
const evidencePath = args.get("--evidence") || "artifacts/storage/sqlite-migration-evidence.json";
const force = cliArgs.includes("--force");
const stateVersion = 2;

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

const sqliteRuntime = () => {
  try {
    return require("node:sqlite");
  } catch {
    throw new Error("SQLite migration requires a Node.js runtime with node:sqlite support.");
  }
};

const normalizeState = (candidate) => {
  const seeded = createSeedState();
  const tenants = candidate?.tenants || seeded.tenants;
  return {
    ...seeded,
    ...candidate,
    metadata: { version: stateVersion, ...(candidate?.metadata || {}) },
    users: candidate?.users || seeded.users,
    deviceInventory: candidate?.deviceInventory || seeded.deviceInventory,
    tenants,
    vaults: (candidate?.vaults || seeded.vaults).map((vault) => ({
      tenantId: tenants[0]?.id || "t1",
      ...vault
    })),
    secrets: candidate?.secrets || seeded.secrets,
    serviceTokens: candidate?.serviceTokens || seeded.serviceTokens,
    secretImports: candidate?.secretImports || seeded.secretImports,
    accessRequests: candidate?.accessRequests || seeded.accessRequests,
    integrationOutbox: candidate?.integrationOutbox || seeded.integrationOutbox,
    audit: candidate?.audit || seeded.audit,
    policies: { ...seeded.policies, ...(candidate?.policies || {}) }
  };
};

const toPersistedState = (state) => {
  const { sessions: _sessions, loginFailures: _loginFailures, ...persisted } = state;
  return {
    ...persisted,
    metadata: {
      version: stateVersion,
      migratedAt: new Date().toISOString(),
      source: "json-to-sqlite"
    }
  };
};

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("base64url");
const hasEncryptedPayload = (secret) => secret.encrypted?.iv && secret.encrypted?.tag && (secret.encrypted?.ciphertext || secret.encrypted?.value);

const replaceJsonRows = (db, table, rows, columns = {}) => {
  db.prepare(`DELETE FROM ${table}`).run();
  const columnNames = ["id", ...Object.keys(columns), "data"];
  const placeholders = columnNames.map(() => "?").join(", ");
  const insert = db.prepare(`INSERT INTO ${table} (${columnNames.join(", ")}) VALUES (${placeholders})`);
  for (const row of rows || []) {
    const id = row.id || sha256(JSON.stringify(row));
    insert.run(id, ...Object.values(columns).map((column) => row[column] ?? null), JSON.stringify(row));
  }
};

const syncMirrorTables = (db, persisted) => {
  replaceJsonRows(db, "users", persisted.users);
  replaceJsonRows(db, "device_inventory", persisted.deviceInventory);
  replaceJsonRows(db, "tenants", persisted.tenants);
  replaceJsonRows(db, "vaults", persisted.vaults, { tenant_id: "tenantId" });
  replaceJsonRows(db, "secrets", persisted.secrets, { vault_id: "vaultId", risk: "risk", deleted_at: "deletedAt" });
  replaceJsonRows(db, "service_tokens", persisted.serviceTokens, { revoked_at: "revokedAt" });
  replaceJsonRows(db, "secret_imports", persisted.secretImports, { status: "status" });
  replaceJsonRows(db, "access_requests", persisted.accessRequests, { secret_id: "secretId", requester_id: "requesterId", status: "status" });
  replaceJsonRows(db, "integration_outbox", persisted.integrationOutbox, { target: "target", status: "status" });
  replaceJsonRows(db, "audit_events", persisted.audit, { ts: "ts", action: "action", actor: "actor" });
  db.prepare("DELETE FROM policies").run();
  db.prepare("INSERT INTO policies (id, data) VALUES ('main', ?)").run(JSON.stringify(persisted.policies));
};

assert.ok(existsSync(statePath), `State file not found: ${statePath}`);
if (existsSync(sqlitePath) && !force) {
  throw new Error(`SQLite target already exists: ${sqlitePath}. Pass --force to overwrite it.`);
}

const raw = readFileSync(statePath, "utf8");
const parsed = JSON.parse(raw);
const normalized = normalizeState(parsed);
const missingCollections = requiredCollections.filter((collection) => !Array.isArray(parsed[collection]));
const transientCollectionsPresent = ["sessions", "loginFailures"].filter((collection) => Object.hasOwn(parsed, collection));
const plaintextSecretFields = (normalized.secrets || []).flatMap((secret) => (
  Object.hasOwn(secret, "password") && secret.password ? [{ id: secret.id, field: "password" }] : []
));
const unencryptedSecretIds = (normalized.secrets || []).filter((secret) => !hasEncryptedPayload(secret)).map((secret) => secret.id);
const vaultIds = new Set((normalized.vaults || []).map((vault) => vault.id));
const orphanSecrets = (normalized.secrets || []).filter((secret) => !vaultIds.has(secret.vaultId)).map((secret) => secret.id);
const userIds = new Set((normalized.users || []).map((user) => user.id));
const orphanVaultMembers = (normalized.vaults || []).flatMap((vault) => (
  (vault.members || []).filter((member) => !userIds.has(member)).map((member) => ({ vaultId: vault.id, member }))
));

const checks = {
  requiredCollectionsPresent: missingCollections.length === 0,
  transientCollectionsExcluded: transientCollectionsPresent.length === 0,
  plaintextSecretsAbsent: plaintextSecretFields.length === 0,
  encryptedSecretPayloadsPresent: unencryptedSecretIds.length === 0,
  orphanSecretsAbsent: orphanSecrets.length === 0,
  orphanVaultMembersAbsent: orphanVaultMembers.length === 0
};
const failed = Object.entries(checks).filter(([, passed]) => !passed);
if (failed.length) {
  throw new Error(`JSON state is not safe to migrate: ${failed.map(([name]) => name).join(", ")}`);
}

const persisted = toPersistedState(normalized);
const payload = JSON.stringify(persisted);
mkdirSync(path.dirname(sqlitePath), { recursive: true });
const { DatabaseSync } = sqliteRuntime();
const db = new DatabaseSync(sqlitePath);
try {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
  `);
  db.exec("BEGIN IMMEDIATE TRANSACTION");
  db.exec(`
    DROP TABLE IF EXISTS sentinel_state;
    CREATE TABLE sentinel_state (
      id TEXT PRIMARY KEY,
      version INTEGER NOT NULL,
      data TEXT NOT NULL,
      saved_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS device_inventory (id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS vaults (id TEXT PRIMARY KEY, tenant_id TEXT, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS secrets (id TEXT PRIMARY KEY, vault_id TEXT, risk TEXT, deleted_at TEXT, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS service_tokens (id TEXT PRIMARY KEY, revoked_at TEXT, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS secret_imports (id TEXT PRIMARY KEY, status TEXT, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS access_requests (id TEXT PRIMARY KEY, secret_id TEXT, requester_id TEXT, status TEXT, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS integration_outbox (id TEXT PRIMARY KEY, target TEXT, status TEXT, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, ts TEXT, action TEXT, actor TEXT, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, data TEXT NOT NULL);
  `);
  db.prepare(`
    INSERT INTO sentinel_state (id, version, data, saved_at)
    VALUES ('main', ?, ?, ?)
  `).run(stateVersion, payload, persisted.metadata.migratedAt);
  syncMirrorTables(db, persisted);
  db.exec("COMMIT");
  db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
} catch (err) {
  db.exec("ROLLBACK");
  throw err;
} finally {
  db.close();
}

const evidence = {
  format: "sentinel-json-to-sqlite-migration-evidence-v1",
  migratedAt: persisted.metadata.migratedAt,
  sourceStateFile: path.resolve(statePath),
  targetSqliteFile: path.resolve(sqlitePath),
  sourceSha256: sha256(raw),
  targetPayloadSha256: sha256(payload),
  stateVersion,
  counts: Object.fromEntries(requiredCollections.map((collection) => [collection, normalized[collection]?.length || 0])),
  migrationTables: [
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

mkdirSync(path.dirname(evidencePath), { recursive: true });
writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

console.log(`SQLite migration completed: ${sqlitePath}`);
console.log(`SQLite migration evidence written: ${evidencePath}`);
