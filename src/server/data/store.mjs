import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { config } from "../config.mjs";
import { createSeedState } from "./seedData.mjs";

const stateVersion = 2;
const require = createRequire(import.meta.url);
const statePath = path.join(config.storage.dataDir, config.storage.stateFile);
const sqlitePath = config.storage.sqlitePath ? path.resolve(config.storage.sqlitePath) : path.join(config.storage.dataDir, "sentinel-vault.sqlite");
const backupDir = path.join(config.storage.dataDir, "backups");
const sqliteMirrorTables = [
  "users",
  "device_inventory",
  "tenants",
  "vaults",
  "secrets",
  "service_tokens",
  "secret_imports",
  "access_requests",
  "integration_outbox",
  "audit_events",
  "policies"
];

const toPersistedState = (state) => {
  const { sessions: _sessions, loginFailures: _loginFailures, ...persisted } = state;
  return {
    ...persisted,
    metadata: {
      version: stateVersion,
      savedAt: new Date().toISOString()
    }
  };
};

const normalizeState = (candidate) => {
  const seeded = createSeedState();
  const tenants = candidate?.tenants || seeded.tenants;
  return {
    ...seeded,
    ...candidate,
    metadata: { version: stateVersion, ...(candidate?.metadata || {}) },
    sessions: new Map(),
    loginFailures: new Map(),
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

const sqliteRuntime = () => {
  try {
    return require("node:sqlite");
  } catch (err) {
    throw new Error("STORAGE_PROVIDER=sqlite requires a Node.js runtime with node:sqlite support. Use Node.js 24+ or switch STORAGE_PROVIDER=json.");
  }
};

const openSqlite = () => {
  const { DatabaseSync } = sqliteRuntime();
  fs.mkdirSync(path.dirname(sqlitePath), { recursive: true });
  const db = new DatabaseSync(sqlitePath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    CREATE TABLE IF NOT EXISTS sentinel_state (
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
  return db;
};

const replaceJsonRows = (db, table, rows, columns = {}) => {
  db.prepare(`DELETE FROM ${table}`).run();
  const columnNames = ["id", ...Object.keys(columns), "data"];
  const placeholders = columnNames.map(() => "?").join(", ");
  const insert = db.prepare(`INSERT INTO ${table} (${columnNames.join(", ")}) VALUES (${placeholders})`);
  for (const row of rows || []) {
    const id = row.id || crypto.createHash("sha256").update(JSON.stringify(row)).digest("base64url");
    insert.run(id, ...Object.values(columns).map((column) => row[column] ?? null), JSON.stringify(row));
  }
};

const syncSqliteMirrorTables = (db, persisted) => {
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

const persistSqliteState = (candidate) => {
  const db = openSqlite();
  try {
    const persisted = toPersistedState(candidate);
    db.exec("BEGIN IMMEDIATE TRANSACTION");
    try {
      db.prepare(`
        INSERT INTO sentinel_state (id, version, data, saved_at)
        VALUES ('main', ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          version = excluded.version,
          data = excluded.data,
          saved_at = excluded.saved_at
      `).run(stateVersion, JSON.stringify(persisted), persisted.metadata.savedAt);
      syncSqliteMirrorTables(db, persisted);
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  } finally {
    db.close();
  }
};

const checkpointSqlite = () => {
  const db = openSqlite();
  try {
    db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
  } finally {
    db.close();
  }
};

const loadJsonState = () => {
  if (config.isTest || !fs.existsSync(statePath)) return createSeedState();
  const raw = fs.readFileSync(statePath, "utf8");
  return normalizeState(JSON.parse(raw));
};

const loadSqliteState = () => {
  const db = openSqlite();
  try {
    const row = db.prepare("SELECT data FROM sentinel_state WHERE id = 'main'").get();
    if (!row?.data) {
      const seeded = createSeedState();
      const persisted = toPersistedState(seeded);
      db.exec("BEGIN IMMEDIATE TRANSACTION");
      try {
        db.prepare(`
          INSERT INTO sentinel_state (id, version, data, saved_at)
          VALUES ('main', ?, ?, ?)
        `).run(stateVersion, JSON.stringify(persisted), persisted.metadata.savedAt);
        syncSqliteMirrorTables(db, persisted);
        db.exec("COMMIT");
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
      return seeded;
    }
    return normalizeState(JSON.parse(row.data));
  } finally {
    db.close();
  }
};

const loadState = () => {
  if (config.storage.provider === "sqlite") return loadSqliteState();
  return loadJsonState();
};

const state = loadState();
let transactionDepth = 0;
let transactionSnapshot = null;
let transactionSaveRequested = false;
let transactionAfterCommit = [];

const sha256File = (filePath) => crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("base64url");
const backupKey = () => crypto.createHash("sha256").update(config.vaultRootKey, "utf8").digest();

const readBackupManifest = (backupPath) => {
  const manifestPath = `${backupPath}.sha256.json`;
  if (!fs.existsSync(manifestPath)) return null;
  return JSON.parse(fs.readFileSync(manifestPath, "utf8"));
};

const validateBackup = (backupPath) => {
  if (!fs.existsSync(backupPath)) return { verified: false, reason: "missing_backup" };
  const manifest = readBackupManifest(backupPath);
  if (!manifest) return { verified: false, reason: "missing_manifest" };
  const actual = sha256File(backupPath);
  return {
    verified: actual === manifest.sha256,
    reason: actual === manifest.sha256 ? null : "hash_mismatch",
    sha256: manifest.sha256,
    checkedAt: new Date().toISOString()
  };
};

const listBackups = () => {
  if (config.isTest || !fs.existsSync(backupDir)) return [];
  return fs.readdirSync(backupDir)
    .filter((file) => file.endsWith(".json") || file.endsWith(".sqlite"))
    .filter((file) => !file.endsWith(".sha256.json"))
    .sort()
    .reverse()
    .map((file) => {
      const fullPath = path.join(backupDir, file);
      const stats = fs.statSync(fullPath);
      const validation = validateBackup(fullPath);
      return {
        file,
        size: stats.size,
        createdAt: stats.birthtime.toISOString(),
        verified: validation.verified,
        verificationReason: validation.reason,
        sha256: validation.sha256 || null
      };
    });
};

const createBackup = () => {
  if (config.isTest) return null;
  fs.mkdirSync(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  if (config.storage.provider === "sqlite") {
    if (!fs.existsSync(sqlitePath)) return null;
    checkpointSqlite();
    const backupPath = path.join(backupDir, `sentinel-vault-${stamp}.sqlite`);
    fs.copyFileSync(sqlitePath, backupPath);
    const manifest = {
      file: path.basename(backupPath),
      sha256: sha256File(backupPath),
      createdAt: new Date().toISOString(),
      algorithm: "sha256",
      provider: "sqlite"
    };
    fs.writeFileSync(`${backupPath}.sha256.json`, JSON.stringify(manifest, null, 2));
    return { path: backupPath, manifest };
  }
  if (!fs.existsSync(statePath)) return null;
  const backupPath = path.join(backupDir, `sentinel-state-${stamp}.json`);
  fs.copyFileSync(statePath, backupPath);
  const manifest = {
    file: path.basename(backupPath),
    sha256: sha256File(backupPath),
    createdAt: new Date().toISOString(),
    algorithm: "sha256"
  };
  fs.writeFileSync(`${backupPath}.sha256.json`, JSON.stringify(manifest, null, 2));
  return { path: backupPath, manifest };
};

const createEncryptedBackup = () => {
  if (config.isTest) {
    const payload = Buffer.from(JSON.stringify(toPersistedState(state)), "utf8");
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", backupKey(), iv);
    const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
    return {
      file: "test-encrypted-backup.json.enc",
      algorithm: "AES-256-GCM",
      iv: iv.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
      size: encrypted.byteLength,
      verified: true
    };
  }

  fs.mkdirSync(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = path.join(backupDir, `sentinel-state-${stamp}.json.enc`);
  const iv = crypto.randomBytes(12);
  const payload = Buffer.from(JSON.stringify(toPersistedState(state)), "utf8");
  const cipher = crypto.createCipheriv("aes-256-gcm", backupKey(), iv);
  const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
  fs.writeFileSync(backupPath, encrypted);
  const manifest = {
    file: path.basename(backupPath),
    sha256: sha256File(backupPath),
    createdAt: new Date().toISOString(),
    algorithm: "AES-256-GCM",
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url")
  };
  fs.writeFileSync(`${backupPath}.sha256.json`, JSON.stringify(manifest, null, 2));
  return { path: backupPath, manifest };
};

const validateEncryptedBackup = (backupPath) => {
  const manifest = readBackupManifest(backupPath);
  if (!manifest) return { verified: false, reason: "missing_manifest" };
  const checksum = validateBackup(backupPath);
  if (!checksum.verified) return checksum;
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", backupKey(), Buffer.from(manifest.iv, "base64url"));
    decipher.setAuthTag(Buffer.from(manifest.tag, "base64url"));
    const decrypted = Buffer.concat([decipher.update(fs.readFileSync(backupPath)), decipher.final()]);
    const parsed = JSON.parse(decrypted.toString("utf8"));
    return {
      verified: true,
      reason: null,
      stateVersion: parsed.metadata?.version || null,
      users: parsed.users?.length || 0,
      vaults: parsed.vaults?.length || 0,
      secrets: parsed.secrets?.length || 0,
      checkedAt: new Date().toISOString()
    };
  } catch (err) {
    return { verified: false, reason: "decrypt_or_parse_failed", detail: err instanceof Error ? err.message : "Unknown validation error" };
  }
};

const validateEncryptedBackups = () => {
  if (config.isTest || !fs.existsSync(backupDir)) return [];
  return fs.readdirSync(backupDir)
    .filter((file) => file.endsWith(".json.enc"))
    .sort()
    .reverse()
    .map((file) => {
      const fullPath = path.join(backupDir, file);
      const stats = fs.statSync(fullPath);
      const validation = validateEncryptedBackup(fullPath);
      return {
        file,
        size: stats.size,
        createdAt: stats.birthtime.toISOString(),
        ...validation
      };
    });
};

const cloneState = (candidate) => structuredClone(candidate);

const restoreState = (snapshot) => {
  for (const key of Object.keys(state)) delete state[key];
  Object.assign(state, cloneState(snapshot));
};

const save = () => {
  if (transactionDepth > 0) {
    transactionSaveRequested = true;
    return;
  }
  if (config.storage.provider === "sqlite") {
    persistSqliteState(state);
    if (!config.isTest) createBackup();
    return;
  }
  if (config.isTest) return;
  fs.mkdirSync(config.storage.dataDir, { recursive: true });
  createBackup();
  const tempPath = `${statePath}.${process.pid}.tmp`;
  fs.writeFileSync(tempPath, JSON.stringify(toPersistedState(state), null, 2));
  fs.renameSync(tempPath, statePath);
};

const commitTransaction = () => {
  const callbacks = transactionAfterCommit;
  const shouldSave = transactionSaveRequested;
  const snapshot = transactionSnapshot;
  transactionSaveRequested = false;
  transactionAfterCommit = [];
  try {
    if (shouldSave) save();
  } catch (err) {
    if (snapshot) restoreState(snapshot);
    transactionSnapshot = null;
    throw err;
  }
  transactionSnapshot = null;
  for (const callback of callbacks) callback();
};

const rollbackTransaction = () => {
  if (transactionSnapshot) restoreState(transactionSnapshot);
  transactionSnapshot = null;
  transactionSaveRequested = false;
  transactionAfterCommit = [];
};

const withTransaction = (callback) => {
  if (transactionDepth === 0) {
    transactionSnapshot = cloneState(state);
    transactionSaveRequested = false;
    transactionAfterCommit = [];
  }
  transactionDepth += 1;

  const finish = (result) => {
    transactionDepth -= 1;
    if (transactionDepth === 0) commitTransaction();
    return result;
  };
  const fail = (err) => {
    transactionDepth -= 1;
    if (transactionDepth === 0) rollbackTransaction();
    throw err;
  };

  try {
    const result = callback();
    if (result && typeof result.then === "function") {
      return result.then(finish, fail);
    }
    return finish(result);
  } catch (err) {
    return fail(err);
  }
};

const afterCommit = (callback) => {
  if (transactionDepth > 0) {
    transactionAfterCommit.push(callback);
    return;
  }
  callback();
};

export const store = {
  state,
  save,
  withTransaction,
  afterCommit,
  createBackup,
  createEncryptedBackup,
  validateBackups() {
    if (config.isTest || !fs.existsSync(backupDir)) return [];
    return listBackups();
  },
  validateEncryptedBackups,
  getStorageStatus() {
    return {
      mode: config.storage.provider === "sqlite" ? "sqlite" : "json",
      provider: config.storage.provider,
      statePath: config.storage.provider === "sqlite" ? sqlitePath : statePath,
      stateVersion,
      exists: fs.existsSync(config.storage.provider === "sqlite" ? sqlitePath : statePath),
      mirrorTables: config.storage.provider === "sqlite" ? sqliteMirrorTables : [],
      backups: listBackups().slice(0, 10)
    };
  },
  findUserByEmail(email) {
    return state.users.find((user) => user.email.toLowerCase() === String(email || "").toLowerCase());
  },
  findUserById(id) {
    return state.users.find((user) => user.id === id);
  },
  findVaultById(id) {
    return state.vaults.find((vault) => vault.id === id);
  },
  findTenantById(id) {
    return state.tenants.find((tenant) => tenant.id === id);
  },
  findSecretById(id) {
    return state.secrets.find((secret) => secret.id === id);
  },
  findServiceTokenById(id) {
    return state.serviceTokens.find((token) => token.id === id);
  },
  findSecretImportById(id) {
    return state.secretImports.find((batch) => batch.id === id);
  },
  findAccessRequestById(id) {
    return state.accessRequests.find((request) => request.id === id);
  }
};
