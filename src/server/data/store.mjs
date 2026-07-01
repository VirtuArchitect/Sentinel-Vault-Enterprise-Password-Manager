import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { config } from "../config.mjs";
import { createSeedState } from "./seedData.mjs";

const stateVersion = 2;
const statePath = path.join(config.dataDir, config.stateFile);
const backupDir = path.join(config.dataDir, "backups");

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
  return {
    ...seeded,
    ...candidate,
    metadata: { version: stateVersion, ...(candidate?.metadata || {}) },
    sessions: new Map(),
    loginFailures: new Map(),
    users: candidate?.users || seeded.users,
    vaults: candidate?.vaults || seeded.vaults,
    secrets: candidate?.secrets || seeded.secrets,
    serviceTokens: candidate?.serviceTokens || seeded.serviceTokens,
    accessRequests: candidate?.accessRequests || seeded.accessRequests,
    integrationOutbox: candidate?.integrationOutbox || seeded.integrationOutbox,
    audit: candidate?.audit || seeded.audit,
    policies: { ...seeded.policies, ...(candidate?.policies || {}) }
  };
};

const loadState = () => {
  if (config.isTest || !fs.existsSync(statePath)) return createSeedState();
  const raw = fs.readFileSync(statePath, "utf8");
  return normalizeState(JSON.parse(raw));
};

const state = loadState();

const sha256File = (filePath) => crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("base64url");

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
    .filter((file) => file.endsWith(".json"))
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
  if (config.isTest || !fs.existsSync(statePath)) return null;
  fs.mkdirSync(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
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

const save = () => {
  if (config.isTest) return;
  fs.mkdirSync(config.dataDir, { recursive: true });
  createBackup();
  const tempPath = `${statePath}.${process.pid}.tmp`;
  fs.writeFileSync(tempPath, JSON.stringify(toPersistedState(state), null, 2));
  fs.renameSync(tempPath, statePath);
};

export const store = {
  state,
  save,
  createBackup,
  validateBackups() {
    if (config.isTest || !fs.existsSync(backupDir)) return [];
    return listBackups();
  },
  getStorageStatus() {
    return {
      mode: "json",
      statePath,
      stateVersion,
      exists: fs.existsSync(statePath),
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
  findSecretById(id) {
    return state.secrets.find((secret) => secret.id === id);
  },
  findServiceTokenById(id) {
    return state.serviceTokens.find((token) => token.id === id);
  },
  findAccessRequestById(id) {
    return state.accessRequests.find((request) => request.id === id);
  }
};
