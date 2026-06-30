import fs from "node:fs";
import path from "node:path";
import { config } from "../config.mjs";
import { createSeedState } from "./seedData.mjs";

const statePath = path.join(config.dataDir, config.stateFile);

const toPersistedState = (state) => {
  const { sessions: _sessions, ...persisted } = state;
  return persisted;
};

const normalizeState = (candidate) => {
  const seeded = createSeedState();
  return {
    ...seeded,
    ...candidate,
    sessions: new Map(),
    users: candidate?.users || seeded.users,
    vaults: candidate?.vaults || seeded.vaults,
    secrets: candidate?.secrets || seeded.secrets,
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

const save = () => {
  if (config.isTest) return;
  fs.mkdirSync(config.dataDir, { recursive: true });
  const tempPath = `${statePath}.${process.pid}.tmp`;
  fs.writeFileSync(tempPath, JSON.stringify(toPersistedState(state), null, 2));
  fs.renameSync(tempPath, statePath);
};

export const store = {
  state,
  save,
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
  findAccessRequestById(id) {
    return state.accessRequests.find((request) => request.id === id);
  }
};
