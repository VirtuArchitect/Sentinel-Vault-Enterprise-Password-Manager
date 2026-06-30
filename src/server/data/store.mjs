import { createSeedState } from "./seedData.mjs";

const state = createSeedState();

export const store = {
  state,
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
