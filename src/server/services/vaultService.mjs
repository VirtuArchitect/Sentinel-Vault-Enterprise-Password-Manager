import crypto from "node:crypto";
import { encryptSecret, decryptSecret, secretStrength } from "../crypto/vaultCrypto.mjs";
import { generateCredential } from "../crypto/passwords.mjs";
import { store } from "../data/store.mjs";
import { publicUser } from "../rbac/roles.mjs";
import { audit } from "./auditService.mjs";

export const canAccessVault = (user, vault) => Boolean(vault && (vault.members.includes(user.id) || user.role === "SECURITY_ADMIN"));

export const canAccessSecret = (user, secret) => {
  const vault = store.findVaultById(secret?.vaultId);
  return Boolean(secret && (canAccessVault(user, vault) || secret.sharedWith.includes(user.id)));
};

export const getConsolePayload = (user) => {
  const readableVaults = store.state.vaults.filter((vault) => canAccessVault(user, vault));
  const readableIds = new Set(readableVaults.map((vault) => vault.id));
  const secrets = store.state.secrets
    .filter((secret) => readableIds.has(secret.vaultId) || secret.sharedWith.includes(user.id))
    .map((secret) => ({
      id: secret.id,
      vaultId: secret.vaultId,
      name: secret.name,
      username: secret.username,
      url: secret.url,
      tags: secret.tags,
      risk: secret.risk,
      rotatedAt: secret.rotatedAt,
      sharedWith: secret.sharedWith,
      strength: secretStrength(secret.encrypted)
    }));

  return {
    user: publicUser(user),
    users: store.state.users.map(publicUser),
    vaults: readableVaults,
    secrets,
    policies: store.state.policies,
    audit: store.state.audit.slice(0, 20),
    metrics: {
      secrets: store.state.secrets.length,
      vaults: store.state.vaults.length,
      stale: store.state.secrets.filter((secret) => Date.now() - Date.parse(secret.rotatedAt) > store.state.policies.rotationDays * 86400000).length,
      highRisk: store.state.secrets.filter((secret) => secret.risk === "high").length
    }
  };
};

export const createSecret = (user, input) => {
  const { vaultId, name, username, password, url, tags } = input;
  if (!vaultId || !name || !username || !password) {
    const error = new Error("Vault, name, username, and password are required");
    error.status = 400;
    throw error;
  }

  const vault = store.findVaultById(vaultId);
  if (!canAccessVault(user, vault)) {
    const error = new Error("Vault access denied");
    error.status = 403;
    throw error;
  }

  const secret = {
    id: crypto.randomUUID(),
    vaultId,
    name,
    username,
    url: url || "",
    tags: String(tags || "").split(",").map((tag) => tag.trim()).filter(Boolean),
    risk: password.length < store.state.policies.minimumLength ? "high" : "low",
    rotatedAt: new Date().toISOString(),
    sharedWith: [user.id],
    encrypted: encryptSecret(password)
  };
  store.state.secrets.unshift(secret);
  audit(user.id, "CREATE_SECRET", name, `Stored in ${vault.name}`);
};

export const revealSecret = (user, id) => {
  const secret = store.findSecretById(id);
  if (!secret) {
    const error = new Error("Secret not found");
    error.status = 404;
    throw error;
  }
  if (!canAccessSecret(user, secret)) {
    const error = new Error("Secret access denied");
    error.status = 403;
    throw error;
  }
  audit(user.id, "REVEAL_SECRET", secret.name, "Credential viewed under active session policy");
  return { password: decryptSecret(secret.encrypted), expiresIn: store.state.policies.clipboardTtl };
};

export const rotateSecret = (user, id) => {
  const secret = store.findSecretById(id);
  if (!secret) {
    const error = new Error("Secret not found");
    error.status = 404;
    throw error;
  }
  const generated = generateCredential();
  secret.encrypted = encryptSecret(generated);
  secret.rotatedAt = new Date().toISOString();
  secret.risk = "low";
  audit(user.id, "ROTATE_SECRET", secret.name, "Generated 170-bit replacement credential");
  return generated;
};

export const shareSecret = (user, id, userId) => {
  const secret = store.findSecretById(id);
  const target = store.findUserById(userId);
  if (!secret || !target) {
    const error = new Error("Secret or user not found");
    error.status = 404;
    throw error;
  }
  if (!secret.sharedWith.includes(target.id)) secret.sharedWith.push(target.id);
  audit(user.id, "SHARE_SECRET", secret.name, `Granted to ${target.name}`);
};

export const updatePolicies = (user, patch) => {
  store.state.policies = { ...store.state.policies, ...patch };
  audit(user.id, "POLICY_UPDATE", "Enterprise policy", "Policy controls updated");
  return store.state.policies;
};
