import crypto from "node:crypto";
import { store } from "../data/store.mjs";
import { roles } from "../rbac/roles.mjs";
import { audit } from "./auditService.mjs";

const normalizeMembers = (members = []) => [...new Set(
  (Array.isArray(members) ? members : String(members || "").split(","))
    .map((member) => String(member).trim())
    .filter((member) => store.findUserById(member))
)];

const requireUser = (id) => {
  const user = store.findUserById(id);
  if (!user) {
    const error = new Error("User not found");
    error.status = 404;
    throw error;
  }
  return user;
};

export const createVault = (actor, input = {}) => {
  const name = String(input.name || "").trim();
  const classification = String(input.classification || "OFFICIAL-SENSITIVE").trim();
  const ownerUnit = String(input.ownerUnit || actor.unit || "Unassigned").trim();
  const members = normalizeMembers([actor.id, ...(Array.isArray(input.members) ? input.members : String(input.members || "").split(","))]);

  if (name.length < 3 || name.length > 80) {
    const error = new Error("Vault name must be between 3 and 80 characters");
    error.status = 400;
    throw error;
  }
  if (store.state.vaults.some((vault) => vault.name.toLowerCase() === name.toLowerCase())) {
    const error = new Error("Vault name already exists");
    error.status = 400;
    throw error;
  }

  const vault = {
    id: crypto.randomUUID(),
    name,
    classification,
    ownerUnit,
    members,
    health: 100
  };
  store.state.vaults.unshift(vault);
  audit(actor.id, "VAULT_CREATE", name, `Created ${classification} vault for ${ownerUnit}`);
  return vault;
};

export const updateVault = (actor, id, patch = {}) => {
  const vault = store.findVaultById(id);
  if (!vault) {
    const error = new Error("Vault not found");
    error.status = 404;
    throw error;
  }

  if (patch.name !== undefined) {
    const name = String(patch.name || "").trim();
    if (name.length < 3 || name.length > 80) {
      const error = new Error("Vault name must be between 3 and 80 characters");
      error.status = 400;
      throw error;
    }
    vault.name = name;
  }
  if (patch.classification !== undefined) vault.classification = String(patch.classification || "").trim();
  if (patch.ownerUnit !== undefined) vault.ownerUnit = String(patch.ownerUnit || "").trim();
  if (patch.members !== undefined) vault.members = normalizeMembers(patch.members);

  audit(actor.id, "VAULT_UPDATE", vault.name, "Updated vault metadata and membership");
  return vault;
};

export const updateUser = (actor, id, patch = {}) => {
  const user = requireUser(id);
  if (patch.role !== undefined) {
    const role = String(patch.role || "").trim();
    if (!roles[role]) {
      const error = new Error("Unsupported user role");
      error.status = 400;
      throw error;
    }
    user.role = role;
  }
  if (patch.enabled !== undefined) {
    user.enabled = Boolean(patch.enabled);
    if (!user.enabled) {
      for (const [token, session] of store.state.sessions.entries()) {
        if (session.userId === user.id) store.state.sessions.delete(token);
      }
    }
  }
  if (patch.mfa !== undefined) user.mfa = Boolean(patch.mfa);
  if (patch.unit !== undefined) user.unit = String(patch.unit || "").trim();

  audit(actor.id, "USER_UPDATE", user.email, "Updated role, status, MFA, or unit metadata");
  return user;
};
