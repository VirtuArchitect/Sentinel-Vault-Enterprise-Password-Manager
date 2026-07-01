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

const normalizeName = (value, label, min = 3, max = 80) => {
  const name = String(value || "").trim();
  if (name.length < min || name.length > max) {
    const error = new Error(`${label} must be between ${min} and ${max} characters`);
    error.status = 400;
    throw error;
  }
  return name;
};

const requireTenant = (id) => {
  const tenant = store.findTenantById(id);
  if (!tenant) {
    const error = new Error("Tenant not found");
    error.status = 404;
    throw error;
  }
  return tenant;
};

const validateTenantParent = (id, parentId) => {
  if (!parentId) return null;
  if (parentId === id) {
    const error = new Error("Tenant cannot be its own parent");
    error.status = 400;
    throw error;
  }
  requireTenant(parentId);
  let cursor = store.findTenantById(parentId);
  while (cursor?.parentId) {
    if (cursor.parentId === id) {
      const error = new Error("Tenant parent would create a hierarchy cycle");
      error.status = 400;
      throw error;
    }
    cursor = store.findTenantById(cursor.parentId);
  }
  return parentId;
};

export const createTenant = (actor, input = {}) => {
  const name = normalizeName(input.name, "Tenant name");
  const parentId = validateTenantParent(null, input.parentId || null);
  const classification = String(input.classification || "OFFICIAL-SENSITIVE").trim();
  const ownerUnit = String(input.ownerUnit || actor.unit || "Unassigned").trim();

  if (store.state.tenants.some((tenant) => tenant.name.toLowerCase() === name.toLowerCase())) {
    const error = new Error("Tenant name already exists");
    error.status = 400;
    throw error;
  }

  const tenant = {
    id: crypto.randomUUID(),
    name,
    parentId,
    classification,
    ownerUnit
  };
  store.state.tenants.unshift(tenant);
  audit(actor.id, "TENANT_CREATE", name, `Created ${classification} tenant for ${ownerUnit}`);
  return tenant;
};

export const updateTenant = (actor, id, patch = {}) => {
  const tenant = requireTenant(id);
  if (patch.name !== undefined) {
    const name = normalizeName(patch.name, "Tenant name");
    if (store.state.tenants.some((candidate) => candidate.id !== id && candidate.name.toLowerCase() === name.toLowerCase())) {
      const error = new Error("Tenant name already exists");
      error.status = 400;
      throw error;
    }
    tenant.name = name;
  }
  if (patch.parentId !== undefined) tenant.parentId = validateTenantParent(id, patch.parentId || null);
  if (patch.classification !== undefined) tenant.classification = String(patch.classification || "").trim();
  if (patch.ownerUnit !== undefined) tenant.ownerUnit = String(patch.ownerUnit || "").trim();

  audit(actor.id, "TENANT_UPDATE", tenant.name, "Updated tenant hierarchy metadata");
  return tenant;
};

export const createVault = (actor, input = {}) => {
  const name = normalizeName(input.name, "Vault name");
  const classification = String(input.classification || "OFFICIAL-SENSITIVE").trim();
  const ownerUnit = String(input.ownerUnit || actor.unit || "Unassigned").trim();
  const members = normalizeMembers([actor.id, ...(Array.isArray(input.members) ? input.members : String(input.members || "").split(","))]);
  const tenantId = input.tenantId || store.state.tenants[0]?.id || null;

  if (tenantId) requireTenant(tenantId);
  if (store.state.vaults.some((vault) => vault.name.toLowerCase() === name.toLowerCase())) {
    const error = new Error("Vault name already exists");
    error.status = 400;
    throw error;
  }

  const vault = {
    id: crypto.randomUUID(),
    tenantId,
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
    vault.name = normalizeName(patch.name, "Vault name");
  }
  if (patch.tenantId !== undefined) {
    if (patch.tenantId) requireTenant(patch.tenantId);
    vault.tenantId = patch.tenantId || null;
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

const publicUserMetadata = (user) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  role: user.role,
  unit: user.unit,
  mfa: Boolean(user.mfa),
  enabled: user.enabled !== false
});

const publicVaultMetadata = (vault) => ({
  id: vault.id,
  tenantId: vault.tenantId || null,
  name: vault.name,
  classification: vault.classification,
  ownerUnit: vault.ownerUnit,
  members: vault.members || [],
  health: vault.health
});

export const exportAdminMetadata = (actor) => {
  audit(actor.id, "ADMIN_METADATA_EXPORT", "Vault administration", "Exported tenant, vault, user, and policy metadata");
  return {
    exportedAt: new Date().toISOString(),
    format: "sentinel-vault-admin-metadata-v1",
    tenants: store.state.tenants.map((tenant) => ({ ...tenant })),
    vaults: store.state.vaults.map(publicVaultMetadata),
    users: store.state.users.map(publicUserMetadata),
    policies: { ...store.state.policies }
  };
};

const upsertTenantMetadata = (tenantInput) => {
  const id = String(tenantInput.id || crypto.randomUUID()).trim();
  const existing = store.findTenantById(id);
  const next = {
    id,
    name: normalizeName(tenantInput.name, "Tenant name"),
    parentId: tenantInput.parentId || null,
    classification: String(tenantInput.classification || "OFFICIAL-SENSITIVE").trim(),
    ownerUnit: String(tenantInput.ownerUnit || "Unassigned").trim()
  };
  validateTenantParent(id, next.parentId);
  if (existing) {
    Object.assign(existing, next);
    return "updated";
  }
  store.state.tenants.push(next);
  return "created";
};

const upsertVaultMetadata = (vaultInput) => {
  const id = String(vaultInput.id || crypto.randomUUID()).trim();
  const existing = store.findVaultById(id);
  const tenantId = vaultInput.tenantId || store.state.tenants[0]?.id || null;
  if (tenantId) requireTenant(tenantId);
  const next = {
    id,
    tenantId,
    name: normalizeName(vaultInput.name, "Vault name"),
    classification: String(vaultInput.classification || "OFFICIAL-SENSITIVE").trim(),
    ownerUnit: String(vaultInput.ownerUnit || "Unassigned").trim(),
    members: normalizeMembers(vaultInput.members || []),
    health: Number.isFinite(Number(vaultInput.health)) ? Math.max(0, Math.min(100, Number(vaultInput.health))) : 100
  };
  if (existing) {
    Object.assign(existing, next);
    return "updated";
  }
  store.state.vaults.push(next);
  return "created";
};

export const importAdminMetadata = (actor, input = {}) => {
  if (input.secrets || input.serviceTokens || input.sessions || input.audit) {
    const error = new Error("Admin metadata import does not accept secrets, tokens, sessions, or audit records");
    error.status = 400;
    throw error;
  }

  const result = {
    tenants: { created: 0, updated: 0 },
    vaults: { created: 0, updated: 0 }
  };

  for (const tenant of Array.isArray(input.tenants) ? input.tenants : []) {
    result.tenants[upsertTenantMetadata(tenant)] += 1;
  }
  for (const vault of Array.isArray(input.vaults) ? input.vaults : []) {
    result.vaults[upsertVaultMetadata(vault)] += 1;
  }

  audit(actor.id, "ADMIN_METADATA_IMPORT", "Vault administration", `Imported ${result.tenants.created + result.tenants.updated} tenants and ${result.vaults.created + result.vaults.updated} vaults`);
  return result;
};
