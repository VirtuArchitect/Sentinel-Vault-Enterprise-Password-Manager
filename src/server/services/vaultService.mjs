import crypto from "node:crypto";
import { encryptSecret, decryptSecret, fingerprintSecret, getCryptoStatus, secretStrength } from "../crypto/vaultCrypto.mjs";
import { generateCredential } from "../crypto/passwords.mjs";
import { store } from "../data/store.mjs";
import { hasPermission, publicUser } from "../rbac/roles.mjs";
import { audit } from "./auditService.mjs";
import { getIdentityStatus } from "./identityService.mjs";
import { getIntegrationStatus } from "./integrationService.mjs";
import { getSessionStatus } from "./sessionService.mjs";

export const canAccessVault = (user, vault) => Boolean(vault && (vault.members.includes(user.id) || user.role === "SECURITY_ADMIN"));

export const canAccessSecret = (user, secret) => {
  const vault = store.findVaultById(secret?.vaultId);
  return Boolean(secret && (canAccessVault(user, vault) || secret.sharedWith.includes(user.id)));
};

const activeGrantFor = (user, secret) => store.state.accessRequests.find((request) => (
  request.secretId === secret?.id &&
  request.requesterId === user.id &&
  request.status === "approved" &&
  request.expiresAt &&
  Date.parse(request.expiresAt) > Date.now()
));

const requireSecretAccess = (user, secret) => {
  if (canAccessSecret(user, secret) || activeGrantFor(user, secret)) return;
  const error = new Error("Secret access denied");
  error.status = 403;
  throw error;
};

const requireVaultAccess = (user, secret) => {
  const vault = store.findVaultById(secret?.vaultId);
  if (canAccessVault(user, vault)) return vault;
  const error = new Error("Vault access denied");
  error.status = 403;
  throw error;
};

const requireSecret = (id) => {
  const secret = store.findSecretById(id);
  if (!secret) {
    const error = new Error("Secret not found");
    error.status = 404;
    throw error;
  }
  return secret;
};

const normalizeTags = (tags) => String(tags || "").split(",").map((tag) => tag.trim()).filter(Boolean);

const publicRequest = (request) => {
  const secret = store.findSecretById(request.secretId);
  const requester = store.findUserById(request.requesterId);
  const approver = store.findUserById(request.approvedBy);
  const approvals = request.approvals || [];
  return {
    ...request,
    approvals,
    approvalCount: approvals.length,
    requiredApprovals: request.requiredApprovals || 1,
    secretName: secret?.name || "Unknown secret",
    requesterName: requester?.name || "Unknown user",
    approvedByName: approver?.name || null
  };
};

const clampInteger = (value, min, max, field) => {
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) {
    const error = new Error(`${field} must be an integer between ${min} and ${max}`);
    error.status = 400;
    throw error;
  }
  return number;
};

const policyValidators = {
  rotationDays: (value) => clampInteger(value, 1, 365, "rotationDays"),
  minimumLength: (value) => clampInteger(value, 12, 128, "minimumLength"),
  clipboardTtl: (value) => clampInteger(value, 5, 300, "clipboardTtl"),
  sessionMinutes: (value) => clampInteger(value, 1, 480, "sessionMinutes"),
  mfaRequired: (value) => Boolean(value),
  justInTimeAccess: (value) => Boolean(value),
  breakGlassApproval: (value) => {
    const text = String(value || "").trim();
    if (text.length < 3 || text.length > 80) {
      const error = new Error("breakGlassApproval must be between 3 and 80 characters");
      error.status = 400;
      throw error;
    }
    return text;
  }
};

const isStale = (secret) => Date.now() - Date.parse(secret.rotatedAt) > store.state.policies.rotationDays * 86400000;

const reusedFingerprints = () => {
  const counts = new Map();
  store.state.secrets.forEach((secret) => {
    if (!secret.fingerprint) return;
    const key = `${secret.vaultId}:${secret.fingerprint}`;
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  return counts;
};

export const getSecretHealthReport = () => {
  const reused = reusedFingerprints();
  return store.state.secrets.map((secret) => ({
    id: secret.id,
    vaultId: secret.vaultId,
    name: secret.name,
    type: secret.type,
    risk: secret.risk,
    stale: isStale(secret),
    reused: Boolean(secret.fingerprint && reused.get(`${secret.vaultId}:${secret.fingerprint}`) > 1),
    rotatedAt: secret.rotatedAt,
    historyCount: secret.history?.length || 0
  }));
};

export const getConsolePayload = (user) => {
  const readableVaults = store.state.vaults.filter((vault) => canAccessVault(user, vault));
  const readableIds = new Set(readableVaults.map((vault) => vault.id));
  const secrets = store.state.secrets
    .filter((secret) => readableIds.has(secret.vaultId) || secret.sharedWith.includes(user.id) || activeGrantFor(user, secret))
    .filter((secret) => !secret.deletedAt)
    .map((secret) => ({
      id: secret.id,
      vaultId: secret.vaultId,
      type: secret.type,
      name: secret.name,
      username: secret.username,
      url: secret.url,
      tags: secret.tags,
      risk: secret.risk,
      rotatedAt: secret.rotatedAt,
      sharedWith: secret.sharedWith,
      approvalsRequired: secret.approvalsRequired,
      notes: secret.notes,
      strength: secretStrength(secret.encrypted)
    }));
  const visibleSecretIds = new Set(secrets.map((secret) => secret.id));
  const accessRequests = store.state.accessRequests
    .filter((request) => hasPermission(user.role, "policy:write") || request.requesterId === user.id || visibleSecretIds.has(request.secretId))
    .map(publicRequest);

  return {
    user: publicUser(user),
    users: hasPermission(user.role, "users:read") ? store.state.users.map(publicUser) : [],
    vaults: readableVaults,
    secrets,
    policies: store.state.policies,
    identity: getIdentityStatus(),
    session: getSessionStatus(),
    crypto: getCryptoStatus(),
    integrations: getIntegrationStatus(),
    storage: store.getStorageStatus(),
    audit: hasPermission(user.role, "audit:read") ? store.state.audit.slice(0, 20) : [],
    accessRequests,
    metrics: {
      secrets: store.state.secrets.length,
      vaults: store.state.vaults.length,
      stale: store.state.secrets.filter(isStale).length,
      highRisk: store.state.secrets.filter((secret) => secret.risk === "high").length,
      reused: getSecretHealthReport().filter((secret) => secret.reused).length,
      pendingRequests: store.state.accessRequests.filter((request) => request.status === "pending").length
    }
  };
};

export const createSecret = (user, input) => {
  const { vaultId, name, username, password, url, tags, notes, type } = input;
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
  const fingerprint = fingerprintSecret(password);
  if (store.state.secrets.some((secret) => secret.vaultId === vaultId && secret.fingerprint === fingerprint)) {
    const error = new Error("Secret material has already been used in this vault");
    error.status = 400;
    throw error;
  }

  const secret = {
    id: crypto.randomUUID(),
    vaultId,
    type: type || "password",
    name,
    username,
    url: url || "",
    tags: normalizeTags(tags),
    risk: password.length < store.state.policies.minimumLength ? "high" : "low",
    rotatedAt: new Date().toISOString(),
    sharedWith: [user.id],
    approvalsRequired: password.length < store.state.policies.minimumLength,
    notes: notes || "",
    history: [],
    fingerprint,
    encrypted: encryptSecret(password)
  };
  store.state.secrets.unshift(secret);
  audit(user.id, "CREATE_SECRET", name, `Stored in ${vault.name}`);
};

export const updateSecret = (user, id, patch) => {
  const secret = requireSecret(id);
  requireVaultAccess(user, secret);
  if (secret.deletedAt) {
    const error = new Error("Deleted secrets cannot be updated");
    error.status = 400;
    throw error;
  }
  if (patch.name) secret.name = String(patch.name).trim();
  if (patch.username) secret.username = String(patch.username).trim();
  if (patch.url !== undefined) secret.url = String(patch.url || "");
  if (patch.tags !== undefined) secret.tags = normalizeTags(patch.tags);
  if (patch.notes !== undefined) secret.notes = String(patch.notes || "");
  if (patch.type) secret.type = String(patch.type);
  if (patch.password) {
    const fingerprint = fingerprintSecret(patch.password);
    if (store.state.secrets.some((candidate) => candidate.id !== secret.id && candidate.vaultId === secret.vaultId && candidate.fingerprint === fingerprint && !candidate.deletedAt)) {
      const error = new Error("Secret material has already been used in this vault");
      error.status = 400;
      throw error;
    }
    secret.history.unshift({
      rotatedAt: secret.rotatedAt,
      rotatedBy: user.id,
      encrypted: secret.encrypted,
      fingerprint: secret.fingerprint
    });
    secret.history = secret.history.slice(0, 10);
    secret.encrypted = encryptSecret(patch.password);
    secret.fingerprint = fingerprint;
    secret.rotatedAt = new Date().toISOString();
    secret.risk = patch.password.length < store.state.policies.minimumLength ? "high" : "low";
    secret.approvalsRequired = secret.risk === "high";
  }
  audit(user.id, "UPDATE_SECRET", secret.name, "Credential metadata updated");
  return { ok: true };
};

export const deleteSecret = (user, id) => {
  const secret = requireSecret(id);
  requireVaultAccess(user, secret);
  secret.deletedAt = new Date().toISOString();
  audit(user.id, "DELETE_SECRET", secret.name, "Credential moved to deleted state");
  return { ok: true };
};

export const restoreSecretVersion = (user, id, index = 0) => {
  const secret = requireSecret(id);
  requireVaultAccess(user, secret);
  const version = secret.history?.[Number(index)];
  if (!version?.encrypted) {
    const error = new Error("Secret version not found");
    error.status = 404;
    throw error;
  }
  secret.history.unshift({
    rotatedAt: secret.rotatedAt,
    rotatedBy: user.id,
    encrypted: secret.encrypted,
    fingerprint: secret.fingerprint
  });
  secret.encrypted = version.encrypted;
  secret.fingerprint = version.fingerprint;
  secret.rotatedAt = new Date().toISOString();
  secret.deletedAt = null;
  secret.history = secret.history.filter((_, versionIndex) => versionIndex !== Number(index) + 1).slice(0, 10);
  audit(user.id, "RESTORE_SECRET_VERSION", secret.name, `Restored version ${index}`);
  return { ok: true };
};

export const revealSecret = (user, id) => {
  const secret = requireSecret(id);
  requireSecretAccess(user, secret);
  audit(user.id, "REVEAL_SECRET", secret.name, "Credential viewed under active session policy");
  return { password: decryptSecret(secret.encrypted), expiresIn: store.state.policies.clipboardTtl };
};

export const rotateSecret = (user, id) => {
  const secret = requireSecret(id);
  requireVaultAccess(user, secret);
  const generated = generateCredential();
  secret.history.unshift({ rotatedAt: secret.rotatedAt, rotatedBy: user.id, encrypted: secret.encrypted, fingerprint: secret.fingerprint });
  secret.history = secret.history.slice(0, 10);
  secret.encrypted = encryptSecret(generated);
  secret.fingerprint = fingerprintSecret(generated);
  secret.rotatedAt = new Date().toISOString();
  secret.risk = "low";
  secret.approvalsRequired = false;
  audit(user.id, "ROTATE_SECRET", secret.name, "Generated 170-bit replacement credential");
  return generated;
};

export const shareSecret = (user, id, userId) => {
  const secret = requireSecret(id);
  const target = store.findUserById(userId);
  if (!target) {
    const error = new Error("User not found");
    error.status = 404;
    throw error;
  }
  requireVaultAccess(user, secret);
  if (!secret.sharedWith.includes(target.id)) secret.sharedWith.push(target.id);
  audit(user.id, "SHARE_SECRET", secret.name, `Granted to ${target.name}`);
};

export const requestSecretAccess = (user, secretId, reason, options = {}) => {
  const secret = requireSecret(secretId);
  if (canAccessSecret(user, secret)) {
    const error = new Error("User already has access to this secret");
    error.status = 400;
    throw error;
  }
  const text = String(reason || "").trim();
  if (text.length < 8 || text.length > 240) {
    const error = new Error("Access reason must be between 8 and 240 characters");
    error.status = 400;
    throw error;
  }
  const requestedMinutes = clampInteger(options.minutes || 30, 5, 240, "minutes");
  const existing = store.state.accessRequests.find((request) => request.secretId === secretId && request.requesterId === user.id && request.status === "pending");
  if (existing) return publicRequest(existing);
  const request = {
    id: crypto.randomUUID(),
    secretId,
    requesterId: user.id,
    reason: text,
    status: "pending",
    requestedAt: new Date().toISOString(),
    expiresAt: null,
    approvedBy: null,
    decidedAt: null,
    ticketRef: String(options.ticketRef || "").trim(),
    requestedMinutes,
    approvals: [],
    requiredApprovals: secret.approvalsRequired ? 2 : 1
  };
  store.state.accessRequests.unshift(request);
  audit(user.id, "ACCESS_REQUEST", secret.name, text);
  return publicRequest(request);
};

export const approveAccessRequest = (user, requestId, minutes = 30) => {
  const request = store.findAccessRequestById(requestId);
  if (!request) {
    const error = new Error("Access request not found");
    error.status = 404;
    throw error;
  }
  const secret = requireSecret(request.secretId);
  requireVaultAccess(user, secret);
  if (request.requesterId === user.id) {
    const error = new Error("Requesters cannot approve their own temporary access");
    error.status = 403;
    throw error;
  }
  if (request.status !== "pending") {
    const error = new Error("Access request has already been decided");
    error.status = 400;
    throw error;
  }
  const ttl = clampInteger(minutes || request.requestedMinutes || 30, 5, 240, "minutes");
  request.approvals = request.approvals || [];
  if (!request.approvals.includes(user.id)) request.approvals.push(user.id);
  request.approvedBy = user.id;
  request.requestedMinutes = ttl;
  request.requiredApprovals = request.requiredApprovals || (secret.approvalsRequired ? 2 : 1);
  const privilegedApproval = user.role === "SECURITY_ADMIN" && secret.approvalsRequired;
  if (privilegedApproval || request.approvals.length >= request.requiredApprovals) {
    request.status = "approved";
    request.expiresAt = new Date(Date.now() + ttl * 60000).toISOString();
    request.decidedAt = new Date().toISOString();
  }
  audit(user.id, "ACCESS_APPROVED", secret.name, `Approval ${request.approvals.length}/${request.requiredApprovals}; temporary access for ${ttl} minutes`);
  return publicRequest(request);
};

export const denyAccessRequest = (user, requestId) => {
  const request = store.findAccessRequestById(requestId);
  if (!request) {
    const error = new Error("Access request not found");
    error.status = 404;
    throw error;
  }
  const secret = requireSecret(request.secretId);
  requireVaultAccess(user, secret);
  request.status = "denied";
  request.approvedBy = user.id;
  request.decidedAt = new Date().toISOString();
  request.expiresAt = null;
  audit(user.id, "ACCESS_DENIED", secret.name, "Temporary access denied");
  return publicRequest(request);
};

export const revokeAccessRequest = (user, requestId) => {
  const request = store.findAccessRequestById(requestId);
  if (!request) {
    const error = new Error("Access request not found");
    error.status = 404;
    throw error;
  }
  const secret = requireSecret(request.secretId);
  requireVaultAccess(user, secret);
  request.status = "revoked";
  request.expiresAt = new Date().toISOString();
  request.decidedAt = new Date().toISOString();
  audit(user.id, "ACCESS_REVOKED", secret.name, "Temporary access revoked");
  return publicRequest(request);
};

export const updatePolicies = (user, patch) => {
  const next = {};
  for (const [key, value] of Object.entries(patch || {})) {
    const validator = policyValidators[key];
    if (!validator) {
      const error = new Error(`Unsupported policy field: ${key}`);
      error.status = 400;
      throw error;
    }
    next[key] = validator(value);
  }
  store.state.policies = { ...store.state.policies, ...next };
  audit(user.id, "POLICY_UPDATE", "Enterprise policy", "Policy controls updated");
  return store.state.policies;
};
