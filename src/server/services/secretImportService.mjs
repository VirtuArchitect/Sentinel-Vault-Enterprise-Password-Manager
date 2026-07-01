import crypto from "node:crypto";
import { encryptSecret, fingerprintSecret } from "../crypto/vaultCrypto.mjs";
import { store } from "../data/store.mjs";
import { canAccessVault } from "./vaultService.mjs";
import { audit } from "./auditService.mjs";

const maxImportEntries = 100;

const normalizeTags = (tags) => Array.isArray(tags)
  ? tags.map((tag) => String(tag).trim()).filter(Boolean)
  : String(tags || "").split(",").map((tag) => tag.trim()).filter(Boolean);

const publicBatch = (batch) => ({
  id: batch.id,
  vaultId: batch.vaultId,
  requestedBy: batch.requestedBy,
  requestedAt: batch.requestedAt,
  decidedBy: batch.decidedBy || null,
  decidedAt: batch.decidedAt || null,
  status: batch.status,
  entryCount: batch.entries.length,
  duplicateCount: batch.duplicates.length,
  duplicates: batch.duplicates,
  reason: batch.reason || "",
  importedSecretIds: batch.importedSecretIds || []
});

const requireBatch = (id) => {
  const batch = store.findSecretImportById(id);
  if (!batch) {
    const error = new Error("Secret import batch not found");
    error.status = 404;
    throw error;
  }
  return batch;
};

const normalizeEntry = (entry, index, vaultId) => {
  const name = String(entry.name || "").trim();
  const username = String(entry.username || "").trim();
  const password = String(entry.password || "").trim();
  if (!name || !username || !password) {
    const error = new Error(`Import entry ${index + 1} requires name, username, and password`);
    error.status = 400;
    throw error;
  }
  const fingerprint = fingerprintSecret(password);
  return {
    id: crypto.randomUUID(),
    vaultId,
    type: String(entry.type || "password").trim(),
    name,
    username,
    url: String(entry.url || "").trim(),
    tags: normalizeTags(entry.tags),
    risk: String(entry.risk || "medium").trim(),
    notes: String(entry.notes || "").trim(),
    approvalsRequired: Boolean(entry.approvalsRequired || entry.risk === "high"),
    encrypted: encryptSecret(password),
    fingerprint
  };
};

const duplicateReport = (entries, vaultId) => {
  const seen = new Map();
  const existing = new Map(store.state.secrets
    .filter((secret) => secret.vaultId === vaultId && !secret.deletedAt && secret.fingerprint)
    .map((secret) => [secret.fingerprint, secret.name]));
  const duplicates = [];
  entries.forEach((entry, index) => {
    if (existing.has(entry.fingerprint)) {
      duplicates.push({ index, name: entry.name, reason: "matches_existing_secret", existingName: existing.get(entry.fingerprint) });
    }
    if (seen.has(entry.fingerprint)) {
      duplicates.push({ index, name: entry.name, reason: "duplicate_in_import", existingName: seen.get(entry.fingerprint) });
    }
    seen.set(entry.fingerprint, entry.name);
  });
  return duplicates;
};

export const listSecretImports = () => (store.state.secretImports || []).map(publicBatch);

export const createSecretImport = (actor, input = {}) => {
  const vault = store.findVaultById(input.vaultId);
  if (!canAccessVault(actor, vault)) {
    const error = new Error("Vault access denied");
    error.status = 403;
    throw error;
  }
  const rawEntries = Array.isArray(input.entries) ? input.entries : [];
  if (!rawEntries.length || rawEntries.length > maxImportEntries) {
    const error = new Error(`Secret import requires 1 to ${maxImportEntries} entries`);
    error.status = 400;
    throw error;
  }

  const entries = rawEntries.map((entry, index) => normalizeEntry(entry, index, vault.id));
  const duplicates = duplicateReport(entries, vault.id);
  if (duplicates.length && input.allowDuplicates !== true) {
    const error = new Error("Secret import contains duplicate secret material");
    error.status = 400;
    error.details = duplicates;
    throw error;
  }

  const batch = {
    id: crypto.randomUUID(),
    vaultId: vault.id,
    requestedBy: actor.id,
    requestedAt: new Date().toISOString(),
    decidedBy: null,
    decidedAt: null,
    status: "pending",
    reason: String(input.reason || "").trim(),
    entries,
    duplicates,
    importedSecretIds: []
  };
  store.state.secretImports.unshift(batch);
  audit(actor.id, "SECRET_IMPORT_REQUEST", vault.name, `Submitted ${entries.length} encrypted import entries for independent approval`);
  return publicBatch(batch);
};

export const approveSecretImport = (actor, id) => {
  const batch = requireBatch(id);
  if (batch.status !== "pending") {
    const error = new Error("Secret import batch is not pending");
    error.status = 400;
    throw error;
  }
  if (batch.requestedBy === actor.id) {
    const error = new Error("Secret import requires independent approval");
    error.status = 403;
    throw error;
  }
  const vault = store.findVaultById(batch.vaultId);
  if (!canAccessVault(actor, vault)) {
    const error = new Error("Vault access denied");
    error.status = 403;
    throw error;
  }

  const now = new Date().toISOString();
  const created = batch.entries.map((entry) => ({
    ...entry,
    id: crypto.randomUUID(),
    rotatedAt: now,
    sharedWith: [],
    deletedAt: null,
    history: []
  }));
  store.state.secrets.unshift(...created);
  batch.status = "approved";
  batch.decidedBy = actor.id;
  batch.decidedAt = now;
  batch.importedSecretIds = created.map((secret) => secret.id);
  audit(actor.id, "SECRET_IMPORT_APPROVE", vault?.name || batch.vaultId, `Approved ${created.length} escrowed import entries`);
  return publicBatch(batch);
};

export const denySecretImport = (actor, id, reason = "") => {
  const batch = requireBatch(id);
  if (batch.status !== "pending") {
    const error = new Error("Secret import batch is not pending");
    error.status = 400;
    throw error;
  }
  if (batch.requestedBy === actor.id) {
    const error = new Error("Secret import requires independent denial");
    error.status = 403;
    throw error;
  }
  batch.status = "denied";
  batch.decidedBy = actor.id;
  batch.decidedAt = new Date().toISOString();
  batch.denialReason = String(reason || "").trim();
  audit(actor.id, "SECRET_IMPORT_DENY", batch.vaultId, batch.denialReason || "Denied escrowed import batch");
  return publicBatch(batch);
};
