import crypto from "node:crypto";
import { config } from "../config.mjs";
import { store } from "../data/store.mjs";
import { canAccessVault, revealSecret } from "./vaultService.mjs";
import { audit } from "./auditService.mjs";

const cacheVersion = 1;
const cacheTtlHours = 12;

const cacheKey = (user) => crypto.createHash("sha256")
  .update(["sentinel-offline-cache", config.vaultRootKey, config.vaultKeyVersion, user.id].join(":"), "utf8")
  .digest();

const cacheSignature = (manifest, encrypted) => crypto.createHmac("sha256", config.vaultRootKey)
  .update(JSON.stringify({ manifest, encrypted }), "utf8")
  .digest("base64url");

const accessibleSecrets = (user) => store.state.secrets
  .filter((secret) => !secret.deletedAt)
  .filter((secret) => {
    const vault = store.findVaultById(secret.vaultId);
    return canAccessVault(user, vault) || secret.sharedWith.includes(user.id);
  });

const buildPayload = (user) => {
  const vaultIds = new Set(accessibleSecrets(user).map((secret) => secret.vaultId));
  const vaults = store.state.vaults
    .filter((vault) => vaultIds.has(vault.id) || canAccessVault(user, vault))
    .map((vault) => ({
      id: vault.id,
      tenantId: vault.tenantId || null,
      name: vault.name,
      classification: vault.classification,
      ownerUnit: vault.ownerUnit
    }));
  const secrets = accessibleSecrets(user).map((secret) => ({
    id: secret.id,
    vaultId: secret.vaultId,
    type: secret.type,
    name: secret.name,
    username: secret.username,
    url: secret.url,
    tags: secret.tags,
    risk: secret.risk,
    rotatedAt: secret.rotatedAt,
    approvalsRequired: Boolean(secret.approvalsRequired),
    notes: secret.notes,
    encrypted: secret.encrypted
  }));

  return {
    version: cacheVersion,
    readOnly: true,
    exportedFor: user.id,
    exportedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + cacheTtlHours * 3600000).toISOString(),
    keyVersion: config.vaultKeyVersion,
    vaults,
    secrets
  };
};

export const createOfflineCache = (user) => {
  const payload = buildPayload(user);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", cacheKey(user), iv);
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const encrypted = {
    algorithm: "AES-256-GCM",
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    ciphertext: ciphertext.toString("base64url")
  };
  const manifest = {
    format: "sentinel-offline-cache-v1",
    readOnly: true,
    exportedFor: user.id,
    exportedAt: payload.exportedAt,
    expiresAt: payload.expiresAt,
    keyVersion: config.vaultKeyVersion,
    vaults: payload.vaults.length,
    secrets: payload.secrets.length,
    index: {
      vaults: payload.vaults.map((vault) => ({
        id: vault.id,
        name: vault.name,
        classification: vault.classification,
        ownerUnit: vault.ownerUnit
      })),
      secrets: payload.secrets.map((secret) => ({
        id: secret.id,
        vaultId: secret.vaultId,
        type: secret.type,
        name: secret.name,
        username: secret.username,
        url: secret.url,
        tags: secret.tags,
        risk: secret.risk,
        rotatedAt: secret.rotatedAt,
        approvalsRequired: secret.approvalsRequired
      }))
    },
    plaintextIncluded: false
  };
  const cache = {
    manifest,
    encrypted,
    signature: cacheSignature(manifest, encrypted)
  };
  audit(user.id, "OFFLINE_CACHE_EXPORT", "Read-only offline cache", `Exported ${manifest.secrets} encrypted secret records`);
  return cache;
};

export const verifyOfflineCache = (user, cache) => {
  if (!cache?.manifest || !cache?.encrypted || !cache?.signature) {
    const error = new Error("Offline cache artifact is incomplete");
    error.status = 400;
    throw error;
  }
  const expectedSignature = cacheSignature(cache.manifest, cache.encrypted);
  if (cache.signature !== expectedSignature) {
    return { verified: false, reason: "signature_mismatch" };
  }
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", cacheKey(user), Buffer.from(cache.encrypted.iv, "base64url"));
    decipher.setAuthTag(Buffer.from(cache.encrypted.tag, "base64url"));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(cache.encrypted.ciphertext, "base64url")),
      decipher.final()
    ]);
    const payload = JSON.parse(decrypted.toString("utf8"));
    return {
      verified: payload.readOnly === true && payload.exportedFor === user.id,
      reason: payload.readOnly === true && payload.exportedFor === user.id ? null : "scope_or_mode_mismatch",
      readOnly: payload.readOnly === true,
      expired: Date.parse(payload.expiresAt) <= Date.now(),
      vaults: payload.vaults?.length || 0,
      secrets: payload.secrets?.length || 0,
      expiresAt: payload.expiresAt || null
    };
  } catch (err) {
    return {
      verified: false,
      reason: "decrypt_or_parse_failed",
      detail: err instanceof Error ? err.message : "Unknown offline cache validation error"
    };
  }
};

export const rehydrateOfflineCacheSecret = (user, cache, secretId) => {
  const verification = verifyOfflineCache(user, cache);
  if (!verification.verified) {
    const error = new Error("Offline cache verification failed");
    error.status = 400;
    error.details = verification;
    throw error;
  }
  if (verification.expired) {
    const error = new Error("Offline cache has expired");
    error.status = 400;
    throw error;
  }

  const indexed = cache.manifest.index?.secrets?.some((secret) => secret.id === secretId);
  if (!indexed) {
    const error = new Error("Secret is not present in the offline cache index");
    error.status = 404;
    throw error;
  }

  const revealed = revealSecret(user, secretId);
  audit(user.id, "OFFLINE_CACHE_REHYDRATE", secretId, "Rehydrated encrypted offline cache entry through live server authorization");
  return revealed;
};
