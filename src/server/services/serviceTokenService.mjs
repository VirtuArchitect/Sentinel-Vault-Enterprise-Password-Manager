import crypto from "node:crypto";
import { store } from "../data/store.mjs";
import { audit } from "./auditService.mjs";

const hashToken = (token) => crypto.createHash("sha256").update(token, "utf8").digest("base64url");
const createRawServiceToken = () => `svt_${crypto.randomBytes(32).toString("base64url")}`;

const publicToken = (token) => ({
  id: token.id,
  name: token.name,
  ownerId: token.ownerId,
  allowedVaults: token.allowedVaults,
  allowedSecrets: token.allowedSecrets,
  expiresAt: token.expiresAt,
  revokedAt: token.revokedAt || null,
  createdAt: token.createdAt,
  rotatedAt: token.rotatedAt || null,
  rotationCount: token.rotationCount || 0,
  lastUsedAt: token.lastUsedAt || null,
  lastUsedSecretId: token.lastUsedSecretId || null,
  lastUsedSource: token.lastUsedSource || null,
  useCount: token.useCount || 0
});

export const listServiceTokens = () => store.state.serviceTokens.map(publicToken);

export const createServiceToken = (user, input = {}) => {
  const name = String(input.name || "").trim();
  if (name.length < 3 || name.length > 80) {
    const error = new Error("Service token name must be between 3 and 80 characters");
    error.status = 400;
    throw error;
  }
  const ttlDays = Number(input.ttlDays || 30);
  if (!Number.isInteger(ttlDays) || ttlDays < 1 || ttlDays > 365) {
    const error = new Error("ttlDays must be an integer between 1 and 365");
    error.status = 400;
    throw error;
  }
  const raw = createRawServiceToken();
  const token = {
    id: crypto.randomUUID(),
    name,
    ownerId: user.id,
    tokenHash: hashToken(raw),
    allowedVaults: Array.isArray(input.allowedVaults) ? input.allowedVaults : [],
    allowedSecrets: Array.isArray(input.allowedSecrets) ? input.allowedSecrets : [],
    expiresAt: new Date(Date.now() + ttlDays * 86400000).toISOString(),
    createdAt: new Date().toISOString(),
    rotatedAt: null,
    rotationCount: 0,
    revokedAt: null,
    lastUsedAt: null,
    lastUsedSecretId: null,
    lastUsedSource: null,
    useCount: 0
  };
  store.state.serviceTokens.unshift(token);
  audit(user.id, "SERVICE_TOKEN_CREATE", name, "Created scoped DevOps service token");
  return { token: publicToken(token), secret: raw };
};

export const revokeServiceToken = (user, id) => {
  const token = store.findServiceTokenById(id);
  if (!token) {
    const error = new Error("Service token not found");
    error.status = 404;
    throw error;
  }
  token.revokedAt = new Date().toISOString();
  audit(user.id, "SERVICE_TOKEN_REVOKE", token.name, "Revoked DevOps service token");
  return { token: publicToken(token) };
};

export const rotateServiceToken = (user, id) => {
  const token = store.findServiceTokenById(id);
  if (!token) {
    const error = new Error("Service token not found");
    error.status = 404;
    throw error;
  }
  if (token.revokedAt) {
    const error = new Error("Revoked service tokens cannot be rotated");
    error.status = 400;
    throw error;
  }

  const raw = createRawServiceToken();
  token.tokenHash = hashToken(raw);
  token.rotatedAt = new Date().toISOString();
  token.rotationCount = Number(token.rotationCount || 0) + 1;
  token.lastUsedAt = null;
  token.lastUsedSecretId = null;
  token.lastUsedSource = null;
  token.useCount = 0;
  audit(user.id, "SERVICE_TOKEN_ROTATE", token.name, "Rotated scoped DevOps service token");
  return { token: publicToken(token), secret: raw };
};

export const resolveServiceToken = (rawToken, secret, source = "127.0.0.1") => {
  const hash = hashToken(String(rawToken || ""));
  const token = store.state.serviceTokens.find((candidate) => candidate.tokenHash === hash);
  if (!token || token.revokedAt || Date.parse(token.expiresAt) <= Date.now()) return null;
  if (token.allowedSecrets.length && !token.allowedSecrets.includes(secret.id)) return null;
  if (token.allowedVaults.length && !token.allowedVaults.includes(secret.vaultId)) return null;
  if (!token.allowedSecrets.length && !token.allowedVaults.length) return null;
  token.lastUsedAt = new Date().toISOString();
  token.lastUsedSecretId = secret.id;
  token.lastUsedSource = source;
  token.useCount = Number(token.useCount || 0) + 1;
  store.save();
  return token;
};
