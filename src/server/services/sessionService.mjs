import crypto from "node:crypto";
import { config } from "../config.mjs";
import { store } from "../data/store.mjs";

const sessionTtlMs = () => Math.max(1, Number(store.state.policies.sessionMinutes || 15)) * 60000;
const refreshTtlMs = () => Math.max(1, Number(config.refreshTokens.ttlDays || 7)) * 24 * 60 * 60000;

const sessionId = (token) => crypto.createHash("sha256").update(String(token || ""), "utf8").digest("base64url").slice(0, 22);
const refreshTokenHash = (token) => crypto.createHash("sha256").update(String(token || ""), "utf8").digest("base64url");
const refreshTokenId = (tokenHash) => tokenHash.slice(0, 22);
const isRefreshTokenIssueEnabled = () => config.refreshTokens.enabled && config.identityProvider.mode !== "local";

const rememberDevice = (publicId, session) => {
  store.state.deviceInventory = store.state.deviceInventory || [];
  const userAgent = session.userAgent || "unknown";
  const source = session.source || "unknown";
  const fingerprint = crypto.createHash("sha256").update(`${session.userId}|${source}|${userAgent}`, "utf8").digest("base64url").slice(0, 22);
  const existing = store.state.deviceInventory.find((device) => device.fingerprint === fingerprint);
  const now = new Date().toISOString();
  if (existing) {
    existing.lastSeenAt = now;
    existing.lastSessionId = publicId;
    existing.seenCount = Number(existing.seenCount || 0) + 1;
    existing.revokedAt = null;
    return existing;
  }
  const device = {
    id: crypto.randomUUID(),
    fingerprint,
    userId: session.userId,
    firstSeenAt: now,
    lastSeenAt: now,
    lastSessionId: publicId,
    source,
    userAgent,
    seenCount: 1,
    revokedAt: null
  };
  store.state.deviceInventory.unshift(device);
  store.state.deviceInventory = store.state.deviceInventory.slice(0, 250);
  return device;
};

const publicDevice = (device) => {
  const user = store.findUserById(device.userId);
  return {
    id: device.id,
    userId: device.userId,
    userName: user?.name || "Unknown user",
    role: user?.role || "UNKNOWN",
    firstSeenAt: device.firstSeenAt,
    lastSeenAt: device.lastSeenAt,
    lastSessionId: device.lastSessionId,
    source: device.source,
    userAgent: device.userAgent,
    seenCount: device.seenCount || 0,
    revokedAt: device.revokedAt || null
  };
};

const publicSession = ([token, session]) => {
  const user = store.findUserById(session.userId);
  return {
    id: sessionId(token),
    userId: session.userId,
    userName: user?.name || "Unknown user",
    role: user?.role || "UNKNOWN",
    createdAt: new Date(session.createdAt).toISOString(),
    lastSeenAt: new Date(session.lastSeenAt || session.createdAt).toISOString(),
    source: session.source || "unknown",
    userAgent: session.userAgent || "unknown"
  };
};

export const createSession = (userId, metadata = {}) => {
  const token = crypto.randomBytes(32).toString("base64url");
  const publicId = sessionId(token);
  store.state.sessions.set(token, {
    userId,
    createdAt: Date.now(),
    lastSeenAt: Date.now(),
    source: metadata.source || "127.0.0.1",
    userAgent: metadata.userAgent || "unknown"
  });
  rememberDevice(publicId, store.state.sessions.get(token));
  return token;
};

const createRefreshTokenRecord = (userId, sessionPublicId, metadata = {}, familyId = crypto.randomUUID()) => {
  if (!isRefreshTokenIssueEnabled()) return null;
  const token = crypto.randomBytes(48).toString("base64url");
  const tokenHash = refreshTokenHash(token);
  const now = new Date();
  const record = {
    id: refreshTokenId(tokenHash),
    familyId,
    userId,
    sessionId: sessionPublicId,
    tokenHash,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + refreshTtlMs()).toISOString(),
    usedAt: null,
    revokedAt: null,
    replacedBy: null,
    source: metadata.source || "127.0.0.1",
    userAgent: metadata.userAgent || "unknown",
    identityProvider: metadata.identityProvider || config.identityProvider.mode,
    subject: metadata.subject || null
  };
  store.state.refreshTokens = store.state.refreshTokens || [];
  store.state.refreshTokens.unshift(record);
  store.state.refreshTokens = store.state.refreshTokens.slice(0, 500);
  return { token, record };
};

const revokeRefreshTokenFamily = (familyId, reason = "revoked") => {
  const now = new Date().toISOString();
  for (const token of store.state.refreshTokens || []) {
    if (token.familyId === familyId && !token.revokedAt) {
      token.revokedAt = now;
      token.revocationReason = reason;
    }
  }
};

const revokeRefreshTokensForSession = (publicSessionId, reason = "session_revoked") => {
  const now = new Date().toISOString();
  for (const token of store.state.refreshTokens || []) {
    if (token.sessionId === publicSessionId && !token.revokedAt) {
      token.revokedAt = now;
      token.revocationReason = reason;
    }
  }
};

export const createSessionBundle = (userId, metadata = {}) => {
  const token = createSession(userId, metadata);
  const refresh = createRefreshTokenRecord(userId, sessionId(token), metadata);
  return {
    token,
    refreshToken: refresh?.token || null,
    refreshTokenExpiresAt: refresh?.record.expiresAt || null
  };
};

export const refreshSession = (refreshToken, metadata = {}) => {
  if (!isRefreshTokenIssueEnabled()) {
    const error = new Error("Refresh tokens are disabled");
    error.status = 403;
    throw error;
  }
  const tokenHash = refreshTokenHash(refreshToken);
  const record = (store.state.refreshTokens || []).find((candidate) => candidate.tokenHash === tokenHash);
  if (!record) {
    const error = new Error("Refresh token was not recognized");
    error.status = 401;
    throw error;
  }
  if (record.usedAt) {
    revokeRefreshTokenFamily(record.familyId, "replay_detected");
    const error = new Error("Refresh token replay detected");
    error.status = 401;
    throw error;
  }
  if (record.revokedAt || Date.parse(record.expiresAt) <= Date.now()) {
    const error = new Error("Refresh token is expired or revoked");
    error.status = 401;
    throw error;
  }
  const user = store.findUserById(record.userId);
  if (!user || user.enabled === false) {
    revokeRefreshTokenFamily(record.familyId, "user_disabled");
    const error = new Error("Refresh token user is not active");
    error.status = 403;
    throw error;
  }
  record.usedAt = new Date().toISOString();
  const token = createSession(user.id, {
    source: metadata.source || record.source,
    userAgent: metadata.userAgent || record.userAgent,
    identityProvider: record.identityProvider,
    subject: record.subject
  });
  const replacement = createRefreshTokenRecord(user.id, sessionId(token), {
    source: metadata.source || record.source,
    userAgent: metadata.userAgent || record.userAgent,
    identityProvider: record.identityProvider,
    subject: record.subject
  }, record.familyId);
  record.replacedBy = replacement?.record.id || null;
  return {
    user,
    token,
    refreshToken: replacement?.token || null,
    refreshTokenExpiresAt: replacement?.record.expiresAt || null
  };
};

export const resolveSession = (token) => {
  const session = token && store.state.sessions.get(token);
  if (!session) return null;
  if (Date.now() - session.createdAt > sessionTtlMs()) {
    store.state.sessions.delete(token);
    return null;
  }
  session.lastSeenAt = Date.now();
  rememberDevice(sessionId(token), session);
  return store.findUserById(session.userId);
};

export const revokeSession = (token) => {
  if (!token) return false;
  const id = sessionId(token);
  const revoked = store.state.sessions.delete(token);
  if (revoked) {
    const device = store.state.deviceInventory?.find((candidate) => candidate.lastSessionId === id);
    if (device) device.revokedAt = new Date().toISOString();
    revokeRefreshTokensForSession(id);
  }
  return revoked;
};

export const listSessions = () => Array.from(store.state.sessions.entries()).map(publicSession);
export const listDevices = () => (store.state.deviceInventory || []).map(publicDevice);

export const revokeSessionById = (id) => {
  for (const token of store.state.sessions.keys()) {
    if (sessionId(token) === id) return revokeSession(token);
  }
  revokeRefreshTokensForSession(id);
  return false;
};

export const getSessionStatus = () => ({
  activeSessions: store.state.sessions.size,
  ttlMinutes: Math.max(1, Number(store.state.policies.sessionMinutes || 15)),
  reviewable: listSessions().length,
  knownDevices: store.state.deviceInventory?.length || 0,
  refreshTokensEnabled: isRefreshTokenIssueEnabled(),
  activeRefreshTokens: (store.state.refreshTokens || []).filter((token) => !token.usedAt && !token.revokedAt && Date.parse(token.expiresAt) > Date.now()).length
});
