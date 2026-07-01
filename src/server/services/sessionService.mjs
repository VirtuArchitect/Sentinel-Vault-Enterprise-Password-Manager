import crypto from "node:crypto";
import { store } from "../data/store.mjs";

const sessionTtlMs = () => Math.max(1, Number(store.state.policies.sessionMinutes || 15)) * 60000;

const sessionId = (token) => crypto.createHash("sha256").update(String(token || ""), "utf8").digest("base64url").slice(0, 22);

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
  }
  return revoked;
};

export const listSessions = () => Array.from(store.state.sessions.entries()).map(publicSession);
export const listDevices = () => (store.state.deviceInventory || []).map(publicDevice);

export const revokeSessionById = (id) => {
  for (const token of store.state.sessions.keys()) {
    if (sessionId(token) === id) return revokeSession(token);
  }
  return false;
};

export const getSessionStatus = () => ({
  activeSessions: store.state.sessions.size,
  ttlMinutes: Math.max(1, Number(store.state.policies.sessionMinutes || 15)),
  reviewable: listSessions().length,
  knownDevices: store.state.deviceInventory?.length || 0
});
