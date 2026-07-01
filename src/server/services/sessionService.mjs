import crypto from "node:crypto";
import { store } from "../data/store.mjs";

const sessionTtlMs = () => Math.max(1, Number(store.state.policies.sessionMinutes || 15)) * 60000;

const sessionId = (token) => crypto.createHash("sha256").update(String(token || ""), "utf8").digest("base64url").slice(0, 22);

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
  store.state.sessions.set(token, {
    userId,
    createdAt: Date.now(),
    lastSeenAt: Date.now(),
    source: metadata.source || "127.0.0.1",
    userAgent: metadata.userAgent || "unknown"
  });
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
  return store.findUserById(session.userId);
};

export const revokeSession = (token) => {
  if (!token) return false;
  return store.state.sessions.delete(token);
};

export const listSessions = () => Array.from(store.state.sessions.entries()).map(publicSession);

export const revokeSessionById = (id) => {
  for (const token of store.state.sessions.keys()) {
    if (sessionId(token) === id) return store.state.sessions.delete(token);
  }
  return false;
};

export const getSessionStatus = () => ({
  activeSessions: store.state.sessions.size,
  ttlMinutes: Math.max(1, Number(store.state.policies.sessionMinutes || 15)),
  reviewable: listSessions().length
});
