import crypto from "node:crypto";
import { store } from "../data/store.mjs";

const sessionTtlMs = () => Math.max(1, Number(store.state.policies.sessionMinutes || 15)) * 60000;

export const createSession = (userId) => {
  const token = crypto.randomBytes(32).toString("base64url");
  store.state.sessions.set(token, { userId, createdAt: Date.now(), lastSeenAt: Date.now() });
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

export const getSessionStatus = () => ({
  activeSessions: store.state.sessions.size,
  ttlMinutes: Math.max(1, Number(store.state.policies.sessionMinutes || 15))
});
