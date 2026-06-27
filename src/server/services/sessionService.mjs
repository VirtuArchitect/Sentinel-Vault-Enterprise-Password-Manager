import crypto from "node:crypto";
import { store } from "../data/store.mjs";

export const createSession = (userId) => {
  const token = crypto.randomBytes(32).toString("base64url");
  store.state.sessions.set(token, { userId, createdAt: Date.now() });
  return token;
};

export const resolveSession = (token) => {
  const session = token && store.state.sessions.get(token);
  return session ? store.findUserById(session.userId) : null;
};
