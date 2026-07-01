import express from "express";
import { config } from "../config.mjs";
import { store } from "../data/store.mjs";
import { verifyPassword } from "../crypto/passwords.mjs";
import { auth } from "../middleware/auth.mjs";
import { publicUser } from "../rbac/roles.mjs";
import { createSession, revokeSession } from "../services/sessionService.mjs";
import { audit } from "../services/auditService.mjs";
import { validateExternalIdentityToken } from "../services/identityService.mjs";
import { rateLimit } from "../middleware/rateLimit.mjs";

export const authRoutes = express.Router();

const loginFailureKey = (email) => String(email || "").toLowerCase().trim();

const getLoginFailure = (email) => store.state.loginFailures.get(loginFailureKey(email)) || { count: 0, lockedUntil: null };

const isLocked = (failure) => failure.lockedUntil && Date.parse(failure.lockedUntil) > Date.now();

const recordLoginFailure = (email, user, source) => {
  const key = loginFailureKey(email);
  if (!key) return;
  const current = getLoginFailure(email);
  const next = { count: current.count + 1, lockedUntil: current.lockedUntil || null };
  if (next.count >= config.failedLoginLimit) {
    next.lockedUntil = new Date(Date.now() + config.loginLockoutMinutes * 60000).toISOString();
    audit(user?.id || null, "LOGIN_LOCKOUT", "Sentinel Vault Console", `Account locked after ${next.count} failed attempts`, source);
  } else if (user) {
    audit(user.id, "LOGIN_FAILED", "Sentinel Vault Console", `Failed login attempt ${next.count}/${config.failedLoginLimit}`, source);
  }
  store.state.loginFailures.set(key, next);
};

const clearLoginFailure = (email) => {
  store.state.loginFailures.delete(loginFailureKey(email));
};

authRoutes.post("/login", rateLimit({ windowMs: 60000, max: 10 }), (req, res) => {
  if (config.identityProvider.mode !== "local") {
    return res.status(403).json({ error: "Local password login is disabled for external identity mode" });
  }
  const { email, password } = req.body;
  const user = store.findUserByEmail(email);
  const failure = getLoginFailure(email);
  if (isLocked(failure)) {
    return res.status(423).json({ error: "Account temporarily locked", lockedUntil: failure.lockedUntil });
  }
  if (user?.enabled === false) {
    audit(user.id, "LOGIN_DISABLED", "Sentinel Vault Console", "Disabled account attempted login", req.ip);
    return res.status(403).json({ error: "Account disabled" });
  }
  if (!user || !verifyPassword(password, user)) {
    recordLoginFailure(email, user, req.ip);
    return res.status(401).json({ error: "Invalid credentials" });
  }
  clearLoginFailure(email);
  const token = createSession(user.id, { source: req.ip, userAgent: req.get("user-agent") || "unknown" });
  audit(user.id, "LOGIN", "Sentinel Vault Console", "MFA assertion accepted", req.ip);
  res.json({ token, user: publicUser(user) });
});

authRoutes.post("/login/federated", rateLimit({ windowMs: 60000, max: 10 }), async (req, res) => {
  try {
    const { idToken } = req.body;
    const result = await validateExternalIdentityToken(idToken);
    clearLoginFailure(result.claims.email);
    const token = createSession(result.user.id, {
      source: req.ip,
      userAgent: req.get("user-agent") || "unknown",
      identityProvider: config.identityProvider.mode,
      subject: result.claims.subject
    });
    audit(
      result.user.id,
      "FEDERATED_LOGIN",
      "Sentinel Vault Console",
      `${config.identityProvider.mode} token accepted for ${result.claims.subject}`,
      req.ip
    );
    res.json({ token, user: publicUser(result.user) });
  } catch (err) {
    res.status(401).json({ error: err instanceof Error ? err.message : "Federated login failed" });
  }
});

authRoutes.post("/logout", auth, (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  revokeSession(token);
  audit(req.user.id, "LOGOUT", "Sentinel Vault Console", "Session invalidated by user", req.ip);
  res.json({ ok: true });
});
