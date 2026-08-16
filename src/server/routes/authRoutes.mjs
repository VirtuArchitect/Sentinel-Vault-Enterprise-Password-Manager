import express from "express";
import { config } from "../config.mjs";
import { store } from "../data/store.mjs";
import crypto from "node:crypto";
import { verifyPassword } from "../crypto/passwords.mjs";
import { auth } from "../middleware/auth.mjs";
import { publicUser } from "../rbac/roles.mjs";
import { createSessionBundle, refreshSession, revokeSession } from "../services/sessionService.mjs";
import { audit } from "../services/auditService.mjs";
import { parseCookies } from "../middleware/auth.mjs";
import {
  createPkceChallenge,
  createPkceVerifier,
  discoverIdentityProvider,
  exchangeAuthorizationCode,
  getIdentityStatus,
  validateExternalIdentityToken
} from "../services/identityService.mjs";
import { rateLimit } from "../middleware/rateLimit.mjs";

export const authRoutes = express.Router();
const pendingFederatedLogins = new Map();
const pendingLoginTtlMs = 5 * 60 * 1000;
const accessCookieName = "sentinel_session";
const refreshCookieName = "sentinel_refresh";
const csrfCookieName = "sentinel_csrf";

const cookieBase = () => [
  "Path=/",
  "SameSite=Lax",
  ...(config.isProduction ? ["Secure"] : [])
].join("; ");

const cookieMaxAge = (seconds) => `Max-Age=${Math.max(0, Math.floor(seconds))}`;

const appendCookie = (res, value) => {
  res.append("Set-Cookie", value);
};

const setSessionCookies = (res, session) => {
  appendCookie(res, `${accessCookieName}=${encodeURIComponent(session.token)}; HttpOnly; ${cookieBase()}`);
  if (session.csrfToken) {
    appendCookie(res, `${csrfCookieName}=${encodeURIComponent(session.csrfToken)}; ${cookieBase()}`);
  }
  if (session.refreshToken) {
    appendCookie(res, `${refreshCookieName}=${encodeURIComponent(session.refreshToken)}; HttpOnly; ${cookieBase()}; ${cookieMaxAge(config.refreshTokens.ttlDays * 24 * 60 * 60)}`);
  }
};

const clearSessionCookies = (res) => {
  for (const name of [accessCookieName, refreshCookieName, csrfCookieName]) {
    appendCookie(res, `${name}=; ${cookieBase()}; ${cookieMaxAge(0)}`);
  }
};

authRoutes.get("/identity/status", (_req, res) => {
  res.json({ identity: getIdentityStatus() });
});

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

const federatedRedirectBase = (req) => req.get("origin") || `${req.protocol}://${req.get("host")}`;

const normalizeRedirectUri = (value) => {
  try {
    return new URL(String(value || "")).toString();
  } catch {
    return null;
  }
};

const requireAllowedRedirectUri = (redirectUri) => {
  const normalized = normalizeRedirectUri(redirectUri);
  const allowed = new Set(config.identityProvider.redirectUris.map(normalizeRedirectUri).filter(Boolean));
  if (!normalized || !allowed.has(normalized)) {
    const error = new Error("Federated login redirect URI is not allowed");
    error.status = 400;
    throw error;
  }
  return normalized;
};

const createFederatedSessionResponse = (req, res, result) => {
  clearLoginFailure(result.claims.email);
  const session = createSessionBundle(result.user.id, {
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
  setSessionCookies(res, session);
  res.json({
    token: session.token,
    csrfToken: session.csrfToken,
    refreshToken: session.refreshToken,
    refreshTokenExpiresAt: session.refreshTokenExpiresAt,
    user: publicUser(result.user)
  });
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
  const session = createSessionBundle(user.id, { source: req.ip, userAgent: req.get("user-agent") || "unknown" });
  audit(user.id, "LOGIN", "Sentinel Vault Console", "MFA assertion accepted", req.ip);
  setSessionCookies(res, session);
  res.json({ token: session.token, csrfToken: session.csrfToken, user: publicUser(user) });
});

authRoutes.post("/login/federated", rateLimit({ windowMs: 60000, max: 10 }), async (req, res) => {
  try {
    const { idToken } = req.body;
    const result = await validateExternalIdentityToken(idToken);
    createFederatedSessionResponse(req, res, result);
  } catch (err) {
    res.status(401).json({ error: err instanceof Error ? err.message : "Federated login failed" });
  }
});

authRoutes.post("/login/federated/start", rateLimit({ windowMs: 60000, max: 10 }), async (req, res) => {
  try {
    if (config.identityProvider.mode === "local") {
      return res.status(400).json({ error: "External identity login is disabled when IDENTITY_PROVIDER=local" });
    }
    const metadata = await discoverIdentityProvider();
    if (!metadata.authorization_endpoint) throw new Error("OIDC discovery did not return authorization_endpoint");
    const state = crypto.randomBytes(24).toString("base64url");
    const nonce = crypto.randomBytes(24).toString("base64url");
    const codeVerifier = createPkceVerifier();
    const redirectUri = requireAllowedRedirectUri(req.body.redirectUri || `${federatedRedirectBase(req)}/auth/callback`);
    pendingFederatedLogins.set(state, {
      nonce,
      codeVerifier,
      redirectUri,
      createdAt: Date.now()
    });
    const authorizationUrl = new URL(metadata.authorization_endpoint);
    authorizationUrl.searchParams.set("response_type", "code");
    authorizationUrl.searchParams.set("client_id", config.identityProvider.clientId);
    authorizationUrl.searchParams.set("redirect_uri", redirectUri);
    authorizationUrl.searchParams.set("scope", "openid profile email");
    authorizationUrl.searchParams.set("state", state);
    authorizationUrl.searchParams.set("nonce", nonce);
    authorizationUrl.searchParams.set("code_challenge", createPkceChallenge(codeVerifier));
    authorizationUrl.searchParams.set("code_challenge_method", "S256");
    res.json({ authorizationUrl: authorizationUrl.toString(), state, expiresIn: pendingLoginTtlMs / 1000 });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : "Federated login start failed" });
  }
});

authRoutes.post("/login/federated/callback", rateLimit({ windowMs: 60000, max: 10 }), async (req, res) => {
  try {
    const state = String(req.body.state || "");
    const pending = pendingFederatedLogins.get(state);
    pendingFederatedLogins.delete(state);
    if (!pending) throw new Error("Federated login state was not found or already used");
    if (Date.now() - pending.createdAt > pendingLoginTtlMs) throw new Error("Federated login state has expired");
    const redirectUri = String(req.body.redirectUri || pending.redirectUri);
    if (redirectUri !== pending.redirectUri) throw new Error("Federated login redirect URI mismatch");
    const tokenResponse = await exchangeAuthorizationCode({
      code: String(req.body.code || ""),
      redirectUri,
      codeVerifier: pending.codeVerifier
    });
    const result = await validateExternalIdentityToken(tokenResponse.id_token, { nonce: pending.nonce });
    createFederatedSessionResponse(req, res, result);
  } catch (err) {
    res.status(401).json({ error: err instanceof Error ? err.message : "Federated login failed" });
  }
});

authRoutes.post("/session/refresh", rateLimit({ windowMs: 60000, max: 10 }), (req, res) => {
  try {
    const cookies = parseCookies(req.headers.cookie);
    const cookieRefreshToken = cookies[refreshCookieName] || "";
    if (!req.body.refreshToken && cookieRefreshToken && String(req.get("x-csrf-token") || "") !== String(cookies[csrfCookieName] || "")) {
      return res.status(403).json({ error: "CSRF token required" });
    }
    const refreshed = refreshSession(String(req.body.refreshToken || cookieRefreshToken), {
      source: req.ip,
      userAgent: req.get("user-agent") || "unknown"
    });
    audit(refreshed.user.id, "SESSION_REFRESH", "Sentinel Vault Console", "Refresh token rotated and access session renewed", req.ip);
    setSessionCookies(res, refreshed);
    res.json({
      token: refreshed.token,
      csrfToken: refreshed.csrfToken,
      refreshToken: refreshed.refreshToken,
      refreshTokenExpiresAt: refreshed.refreshTokenExpiresAt,
      user: publicUser(refreshed.user)
    });
  } catch (err) {
    audit(null, "SESSION_REFRESH_DENIED", "Sentinel Vault Console", err instanceof Error ? err.message : "Refresh token denied", req.ip, "denied");
    res.status(err.status || 401).json({ error: err instanceof Error ? err.message : "Refresh token denied" });
  }
});

authRoutes.post("/logout", auth, (req, res) => {
  revokeSession(req.authToken);
  audit(req.user.id, "LOGOUT", "Sentinel Vault Console", "Session invalidated by user", req.ip);
  clearSessionCookies(res);
  res.json({ ok: true });
});
