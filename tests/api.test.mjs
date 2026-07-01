import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";

process.env.NODE_ENV = "test";
const { createApp } = await import("../src/server/app.mjs");
const { config } = await import("../src/server/config.mjs");
const { store } = await import("../src/server/data/store.mjs");
const { hashPassword } = await import("../src/server/crypto/passwords.mjs");
const { exportSignedAuditLedger, verifyAuditChain, verifySignedAuditLedger } = await import("../src/server/services/auditService.mjs");
const { buildContentSecurityPolicy, buildSecurityHeaders } = await import("../src/server/middleware/securityHeaders.mjs");
const { deliverQueuedIntegrationEvents, enqueueIntegrationEvent } = await import("../src/server/services/integrationService.mjs");

let nextPort = 18100;

const withApi = async (run) => {
  const app = await createApp();
  const port = nextPort++;
  const server = app.listen(port, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  try {
    await run(`http://127.0.0.1:${port}/api`);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
};

const login = async (baseUrl, email) => {
  const response = await fetch(`${baseUrl}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: "Passw0rd!" })
  });
  assert.equal(response.status, 200);
  return response.json();
};

const jsonFetch = (url, token, options = {}) => fetch(url, {
  ...options,
  headers: {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
    ...(options.headers || {})
  }
});

const waitFor = async (predicate, { timeoutMs = 1000, intervalMs = 20 } = {}) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  assert.ok(predicate(), "Timed out waiting for condition");
};

const startOidcFixture = async (jwks, options = {}) => {
  const issuedCodes = new Map();
  const server = http.createServer((req, res) => {
    const issuer = `http://127.0.0.1:${server.address().port}`;
    if (req.url === "/.well-known/openid-configuration") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({
        issuer,
        jwks_uri: `${issuer}/keys`,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`
      }));
      return;
    }
    if (req.url?.startsWith("/authorize")) {
      const url = new URL(req.url, issuer);
      const code = crypto.randomBytes(16).toString("base64url");
      issuedCodes.set(code, {
        nonce: url.searchParams.get("nonce"),
        redirectUri: url.searchParams.get("redirect_uri")
      });
      const redirect = new URL(url.searchParams.get("redirect_uri"));
      redirect.searchParams.set("code", code);
      redirect.searchParams.set("state", url.searchParams.get("state"));
      res.statusCode = 302;
      res.setHeader("Location", redirect.toString());
      res.end();
      return;
    }
    if (req.url === "/token" && req.method === "POST") {
      let raw = "";
      req.on("data", (chunk) => {
        raw += chunk;
      });
      req.on("end", () => {
        const form = new URLSearchParams(raw);
        const code = form.get("code");
        const issued = issuedCodes.get(code);
        if (!issued || issued.redirectUri !== form.get("redirect_uri") || !form.get("code_verifier")) {
          res.statusCode = 400;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ error: "invalid_grant" }));
          return;
        }
        issuedCodes.delete(code);
        const now = Math.floor(Date.now() / 1000);
        const idToken = signJwt({
          iss: issuer,
          aud: "sentinel-client",
          sub: "ada-subject",
          exp: now + 300,
          nbf: now - 5,
          nonce: issued.nonce,
          email: "ada@defence.local",
          groups: ["Sentinel Vault Admins"],
          amr: ["pwd", "mfa"]
        }, options.privateKey, options.kid);
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ id_token: idToken, token_type: "Bearer", expires_in: 300 }));
      });
      return;
    }
    if (req.url === "/keys") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(jwks));
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  server.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  return server;
};

const startItsmFixture = async (tickets) => {
  const workNotes = [];
  const server = http.createServer((req, res) => {
    const workNoteMatch = req.url?.match(/^\/tickets\/([^/?]+)\/work-notes$/);
    if (workNoteMatch && req.method === "POST") {
      const ticketRef = decodeURIComponent(workNoteMatch[1]).toUpperCase();
      if (!tickets[ticketRef]) {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: "not found" }));
        return;
      }
      let raw = "";
      req.on("data", (chunk) => {
        raw += chunk;
      });
      req.on("end", () => {
        workNotes.push({ ticketRef, body: JSON.parse(raw || "{}") });
        res.statusCode = 201;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ ok: true }));
      });
      return;
    }
    const match = req.url?.match(/^\/tickets\/([^/?]+)$/);
    if (!match) {
      res.statusCode = 404;
      res.end();
      return;
    }
    const ticketRef = decodeURIComponent(match[1]).toUpperCase();
    const ticket = tickets[ticketRef];
    if (!ticket) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: "not found" }));
      return;
    }
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(ticket));
  });
  server.workNotes = workNotes;
  server.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  return server;
};

const signJwt = (claims, privateKey, kid) => {
  const encodedHeader = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid }), "utf8").toString("base64url");
  const encodedPayload = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
};

test("health endpoint is available without authentication", async () => {
  await withApi(async (baseUrl) => {
    const response = await fetch(baseUrl.replace("/api", "/healthz"));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-frame-options"), "DENY");
    assert.match(response.headers.get("content-security-policy"), /default-src 'self'/);
    assert.match(response.headers.get("content-security-policy"), /object-src 'none'/);
    assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
    const health = await response.json();
    assert.equal(health.ok, true);
  });
});

test("identity status is available before login", async () => {
  await withApi(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/identity/status`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.identity.mode, config.identityProvider.mode);
    assert.equal(body.identity.configured, true);
  });
});

test("security headers are environment aware", () => {
  const developmentCsp = buildContentSecurityPolicy({ ...config, isProduction: false, host: "127.0.0.1", port: 5173 });
  assert.match(developmentCsp, /ws:\/\/127\.0\.0\.1:5173/);
  assert.doesNotMatch(developmentCsp, /upgrade-insecure-requests/);

  const productionHeaders = buildSecurityHeaders({ ...config, isProduction: true, host: "127.0.0.1", port: 5173 });
  assert.match(productionHeaders["Content-Security-Policy"], /upgrade-insecure-requests/);
  assert.equal(productionHeaders["Strict-Transport-Security"], "max-age=31536000; includeSubDomains");
});

test("cors allows configured origins and rejects unexpected origins", async () => {
  await withApi(async (baseUrl) => {
    const allowed = await fetch(baseUrl.replace("/api", "/healthz"), { headers: { Origin: "http://127.0.0.1:5173" } });
    assert.equal(allowed.headers.get("access-control-allow-origin"), "http://127.0.0.1:5173");

    const rejected = await fetch(baseUrl.replace("/api", "/healthz"), { headers: { Origin: "https://evil.example" } });
    assert.equal(rejected.status, 403);
  });
});

test("auditor is blocked from policy updates", async () => {
  await withApi(async (baseUrl) => {
    const iris = await login(baseUrl, "iris@defence.local");
    const policyResponse = await jsonFetch(`${baseUrl}/policies`, iris.token, {
      method: "PATCH",
      body: JSON.stringify({ sessionMinutes: 99 })
    });
    assert.equal(policyResponse.status, 403);
  });
});

test("console payload respects users and audit permissions", async () => {
  await withApi(async (baseUrl) => {
    const morgan = await login(baseUrl, "morgan@defence.local");
    const response = await jsonFetch(`${baseUrl}/console`, morgan.token);
    assert.equal(response.status, 200);
    const consoleData = await response.json();
    assert.deepEqual(consoleData.users, []);
    assert.deepEqual(consoleData.audit, []);
    assert.equal(consoleData.identity.mode, "local");
    assert.equal(consoleData.identity.configured, true);
    assert.equal(consoleData.crypto.algorithm, "AES-256-GCM");
    assert.equal(consoleData.crypto.keyVersion, "demo-root-v1");
    assert.equal(consoleData.crypto.keyProvider.provider, "local-root-key");
    assert.equal(consoleData.integrations.siem.mode, "outbox");
    assert.equal(typeof consoleData.session.activeSessions, "number");
    assert.equal(consoleData.session.ttlMinutes, 15);
    assert.equal(typeof consoleData.session.reviewable, "number");
  });
});

test("federated login validates OIDC token claims and local provisioning", async () => {
  const previous = {
    mode: config.identityProvider.mode,
    issuer: config.identityProvider.issuer,
    clientId: config.identityProvider.clientId,
    tenantId: config.identityProvider.tenantId,
    groupClaim: config.identityProvider.groupClaim,
    mfaClaim: config.identityProvider.mfaClaim,
    mfaRequiredValue: config.identityProvider.mfaRequiredValue,
    roleMappings: { ...config.identityProvider.roleMappings }
  };
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = "sentinel-test-key";
  jwk.alg = "RS256";
  jwk.use = "sig";
  const oidcServer = await startOidcFixture({ keys: [jwk] });
  const issuer = `http://127.0.0.1:${oidcServer.address().port}`;
  try {
    Object.assign(config.identityProvider, {
      mode: "entra",
      issuer,
      clientId: "sentinel-client",
      tenantId: "tenant-id",
      groupClaim: "groups",
      mfaClaim: "amr",
      mfaRequiredValue: "mfa"
    });
    config.identityProvider.roleMappings = {
      SECURITY_ADMIN: "Sentinel Vault Admins",
      VAULT_OPERATOR: "Sentinel Vault Operators",
      AUDITOR: "Sentinel Vault Auditors"
    };

    await withApi(async (baseUrl) => {
      const now = Math.floor(Date.now() / 1000);
      const token = signJwt({
        iss: issuer,
        aud: "sentinel-client",
        sub: "ada-subject",
        exp: now + 300,
        nbf: now - 5,
        email: "ada@defence.local",
        groups: ["Sentinel Vault Admins"],
        amr: ["pwd", "mfa"]
      }, privateKey, jwk.kid);

      const localLogin = await fetch(`${baseUrl}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "ada@defence.local", password: "Passw0rd!" })
      });
      assert.equal(localLogin.status, 403);

      const federatedLogin = await fetch(`${baseUrl}/login/federated`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idToken: token })
      });
      assert.equal(federatedLogin.status, 200);
      const body = await federatedLogin.json();
      assert.equal(body.user.email, "ada@defence.local");
      assert.equal(body.user.role, "SECURITY_ADMIN");

      const missingMfa = signJwt({
        iss: issuer,
        aud: "sentinel-client",
        sub: "ada-subject",
        exp: now + 300,
        email: "ada@defence.local",
        groups: ["Sentinel Vault Admins"],
        amr: ["pwd"]
      }, privateKey, jwk.kid);
      const rejected = await fetch(`${baseUrl}/login/federated`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idToken: missingMfa })
      });
      assert.equal(rejected.status, 401);
    });
  } finally {
    await new Promise((resolve) => oidcServer.close(resolve));
    Object.assign(config.identityProvider, previous);
    config.identityProvider.roleMappings = previous.roleMappings;
  }
});

test("federated PKCE flow exchanges authorization code and rejects replay", async () => {
  const previous = {
    mode: config.identityProvider.mode,
    issuer: config.identityProvider.issuer,
    clientId: config.identityProvider.clientId,
    tenantId: config.identityProvider.tenantId,
    groupClaim: config.identityProvider.groupClaim,
    mfaClaim: config.identityProvider.mfaClaim,
    mfaRequiredValue: config.identityProvider.mfaRequiredValue,
    roleMappings: { ...config.identityProvider.roleMappings }
  };
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = "sentinel-pkce-key";
  jwk.alg = "RS256";
  jwk.use = "sig";
  const oidcServer = await startOidcFixture({ keys: [jwk] }, { privateKey, kid: jwk.kid });
  const issuer = `http://127.0.0.1:${oidcServer.address().port}`;
  try {
    Object.assign(config.identityProvider, {
      mode: "oidc",
      issuer,
      clientId: "sentinel-client",
      tenantId: "",
      groupClaim: "groups",
      mfaClaim: "amr",
      mfaRequiredValue: "mfa"
    });
    config.identityProvider.roleMappings = {
      SECURITY_ADMIN: "Sentinel Vault Admins",
      VAULT_OPERATOR: "Sentinel Vault Operators",
      AUDITOR: "Sentinel Vault Auditors"
    };

    await withApi(async (baseUrl) => {
      const redirectUri = "http://127.0.0.1:5173/auth/callback";
      const start = await fetch(`${baseUrl}/login/federated/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: "http://127.0.0.1:5173" },
        body: JSON.stringify({ redirectUri })
      });
      assert.equal(start.status, 200);
      const startBody = await start.json();
      assert.match(startBody.authorizationUrl, /code_challenge=/);

      const authorize = await fetch(startBody.authorizationUrl, { redirect: "manual" });
      assert.equal(authorize.status, 302);
      const callbackUrl = new URL(authorize.headers.get("location"));
      assert.equal(callbackUrl.origin + callbackUrl.pathname, redirectUri);

      const callback = await fetch(`${baseUrl}/login/federated/callback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: callbackUrl.searchParams.get("code"),
          state: callbackUrl.searchParams.get("state"),
          redirectUri
        })
      });
      assert.equal(callback.status, 200);
      const callbackBody = await callback.json();
      assert.equal(callbackBody.user.email, "ada@defence.local");

      const replay = await fetch(`${baseUrl}/login/federated/callback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: callbackUrl.searchParams.get("code"),
          state: callbackUrl.searchParams.get("state"),
          redirectUri
        })
      });
      assert.equal(replay.status, 401);
    });
  } finally {
    await new Promise((resolve) => oidcServer.close(resolve));
    Object.assign(config.identityProvider, previous);
    config.identityProvider.roleMappings = previous.roleMappings;
  }
});

test("federated refresh tokens rotate once and block replay", async () => {
  const previous = {
    mode: config.identityProvider.mode,
    issuer: config.identityProvider.issuer,
    clientId: config.identityProvider.clientId,
    tenantId: config.identityProvider.tenantId,
    groupClaim: config.identityProvider.groupClaim,
    mfaClaim: config.identityProvider.mfaClaim,
    mfaRequiredValue: config.identityProvider.mfaRequiredValue,
    refreshTokensEnabled: config.refreshTokens.enabled,
    refreshTokenDays: config.refreshTokens.ttlDays,
    roleMappings: { ...config.identityProvider.roleMappings }
  };
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = "sentinel-refresh-key";
  jwk.alg = "RS256";
  jwk.use = "sig";
  const oidcServer = await startOidcFixture({ keys: [jwk] });
  const issuer = `http://127.0.0.1:${oidcServer.address().port}`;
  try {
    Object.assign(config.identityProvider, {
      mode: "oidc",
      issuer,
      clientId: "sentinel-client",
      tenantId: "",
      groupClaim: "groups",
      mfaClaim: "amr",
      mfaRequiredValue: "mfa"
    });
    config.identityProvider.roleMappings = {
      SECURITY_ADMIN: "Sentinel Vault Admins",
      VAULT_OPERATOR: "Sentinel Vault Operators",
      AUDITOR: "Sentinel Vault Auditors"
    };
    config.refreshTokens.enabled = true;
    config.refreshTokens.ttlDays = 7;

    await withApi(async (baseUrl) => {
      const now = Math.floor(Date.now() / 1000);
      const idToken = signJwt({
        iss: issuer,
        aud: "sentinel-client",
        sub: "ada-refresh-subject",
        exp: now + 300,
        nbf: now - 5,
        email: "ada@defence.local",
        groups: ["Sentinel Vault Admins"],
        amr: ["pwd", "mfa"]
      }, privateKey, jwk.kid);

      const loginResponse = await fetch(`${baseUrl}/login/federated`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idToken })
      });
      assert.equal(loginResponse.status, 200);
      const loginBody = await loginResponse.json();
      assert.ok(loginBody.refreshToken);
      assert.ok(loginBody.refreshTokenExpiresAt);
      assert.equal(JSON.stringify(store.state.refreshTokens).includes(loginBody.refreshToken), false);

      const refreshResponse = await fetch(`${baseUrl}/session/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: loginBody.refreshToken })
      });
      assert.equal(refreshResponse.status, 200);
      const refreshBody = await refreshResponse.json();
      assert.ok(refreshBody.token);
      assert.ok(refreshBody.refreshToken);
      assert.notEqual(refreshBody.refreshToken, loginBody.refreshToken);

      const renewedConsole = await jsonFetch(`${baseUrl}/console`, refreshBody.token);
      assert.equal(renewedConsole.status, 200);

      const replayResponse = await fetch(`${baseUrl}/session/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: loginBody.refreshToken })
      });
      assert.equal(replayResponse.status, 401);

      const revokedFamilyResponse = await fetch(`${baseUrl}/session/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: refreshBody.refreshToken })
      });
      assert.equal(revokedFamilyResponse.status, 401);
      assert.ok(store.state.refreshTokens.some((token) => token.revocationReason === "replay_detected"));
    });
  } finally {
    await new Promise((resolve) => oidcServer.close(resolve));
    Object.assign(config.identityProvider, previous);
    config.identityProvider.roleMappings = previous.roleMappings;
    config.refreshTokens.enabled = previous.refreshTokensEnabled;
    config.refreshTokens.ttlDays = previous.refreshTokenDays;
    store.state.refreshTokens = [];
  }
});

test("security admins can manage vaults and user status", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const createTenant = await jsonFetch(`${baseUrl}/tenants`, ada.token, {
      method: "POST",
      body: JSON.stringify({
        name: "Red Team Directorate",
        parentId: "t1",
        classification: "SECRET",
        ownerUnit: "Cyber Operations"
      })
    });
    assert.equal(createTenant.status, 201);
    const createdTenant = await createTenant.json();
    assert.equal(createdTenant.tenant.parentId, "t1");

    const createVault = await jsonFetch(`${baseUrl}/vaults`, ada.token, {
      method: "POST",
      body: JSON.stringify({
        name: "Red Team Operations",
        tenantId: createdTenant.tenant.id,
        classification: "SECRET",
        ownerUnit: "Cyber Operations",
        members: ["u1", "u2"]
      })
    });
    assert.equal(createVault.status, 201);
    const created = await createVault.json();
    assert.equal(created.vault.name, "Red Team Operations");
    assert.equal(created.vault.tenantId, createdTenant.tenant.id);
    assert.deepEqual(created.vault.members.sort(), ["u1", "u2"]);

    const updateTenant = await jsonFetch(`${baseUrl}/tenants/${createdTenant.tenant.id}`, ada.token, {
      method: "PATCH",
      body: JSON.stringify({ ownerUnit: "Assurance" })
    });
    assert.equal(updateTenant.status, 200);
    const updatedTenant = await updateTenant.json();
    assert.equal(updatedTenant.tenant.ownerUnit, "Assurance");

    const updateVault = await jsonFetch(`${baseUrl}/vaults/${created.vault.id}`, ada.token, {
      method: "PATCH",
      body: JSON.stringify({ members: ["u1", "u3"], classification: "TOP SECRET" })
    });
    assert.equal(updateVault.status, 200);
    const updatedVault = await updateVault.json();
    assert.equal(updatedVault.vault.classification, "TOP SECRET");
    assert.deepEqual(updatedVault.vault.members.sort(), ["u1", "u3"]);

    const disableMorgan = await jsonFetch(`${baseUrl}/users/u2`, ada.token, {
      method: "PATCH",
      body: JSON.stringify({ enabled: false, role: "AUDITOR" })
    });
    assert.equal(disableMorgan.status, 200);
    const disabled = await disableMorgan.json();
    assert.equal(disabled.user.enabled, false);
    assert.equal(disabled.user.role, "AUDITOR");

    const blockedLogin = await fetch(`${baseUrl}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "morgan@defence.local", password: "Passw0rd!" })
    });
    assert.equal(blockedLogin.status, 403);

    const restoreMorgan = await jsonFetch(`${baseUrl}/users/u2`, ada.token, {
      method: "PATCH",
      body: JSON.stringify({ enabled: true, role: "VAULT_OPERATOR" })
    });
    assert.equal(restoreMorgan.status, 200);
  });
});

test("security admins can export and import safe administration metadata", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const exportResponse = await jsonFetch(`${baseUrl}/admin/export`, ada.token);
    assert.equal(exportResponse.status, 200);
    assert.match(exportResponse.headers.get("content-disposition"), /sentinel-admin-metadata/);
    const exported = await exportResponse.json();

    assert.equal(exported.metadata.format, "sentinel-vault-admin-metadata-v1");
    assert.ok(exported.metadata.tenants.length >= 1);
    assert.ok(exported.metadata.vaults.every((vault) => Object.hasOwn(vault, "tenantId")));
    assert.equal(exported.metadata.secrets, undefined);
    assert.equal(exported.metadata.serviceTokens, undefined);
    assert.equal(exported.metadata.users.some((user) => Object.hasOwn(user, "hash") || Object.hasOwn(user, "salt")), false);

    const rejected = await jsonFetch(`${baseUrl}/admin/import`, ada.token, {
      method: "POST",
      body: JSON.stringify({ secrets: [{ id: "unsafe" }] })
    });
    assert.equal(rejected.status, 400);

    const importResponse = await jsonFetch(`${baseUrl}/admin/import`, ada.token, {
      method: "POST",
      body: JSON.stringify({
        tenants: [{ id: "t-import", name: "Imported Tenant", parentId: "t1", classification: "SECRET", ownerUnit: "Integration" }],
        vaults: [{ id: "v-import", tenantId: "t-import", name: "Imported Vault", classification: "SECRET", ownerUnit: "Integration", members: ["u1"], health: 87 }]
      })
    });
    assert.equal(importResponse.status, 200);
    const imported = await importResponse.json();
    assert.equal(imported.result.tenants.created, 1);
    assert.equal(imported.result.vaults.created, 1);

    const consoleResponse = await jsonFetch(`${baseUrl}/console`, ada.token);
    const consoleData = await consoleResponse.json();
    assert.ok(consoleData.tenants.some((tenant) => tenant.id === "t-import"));
    assert.ok(consoleData.vaults.some((vault) => vault.id === "v-import" && vault.tenantId === "t-import"));
  });
});

test("bulk secret import uses encrypted escrow and independent approval", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    await jsonFetch(`${baseUrl}/users/u3`, ada.token, {
      method: "PATCH",
      body: JSON.stringify({ role: "SECURITY_ADMIN" })
    });
    const iris = await login(baseUrl, "iris@defence.local");

    const duplicate = await jsonFetch(`${baseUrl}/secret-imports`, ada.token, {
      method: "POST",
      body: JSON.stringify({
        vaultId: "v1",
        entries: [{ name: "Duplicate Import", username: "svc_duplicate_import", password: "E7#hP9!qZ2@Lw8$mV4" }]
      })
    });
    assert.equal(duplicate.status, 400);

    const create = await jsonFetch(`${baseUrl}/secret-imports`, ada.token, {
      method: "POST",
      body: JSON.stringify({
        vaultId: "v1",
        reason: "Bulk onboarding from approved escrow",
        entries: [{
          type: "password",
          name: "Imported Escrow Secret",
          username: "svc_imported",
          password: "ImportedEscrowSecret!2026",
          url: "https://imported.defence.local",
          tags: ["import", "escrow"],
          risk: "medium"
        }]
      })
    });
    assert.equal(create.status, 201);
    const created = await create.json();
    assert.equal(created.importBatch.status, "pending");
    assert.equal(created.importBatch.entryCount, 1);
    assert.equal(JSON.stringify(created).includes("ImportedEscrowSecret!2026"), false);
    assert.equal(JSON.stringify(created).includes("encrypted"), false);

    const selfApprove = await jsonFetch(`${baseUrl}/secret-imports/${created.importBatch.id}/approve`, ada.token, { method: "POST" });
    assert.equal(selfApprove.status, 403);

    const approve = await jsonFetch(`${baseUrl}/secret-imports/${created.importBatch.id}/approve`, iris.token, { method: "POST" });
    assert.equal(approve.status, 200);
    const approved = await approve.json();
    assert.equal(approved.importBatch.status, "approved");
    assert.equal(approved.importBatch.importedSecretIds.length, 1);

    const consoleResponse = await jsonFetch(`${baseUrl}/console`, ada.token);
    const consoleData = await consoleResponse.json();
    const imported = consoleData.secrets.find((secret) => secret.name === "Imported Escrow Secret");
    assert.ok(imported);
    assert.equal(imported.username, "svc_imported");

    const listed = await jsonFetch(`${baseUrl}/secret-imports`, ada.token);
    const listedBody = await listed.json();
    assert.equal(JSON.stringify(listedBody).includes("ImportedEscrowSecret!2026"), false);
    assert.equal(JSON.stringify(listedBody).includes("encrypted"), false);

    await jsonFetch(`${baseUrl}/users/u3`, ada.token, {
      method: "PATCH",
      body: JSON.stringify({ role: "AUDITOR" })
    });
  });
});

test("logout revokes the active session token", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const beforeLogout = await jsonFetch(`${baseUrl}/console`, ada.token);
    assert.equal(beforeLogout.status, 200);

    const logout = await jsonFetch(`${baseUrl}/logout`, ada.token, { method: "POST" });
    assert.equal(logout.status, 200);

    const afterLogout = await jsonFetch(`${baseUrl}/console`, ada.token);
    assert.equal(afterLogout.status, 401);
  });
});

test("security admins can review and revoke active sessions", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const morgan = await login(baseUrl, "morgan@defence.local");

    const denied = await jsonFetch(`${baseUrl}/sessions`, morgan.token);
    assert.equal(denied.status, 403);

    const sessionsResponse = await jsonFetch(`${baseUrl}/sessions`, ada.token);
    assert.equal(sessionsResponse.status, 200);
    const body = await sessionsResponse.json();
    assert.ok(body.sessions.length >= 2);
    assert.ok(body.devices.length >= 2);
    assert.ok(body.devices.some((device) => device.userId === "u2"));
    const morganSession = body.sessions
      .filter((session) => session.userId === "u2")
      .sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt))[0];
    assert.ok(morganSession);
    assert.ok(morganSession.id);
    assert.ok(morganSession.source);
    assert.ok(morganSession.userAgent);

    const revoke = await jsonFetch(`${baseUrl}/sessions/${morganSession.id}/revoke`, ada.token, { method: "POST" });
    assert.equal(revoke.status, 200);

    const afterSessions = await jsonFetch(`${baseUrl}/sessions`, ada.token);
    const afterSessionsBody = await afterSessions.json();
    assert.ok(afterSessionsBody.devices.some((device) => device.lastSessionId === morganSession.id && device.revokedAt));

    const afterRevoke = await jsonFetch(`${baseUrl}/console`, morgan.token);
    assert.equal(afterRevoke.status, 401);
  });
});

test("repeated failed logins temporarily lock the account", async () => {
  const previousLimit = config.failedLoginLimit;
  const previousLockout = config.loginLockoutMinutes;
  config.failedLoginLimit = 2;
  config.loginLockoutMinutes = 15;
  store.state.users.push({
    id: "u-lockout",
    name: "Lockout Test User",
    email: "lockout@defence.local",
    role: "VAULT_OPERATOR",
    unit: "Test",
    mfa: true,
    ...hashPassword("CorrectPassw0rd!")
  });
  try {
    await withApi(async (baseUrl) => {
      for (let attempt = 0; attempt < config.failedLoginLimit; attempt += 1) {
        const failed = await fetch(`${baseUrl}/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: "lockout@defence.local", password: "wrong-password" })
        });
        assert.equal(failed.status, 401);
      }

      const locked = await fetch(`${baseUrl}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "lockout@defence.local", password: "CorrectPassw0rd!" })
      });
      assert.equal(locked.status, 423);
      const body = await locked.json();
      assert.ok(body.lockedUntil);
    });
  } finally {
    config.failedLoginLimit = previousLimit;
    config.loginLockoutMinutes = previousLockout;
    store.state.loginFailures.delete("lockout@defence.local");
    store.state.users = store.state.users.filter((user) => user.id !== "u-lockout");
  }
});

test("object-level authorization blocks cross-tenant secret operations", async () => {
  await withApi(async (baseUrl) => {
    const morgan = await login(baseUrl, "morgan@defence.local");
    const beforeRequests = store.state.accessRequests.map((request) => ({ ...request, approvals: [...(request.approvals || [])] }));

    const blockedReveal = await jsonFetch(`${baseUrl}/secrets/s3/reveal`, morgan.token, { method: "POST" });
    assert.equal(blockedReveal.status, 403);

    const blockedUpdate = await jsonFetch(`${baseUrl}/secrets/s3`, morgan.token, {
      method: "PATCH",
      body: JSON.stringify({ notes: "cross-tenant mutation attempt" })
    });
    assert.equal(blockedUpdate.status, 403);

    const blockedDelete = await jsonFetch(`${baseUrl}/secrets/s3`, morgan.token, { method: "DELETE" });
    assert.equal(blockedDelete.status, 403);

    const blockedRestore = await jsonFetch(`${baseUrl}/secrets/s3/restore`, morgan.token, { method: "POST" });
    assert.equal(blockedRestore.status, 403);

    const blockedVersionRestore = await jsonFetch(`${baseUrl}/secrets/s3/versions/0/restore`, morgan.token, { method: "POST" });
    assert.equal(blockedVersionRestore.status, 403);

    const blockedRotate = await jsonFetch(`${baseUrl}/secrets/s3/rotate`, morgan.token, { method: "POST" });
    assert.equal(blockedRotate.status, 403);

    const blockedShare = await jsonFetch(`${baseUrl}/secrets/s3/share`, morgan.token, {
      method: "POST",
      body: JSON.stringify({ userId: "u2" })
    });
    assert.equal(blockedShare.status, 403);

    const request = await jsonFetch(`${baseUrl}/access-requests`, morgan.token, {
      method: "POST",
      body: JSON.stringify({ secretId: "s3", reason: "Need supplier credential review", minutes: 30 })
    });
    assert.equal(request.status, 201);
    const requestBody = await request.json();

    const blockedApprove = await jsonFetch(`${baseUrl}/access-requests/${requestBody.request.id}/approve`, morgan.token, { method: "POST" });
    assert.equal(blockedApprove.status, 403);

    store.state.accessRequests = beforeRequests;
  });
});

test("policy validation rejects unsupported or unsafe values", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const unknown = await jsonFetch(`${baseUrl}/policies`, ada.token, {
      method: "PATCH",
      body: JSON.stringify({ arbitraryField: true })
    });
    assert.equal(unknown.status, 400);

    const invalid = await jsonFetch(`${baseUrl}/policies`, ada.token, {
      method: "PATCH",
      body: JSON.stringify({ sessionMinutes: -1 })
    });
    assert.equal(invalid.status, 400);
  });
});

test("secret edit, version restore, and delete workflows work", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const create = await jsonFetch(`${baseUrl}/secrets`, ada.token, {
      method: "POST",
      body: JSON.stringify({
        vaultId: "v1",
        type: "password",
        name: "Lifecycle Test",
        username: "svc_lifecycle",
        password: "LifecycleSecretValue!2026",
        tags: "test"
      })
    });
    assert.equal(create.status, 201);

    const consoleResponse = await jsonFetch(`${baseUrl}/console`, ada.token);
    const data = await consoleResponse.json();
    const secret = data.secrets.find((candidate) => candidate.name === "Lifecycle Test");
    assert.ok(secret);

    const update = await jsonFetch(`${baseUrl}/secrets/${secret.id}`, ada.token, {
      method: "PATCH",
      body: JSON.stringify({ notes: "Updated notes", password: "LifecycleSecretValue!2027" })
    });
    assert.equal(update.status, 200);

    const restore = await jsonFetch(`${baseUrl}/secrets/${secret.id}/versions/0/restore`, ada.token, { method: "POST" });
    assert.equal(restore.status, 200);

    const deleted = await jsonFetch(`${baseUrl}/secrets/${secret.id}`, ada.token, { method: "DELETE" });
    assert.equal(deleted.status, 200);

    const deletedConsoleResponse = await jsonFetch(`${baseUrl}/console`, ada.token);
    const deletedConsole = await deletedConsoleResponse.json();
    assert.equal(deletedConsole.secrets.some((candidate) => candidate.id === secret.id), false);
    const deletedSecret = deletedConsole.deletedSecrets.find((candidate) => candidate.id === secret.id);
    assert.ok(deletedSecret);
    assert.ok(deletedSecret.deletedAt);
    assert.ok(deletedSecret.history.length >= 1);

    const restoreDeleted = await jsonFetch(`${baseUrl}/secrets/${secret.id}/restore`, ada.token, { method: "POST" });
    assert.equal(restoreDeleted.status, 200);

    const restoredConsoleResponse = await jsonFetch(`${baseUrl}/console`, ada.token);
    const restoredConsole = await restoredConsoleResponse.json();
    assert.ok(restoredConsole.secrets.find((candidate) => candidate.id === secret.id));
    assert.equal(restoredConsole.deletedSecrets.some((candidate) => candidate.id === secret.id), false);
  });
});

test("secret health report is auditor-only and reuse is blocked", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const morgan = await login(baseUrl, "morgan@defence.local");

    const health = await jsonFetch(`${baseUrl}/reports/secret-health`, ada.token);
    assert.equal(health.status, 200);
    const report = await health.json();
    assert.ok(report.secrets.length >= 3);
    assert.equal(typeof report.secrets[0].stale, "boolean");

    const blocked = await jsonFetch(`${baseUrl}/secrets`, morgan.token, {
      method: "POST",
      body: JSON.stringify({
        vaultId: "v1",
        type: "password",
        name: "Duplicate Telemetry Secret",
        username: "svc_duplicate",
        password: "E7#hP9!qZ2@Lw8$mV4",
        tags: "duplicate"
      })
    });
    assert.equal(blocked.status, 400);
  });
});

test("integration status is available to audit-capable users", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const response = await jsonFetch(`${baseUrl}/integrations/status`, ada.token);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.integrations.siem.configured, false);
    assert.equal(body.integrations.devopsApi.enabled, false);
  });
});

test("siem webhook delivery signs payloads and records retries", async () => {
  const previousWebhookUrl = config.integrations.siemWebhookUrl;
  const previousWebhookSecret = config.integrations.siemWebhookSecret;
  const previousWebhookKeyId = config.integrations.siemWebhookKeyId;
  const previousWebhookPreviousSecret = config.integrations.siemWebhookPreviousSecret;
  const previousWebhookPreviousKeyId = config.integrations.siemWebhookPreviousKeyId;
  const previousMaxAttempts = config.integrations.siemMaxAttempts;
  const previousRetrySeconds = config.integrations.siemRetrySeconds;
  const previousOutbox = store.state.integrationOutbox;

  config.integrations.siemWebhookUrl = "https://siem.example.test/events";
  config.integrations.siemWebhookSecret = "test-webhook-signing-key";
  config.integrations.siemWebhookKeyId = "siem-key-2026-07";
  config.integrations.siemWebhookPreviousSecret = "old-test-webhook-signing-key";
  config.integrations.siemWebhookPreviousKeyId = "siem-key-2026-06";
  config.integrations.siemMaxAttempts = 2;
  config.integrations.siemRetrySeconds = 5;
  store.state.integrationOutbox = [];

  try {
    enqueueIntegrationEvent({ id: "audit-1", action: "LOGIN", target: "Sentinel Vault" });
    const deliveredCalls = [];
    const delivered = await deliverQueuedIntegrationEvents({
      fetchImpl: async (url, options) => {
        deliveredCalls.push({ url, options });
        return { ok: true, status: 202 };
      },
      now: new Date()
    });

    assert.deepEqual(delivered, { attempted: 1, delivered: 1, failed: 0 });
    assert.equal(store.state.integrationOutbox[0].status, "delivered");
    assert.equal(deliveredCalls[0].url, "https://siem.example.test/events");
    assert.ok(deliveredCalls[0].options.headers["X-Sentinel-Delivery-Id"]);
    assert.ok(deliveredCalls[0].options.headers["X-Sentinel-Timestamp"]);
    assert.ok(deliveredCalls[0].options.headers["X-Sentinel-Nonce"]);
    assert.equal(deliveredCalls[0].options.headers["X-Sentinel-Replay-Window"], "300");
    assert.equal(deliveredCalls[0].options.headers["X-Sentinel-Key-Id"], "siem-key-2026-07");
    assert.equal(deliveredCalls[0].options.headers["X-Sentinel-Previous-Key-Id"], "siem-key-2026-06");
    const parsedDelivery = JSON.parse(deliveredCalls[0].options.body).delivery;
    assert.equal(parsedDelivery.id, deliveredCalls[0].options.headers["X-Sentinel-Delivery-Id"]);
    assert.equal(parsedDelivery.ts, deliveredCalls[0].options.headers["X-Sentinel-Timestamp"]);
    assert.equal(parsedDelivery.replayWindowSeconds, 300);
    const signedEnvelope = [
      deliveredCalls[0].options.headers["X-Sentinel-Timestamp"],
      deliveredCalls[0].options.headers["X-Sentinel-Nonce"],
      deliveredCalls[0].options.body
    ].join(".");
    const expectedSignature = crypto.createHmac("sha256", config.integrations.siemWebhookSecret).update(signedEnvelope, "utf8").digest("hex");
    assert.equal(deliveredCalls[0].options.headers["X-Sentinel-Signature"], `sha256=${expectedSignature}`);

    store.state.integrationOutbox = [];
    enqueueIntegrationEvent({ id: "audit-2", action: "REVEAL_SECRET", target: "Test Secret" });
    const firstFailure = await deliverQueuedIntegrationEvents({
      fetchImpl: async () => ({ ok: false, status: 503 }),
      now: new Date()
    });
    assert.deepEqual(firstFailure, { attempted: 1, delivered: 0, failed: 0 });
    assert.equal(store.state.integrationOutbox[0].status, "retrying");
    assert.equal(store.state.integrationOutbox[0].attempts, 1);
    assert.ok(store.state.integrationOutbox[0].nextAttemptAt);

    store.state.integrationOutbox[0].nextAttemptAt = new Date(Date.now() - 1000).toISOString();
    const finalFailure = await deliverQueuedIntegrationEvents({
      fetchImpl: async () => ({ ok: false, status: 503 }),
      now: new Date()
    });
    assert.deepEqual(finalFailure, { attempted: 1, delivered: 0, failed: 1 });
    assert.equal(store.state.integrationOutbox[0].status, "failed");
    assert.match(store.state.integrationOutbox[0].lastError, /HTTP 503/);
  } finally {
    config.integrations.siemWebhookUrl = previousWebhookUrl;
    config.integrations.siemWebhookSecret = previousWebhookSecret;
    config.integrations.siemWebhookKeyId = previousWebhookKeyId;
    config.integrations.siemWebhookPreviousSecret = previousWebhookPreviousSecret;
    config.integrations.siemWebhookPreviousKeyId = previousWebhookPreviousKeyId;
    config.integrations.siemMaxAttempts = previousMaxAttempts;
    config.integrations.siemRetrySeconds = previousRetrySeconds;
    store.state.integrationOutbox = previousOutbox;
  }
});

test("integration config updates and ITSM ticket validation are enforced", async () => {
  const previousItsmBaseUrl = config.integrations.itsmBaseUrl;
  const previousPrefixes = config.integrations.itsmTicketPrefixes;
  const previousAllowedStates = config.integrations.itsmAllowedStates;
  const previousDevops = config.integrations.devopsApiEnabled;
  const previousAccessRequests = store.state.accessRequests.map((request) => ({ ...request, approvals: [...(request.approvals || [])] }));
  const itsmServer = await startItsmFixture({
    "INC-12345": { state: "open", active: true, requester: "morgan@defence.local", assignmentGroup: "Cyber Operations" },
    "INC-99999": { state: "closed", active: false, requester: "morgan@defence.local", assignmentGroup: "Cyber Operations" },
    "INC-88888": { state: "awaiting_approval", active: true, requester: "morgan@defence.local", assignmentGroup: "Cyber Operations" },
    "CHG-12345": { state: "scheduled", active: true, requester: "morgan@defence.local", assignmentGroup: "Cyber Operations", changeWindow: { start: new Date(Date.now() + 3600000).toISOString(), end: new Date(Date.now() + 7200000).toISOString() } }
  });
  const itsmBaseUrl = `http://127.0.0.1:${itsmServer.address().port}`;
  try {
    await withApi(async (baseUrl) => {
      const ada = await login(baseUrl, "ada@defence.local");
      const morgan = await login(baseUrl, "morgan@defence.local");

      const update = await jsonFetch(`${baseUrl}/integrations/config`, ada.token, {
        method: "PATCH",
        body: JSON.stringify({
          itsmBaseUrl,
          itsmTicketPrefixes: "INC,CHG",
          itsmAllowedStates: "open,approved,scheduled",
          devopsApiEnabled: true
        })
      });
      assert.equal(update.status, 200);
      const updated = await update.json();
      assert.equal(updated.integrations.itsm.configured, true);
      assert.deepEqual(updated.integrations.itsm.ticketPrefixes, ["INC", "CHG"]);
      assert.deepEqual(updated.integrations.itsm.allowedStates, ["open", "approved", "scheduled"]);
      assert.equal(updated.integrations.devopsApi.enabled, true);

      const invalidTicket = await fetch(`${baseUrl}/access-requests`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${morgan.token}` },
        body: JSON.stringify({ secretId: "s3", reason: "Need temporary admin access", ticketRef: "TASK-12345" })
      });
      assert.equal(invalidTicket.status, 400);

      const closedTicket = await jsonFetch(`${baseUrl}/access-requests`, morgan.token, {
        method: "POST",
        body: JSON.stringify({ secretId: "s3", reason: "Need temporary admin access", ticketRef: "INC-99999" })
      });
      assert.equal(closedTicket.status, 400);

      const unapprovedTicket = await jsonFetch(`${baseUrl}/access-requests`, morgan.token, {
        method: "POST",
        body: JSON.stringify({ secretId: "s3", reason: "Need temporary admin access", ticketRef: "INC-88888" })
      });
      assert.equal(unapprovedTicket.status, 400);

      const futureWindowTicket = await jsonFetch(`${baseUrl}/access-requests`, morgan.token, {
        method: "POST",
        body: JSON.stringify({ secretId: "s3", reason: "Need temporary admin access", ticketRef: "CHG-12345" })
      });
      assert.equal(futureWindowTicket.status, 400);

      const validTicket = await jsonFetch(`${baseUrl}/access-requests`, morgan.token, {
        method: "POST",
        body: JSON.stringify({ secretId: "s3", reason: "Need temporary admin access", ticketRef: "INC-12345" })
      });
      assert.equal(validTicket.status, 201);
      const validBody = await validTicket.json();
      assert.equal(validBody.request.ticketValidation.state, "open");
      assert.equal(validBody.request.ticketValidation.assignmentGroup, "Cyber Operations");
      await waitFor(() => itsmServer.workNotes.length === 1);
      assert.equal(itsmServer.workNotes[0].ticketRef, "INC-12345");
      assert.equal(itsmServer.workNotes[0].body.source, "Sentinel Vault");
      assert.equal(itsmServer.workNotes[0].body.action, "access_requested");
      assert.equal(itsmServer.workNotes[0].body.requestId, validBody.request.id);
      assert.equal(itsmServer.workNotes[0].body.redaction.secretValueIncluded, false);
      assert.equal(itsmServer.workNotes[0].body.redaction.freeFormReasonIncluded, false);
      assert.doesNotMatch(JSON.stringify(itsmServer.workNotes[0].body), /Need temporary admin access/);

      const approve = await jsonFetch(`${baseUrl}/access-requests/${validBody.request.id}/approve`, ada.token, {
        method: "POST",
        body: JSON.stringify({ minutes: 15 })
      });
      assert.equal(approve.status, 200);
      await waitFor(() => itsmServer.workNotes.length === 2);
      assert.equal(itsmServer.workNotes[1].body.action, "access_approved");
      assert.equal(itsmServer.workNotes[1].body.requestStatus, "approved");

      const revoke = await jsonFetch(`${baseUrl}/access-requests/${validBody.request.id}/revoke`, ada.token, { method: "POST" });
      assert.equal(revoke.status, 200);
      await waitFor(() => itsmServer.workNotes.length === 3);
      assert.equal(itsmServer.workNotes[2].body.action, "access_revoked");
      assert.equal(itsmServer.workNotes[2].body.requestStatus, "revoked");

      const secondTicket = await jsonFetch(`${baseUrl}/access-requests`, morgan.token, {
        method: "POST",
        body: JSON.stringify({ secretId: "s3", reason: "Need temporary admin access", ticketRef: "INC-12345" })
      });
      assert.equal(secondTicket.status, 201);
      const secondBody = await secondTicket.json();
      await waitFor(() => itsmServer.workNotes.length === 4);
      assert.equal(itsmServer.workNotes[3].body.action, "access_requested");

      const deny = await jsonFetch(`${baseUrl}/access-requests/${secondBody.request.id}/deny`, ada.token, { method: "POST" });
      assert.equal(deny.status, 200);
      await waitFor(() => itsmServer.workNotes.length === 5);
      assert.equal(itsmServer.workNotes[4].body.action, "access_denied");
      assert.equal(itsmServer.workNotes[4].body.requestStatus, "denied");
    });
  } finally {
    await new Promise((resolve) => itsmServer.close(resolve));
    config.integrations.itsmBaseUrl = previousItsmBaseUrl;
    config.integrations.itsmTicketPrefixes = previousPrefixes;
    config.integrations.itsmAllowedStates = previousAllowedStates;
    config.integrations.devopsApiEnabled = previousDevops;
    store.state.accessRequests = previousAccessRequests;
  }
});

test("compliance report summarizes implemented controls", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const response = await jsonFetch(`${baseUrl}/reports/compliance`, ada.token);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.ok(body.report.standards.includes("ISO/IEC 27001"));
    assert.ok(body.report.summary.implemented >= 1);
    assert.ok(body.report.controls.some((control) => control.control === "audit_logging"));
    assert.ok(body.report.controls.some((control) => control.control === "audit_integrity"));

    const exportResponse = await jsonFetch(`${baseUrl}/reports/compliance/export`, ada.token);
    assert.equal(exportResponse.status, 200);
    assert.match(exportResponse.headers.get("content-disposition"), /sentinel-compliance-evidence/);
  });
});

test("devops secret retrieval is disabled unless configured", async () => {
  await withApi(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/devops/secrets/s1`, {
      headers: { "X-Sentinel-Service-Token": "not-configured" }
    });
    assert.equal(response.status, 404);
  });
});

test("managed service tokens are scoped to allowed secrets", async () => {
  const previousEnabled = config.integrations.devopsApiEnabled;
  config.integrations.devopsApiEnabled = true;
  try {
    await withApi(async (baseUrl) => {
      const ada = await login(baseUrl, "ada@defence.local");
      const create = await jsonFetch(`${baseUrl}/service-tokens`, ada.token, {
        method: "POST",
        body: JSON.stringify({ name: "CI pipeline", allowedSecrets: ["s1"], ttlDays: 7 })
      });
      assert.equal(create.status, 201);
      const body = await create.json();
      assert.match(body.secret, /^svt_/);
      assert.equal(body.token.allowedSecrets[0], "s1");
      assert.equal(body.token.tokenHashVersion, "hmac-sha256:v2");
      assert.equal(Object.hasOwn(body.token, "tokenHash"), false);

      const allowed = await fetch(`${baseUrl}/devops/secrets/s1`, {
        headers: { "X-Sentinel-Service-Token": body.secret }
      });
      assert.equal(allowed.status, 200);

      const listed = await jsonFetch(`${baseUrl}/service-tokens`, ada.token);
      assert.equal(listed.status, 200);
      const listedBody = await listed.json();
      const usedToken = listedBody.tokens.find((token) => token.id === body.token.id);
      assert.equal(usedToken.useCount, 1);
      assert.equal(usedToken.lastUsedSecretId, "s1");
      assert.ok(usedToken.lastUsedAt);
      assert.ok(usedToken.lastUsedSource);

      const rotate = await jsonFetch(`${baseUrl}/service-tokens/${body.token.id}/rotate`, ada.token, { method: "POST" });
      assert.equal(rotate.status, 200);
      const rotated = await rotate.json();
      assert.match(rotated.secret, /^svt_/);
      assert.notEqual(rotated.secret, body.secret);
      assert.equal(rotated.token.rotationCount, 1);
      assert.ok(rotated.token.rotatedAt);
      assert.equal(rotated.token.useCount, 0);
      assert.equal(rotated.token.lastUsedAt, null);

      const oldTokenDenied = await fetch(`${baseUrl}/devops/secrets/s1`, {
        headers: { "X-Sentinel-Service-Token": body.secret }
      });
      assert.equal(oldTokenDenied.status, 401);

      const newTokenAllowed = await fetch(`${baseUrl}/devops/secrets/s1`, {
        headers: { "X-Sentinel-Service-Token": rotated.secret }
      });
      assert.equal(newTokenAllowed.status, 200);

      const denied = await fetch(`${baseUrl}/devops/secrets/s2`, {
        headers: { "X-Sentinel-Service-Token": rotated.secret }
      });
      assert.equal(denied.status, 401);

      const revoke = await jsonFetch(`${baseUrl}/service-tokens/${body.token.id}/revoke`, ada.token, { method: "POST" });
      assert.equal(revoke.status, 200);
    });
  } finally {
    config.integrations.devopsApiEnabled = previousEnabled;
  }
});

test("legacy service token hashes migrate after successful scoped use", async () => {
  const previousEnabled = config.integrations.devopsApiEnabled;
  config.integrations.devopsApiEnabled = true;
  const legacyRaw = "legacy-presented-value-for-hash-upgrade";
  const legacyToken = {
    id: crypto.randomUUID(),
    name: "Legacy CI pipeline",
    ownerId: "u1",
    tokenHash: crypto.createHash("sha256").update(legacyRaw, "utf8").digest("base64url"),
    allowedVaults: [],
    allowedSecrets: ["s1"],
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
    createdAt: new Date().toISOString(),
    rotatedAt: null,
    rotationCount: 0,
    revokedAt: null,
    lastUsedAt: null,
    lastUsedSecretId: null,
    lastUsedSource: null,
    useCount: 0
  };
  store.state.serviceTokens.unshift(legacyToken);

  try {
    await withApi(async (baseUrl) => {
      const allowed = await fetch(`${baseUrl}/devops/secrets/s1`, {
        headers: { "X-Sentinel-Service-Token": legacyRaw }
      });

      assert.equal(allowed.status, 200);
      assert.match(legacyToken.tokenHash, /^hmac-sha256:v2:/);
      assert.equal(legacyToken.tokenHashVersion, "hmac-sha256:v2");
      assert.ok(legacyToken.legacyHashUpgradedAt);
      assert.equal(legacyToken.useCount, 1);
    });
  } finally {
    store.state.serviceTokens = store.state.serviceTokens.filter((token) => token.id !== legacyToken.id);
    config.integrations.devopsApiEnabled = previousEnabled;
  }
});

test("storage status and backup endpoints are admin-only", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const status = await jsonFetch(`${baseUrl}/storage/status`, ada.token);
    assert.equal(status.status, 200);
    const body = await status.json();
    assert.equal(body.storage.mode, config.storage.provider === "sqlite" ? "sqlite" : "json");
    assert.equal(body.storage.stateVersion, 3);

    const backup = await jsonFetch(`${baseUrl}/storage/backup`, ada.token, { method: "POST" });
    assert.equal(backup.status, 200);

    const encryptedBackup = await jsonFetch(`${baseUrl}/storage/backup/encrypted`, ada.token, { method: "POST" });
    assert.equal(encryptedBackup.status, 200);
    const encryptedBody = await encryptedBackup.json();
    assert.equal(encryptedBody.backup.algorithm, "AES-256-GCM");
    assert.equal(encryptedBody.backup.verified, true);

    const verification = await jsonFetch(`${baseUrl}/storage/backups/verify`, ada.token);
    assert.equal(verification.status, 200);
    const verificationBody = await verification.json();
    assert.ok(Array.isArray(verificationBody.backups));

    const restoreValidation = await jsonFetch(`${baseUrl}/storage/backups/restore-validate`, ada.token);
    assert.equal(restoreValidation.status, 200);
    const restoreBody = await restoreValidation.json();
    assert.ok(Array.isArray(restoreBody.backups));
  });
});

test("offline cache export is encrypted, read-only, and scoped to the user", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const morgan = await login(baseUrl, "morgan@defence.local");

    const exportResponse = await jsonFetch(`${baseUrl}/offline-cache/export`, ada.token, { method: "POST" });
    assert.equal(exportResponse.status, 200);
    assert.match(exportResponse.headers.get("content-disposition"), /sentinel-offline-cache/);
    const exported = await exportResponse.json();

    assert.equal(exported.cache.manifest.format, "sentinel-offline-cache-v1");
    assert.equal(exported.cache.manifest.readOnly, true);
    assert.equal(exported.cache.manifest.plaintextIncluded, false);
    assert.ok(exported.cache.manifest.secrets >= 3);
    assert.equal(exported.cache.manifest.index.secrets.length, exported.cache.manifest.secrets);
    assert.equal(exported.cache.manifest.index.secrets.some((secret) => Object.hasOwn(secret, "encrypted") || Object.hasOwn(secret, "password")), false);
    assert.ok(exported.cache.encrypted.ciphertext);
    assert.equal(JSON.stringify(exported.cache).includes("E7#hP9!qZ2@Lw8$mV4"), false);

    const verifyResponse = await jsonFetch(`${baseUrl}/offline-cache/verify`, ada.token, {
      method: "POST",
      body: JSON.stringify({ cache: exported.cache })
    });
    assert.equal(verifyResponse.status, 200);
    const verified = await verifyResponse.json();
    assert.equal(verified.verification.verified, true);
    assert.equal(verified.verification.readOnly, true);
    assert.equal(verified.verification.secrets, exported.cache.manifest.secrets);

    const rehydrateResponse = await jsonFetch(`${baseUrl}/offline-cache/rehydrate`, ada.token, {
      method: "POST",
      body: JSON.stringify({ cache: exported.cache, secretId: "s1" })
    });
    assert.equal(rehydrateResponse.status, 200);
    const rehydrated = await rehydrateResponse.json();
    assert.equal(rehydrated.password, "E7#hP9!qZ2@Lw8$mV4");

    const missingResponse = await jsonFetch(`${baseUrl}/offline-cache/rehydrate`, ada.token, {
      method: "POST",
      body: JSON.stringify({ cache: exported.cache, secretId: "not-in-cache" })
    });
    assert.equal(missingResponse.status, 404);

    const wrongUserResponse = await jsonFetch(`${baseUrl}/offline-cache/verify`, morgan.token, {
      method: "POST",
      body: JSON.stringify({ cache: exported.cache })
    });
    assert.equal(wrongUserResponse.status, 200);
    const wrongUser = await wrongUserResponse.json();
    assert.equal(wrongUser.verification.verified, false);

    const tampered = structuredClone(exported.cache);
    tampered.manifest.secrets += 1;
    const tamperResponse = await jsonFetch(`${baseUrl}/offline-cache/verify`, ada.token, {
      method: "POST",
      body: JSON.stringify({ cache: tampered })
    });
    assert.equal(tamperResponse.status, 200);
    const tamper = await tamperResponse.json();
    assert.equal(tamper.verification.verified, false);
    assert.equal(tamper.verification.reason, "signature_mismatch");

    const tamperedRehydrate = await jsonFetch(`${baseUrl}/offline-cache/rehydrate`, ada.token, {
      method: "POST",
      body: JSON.stringify({ cache: tampered, secretId: "s1" })
    });
    assert.equal(tamperedRehydrate.status, 400);
  });
});

test("new audit events are hash chained and verified", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const reveal = await jsonFetch(`${baseUrl}/secrets/s1/reveal`, ada.token, { method: "POST" });
    assert.equal(reveal.status, 200);
    const latest = store.state.audit[0];
    assert.equal(latest.action, "REVEAL_SECRET");
    assert.ok(latest.hash);
    assert.ok(latest.signature);
    assert.ok("previousHash" in latest);
    const integrity = verifyAuditChain(store.state.audit);
    assert.equal(integrity.verified, true);
    assert.ok(integrity.checked >= 1);

    const ledger = exportSignedAuditLedger(store.state.audit);
    assert.equal(ledger.manifest.signatureAlgorithm, "HMAC-SHA256");
    assert.equal(verifySignedAuditLedger(ledger).verified, true);

    const exportResponse = await jsonFetch(`${baseUrl}/reports/audit-ledger/export`, ada.token);
    assert.equal(exportResponse.status, 200);
    const exportBody = await exportResponse.json();
    assert.ok(exportBody.ledger.manifest.payloadHash);

    const verifyResponse = await jsonFetch(`${baseUrl}/reports/audit-ledger/verify`, ada.token);
    assert.equal(verifyResponse.status, 200);
    const verifyBody = await verifyResponse.json();
    assert.equal(verifyBody.verification.verified, true);
  });
});

test("approved access request grants temporary reveal access", async () => {
  await withApi(async (baseUrl) => {
    const morgan = await login(baseUrl, "morgan@defence.local");
    const ada = await login(baseUrl, "ada@defence.local");

    const requestResponse = await jsonFetch(`${baseUrl}/access-requests`, morgan.token, {
      method: "POST",
      body: JSON.stringify({ secretId: "s3", reason: "Need temporary supplier incident support", ticketRef: "INC-123", minutes: 30 })
    });
    assert.equal(requestResponse.status, 201);
    const { request } = await requestResponse.json();
    assert.equal(request.ticketRef, "INC-123");
    assert.equal(request.requiredApprovals, 1);

    const approveResponse = await jsonFetch(`${baseUrl}/access-requests/${request.id}/approve`, ada.token, {
      method: "POST",
      body: JSON.stringify({ minutes: 30 })
    });
    assert.equal(approveResponse.status, 200);

    const revealResponse = await jsonFetch(`${baseUrl}/secrets/s3/reveal`, morgan.token, { method: "POST" });
    assert.equal(revealResponse.status, 200);
    const reveal = await revealResponse.json();
    assert.equal(typeof reveal.password, "string");
    assert.ok(reveal.password.length > 0);
  });
});
