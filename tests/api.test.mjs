import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
const { createApp } = await import("../src/server/app.mjs");
const { config } = await import("../src/server/config.mjs");
const { store } = await import("../src/server/data/store.mjs");
const { hashPassword } = await import("../src/server/crypto/passwords.mjs");
const { verifyAuditChain } = await import("../src/server/services/auditService.mjs");
const { buildContentSecurityPolicy, buildSecurityHeaders } = await import("../src/server/middleware/securityHeaders.mjs");

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
    assert.equal(rejected.status, 500);
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
    assert.equal(consoleData.integrations.siem.mode, "outbox");
    assert.equal(typeof consoleData.session.activeSessions, "number");
    assert.equal(consoleData.session.ttlMinutes, 15);
    assert.equal(typeof consoleData.session.reviewable, "number");
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
    const morganSession = body.sessions
      .filter((session) => session.userId === "u2")
      .sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt))[0];
    assert.ok(morganSession);
    assert.ok(morganSession.id);
    assert.ok(morganSession.source);
    assert.ok(morganSession.userAgent);

    const revoke = await jsonFetch(`${baseUrl}/sessions/${morganSession.id}/revoke`, ada.token, { method: "POST" });
    assert.equal(revoke.status, 200);

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

test("object-level authorization blocks secret rotation outside accessible vaults", async () => {
  await withApi(async (baseUrl) => {
    const morgan = await login(baseUrl, "morgan@defence.local");
    const response = await jsonFetch(`${baseUrl}/secrets/s3/rotate`, morgan.token, { method: "POST" });
    assert.equal(response.status, 403);
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

      const denied = await fetch(`${baseUrl}/devops/secrets/s2`, {
        headers: { "X-Sentinel-Service-Token": body.secret }
      });
      assert.equal(denied.status, 401);

      const revoke = await jsonFetch(`${baseUrl}/service-tokens/${body.token.id}/revoke`, ada.token, { method: "POST" });
      assert.equal(revoke.status, 200);
    });
  } finally {
    config.integrations.devopsApiEnabled = previousEnabled;
  }
});

test("storage status and backup endpoints are admin-only", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const status = await jsonFetch(`${baseUrl}/storage/status`, ada.token);
    assert.equal(status.status, 200);
    const body = await status.json();
    assert.equal(body.storage.mode, "json");
    assert.equal(body.storage.stateVersion, 2);

    const backup = await jsonFetch(`${baseUrl}/storage/backup`, ada.token, { method: "POST" });
    assert.equal(backup.status, 200);

    const verification = await jsonFetch(`${baseUrl}/storage/backups/verify`, ada.token);
    assert.equal(verification.status, 200);
    const verificationBody = await verification.json();
    assert.ok(Array.isArray(verificationBody.backups));
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
    assert.ok("previousHash" in latest);
    const integrity = verifyAuditChain(store.state.audit);
    assert.equal(integrity.verified, true);
    assert.ok(integrity.checked >= 1);
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
