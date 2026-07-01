import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

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
    assert.equal(consoleData.crypto.keyProvider.provider, "local-root-key");
    assert.equal(consoleData.integrations.siem.mode, "outbox");
    assert.equal(typeof consoleData.session.activeSessions, "number");
    assert.equal(consoleData.session.ttlMinutes, 15);
    assert.equal(typeof consoleData.session.reviewable, "number");
  });
});

test("security admins can manage vaults and user status", async () => {
  await withApi(async (baseUrl) => {
    const ada = await login(baseUrl, "ada@defence.local");
    const createVault = await jsonFetch(`${baseUrl}/vaults`, ada.token, {
      method: "POST",
      body: JSON.stringify({
        name: "Red Team Operations",
        classification: "SECRET",
        ownerUnit: "Cyber Operations",
        members: ["u1", "u2"]
      })
    });
    assert.equal(createVault.status, 201);
    const created = await createVault.json();
    assert.equal(created.vault.name, "Red Team Operations");
    assert.deepEqual(created.vault.members.sort(), ["u1", "u2"]);

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
  const previousMaxAttempts = config.integrations.siemMaxAttempts;
  const previousRetrySeconds = config.integrations.siemRetrySeconds;
  const previousOutbox = store.state.integrationOutbox;

  config.integrations.siemWebhookUrl = "https://siem.example.test/events";
  config.integrations.siemWebhookSecret = "test-webhook-signing-key";
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
    const expectedSignature = crypto.createHmac("sha256", config.integrations.siemWebhookSecret).update(deliveredCalls[0].options.body, "utf8").digest("hex");
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
    config.integrations.siemMaxAttempts = previousMaxAttempts;
    config.integrations.siemRetrySeconds = previousRetrySeconds;
    store.state.integrationOutbox = previousOutbox;
  }
});

test("integration config updates and ITSM ticket validation are enforced", async () => {
  const previousItsmBaseUrl = config.integrations.itsmBaseUrl;
  const previousPrefixes = config.integrations.itsmTicketPrefixes;
  const previousDevops = config.integrations.devopsApiEnabled;
  const previousAccessRequests = store.state.accessRequests.map((request) => ({ ...request, approvals: [...(request.approvals || [])] }));
  try {
    await withApi(async (baseUrl) => {
      const ada = await login(baseUrl, "ada@defence.local");
      const morgan = await login(baseUrl, "morgan@defence.local");

      const update = await jsonFetch(`${baseUrl}/integrations/config`, ada.token, {
        method: "PATCH",
        body: JSON.stringify({
          itsmBaseUrl: "https://itsm.example.test",
          itsmTicketPrefixes: "INC,CHG",
          devopsApiEnabled: true
        })
      });
      assert.equal(update.status, 200);
      const updated = await update.json();
      assert.equal(updated.integrations.itsm.configured, true);
      assert.deepEqual(updated.integrations.itsm.ticketPrefixes, ["INC", "CHG"]);
      assert.equal(updated.integrations.devopsApi.enabled, true);

      const invalidTicket = await fetch(`${baseUrl}/access-requests`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${morgan.token}` },
        body: JSON.stringify({ secretId: "s3", reason: "Need temporary admin access", ticketRef: "TASK-12345" })
      });
      assert.equal(invalidTicket.status, 400);

      const validTicket = await jsonFetch(`${baseUrl}/access-requests`, morgan.token, {
        method: "POST",
        body: JSON.stringify({ secretId: "s3", reason: "Need temporary admin access", ticketRef: "INC-12345" })
      });
      assert.equal(validTicket.status, 201);
    });
  } finally {
    config.integrations.itsmBaseUrl = previousItsmBaseUrl;
    config.integrations.itsmTicketPrefixes = previousPrefixes;
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
