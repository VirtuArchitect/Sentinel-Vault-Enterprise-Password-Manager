import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
const { createApp } = await import("../src/server/app.mjs");

const withApi = async (run) => {
  const app = await createApp();
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const { port } = server.address();
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
    const health = await response.json();
    assert.equal(health.ok, true);
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
  });
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
