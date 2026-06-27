import test from "node:test";
import assert from "node:assert/strict";
import { createApp } from "../src/server/app.mjs";

test("auditor is blocked from policy updates", async () => {
  const app = await createApp();
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}/api`;

  try {
    const loginResponse = await fetch(`${baseUrl}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "iris@defence.local", password: "Passw0rd!" })
    });
    assert.equal(loginResponse.status, 200);
    const login = await loginResponse.json();

    const policyResponse = await fetch(`${baseUrl}/policies`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${login.token}`
      },
      body: JSON.stringify({ sessionMinutes: 99 })
    });
    assert.equal(policyResponse.status, 403);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
});
