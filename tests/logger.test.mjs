import test from "node:test";
import assert from "node:assert/strict";
import { redactForLog } from "../src/server/logging/logger.mjs";

test("log redaction masks sensitive keys recursively", () => {
  const output = redactForLog({
    email: "avery.stone@enterprise.example",
    password: "Passw0rd!",
    nested: {
      serviceToken: "svc-token-value",
      headers: {
        Authorization: "Bearer abc.def.ghi"
      }
    },
    secrets: [{ value: "hidden" }]
  });

  assert.equal(output.email, "avery.stone@enterprise.example");
  assert.equal(output.password, "[REDACTED]");
  assert.equal(output.nested.serviceToken, "[REDACTED]");
  assert.equal(output.nested.headers.Authorization, "[REDACTED]");
  assert.equal(output.secrets, "[REDACTED]");
  assert.equal(JSON.stringify(output).includes("Passw0rd!"), false);
  assert.equal(JSON.stringify(output).includes("svc-token-value"), false);
  assert.equal(JSON.stringify(output).includes("abc.def.ghi"), false);
});

test("log redaction masks bearer tokens inside safe string fields", () => {
  const output = redactForLog({
    message: "Request failed with Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.signature"
  });

  assert.equal(output.message.includes("Bearer [REDACTED]"), true);
  assert.equal(output.message.includes("eyJhbGciOiJSUzI1NiJ9"), false);
});

test("log redaction handles circular references", () => {
  const input = { name: "root" };
  input.self = input;

  const output = redactForLog(input);

  assert.equal(output.self, "[Circular]");
});

test("log redaction masks tokens inside errors", () => {
  const error = new Error("Upstream rejected Bearer secret.jwt.value");
  const output = redactForLog({ err: error });

  assert.equal(output.err.message, "Upstream rejected Bearer [REDACTED]");
  assert.equal(JSON.stringify(output).includes("secret.jwt.value"), false);
});
