import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { encryptSecret, decryptSecret, getCryptoStatus, signVaultValue } from "../src/server/crypto/vaultCrypto.mjs";
import { hashPassword, verifyPassword } from "../src/server/crypto/passwords.mjs";
import { config } from "../src/server/config.mjs";

test("vault crypto round trips secret material", () => {
  const encrypted = encryptSecret("correct horse battery staple");
  assert.notEqual(encrypted.value, "correct horse battery staple");
  assert.equal(decryptSecret(encrypted), "correct horse battery staple");
});

const startSigningGateway = async (options = {}) => {
  const requests = [];
  const server = http.createServer((req, res) => {
    if (req.url === "/sign" && req.method === "POST") {
      let raw = "";
      req.on("data", (chunk) => {
        raw += chunk;
      });
      req.on("end", () => {
        const body = JSON.parse(raw || "{}");
        requests.push(body);
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({
          keyId: options.keyId || body.keyId,
          algorithm: "HMAC-SHA256-GATEWAY",
          signature: crypto.createHmac("sha256", "gateway-fixture-key").update(`${body.keyId}:${body.purpose}:${body.value}`).digest("base64url")
        }));
      });
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  server.requests = requests;
  server.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  return server;
};

test("key provider status is explicit and can sign scoped values", async () => {
  const status = getCryptoStatus();
  assert.equal(status.keyProvider.provider, "local-root-key");
  assert.equal(status.keyProvider.configured, true);
  assert.equal(status.keyProvider.supported, true);
  assert.equal(status.keyProvider.signingMode, "local-hmac");
  assert.match(await signVaultValue("test", "value"), /^[A-Za-z0-9_-]+$/);
});

test("external key provider can sign through a configured gateway", async () => {
  const previous = {
    provider: config.kms.provider,
    keyId: config.kms.keyId,
    endpoint: config.kms.endpoint,
    timeoutMs: config.kms.timeoutMs
  };
  const gateway = await startSigningGateway();
  try {
    config.kms.provider = "external-kms";
    config.kms.keyId = "sentinel-test-key";
    config.kms.endpoint = `http://127.0.0.1:${gateway.address().port}`;
    config.kms.timeoutMs = 5000;

    const status = getCryptoStatus();
    assert.equal(status.keyProvider.signingMode, "gateway-sign");

    const signature = await signVaultValue("audit", "payload");
    assert.match(signature, /^[A-Za-z0-9_-]+$/);
    assert.equal(gateway.requests.length, 1);
    assert.equal(gateway.requests[0].keyId, "sentinel-test-key");
    assert.equal(gateway.requests[0].purpose, "audit");
    assert.equal(gateway.requests[0].value, "payload");
  } finally {
    config.kms.provider = previous.provider;
    config.kms.keyId = previous.keyId;
    config.kms.endpoint = previous.endpoint;
    config.kms.timeoutMs = previous.timeoutMs;
    await new Promise((resolve, reject) => gateway.close((err) => (err ? reject(err) : resolve())));
  }
});

test("password hashing verifies exact password only", () => {
  const stored = hashPassword("Passw0rd!");
  assert.equal(verifyPassword("Passw0rd!", stored), true);
  assert.equal(verifyPassword("wrong", stored), false);
  assert.equal(verifyPassword("Passw0rd!", { salt: stored.salt, hash: "not-hex" }), false);
  assert.equal(verifyPassword("Passw0rd!", { hash: stored.hash }), false);
  assert.equal(verifyPassword("Passw0rd!", null), false);
});
