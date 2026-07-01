import test from "node:test";
import assert from "node:assert/strict";
import { encryptSecret, decryptSecret, getCryptoStatus, signVaultValue } from "../src/server/crypto/vaultCrypto.mjs";
import { hashPassword, verifyPassword } from "../src/server/crypto/passwords.mjs";

test("vault crypto round trips secret material", () => {
  const encrypted = encryptSecret("correct horse battery staple");
  assert.notEqual(encrypted.value, "correct horse battery staple");
  assert.equal(decryptSecret(encrypted), "correct horse battery staple");
});

test("key provider status is explicit and can sign scoped values", () => {
  const status = getCryptoStatus();
  assert.equal(status.keyProvider.provider, "local-root-key");
  assert.equal(status.keyProvider.configured, true);
  assert.equal(status.keyProvider.supported, true);
  assert.match(signVaultValue("test", "value"), /^[A-Za-z0-9_-]+$/);
});

test("password hashing verifies exact password only", () => {
  const stored = hashPassword("Passw0rd!");
  assert.equal(verifyPassword("Passw0rd!", stored), true);
  assert.equal(verifyPassword("wrong", stored), false);
});
