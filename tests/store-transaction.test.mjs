import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
const { store } = await import("../src/server/data/store.mjs");
const { audit } = await import("../src/server/services/auditService.mjs");

const testSecret = (id) => ({
  id,
  vaultId: "v1",
  type: "password",
  name: id,
  username: "txn",
  url: "",
  tags: [],
  risk: "low",
  rotatedAt: new Date().toISOString(),
  sharedWith: ["u1"],
  approvalsRequired: false,
  notes: "",
  history: [],
  fingerprint: id,
  encrypted: { iv: "iv", tag: "tag", ciphertext: "ciphertext" }
});

test("store transaction rolls back state, audit, outbox, and commit hooks", () => {
  const before = {
    secrets: store.state.secrets.length,
    audit: store.state.audit.length,
    outbox: store.state.integrationOutbox.length
  };
  let committed = false;

  assert.throws(() => store.withTransaction(() => {
    store.state.secrets.unshift(testSecret("txn-rollback-secret"));
    audit("u1", "TXN_ROLLBACK_TEST", "transaction", "rollback should discard this");
    store.afterCommit(() => {
      committed = true;
    });
    throw new Error("force rollback");
  }), /force rollback/);

  assert.equal(committed, false);
  assert.equal(store.state.secrets.length, before.secrets);
  assert.equal(store.state.audit.length, before.audit);
  assert.equal(store.state.integrationOutbox.length, before.outbox);
  assert.equal(store.state.secrets.some((secret) => secret.id === "txn-rollback-secret"), false);
  assert.equal(store.state.audit.some((event) => event.action === "TXN_ROLLBACK_TEST"), false);
});

test("store transaction commits state and deferred hooks once", () => {
  let commitHooks = 0;

  try {
    const result = store.withTransaction(() => {
      store.state.secrets.unshift(testSecret("txn-commit-secret"));
      audit("u1", "TXN_COMMIT_TEST", "transaction", "commit should keep this");
      store.afterCommit(() => {
        commitHooks += 1;
      });
      return "committed";
    });

    assert.equal(result, "committed");
    assert.equal(commitHooks, 1);
    assert.equal(store.state.secrets.some((secret) => secret.id === "txn-commit-secret"), true);
    assert.equal(store.state.audit.some((event) => event.action === "TXN_COMMIT_TEST"), true);
    assert.equal(store.state.integrationOutbox.some((item) => item.event?.action === "TXN_COMMIT_TEST"), true);
  } finally {
    store.state.secrets = store.state.secrets.filter((secret) => secret.id !== "txn-commit-secret");
    store.state.audit = store.state.audit.filter((event) => event.action !== "TXN_COMMIT_TEST");
    store.state.integrationOutbox = store.state.integrationOutbox.filter((item) => item.event?.action !== "TXN_COMMIT_TEST");
  }
});
