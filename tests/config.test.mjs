import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
const { config, validateConfig } = await import("../src/server/config.mjs");

test("external key providers require a configured key id", () => {
  const previousProvider = config.kms.provider;
  const previousKeyId = config.kms.keyId;
  try {
    config.kms.provider = "external-kms";
    config.kms.keyId = "";
    assert.ok(validateConfig().some((issue) => issue.includes("KMS_KEY_ID")));

    config.kms.keyId = "sentinel-test-key";
    assert.equal(validateConfig().some((issue) => issue.includes("KMS_KEY_ID")), false);
  } finally {
    config.kms.provider = previousProvider;
    config.kms.keyId = previousKeyId;
  }
});

test("storage provider boundary validates planned database modes", () => {
  const previousProvider = config.storage.provider;
  const previousSqlitePath = config.storage.sqlitePath;
  const previousDatabaseUrl = config.storage.databaseUrl;
  try {
    config.storage.provider = "sqlite";
    config.storage.sqlitePath = "";
    assert.ok(validateConfig().some((issue) => issue.includes("SQLITE_PATH")));
    assert.ok(validateConfig().some((issue) => issue.includes("not available")));

    config.storage.provider = "postgres";
    config.storage.databaseUrl = "";
    assert.ok(validateConfig().some((issue) => issue.includes("DATABASE_URL")));

    config.storage.provider = "json";
    assert.equal(validateConfig().some((issue) => issue.includes("STORAGE_PROVIDER")), false);
  } finally {
    config.storage.provider = previousProvider;
    config.storage.sqlitePath = previousSqlitePath;
    config.storage.databaseUrl = previousDatabaseUrl;
  }
});
