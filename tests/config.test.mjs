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
    assert.equal(validateConfig().some((issue) => issue.includes("not available")), false);

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

test("external identity providers require role and MFA claim mapping", () => {
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
  try {
    config.identityProvider.mode = "entra";
    config.identityProvider.issuer = "https://login.microsoftonline.com/test/v2.0";
    config.identityProvider.clientId = "sentinel-client";
    config.identityProvider.tenantId = "";
    assert.ok(validateConfig().some((issue) => issue.includes("ENTRA_TENANT_ID")));

    config.identityProvider.tenantId = "tenant-id";
    config.identityProvider.mfaClaim = "";
    assert.ok(validateConfig().some((issue) => issue.includes("IDENTITY_MFA_CLAIM")));

    config.identityProvider.mfaClaim = "amr";
    config.identityProvider.roleMappings.SECURITY_ADMIN = "";
    assert.ok(validateConfig().some((issue) => issue.includes("IDENTITY_ROLE_SECURITY_ADMIN")));

    config.identityProvider.roleMappings.SECURITY_ADMIN = "Sentinel Vault Admins";
    assert.equal(validateConfig().some((issue) => issue.includes("IDENTITY_ROLE_SECURITY_ADMIN")), false);
  } finally {
    Object.assign(config.identityProvider, previous);
    config.identityProvider.roleMappings = previous.roleMappings;
  }
});
