import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
const { config, validateConfig } = await import("../src/server/config.mjs");

test("external key providers require a configured key id", () => {
  const previousProvider = config.kms.provider;
  const previousKeyId = config.kms.keyId;
  const previousTimeoutMs = config.kms.timeoutMs;
  try {
    config.kms.provider = "external-kms";
    config.kms.keyId = "";
    assert.ok(validateConfig().some((issue) => issue.includes("KMS_KEY_ID")));

    config.kms.keyId = "sentinel-test-key";
    assert.equal(validateConfig().some((issue) => issue.includes("KMS_KEY_ID")), false);

    config.kms.timeoutMs = 100;
    assert.ok(validateConfig().some((issue) => issue.includes("KMS_GATEWAY_TIMEOUT_MS")));
  } finally {
    config.kms.provider = previousProvider;
    config.kms.keyId = previousKeyId;
    config.kms.timeoutMs = previousTimeoutMs;
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

test("refresh tokens require external identity mode and bounded lifetime", () => {
  const previous = {
    enabled: config.refreshTokens.enabled,
    ttlDays: config.refreshTokens.ttlDays,
    identityMode: config.identityProvider.mode
  };
  try {
    config.refreshTokens.enabled = true;
    config.refreshTokens.ttlDays = 7;
    config.identityProvider.mode = "local";
    assert.ok(validateConfig().some((issue) => issue.includes("REFRESH_TOKENS_ENABLED")));

    config.identityProvider.mode = "oidc";
    assert.equal(validateConfig().some((issue) => issue.includes("REFRESH_TOKENS_ENABLED")), false);

    config.refreshTokens.ttlDays = 31;
    assert.ok(validateConfig().some((issue) => issue.includes("REFRESH_TOKEN_DAYS")));
  } finally {
    config.refreshTokens.enabled = previous.enabled;
    config.refreshTokens.ttlDays = previous.ttlDays;
    config.identityProvider.mode = previous.identityMode;
  }
});

test("siem webhook signing key rotation metadata is validated", () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalWebhookUrl = config.integrations.siemWebhookUrl;
  const originalWebhookSecret = config.integrations.siemWebhookSecret;
  const originalWebhookKeyId = config.integrations.siemWebhookKeyId;
  const originalPreviousSecret = config.integrations.siemWebhookPreviousSecret;
  const originalPreviousKeyId = config.integrations.siemWebhookPreviousKeyId;
  const originalProduction = config.isProduction;

  try {
    config.isProduction = true;
    config.integrations.siemWebhookUrl = "https://siem.example.test/events";
    config.integrations.siemWebhookSecret = "configured-signing-secret";
    config.integrations.siemWebhookKeyId = "";
    config.integrations.siemWebhookPreviousSecret = "old-signing-secret";
    config.integrations.siemWebhookPreviousKeyId = "";

    const issues = validateConfig();
    assert.ok(issues.includes("SIEM_WEBHOOK_KEY_ID is required when SIEM webhook signing is enabled in production."));
    assert.ok(issues.includes("SIEM_WEBHOOK_PREVIOUS_KEY_ID is required when SIEM_WEBHOOK_PREVIOUS_SECRET is set."));

    config.integrations.siemWebhookKeyId = "siem-key-2026-07";
    config.integrations.siemWebhookPreviousKeyId = "siem-key-2026-07";
    assert.ok(validateConfig().includes("SIEM_WEBHOOK_KEY_ID and SIEM_WEBHOOK_PREVIOUS_KEY_ID must be different during rotation."));
  } finally {
    process.env.NODE_ENV = originalNodeEnv;
    config.integrations.siemWebhookUrl = originalWebhookUrl;
    config.integrations.siemWebhookSecret = originalWebhookSecret;
    config.integrations.siemWebhookKeyId = originalWebhookKeyId;
    config.integrations.siemWebhookPreviousSecret = originalPreviousSecret;
    config.integrations.siemWebhookPreviousKeyId = originalPreviousKeyId;
    config.isProduction = originalProduction;
  }
});
