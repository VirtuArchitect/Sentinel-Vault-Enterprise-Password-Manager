import path from "node:path";
import { fileURLToPath } from "node:url";

export const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export const config = {
  host: process.env.HOST || "127.0.0.1",
  port: Number(process.env.PORT || 5173),
  isProduction: process.env.NODE_ENV === "production",
  isTest: process.env.NODE_ENV === "test",
  vaultRootKey: process.env.VAULT_ROOT_KEY || "sentinel-demo-root-key",
  vaultKeyVersion: process.env.VAULT_KEY_VERSION || "demo-root-v1",
  vaultKeySalt: process.env.VAULT_KEY_SALT || "sentinel-vault",
  kms: {
    provider: process.env.KMS_PROVIDER || "local-root-key",
    keyId: process.env.KMS_KEY_ID || "",
    endpoint: process.env.KMS_ENDPOINT || ""
  },
  sessionMinutes: Number(process.env.SESSION_MINUTES || 15),
  failedLoginLimit: Number(process.env.FAILED_LOGIN_LIMIT || 5),
  loginLockoutMinutes: Number(process.env.LOGIN_LOCKOUT_MINUTES || 15),
  corsOrigins: String(process.env.CORS_ORIGINS || "http://127.0.0.1:5173,http://localhost:5173")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
  rootDir,
  storage: {
    provider: process.env.STORAGE_PROVIDER || "json",
    dataDir: process.env.DATA_DIR || path.join(rootDir, "data"),
    stateFile: process.env.STATE_FILE || "sentinel-state.json",
    sqlitePath: process.env.SQLITE_PATH || "",
    databaseUrl: process.env.DATABASE_URL || ""
  },
  get dataDir() {
    return this.storage.dataDir;
  },
  get stateFile() {
    return this.storage.stateFile;
  },
  identityProvider: {
    mode: process.env.IDENTITY_PROVIDER || "local",
    issuer: process.env.OIDC_ISSUER || "",
    clientId: process.env.OIDC_CLIENT_ID || "",
    tenantId: process.env.ENTRA_TENANT_ID || "",
    groupClaim: process.env.IDENTITY_GROUP_CLAIM || "groups"
  },
  integrations: {
    siemWebhookUrl: process.env.SIEM_WEBHOOK_URL || "",
    siemWebhookSecret: process.env.SIEM_WEBHOOK_SECRET || "",
    siemMaxAttempts: Number(process.env.SIEM_MAX_ATTEMPTS || 5),
    siemRetrySeconds: Number(process.env.SIEM_RETRY_SECONDS || 60),
    itsmBaseUrl: process.env.ITSM_BASE_URL || "",
    itsmTicketPrefixes: String(process.env.ITSM_TICKET_PREFIXES || "INC,CHG,REQ")
      .split(",")
      .map((prefix) => prefix.trim().toUpperCase())
      .filter(Boolean),
    devopsApiEnabled: process.env.DEVOPS_API_ENABLED === "true",
    outboxLimit: Number(process.env.INTEGRATION_OUTBOX_LIMIT || 100)
  },
  distDir: path.join(rootDir, "dist")
};

export const validateConfig = () => {
  const issues = [];
  if (config.isProduction && config.vaultRootKey === "sentinel-demo-root-key") {
    issues.push("VAULT_ROOT_KEY must be set in production.");
  }
  if (!["local-root-key", "external-kms", "hsm"].includes(config.kms.provider)) {
    issues.push("KMS_PROVIDER must be one of local-root-key, external-kms, or hsm.");
  }
  if (config.kms.provider !== "local-root-key" && !config.kms.keyId) {
    issues.push("KMS_KEY_ID is required when KMS_PROVIDER is external-kms or hsm.");
  }
  if (!["json", "sqlite", "postgres"].includes(config.storage.provider)) {
    issues.push("STORAGE_PROVIDER must be one of json, sqlite, or postgres.");
  }
  if (config.storage.provider !== "json") {
    issues.push(`${config.storage.provider} storage is planned but not available until the database dependency is approved and installed.`);
  }
  if (config.storage.provider === "sqlite" && !config.storage.sqlitePath) {
    issues.push("SQLITE_PATH is required when STORAGE_PROVIDER is sqlite.");
  }
  if (config.storage.provider === "postgres" && !config.storage.databaseUrl) {
    issues.push("DATABASE_URL is required when STORAGE_PROVIDER is postgres.");
  }
  if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
    issues.push("PORT must be an integer between 1 and 65535.");
  }
  if (!Number.isInteger(config.failedLoginLimit) || config.failedLoginLimit < 1 || config.failedLoginLimit > 25) {
    issues.push("FAILED_LOGIN_LIMIT must be an integer between 1 and 25.");
  }
  if (!Number.isInteger(config.loginLockoutMinutes) || config.loginLockoutMinutes < 1 || config.loginLockoutMinutes > 1440) {
    issues.push("LOGIN_LOCKOUT_MINUTES must be an integer between 1 and 1440.");
  }
  if (config.identityProvider.mode !== "local" && (!config.identityProvider.issuer || !config.identityProvider.clientId)) {
    issues.push("OIDC_ISSUER and OIDC_CLIENT_ID are required for external identity providers.");
  }
  if (config.integrations.siemWebhookUrl && config.isProduction && !config.integrations.siemWebhookSecret) {
    issues.push("SIEM_WEBHOOK_SECRET is required when SIEM_WEBHOOK_URL is set in production.");
  }
  if (!Number.isInteger(config.integrations.siemMaxAttempts) || config.integrations.siemMaxAttempts < 1 || config.integrations.siemMaxAttempts > 25) {
    issues.push("SIEM_MAX_ATTEMPTS must be an integer between 1 and 25.");
  }
  if (!Number.isInteger(config.integrations.siemRetrySeconds) || config.integrations.siemRetrySeconds < 5 || config.integrations.siemRetrySeconds > 3600) {
    issues.push("SIEM_RETRY_SECONDS must be an integer between 5 and 3600.");
  }
  if (!Array.isArray(config.integrations.itsmTicketPrefixes) || !config.integrations.itsmTicketPrefixes.length) {
    issues.push("ITSM_TICKET_PREFIXES must include at least one prefix.");
  }
  return issues;
};
