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
  sessionMinutes: Number(process.env.SESSION_MINUTES || 15),
  failedLoginLimit: Number(process.env.FAILED_LOGIN_LIMIT || 5),
  loginLockoutMinutes: Number(process.env.LOGIN_LOCKOUT_MINUTES || 15),
  corsOrigins: String(process.env.CORS_ORIGINS || "http://127.0.0.1:5173,http://localhost:5173")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
  rootDir,
  dataDir: process.env.DATA_DIR || path.join(rootDir, "data"),
  stateFile: process.env.STATE_FILE || "sentinel-state.json",
  identityProvider: {
    mode: process.env.IDENTITY_PROVIDER || "local",
    issuer: process.env.OIDC_ISSUER || "",
    clientId: process.env.OIDC_CLIENT_ID || "",
    tenantId: process.env.ENTRA_TENANT_ID || "",
    groupClaim: process.env.IDENTITY_GROUP_CLAIM || "groups"
  },
  integrations: {
    siemWebhookUrl: process.env.SIEM_WEBHOOK_URL || "",
    itsmBaseUrl: process.env.ITSM_BASE_URL || "",
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
  return issues;
};
