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
    endpoint: process.env.KMS_ENDPOINT || "",
    timeoutMs: Number(process.env.KMS_GATEWAY_TIMEOUT_MS || 5000)
  },
  sessionMinutes: Number(process.env.SESSION_MINUTES || 15),
  refreshTokens: {
    enabled: process.env.REFRESH_TOKENS_ENABLED === "true",
    ttlDays: Number(process.env.REFRESH_TOKEN_DAYS || 7)
  },
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
    clientSecret: process.env.OIDC_CLIENT_SECRET || "",
    redirectUris: String(process.env.OIDC_REDIRECT_URIS || "http://127.0.0.1:5173/auth/callback,http://localhost:5173/auth/callback")
      .split(",")
      .map((uri) => uri.trim())
      .filter(Boolean),
    tenantId: process.env.ENTRA_TENANT_ID || "",
    groupClaim: process.env.IDENTITY_GROUP_CLAIM || "groups",
    mfaClaim: process.env.IDENTITY_MFA_CLAIM || "amr",
    mfaRequiredValue: process.env.IDENTITY_MFA_REQUIRED_VALUE || "mfa",
    roleMappings: {
      SECURITY_ADMIN: process.env.IDENTITY_ROLE_SECURITY_ADMIN || "Sentinel Vault Admins",
      VAULT_OPERATOR: process.env.IDENTITY_ROLE_VAULT_OPERATOR || "Sentinel Vault Operators",
      AUDITOR: process.env.IDENTITY_ROLE_AUDITOR || "Sentinel Vault Auditors"
    }
  },
  integrations: {
    siemWebhookUrl: process.env.SIEM_WEBHOOK_URL || "",
    siemWebhookSecret: process.env.SIEM_WEBHOOK_SECRET || "",
    siemWebhookKeyId: process.env.SIEM_WEBHOOK_KEY_ID || "",
    siemWebhookPreviousSecret: process.env.SIEM_WEBHOOK_PREVIOUS_SECRET || "",
    siemWebhookPreviousKeyId: process.env.SIEM_WEBHOOK_PREVIOUS_KEY_ID || "",
    siemMaxAttempts: Number(process.env.SIEM_MAX_ATTEMPTS || 5),
    siemRetrySeconds: Number(process.env.SIEM_RETRY_SECONDS || 60),
    itsmBaseUrl: process.env.ITSM_BASE_URL || "",
    itsmTicketPrefixes: String(process.env.ITSM_TICKET_PREFIXES || "INC,CHG,REQ")
      .split(",")
      .map((prefix) => prefix.trim().toUpperCase())
      .filter(Boolean),
    itsmAllowedStates: String(process.env.ITSM_ALLOWED_STATES || "open,active,approved,in_progress,scheduled")
      .split(",")
      .map((state) => state.trim().toLowerCase())
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
  if (!Number.isInteger(config.kms.timeoutMs) || config.kms.timeoutMs < 500 || config.kms.timeoutMs > 30000) {
    issues.push("KMS_GATEWAY_TIMEOUT_MS must be an integer between 500 and 30000.");
  }
  if (!["json", "sqlite", "postgres"].includes(config.storage.provider)) {
    issues.push("STORAGE_PROVIDER must be one of json, sqlite, or postgres.");
  }
  if (config.storage.provider === "sqlite" && !config.storage.sqlitePath) {
    issues.push("SQLITE_PATH is required when STORAGE_PROVIDER is sqlite.");
  }
  if (config.storage.provider === "postgres") {
    issues.push("postgres storage is planned but not available until the database dependency is approved and installed.");
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
  if (!Number.isInteger(config.refreshTokens.ttlDays) || config.refreshTokens.ttlDays < 1 || config.refreshTokens.ttlDays > 30) {
    issues.push("REFRESH_TOKEN_DAYS must be an integer between 1 and 30.");
  }
  if (config.refreshTokens.enabled && config.identityProvider.mode === "local") {
    issues.push("REFRESH_TOKENS_ENABLED requires IDENTITY_PROVIDER to be oidc or entra.");
  }
  if (!["local", "oidc", "entra"].includes(config.identityProvider.mode)) {
    issues.push("IDENTITY_PROVIDER must be one of local, oidc, or entra.");
  }
  if (config.identityProvider.mode !== "local" && (!config.identityProvider.issuer || !config.identityProvider.clientId)) {
    issues.push("OIDC_ISSUER and OIDC_CLIENT_ID are required for external identity providers.");
  }
  if (config.identityProvider.mode !== "local" && !config.identityProvider.redirectUris.length) {
    issues.push("OIDC_REDIRECT_URIS must include at least one exact callback URI for external identity providers.");
  }
  for (const redirectUri of config.identityProvider.redirectUris) {
    try {
      const parsed = new URL(redirectUri);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        issues.push("OIDC_REDIRECT_URIS entries must use http or https.");
      }
    } catch {
      issues.push("OIDC_REDIRECT_URIS entries must be absolute URLs.");
    }
  }
  if (config.identityProvider.mode === "entra" && !config.identityProvider.tenantId) {
    issues.push("ENTRA_TENANT_ID is required when IDENTITY_PROVIDER is entra.");
  }
  if (config.identityProvider.mode !== "local") {
    if (!config.identityProvider.groupClaim) issues.push("IDENTITY_GROUP_CLAIM is required for external identity providers.");
    if (!config.identityProvider.mfaClaim || !config.identityProvider.mfaRequiredValue) {
      issues.push("IDENTITY_MFA_CLAIM and IDENTITY_MFA_REQUIRED_VALUE are required for external identity providers.");
    }
    for (const [role, groupName] of Object.entries(config.identityProvider.roleMappings)) {
      if (!String(groupName || "").trim()) {
        issues.push(`IDENTITY_ROLE_${role} must map ${role} to a provider group.`);
      }
    }
  }
  if (config.integrations.siemWebhookUrl && config.isProduction && !config.integrations.siemWebhookSecret) {
    issues.push("SIEM_WEBHOOK_SECRET is required when SIEM_WEBHOOK_URL is set in production.");
  }
  if (config.integrations.siemWebhookUrl && config.isProduction && config.integrations.siemWebhookSecret && !config.integrations.siemWebhookKeyId) {
    issues.push("SIEM_WEBHOOK_KEY_ID is required when SIEM webhook signing is enabled in production.");
  }
  if (config.integrations.siemWebhookPreviousSecret && !config.integrations.siemWebhookPreviousKeyId) {
    issues.push("SIEM_WEBHOOK_PREVIOUS_KEY_ID is required when SIEM_WEBHOOK_PREVIOUS_SECRET is set.");
  }
  if (config.integrations.siemWebhookPreviousKeyId && !config.integrations.siemWebhookPreviousSecret) {
    issues.push("SIEM_WEBHOOK_PREVIOUS_SECRET is required when SIEM_WEBHOOK_PREVIOUS_KEY_ID is set.");
  }
  if (config.integrations.siemWebhookKeyId && config.integrations.siemWebhookPreviousKeyId && config.integrations.siemWebhookKeyId === config.integrations.siemWebhookPreviousKeyId) {
    issues.push("SIEM_WEBHOOK_KEY_ID and SIEM_WEBHOOK_PREVIOUS_KEY_ID must be different during rotation.");
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
  if (!Array.isArray(config.integrations.itsmAllowedStates) || !config.integrations.itsmAllowedStates.length) {
    issues.push("ITSM_ALLOWED_STATES must include at least one allowed provider state.");
  }
  return issues;
};
