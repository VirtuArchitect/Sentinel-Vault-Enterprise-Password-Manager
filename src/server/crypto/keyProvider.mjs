import crypto from "node:crypto";
import { config } from "../config.mjs";

const supportedProviders = new Set(["local-root-key", "external-kms", "hsm"]);

export const getKeyProviderStatus = () => ({
  provider: config.kms.provider,
  configured: config.kms.provider === "local-root-key" || Boolean(config.kms.keyId),
  keyId: config.kms.keyId || null,
  endpoint: config.kms.endpoint || null,
  mode: config.kms.provider === "local-root-key" ? "demo-local" : "external-envelope",
  supported: supportedProviders.has(config.kms.provider)
});

export const deriveVaultKey = () => {
  if (!supportedProviders.has(config.kms.provider)) {
    throw new Error(`Unsupported KMS_PROVIDER: ${config.kms.provider}`);
  }

  // External providers are modeled as envelope-key references until a provider SDK is approved.
  const keyMaterial = config.kms.provider === "local-root-key"
    ? config.vaultRootKey
    : `${config.kms.provider}:${config.kms.keyId}:${config.vaultRootKey}`;

  return crypto.scryptSync(keyMaterial, config.vaultKeySalt, 32);
};

export const signWithKeyProvider = (purpose, value) => crypto
  .createHmac("sha256", deriveVaultKey())
  .update(`${purpose}:${String(value || "")}`, "utf8")
  .digest("base64url");
