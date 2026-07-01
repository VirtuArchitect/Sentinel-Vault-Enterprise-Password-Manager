import crypto from "node:crypto";
import { config } from "../config.mjs";

const supportedProviders = new Set(["local-root-key", "external-kms", "hsm"]);

const gatewayEnabled = () => config.kms.provider !== "local-root-key" && Boolean(config.kms.endpoint);

export const getKeyProviderStatus = () => ({
  provider: config.kms.provider,
  configured: config.kms.provider === "local-root-key" || Boolean(config.kms.keyId),
  keyId: config.kms.keyId || null,
  endpoint: config.kms.endpoint || null,
  mode: config.kms.provider === "local-root-key" ? "demo-local" : "external-envelope",
  signingMode: config.kms.provider === "local-root-key" ? "local-hmac" : (gatewayEnabled() ? "gateway-sign" : "envelope-reference-hmac"),
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

const signWithLocalKey = (purpose, value) => crypto
  .createHmac("sha256", deriveVaultKey())
  .update(`${purpose}:${String(value || "")}`, "utf8")
  .digest("base64url");

const parseGatewayResponse = async (response) => {
  let body = null;
  try {
    body = await response.json();
  } catch {
    throw new Error("KMS/HSM signing gateway did not return JSON");
  }
  if (!response.ok) {
    throw new Error(`KMS/HSM signing gateway returned HTTP ${response.status}`);
  }
  return body;
};

export const signWithKeyProvider = async (purpose, value) => {
  if (!gatewayEnabled()) return signWithLocalKey(purpose, value);

  const endpoint = config.kms.endpoint.replace(/\/$/, "");
  const response = await fetch(`${endpoint}/sign`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": "SentinelVault-KeyProvider/1.0"
    },
    signal: AbortSignal.timeout(config.kms.timeoutMs),
    body: JSON.stringify({
      keyId: config.kms.keyId,
      purpose,
      value: String(value || "")
    })
  });
  const signed = await parseGatewayResponse(response);
  if (signed.keyId && signed.keyId !== config.kms.keyId) {
    throw new Error("KMS/HSM signing gateway returned a mismatched key ID");
  }
  if (!/^[A-Za-z0-9_-]{32,}$/.test(String(signed.signature || ""))) {
    throw new Error("KMS/HSM signing gateway returned an invalid signature");
  }
  return String(signed.signature);
};
