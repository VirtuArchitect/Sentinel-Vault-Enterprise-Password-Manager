import crypto from "node:crypto";
import { config } from "../config.mjs";
import { deriveVaultKey, getKeyProviderStatus, signWithKeyProvider } from "./keyProvider.mjs";

const vaultKey = deriveVaultKey();

export const encryptSecret = (value) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", vaultKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    value: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    alg: "AES-256-GCM",
    keyVersion: config.vaultKeyVersion
  };
};

export const fingerprintSecret = (value) => crypto
  .createHmac("sha256", vaultKey)
  .update(`fingerprint:${String(value || "")}`, "utf8")
  .digest("base64url");

export const decryptSecret = (payload) => {
  const decipher = crypto.createDecipheriv("aes-256-gcm", vaultKey, Buffer.from(payload.iv, "base64"));
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(payload.value, "base64")), decipher.final()]).toString("utf8");
};

export const secretStrength = (payload) => {
  try {
    return Math.min(100, Math.round(decryptSecret(payload).length * 4.6));
  } catch {
    return 0;
  }
};

export const getCryptoStatus = () => ({
  algorithm: "AES-256-GCM",
  keyDerivation: "scrypt",
  keyVersion: config.vaultKeyVersion,
  saltConfigured: Boolean(config.vaultKeySalt),
  kmsMode: config.kms.provider,
  keyProvider: getKeyProviderStatus()
});

export const signVaultValue = (purpose, value) => signWithKeyProvider(purpose, value);
