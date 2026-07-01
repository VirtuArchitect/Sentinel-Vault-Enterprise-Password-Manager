import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const provider = args.get("--provider") || process.env.KMS_PROVIDER || "external-kms";
const endpoint = args.get("--endpoint") || process.env.KMS_ENDPOINT || "";
const keyId = args.get("--key-id") || process.env.KMS_KEY_ID || "";
const outputPath = args.get("--out") || "artifacts/security/kms-hsm-gateway-preflight.json";
const allowedProviders = new Set(["external-kms", "hsm"]);

assert.ok(allowedProviders.has(provider), "KMS gateway preflight requires --provider external-kms or hsm");
assert.ok(endpoint, "KMS gateway preflight requires --endpoint or KMS_ENDPOINT");
assert.ok(keyId, "KMS gateway preflight requires --key-id or KMS_KEY_ID");
assert.equal(typeof fetch, "function", "KMS gateway preflight requires a Node.js runtime with fetch support");

const baseUrl = endpoint.replace(/\/$/, "");
const nonce = crypto.randomBytes(18).toString("base64url");
const purpose = "sentinel-vault-preflight";
const payload = `${purpose}:${keyId}:${nonce}`;
const checkedAt = new Date().toISOString();
const timeoutMs = Number(args.get("--timeout-ms") || process.env.KMS_PREFLIGHT_TIMEOUT_MS || 5000);

const parseJsonResponse = async (response, label) => {
  let body = null;
  try {
    body = await response.json();
  } catch {
    throw new Error(`${label} did not return JSON`);
  }
  if (!response.ok) {
    throw new Error(`${label} returned HTTP ${response.status}: ${JSON.stringify(body)}`);
  }
  return body;
};

const statusResponse = await fetch(`${baseUrl}/status?keyId=${encodeURIComponent(keyId)}`, {
  headers: { Accept: "application/json", "User-Agent": "SentinelVault-KMS-Preflight/1.0" },
  signal: AbortSignal.timeout(timeoutMs)
});
const status = await parseJsonResponse(statusResponse, "KMS/HSM status endpoint");

const signResponse = await fetch(`${baseUrl}/sign`, {
  method: "POST",
  headers: {
    Accept: "application/json",
    "Content-Type": "application/json",
    "User-Agent": "SentinelVault-KMS-Preflight/1.0"
  },
  signal: AbortSignal.timeout(timeoutMs),
  body: JSON.stringify({ keyId, purpose, value: payload, nonce })
});
const signed = await parseJsonResponse(signResponse, "KMS/HSM sign endpoint");

const signaturePattern = /^[A-Za-z0-9_-]{32,}$/;
const operations = new Set(status.operations || []);
const checks = {
  statusEndpointReachable: Boolean(status),
  providerMatches: status.provider === provider,
  keyIdMatches: status.keyId === keyId,
  keyExportDisabled: status.keyExportDisabled === true,
  auditLoggingEnabled: status.auditLoggingEnabled === true,
  signOperationAdvertised: operations.has("sign") || status.signing === true,
  signEndpointReachable: Boolean(signed),
  signatureReturned: signaturePattern.test(String(signed.signature || "")),
  signatureKeyMatches: !signed.keyId || signed.keyId === keyId,
  signatureAlgorithmRecorded: Boolean(signed.algorithm)
};

const evidence = {
  format: "sentinel-kms-hsm-gateway-preflight-v1",
  checkedAt,
  provider,
  endpoint: baseUrl,
  keyId,
  nonceHash: crypto.createHash("sha256").update(nonce, "utf8").digest("base64url"),
  status: {
    provider: status.provider || null,
    keyId: status.keyId || null,
    keyVersion: status.keyVersion || null,
    keyExportDisabled: status.keyExportDisabled === true,
    auditLoggingEnabled: status.auditLoggingEnabled === true,
    operations: status.operations || []
  },
  signature: {
    keyId: signed.keyId || null,
    algorithm: signed.algorithm || null,
    signatureHash: signed.signature ? crypto.createHash("sha256").update(String(signed.signature), "utf8").digest("base64url") : null
  },
  checks
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));

const failed = Object.entries(checks).filter(([, passed]) => !passed);
if (failed.length) {
  console.error(JSON.stringify(evidence, null, 2));
  throw new Error(`KMS/HSM gateway preflight failed: ${failed.map(([name]) => name).join(", ")}`);
}

console.log(`KMS/HSM gateway preflight evidence written: ${outputPath}`);
