import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const baseUrl = String(args.get("--base-url") || process.env.SENTINEL_DEVOPS_BASE_URL || "").replace(/\/$/, "");
const secretId = String(args.get("--secret-id") || process.env.SENTINEL_DEVOPS_SECRET_ID || "").trim();
const revokedToken = String(args.get("--revoked-token") || process.env.SENTINEL_DEVOPS_REVOKED_TOKEN || "");
const replacementToken = String(args.get("--replacement-token") || process.env.SENTINEL_DEVOPS_REPLACEMENT_TOKEN || "");
const blockedSecretId = String(args.get("--blocked-secret-id") || process.env.SENTINEL_DEVOPS_BLOCKED_SECRET_ID || "").trim();
const outputPath = args.get("--out") || "artifacts/integrations/devops-token-response-evidence.json";
const timeoutMs = Number(args.get("--timeout-ms") || 5000);

assert.ok(baseUrl, "--base-url or SENTINEL_DEVOPS_BASE_URL is required");
assert.ok(secretId, "--secret-id or SENTINEL_DEVOPS_SECRET_ID is required");
assert.ok(revokedToken, "--revoked-token or SENTINEL_DEVOPS_REVOKED_TOKEN is required");
assert.ok(replacementToken, "--replacement-token or SENTINEL_DEVOPS_REPLACEMENT_TOKEN is required");
assert.notEqual(revokedToken, replacementToken, "revoked and replacement tokens must be different");

const sha256 = (value) => crypto.createHash("sha256").update(String(value), "utf8").digest("base64url");

const retrieveSecret = async (token, targetSecretId) => {
  const response = await fetch(`${baseUrl}/api/devops/secrets/${encodeURIComponent(targetSecretId)}`, {
    headers: {
      Accept: "application/json",
      "X-Sentinel-Service-Token": token,
      "User-Agent": "SentinelVault-DevOps-Token-Response-Preflight/1.0"
    },
    signal: AbortSignal.timeout(timeoutMs)
  });
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return {
    status: response.status,
    ok: response.ok,
    returnedSecretId: body?.id || null,
    returnedValue: body?.value || null
  };
};

const revokedCheck = await retrieveSecret(revokedToken, secretId);
const replacementCheck = await retrieveSecret(replacementToken, secretId);
const blockedScopeCheck = blockedSecretId ? await retrieveSecret(replacementToken, blockedSecretId) : null;

const evidence = {
  format: "sentinel-devops-token-response-preflight-v1",
  checkedAt: new Date().toISOString(),
  target: {
    endpointHost: new URL(baseUrl).host,
    secretId,
    blockedSecretId: blockedSecretId || null
  },
  tokenFingerprints: {
    revokedTokenSha256: sha256(revokedToken),
    replacementTokenSha256: sha256(replacementToken)
  },
  checks: {
    revokedTokenRejected: revokedCheck.status === 401 || revokedCheck.status === 403,
    replacementTokenAccepted: replacementCheck.ok === true && replacementCheck.returnedSecretId === secretId,
    replacementScopeEnforced: blockedScopeCheck ? blockedScopeCheck.status === 401 || blockedScopeCheck.status === 403 || blockedScopeCheck.status === 404 : true,
    redactedOutput: true
  },
  results: {
    revokedTokenStatus: revokedCheck.status,
    replacementTokenStatus: replacementCheck.status,
    blockedScopeStatus: blockedScopeCheck?.status ?? null,
    replacementReturnedValueSha256: replacementCheck.returnedValue ? sha256(replacementCheck.returnedValue) : null
  }
};

evidence.checks.redactedOutput =
  JSON.stringify(evidence).includes(revokedToken) === false &&
  JSON.stringify(evidence).includes(replacementToken) === false &&
  JSON.stringify(evidence).includes(replacementCheck.returnedValue || "\u0000") === false;

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));

const failed = Object.entries(evidence.checks).filter(([, passed]) => !passed);
if (failed.length) {
  console.error(JSON.stringify(evidence, null, 2));
  throw new Error(`DevOps token response preflight failed: ${failed.map(([name]) => name).join(", ")}`);
}

console.log(`DevOps token response evidence written: ${outputPath}`);
