import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const issuer = String(args.get("--issuer") || process.env.OIDC_ISSUER || "").replace(/\/$/, "");
const clientId = String(args.get("--client-id") || process.env.OIDC_CLIENT_ID || "");
const idToken = String(args.get("--id-token") || process.env.OIDC_PREFLIGHT_ID_TOKEN || "");
const groupClaim = String(args.get("--group-claim") || process.env.IDENTITY_GROUP_CLAIM || "groups");
const mfaClaim = String(args.get("--mfa-claim") || process.env.IDENTITY_MFA_CLAIM || "amr");
const mfaRequiredValue = String(args.get("--mfa-required-value") || process.env.IDENTITY_MFA_REQUIRED_VALUE || "mfa");
const roleMappings = Object.fromEntries([
  ["SECURITY_ADMIN", args.get("--role-security-admin") || process.env.IDENTITY_ROLE_SECURITY_ADMIN || "Sentinel Vault Admins"],
  ["VAULT_OPERATOR", args.get("--role-vault-operator") || process.env.IDENTITY_ROLE_VAULT_OPERATOR || "Sentinel Vault Operators"],
  ["AUDITOR", args.get("--role-auditor") || process.env.IDENTITY_ROLE_AUDITOR || "Sentinel Vault Auditors"]
]);
const outputPath = args.get("--out") || "artifacts/identity/identity-provider-preflight.json";
const timeoutMs = Number(args.get("--timeout-ms") || 5000);

assert.ok(issuer, "--issuer or OIDC_ISSUER is required");
assert.ok(clientId, "--client-id or OIDC_CLIENT_ID is required");
assert.match(issuer, /^https?:\/\//i, "issuer must be an HTTP(S) URL for preflight");

const sha256 = (value) => crypto.createHash("sha256").update(String(value), "utf8").digest("base64url");
const claimValues = (value) => {
  if (Array.isArray(value)) return value.map(String);
  if (!value) return [];
  return [String(value)];
};
const parseJson = async (response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};
const base64urlJson = (value) => JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
const verifyRs256 = (signingInput, signature, jwk) => {
  const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
  return crypto.verify("RSA-SHA256", Buffer.from(signingInput), publicKey, Buffer.from(signature, "base64url"));
};

const discoveryResponse = await fetch(`${issuer}/.well-known/openid-configuration`, {
  headers: { Accept: "application/json", "User-Agent": "SentinelVault-Identity-Preflight/1.0" },
  signal: AbortSignal.timeout(timeoutMs)
});
const metadata = await parseJson(discoveryResponse);
const jwksUri = metadata?.jwks_uri || "";

let jwksResponse = null;
let jwks = null;
if (jwksUri) {
  jwksResponse = await fetch(jwksUri, {
    headers: { Accept: "application/json", "User-Agent": "SentinelVault-Identity-Preflight/1.0" },
    signal: AbortSignal.timeout(timeoutMs)
  });
  jwks = await parseJson(jwksResponse);
}

let token = null;
if (idToken) {
  const parts = idToken.split(".");
  assert.equal(parts.length, 3, "ID token must be a compact JWT");
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = base64urlJson(encodedHeader);
  const claims = base64urlJson(encodedPayload);
  const jwk = jwks?.keys?.find((candidate) => candidate.kid === header.kid);
  const groups = claimValues(claims[groupClaim]);
  const mfaValues = claimValues(claims[mfaClaim]);
  const mappedRoles = Object.entries(roleMappings)
    .filter(([, groupName]) => groups.includes(groupName))
    .map(([role]) => role);

  token = {
    header: {
      alg: header.alg || null,
      kidHash: header.kid ? sha256(header.kid) : null
    },
    claims: {
      issuer: claims.iss || null,
      subjectHash: claims.sub ? sha256(claims.sub) : null,
      emailHash: (claims.email || claims.preferred_username || claims.upn) ? sha256(claims.email || claims.preferred_username || claims.upn) : null,
      audienceHashes: claimValues(claims.aud).map(sha256),
      expiresAt: claims.exp ? new Date(Number(claims.exp) * 1000).toISOString() : null,
      groupCount: groups.length,
      groupHashes: groups.map(sha256),
      mfaValues,
      mappedRoles
    },
    checks: {
      algRs256: header.alg === "RS256",
      signingKeyFound: Boolean(jwk),
      signatureValid: Boolean(jwk) && verifyRs256(`${encodedHeader}.${encodedPayload}`, encodedSignature, jwk),
      issuerMatches: claims.iss === issuer,
      audienceIncludesClient: claimValues(claims.aud).includes(clientId),
      expiryValid: Number(claims.exp || 0) > Math.floor(Date.now() / 1000),
      notBeforeValid: !claims.nbf || Number(claims.nbf) <= Math.floor(Date.now() / 1000) + 60,
      mfaClaimPresent: mfaValues.includes(mfaRequiredValue),
      roleMappingPresent: mappedRoles.length > 0
    }
  };
}

const evidence = {
  format: "sentinel-identity-provider-preflight-v1",
  checkedAt: new Date().toISOString(),
  issuer,
  clientIdHash: sha256(clientId),
  discovery: {
    status: discoveryResponse.status,
    ok: discoveryResponse.ok,
    issuer: metadata?.issuer || null,
    authorizationEndpointPresent: Boolean(metadata?.authorization_endpoint),
    tokenEndpointPresent: Boolean(metadata?.token_endpoint),
    jwksUriHost: jwksUri ? new URL(jwksUri).host : null,
    responseTypesSupported: metadata?.response_types_supported || []
  },
  jwks: {
    status: jwksResponse?.status || null,
    ok: jwksResponse?.ok || false,
    keyCount: jwks?.keys?.length || 0,
    rs256KeyCount: jwks?.keys?.filter((key) => key.kty === "RSA" && (!key.alg || key.alg === "RS256")).length || 0
  },
  token,
  roleMappings: Object.fromEntries(Object.entries(roleMappings).map(([role, group]) => [role, sha256(group)])),
  checks: {
    discoveryReachable: discoveryResponse.ok,
    issuerMatchesDiscovery: metadata?.issuer === issuer,
    authorizationEndpointPresent: Boolean(metadata?.authorization_endpoint),
    tokenEndpointPresent: Boolean(metadata?.token_endpoint),
    jwksReachable: jwksResponse?.ok === true,
    rs256KeyAvailable: (jwks?.keys?.filter((key) => key.kty === "RSA" && (!key.alg || key.alg === "RS256")).length || 0) > 0,
    idTokenValidated: token ? Object.values(token.checks).every(Boolean) : true,
    redactedOutput: true
  }
};

evidence.checks.redactedOutput =
  JSON.stringify(evidence).includes(idToken) === false &&
  JSON.stringify(evidence).includes(clientId) === false;

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));

const failed = Object.entries(evidence.checks).filter(([, passed]) => !passed);
if (failed.length) {
  console.error(JSON.stringify(evidence, null, 2));
  throw new Error(`Identity provider preflight failed: ${failed.map(([name]) => name).join(", ")}`);
}

console.log(`Identity provider preflight evidence written: ${outputPath}`);
