import crypto from "node:crypto";
import { config } from "../config.mjs";
import { store } from "../data/store.mjs";

const providerNames = {
  local: "Local demo identity",
  oidc: "OpenID Connect",
  entra: "Microsoft Entra ID"
};

const base64urlJson = (value) => JSON.parse(Buffer.from(value, "base64url").toString("utf8"));

const claimValues = (value) => {
  if (Array.isArray(value)) return value.map(String);
  if (!value) return [];
  return [String(value)];
};

const discoverJwksUri = async (issuer) => {
  const discoveryUrl = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const response = await fetch(discoveryUrl);
  if (!response.ok) throw new Error(`OIDC discovery failed with HTTP ${response.status}`);
  const metadata = await response.json();
  if (metadata.issuer && metadata.issuer !== issuer) throw new Error("OIDC discovery issuer mismatch");
  if (!metadata.jwks_uri) throw new Error("OIDC discovery did not return jwks_uri");
  return metadata.jwks_uri;
};

const verifyRs256 = (signingInput, signature, jwk) => {
  const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
  return crypto.verify("RSA-SHA256", Buffer.from(signingInput), publicKey, Buffer.from(signature, "base64url"));
};

const roleFromGroups = (groups) => {
  const groupSet = new Set(groups);
  for (const [role, groupName] of Object.entries(config.identityProvider.roleMappings)) {
    if (groupSet.has(groupName)) return role;
  }
  return null;
};

const emailFromClaims = (claims) => claims.email || claims.preferred_username || claims.upn || claims.unique_name;

export const validateExternalIdentityToken = async (idToken) => {
  if (config.identityProvider.mode === "local") {
    throw new Error("External identity login is disabled when IDENTITY_PROVIDER=local");
  }
  const parts = String(idToken || "").split(".");
  if (parts.length !== 3) throw new Error("ID token must be a compact JWT");
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = base64urlJson(encodedHeader);
  const claims = base64urlJson(encodedPayload);

  if (header.alg !== "RS256") throw new Error("Only RS256 identity tokens are supported");
  if (claims.iss !== config.identityProvider.issuer) throw new Error("Identity token issuer mismatch");
  if (!claimValues(claims.aud).includes(config.identityProvider.clientId)) throw new Error("Identity token audience mismatch");
  if (Number(claims.exp || 0) <= Math.floor(Date.now() / 1000)) throw new Error("Identity token has expired");
  if (claims.nbf && Number(claims.nbf) > Math.floor(Date.now() / 1000) + 60) throw new Error("Identity token is not valid yet");

  const jwksUri = await discoverJwksUri(config.identityProvider.issuer);
  const jwksResponse = await fetch(jwksUri);
  if (!jwksResponse.ok) throw new Error(`JWKS fetch failed with HTTP ${jwksResponse.status}`);
  const jwks = await jwksResponse.json();
  const jwk = jwks.keys?.find((candidate) => candidate.kid === header.kid);
  if (!jwk) throw new Error("Signing key was not found in JWKS");
  if (!verifyRs256(`${encodedHeader}.${encodedPayload}`, encodedSignature, jwk)) {
    throw new Error("Identity token signature verification failed");
  }

  const mfaValues = claimValues(claims[config.identityProvider.mfaClaim]);
  if (!mfaValues.includes(config.identityProvider.mfaRequiredValue)) {
    throw new Error("Required MFA claim was not present");
  }

  const groups = claimValues(claims[config.identityProvider.groupClaim]);
  const mappedRole = roleFromGroups(groups);
  if (!mappedRole) throw new Error("Identity token groups do not map to a Sentinel Vault role");

  const email = emailFromClaims(claims);
  const user = store.findUserByEmail(email);
  if (!user) throw new Error("Federated user is not provisioned locally");
  if (user.enabled === false) throw new Error("Federated user is disabled locally");
  if (user.role !== mappedRole) throw new Error("Federated role does not match the local user role");

  return {
    user,
    claims: {
      issuer: claims.iss,
      subject: claims.sub,
      email,
      groups,
      mfa: mfaValues,
      role: mappedRole
    }
  };
};

export const getIdentityStatus = () => {
  const provider = config.identityProvider;
  const external = provider.mode !== "local";
  const configured = provider.mode === "local" || Boolean(provider.issuer && provider.clientId);

  return {
    mode: provider.mode,
    name: providerNames[provider.mode] || provider.mode,
    configured,
    issuer: external ? provider.issuer : "",
    clientId: external ? provider.clientId : "",
    tenantId: provider.mode === "entra" ? provider.tenantId : "",
    groupClaim: provider.groupClaim,
    mfaClaim: provider.mfaClaim,
    mfaRequiredValue: provider.mfaRequiredValue,
    mfaSource: external ? "identity_provider" : "demo_user_seed",
    roleMapping: provider.roleMappings
  };
};
