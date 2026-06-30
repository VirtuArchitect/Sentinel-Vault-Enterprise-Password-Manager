import { config } from "../config.mjs";

const providerNames = {
  local: "Local demo identity",
  oidc: "OpenID Connect",
  entra: "Microsoft Entra ID"
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
    mfaSource: external ? "identity_provider" : "demo_user_seed",
    roleMapping: {
      SECURITY_ADMIN: "Sentinel Vault Admins",
      VAULT_OPERATOR: "Sentinel Vault Operators",
      AUDITOR: "Sentinel Vault Auditors"
    }
  };
};
