import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const outputPath = args.get("--out") || "artifacts/identity/identity-provider-evidence.json";
const preflightPath = args.get("--preflight") || "artifacts/identity/identity-provider-preflight.json";
const status = args.get("--status") || "planned";
const provider = args.get("--provider") || "entra";
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const preflight = existsSync(preflightPath) ? readJson(preflightPath) : null;
const checks = preflight?.checks || {};
const tokenChecks = preflight?.token?.checks || {};
const statusFrom = (value) => value === true ? "passed" : value === false ? "failed" : "planned";
const checkStatus = (argName, fallback) => {
  const value = args.get(argName) || fallback;
  const allowed = new Set(["planned", "passed", "failed", "not-applicable"]);
  if (!allowed.has(value)) {
    throw new Error(`${argName} must be planned, passed, failed, or not-applicable`);
  }
  return value;
};
const asBool = (value, fallback) => {
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  return fallback;
};

const issuer = args.get("--issuer") || preflight?.issuer || "https://login.microsoftonline.com/replace-with-tenant-id/v2.0";
const tenantId = args.get("--tenant-id") || (provider === "entra" ? issuer.match(/login\.microsoftonline\.com\/([^/]+)/i)?.[1] : "") || "replace-with-tenant-id";
const clientId = args.get("--client-id") || "replace-with-client-id";
const jwksUri = args.get("--jwks-uri") || (preflight?.discovery?.jwksUriHost ? `https://${preflight.discovery.jwksUriHost}/discovery/v2.0/keys` : "https://login.microsoftonline.com/replace-with-tenant-id/discovery/v2.0/keys");

const evidence = {
  format: "sentinel-identity-provider-evidence-v1",
  status,
  provider,
  environment: args.get("--environment") || "replace-with-environment",
  issuer,
  clientId,
  tenantId,
  jwksUri,
  audience: args.get("--audience") || clientId,
  claims: {
    subject: args.get("--subject-claim") || "sub",
    groups: args.get("--groups-claim") || "groups",
    mfa: args.get("--mfa-claim") || "amr",
    mfaRequiredValue: args.get("--mfa-required-value") || "mfa"
  },
  roleMappings: {
    SECURITY_ADMIN: args.get("--role-security-admin") || "Sentinel Vault Admins",
    VAULT_OPERATOR: args.get("--role-vault-operator") || "Sentinel Vault Operators",
    AUDITOR: args.get("--role-auditor") || "Sentinel Vault Auditors"
  },
  checks: {
    issuerDiscovery: checkStatus("--issuer-discovery", statusFrom(checks.discoveryReachable && checks.issuerMatchesDiscovery)),
    jwksReachable: checkStatus("--jwks-reachable", statusFrom(checks.jwksReachable && checks.rs256KeyAvailable)),
    audienceValidation: checkStatus("--audience-validation", statusFrom(tokenChecks.audienceIncludesClient)),
    signatureValidation: checkStatus("--signature-validation", statusFrom(tokenChecks.signatureValid && tokenChecks.algRs256 && tokenChecks.signingKeyFound)),
    expiryValidation: checkStatus("--expiry-validation", statusFrom(tokenChecks.expiryValid && tokenChecks.notBeforeValid)),
    mfaClaimValidation: checkStatus("--mfa-claim-validation", statusFrom(tokenChecks.mfaClaimPresent)),
    roleMappingValidation: checkStatus("--role-mapping-validation", statusFrom(tokenChecks.roleMappingPresent)),
    logoutRevocation: checkStatus("--logout-revocation", "planned")
  },
  rollback: {
    disableProcedure: args.get("--disable-procedure") || "Set IDENTITY_PROVIDER=local and restart the console in a controlled break-glass window.",
    tested: asBool(args.get("--rollback-tested"), false)
  },
  approvals: {
    identityOwner: args.get("--identity-owner") || "replace-with-owner",
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    changeTicket: args.get("--change-ticket") || "replace-with-ticket"
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Identity provider evidence written: ${outputPath}`);
