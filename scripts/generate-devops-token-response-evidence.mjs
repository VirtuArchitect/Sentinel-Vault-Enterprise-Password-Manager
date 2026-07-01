import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const outputPath = args.get("--out") || "artifacts/integrations/devops-token-response-evidence.json";
const preflightPath = args.get("--preflight") || "artifacts/integrations/devops-token-response-evidence.json";
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const preflight = existsSync(preflightPath) ? readJson(preflightPath) : null;

const evidence = {
  format: "sentinel-devops-token-response-preflight-v1",
  status: args.get("--status") || preflight?.status || "planned",
  environment: args.get("--environment") || preflight?.environment || "replace-with-environment",
  owner: args.get("--owner") || preflight?.owner || "replace-with-owner",
  checkedAt: args.get("--checked-at") || preflight?.checkedAt || "YYYY-MM-DDTHH:mm:ssZ",
  target: {
    endpointHost: args.get("--endpoint-host") || preflight?.target?.endpointHost || "replace-with-host",
    secretId: args.get("--secret-id") || preflight?.target?.secretId || "replace-with-secret-id",
    blockedSecretId: args.get("--blocked-secret-id") || preflight?.target?.blockedSecretId || "replace-with-out-of-scope-secret-id"
  },
  tokenFingerprints: {
    revokedTokenSha256: args.get("--revoked-token-sha256") || preflight?.tokenFingerprints?.revokedTokenSha256 || "replace-with-sha256-base64url",
    replacementTokenSha256: args.get("--replacement-token-sha256") || preflight?.tokenFingerprints?.replacementTokenSha256 || "replace-with-sha256-base64url"
  },
  checks: {
    revokedTokenRejected: args.get("--revoked-token-rejected") === "true" || preflight?.checks?.revokedTokenRejected === true,
    replacementTokenAccepted: args.get("--replacement-token-accepted") === "true" || preflight?.checks?.replacementTokenAccepted === true,
    replacementScopeEnforced: args.get("--replacement-scope-enforced") === "true" || preflight?.checks?.replacementScopeEnforced === true,
    redactedOutput: args.get("--redacted-output") === "true" || preflight?.checks?.redactedOutput === true
  },
  results: {
    revokedTokenStatus: Number(args.get("--revoked-token-status") || preflight?.results?.revokedTokenStatus || 0),
    replacementTokenStatus: Number(args.get("--replacement-token-status") || preflight?.results?.replacementTokenStatus || 0),
    blockedScopeStatus: args.has("--blocked-scope-status") ? Number(args.get("--blocked-scope-status")) : preflight?.results?.blockedScopeStatus ?? null,
    replacementReturnedValueSha256: args.get("--replacement-returned-value-sha256") || preflight?.results?.replacementReturnedValueSha256 || null
  },
  approvals: {
    securityReviewer: args.get("--security-reviewer") || preflight?.approvals?.securityReviewer || "replace-with-reviewer",
    devopsOwner: args.get("--devops-owner") || preflight?.approvals?.devopsOwner || "replace-with-owner",
    operationsOwner: args.get("--operations-owner") || preflight?.approvals?.operationsOwner || "replace-with-owner",
    incidentOrChangeTicket: args.get("--incident-or-change-ticket") || preflight?.approvals?.incidentOrChangeTicket || "replace-with-ticket"
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`DevOps token response evidence written: ${outputPath}`);
