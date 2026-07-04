import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const outputPath = args.get("--out") || "artifacts/integrations/connector-certification-evidence.json";
const preflightPath = args.get("--preflight") || "artifacts/integrations/connector-live-preflight.json";
const status = args.get("--status") || "pilot";
const connector = args.get("--connector") || "siem-or-itsm-or-devops";
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const preflight = existsSync(preflightPath) ? readJson(preflightPath) : null;
const connectors = preflight?.connectors || {};
const selected = connector === "siem" ? connectors.siem : connector === "itsm" ? connectors.itsm : connector === "devops" ? connectors.devops : connectors.siem || connectors.itsm || connectors.devops || {};
const preflightChecks = preflight?.checks || {};
const preflightConnectorNames = Object.keys(connectors);
const today = new Date().toISOString().slice(0, 10);
const checkStatus = (argName, fallback) => {
  const value = args.get(argName) || fallback;
  const allowed = new Set(["passed", "failed", "planned", "not-applicable"]);
  if (!allowed.has(value)) {
    throw new Error(`${argName} must be passed, failed, planned, or not-applicable`);
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
const redactedOutput = preflight?.checks?.redactedOutput !== false;
const preflightValidated = Boolean(preflight) && Object.values(preflightChecks).every((value) => value === true);

const evidence = {
  format: "sentinel-connector-certification-evidence-v1",
  connector,
  environment: args.get("--environment") || "replace-with-environment",
  status,
  owner: args.get("--owner") || "replace-with-owner",
  supportContact: args.get("--support-contact") || "replace-with-support-contact",
  targetSystem: args.get("--target-system") || selected.endpointHost || "replace-with-target-system",
  classification: args.get("--classification") || "replace-with-classification",
  networkPath: args.get("--network-path") || "replace-with-network-path",
  tlsPolicy: args.get("--tls-policy") || "TLS 1.2+ required with trusted certificate chain",
  authMethod: args.get("--auth-method") || (connector === "siem" ? "HMAC signed webhook" : "replace-with-auth-method"),
  credentialStorage: args.get("--credential-storage") || "replace-with-storage-location",
  leastPrivilegeScopes: (args.get("--least-privilege-scopes") || "replace-with-scope").split(",").map((scope) => scope.trim()).filter(Boolean),
  livePreflight: {
    reportPath: preflight ? path.resolve(preflightPath) : "replace-with-connector-live-preflight.json",
    format: preflight?.format || "sentinel-enterprise-connector-live-preflight-v1",
    checkedAt: preflight?.checkedAt || "YYYY-MM-DDTHH:mm:ssZ",
    validated: preflightValidated,
    connectorTypes: preflightConnectorNames,
    checkCount: Object.keys(preflightChecks).length,
    checks: preflightChecks,
    selectedConnector: connector,
    selectedEndpointHost: selected.endpointHost || "replace-with-target-system"
  },
  replayProtection: {
    implemented: asBool(args.get("--replay-protection-implemented"), connector === "siem" ? connectors.siem?.signed === true || preflight?.checks?.siemReplayEvidencePresent === true : true),
    windowSeconds: Number(args.get("--replay-window-seconds") || connectors.siem?.replayWindowSeconds || 300),
    dedupeStore: args.get("--dedupe-store") || "replace-with-dedupe-store"
  },
  failureModes: {
    receiverOutage: args.get("--receiver-outage") || "replace-with-behavior",
    rateLimit: args.get("--rate-limit") || "replace-with-behavior",
    malformedPayload: args.get("--malformed-payload") || "replace-with-behavior"
  },
  redactionEvidence: {
    logsReviewed: asBool(args.get("--logs-reviewed"), redactedOutput),
    dashboardsReviewed: asBool(args.get("--dashboards-reviewed"), false),
    ticketsReviewed: asBool(args.get("--tickets-reviewed"), connector === "itsm" ? Boolean(connectors.itsm) : false),
    secretValuesFound: asBool(args.get("--secret-values-found"), !redactedOutput)
  },
  testResults: {
    nonProductionTestDate: args.get("--non-production-test-date") || today,
    deliveryTest: checkStatus("--delivery-test", preflight?.checks?.siemDeliveryAccepted === true || preflight?.checks?.itsmTicketLookupPassed === true ? "passed" : "planned"),
    authFailureTest: checkStatus("--auth-failure-test", "planned"),
    retryTest: checkStatus("--retry-test", "planned"),
    replayTest: checkStatus("--replay-test", preflight?.checks?.siemReplayEvidencePresent === true ? "passed" : "planned"),
    redactionTest: checkStatus("--redaction-test", redactedOutput ? "passed" : "failed")
  },
  rollback: {
    disableProcedure: args.get("--disable-procedure") || "replace-with-procedure",
    tested: asBool(args.get("--rollback-tested"), false)
  },
  approvals: {
    connectorOwner: args.get("--connector-owner") || "replace-with-owner",
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    operationsReviewer: args.get("--operations-reviewer") || "replace-with-reviewer"
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Connector certification evidence written: ${outputPath}`);
