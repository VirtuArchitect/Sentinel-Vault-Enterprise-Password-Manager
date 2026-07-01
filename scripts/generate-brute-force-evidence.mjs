import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const checkStatuses = new Set(["planned", "passed", "failed", "not-applicable"]);
const outputPath = args.get("--out") || "artifacts/security/brute-force-evidence.json";
const reportPath = args.get("--report") || "artifacts/security/brute-force-drill.json";
const status = args.get("--status") || "planned";

assert.ok(allowedStatuses.has(status), "status must be planned, pilot, production, or retired");

const toIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const readText = (filePath) => readFileSync(filePath, "utf8").replace(/^\uFEFF/, "");
const argStatus = (name, fallback) => {
  const value = args.get(name) || fallback;
  assert.ok(checkStatuses.has(value), `${name} must be planned, passed, failed, or not-applicable`);
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

const report = existsSync(reportPath) ? readJson(reportPath) : null;
const events = Array.isArray(report)
  ? report
  : Array.isArray(report?.events)
    ? report.events
    : [];
const failedLoginLimit = Number(args.get("--failed-login-limit") || report?.policy?.failedLoginLimit || 5);
const lockoutMinutes = Number(args.get("--lockout-minutes") || report?.policy?.lockoutMinutes || 15);
assert.ok(Number.isInteger(failedLoginLimit) && failedLoginLimit >= 1 && failedLoginLimit <= 25, "failed-login-limit must be 1-25");
assert.ok(Number.isInteger(lockoutMinutes) && lockoutMinutes >= 1 && lockoutMinutes <= 1440, "lockout-minutes must be 1-1440");

const eventText = report ? JSON.stringify(report) : "";
const samplePath = args.get("--samples");
const sampleText = samplePath && existsSync(samplePath) && !statSync(samplePath).isDirectory() ? readText(samplePath) : "";
const combinedText = `${eventText}\n${sampleText}`;
const normalize = (value) => String(value ?? "").trim().toLowerCase();
const failedAttemptsFromEvents = events.filter((event) => /fail|denied|invalid/.test(normalize(event.outcome || event.result || event.type))).length;
const lockedAccountsFromEvents = new Set(events
  .filter((event) => event.locked === true || /lock/.test(normalize(event.outcome || event.result || event.type)))
  .map((event) => event.account || event.userId || event.user || "unknown")).size;
const alertCountFromEvents = events.filter((event) => event.alert === true || /alert|incident|ticket/.test(normalize(event.outcome || event.result || event.type))).length;
const distinctIpsFromEvents = new Set(events
  .map((event) => event.sourceIp || event.sourceBucket || event.ipHash || event.ip)
  .filter(Boolean)).size;
const sampleCounts = report?.samples || {};

const passwordsFound = /password\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{6,}|Passw0rd!/i.test(combinedText);
const tokensFound = /bearer\s+(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}|token\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}/i.test(combinedText);
const rawIpsFound = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(combinedText);

const evidence = {
  format: "sentinel-brute-force-evidence-v1",
  status,
  environment: args.get("--environment") || "replace-with-environment",
  testedAt: args.get("--tested-at") || report?.testedAt || (status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : toIso()),
  appControls: {
    failedLoginLimit,
    lockoutMinutes,
    temporaryAccountLockout: argStatus("--temporary-account-lockout", "planned"),
    sessionInvalidationAfterLogout: argStatus("--session-invalidation-after-logout", "planned"),
    mfaClaimRequired: argStatus("--mfa-claim-required", "planned"),
    identityProviderPreflight: argStatus("--identity-provider-preflight", "planned")
  },
  networkControls: {
    edgeName: args.get("--edge-name") || "replace-with-waf-or-reverse-proxy",
    sourceIpPreserved: argStatus("--source-ip-preserved", "planned"),
    trustedProxyConfigured: argStatus("--trusted-proxy-configured", "planned"),
    perIpRateLimit: argStatus("--per-ip-rate-limit", "planned"),
    distributedAttackDetection: argStatus("--distributed-attack-detection", "planned"),
    geoOrAsnPolicy: argStatus("--geo-or-asn-policy", "planned"),
    wafOrReverseProxyLogging: argStatus("--waf-or-reverse-proxy-logging", "planned")
  },
  drills: {
    singleAccountLockout: argStatus("--single-account-lockout", "planned"),
    singleIpSpray: argStatus("--single-ip-spray", "planned"),
    distributedSpray: argStatus("--distributed-spray", "planned"),
    validUserAfterLockout: argStatus("--valid-user-after-lockout", "planned"),
    mfaRequiredAfterNewDevice: argStatus("--mfa-required-after-new-device", "planned")
  },
  samples: {
    failedAttempts: Number(args.get("--failed-attempts") || sampleCounts.failedAttempts || failedAttemptsFromEvents),
    distinctSourceIps: Number(args.get("--distinct-source-ips") || sampleCounts.distinctSourceIps || distinctIpsFromEvents),
    lockedAccounts: Number(args.get("--locked-accounts") || sampleCounts.lockedAccounts || lockedAccountsFromEvents),
    alertsGenerated: Number(args.get("--alerts-generated") || sampleCounts.alertsGenerated || alertCountFromEvents)
  },
  monitoring: {
    siemAlertCreated: argStatus("--siem-alert-created", "planned"),
    ticketOrIncidentCreated: argStatus("--ticket-or-incident-created", "planned"),
    dashboardReviewed: argStatus("--dashboard-reviewed", "planned"),
    falsePositiveDisposition: argStatus("--false-positive-disposition", "planned")
  },
  redaction: {
    passwordsFound: asBool(args.get("--passwords-found"), passwordsFound),
    tokensFound: asBool(args.get("--tokens-found"), tokensFound),
    sourceIpsScopedOrHashed: argStatus("--source-ips-scoped-or-hashed", rawIpsFound ? "planned" : "passed")
  },
  approvals: {
    identityOwner: args.get("--identity-owner") || "replace-with-owner",
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    operationsOwner: args.get("--operations-owner") || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || "replace-with-ticket"
  }
};

for (const name of ["failedAttempts", "distinctSourceIps", "lockedAccounts", "alertsGenerated"]) {
  assert.ok(Number.isInteger(evidence.samples[name]) && evidence.samples[name] >= 0, `${name} must be a non-negative integer`);
}

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Brute-force evidence written: ${outputPath}`);
