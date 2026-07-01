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
const frequencies = new Set(["per-release", "monthly", "quarterly"]);
const outputPath = args.get("--out") || "artifacts/security/tenant-isolation-evidence.json";
const reportPath = args.get("--report") || "artifacts/security/tenant-isolation-tests.json";
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
const normalizeStatus = (value) => {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (["passed", "pass", "blocked", "denied", "rejected", "forbidden"].includes(normalized)) {
    return "passed";
  }
  if (["failed", "fail", "allowed", "leaked"].includes(normalized)) {
    return "failed";
  }
  if (["not-applicable", "not_applicable", "n/a", "skipped"].includes(normalized)) {
    return "not-applicable";
  }
  return "planned";
};

const report = existsSync(reportPath) ? readJson(reportPath) : null;
const tests = Array.isArray(report)
  ? report
  : Array.isArray(report?.negativeTests)
    ? report.negativeTests
    : [];
const scope = report?.scope || {};
const testByName = new Map(tests.map((entry) => [String(entry.name || entry.test || entry.operation || "").trim(), entry]));
const statusFor = (name) => {
  const entry = testByName.get(name);
  return normalizeStatus(entry?.status || entry?.result || entry?.outcome);
};
const samplePath = args.get("--samples");
const sampleText = samplePath && existsSync(samplePath) && !statSync(samplePath).isDirectory() ? readText(samplePath) : "";
const combinedText = `${report ? JSON.stringify(report) : ""}\n${sampleText}`;
const secretValuesFound = /secret(Value)?\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[^"',\s]{8,}|Passw0rd!/i.test(combinedText);
const sessionTokensFound = /bearer\s+(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}|session[_-]?token\s*[:=]\s*["']?(?!\[REDACTED\]|redacted)[A-Za-z0-9._-]{12,}/i.test(combinedText);

const evidence = {
  format: "sentinel-tenant-isolation-evidence-v1",
  status,
  environment: args.get("--environment") || "replace-with-environment",
  testedAt: args.get("--tested-at") || report?.testedAt || (status === "planned" ? "YYYY-MM-DDTHH:mm:ssZ" : toIso()),
  scope: {
    tenantCount: Number(args.get("--tenant-count") || scope.tenantCount || 0),
    vaultCount: Number(args.get("--vault-count") || scope.vaultCount || 0),
    userCount: Number(args.get("--user-count") || scope.userCount || 0),
    sampledTenantPairs: Number(args.get("--sampled-tenant-pairs") || scope.sampledTenantPairs || 0),
    testCadence: args.get("--test-cadence") || scope.testCadence || "per-release"
  },
  controls: {
    serviceLayerObjectChecks: argStatus("--service-layer-object-checks", "planned"),
    routeRbacChecks: argStatus("--route-rbac-checks", "planned"),
    consolePayloadFiltering: argStatus("--console-payload-filtering", "planned"),
    offlineCacheScoping: argStatus("--offline-cache-scoping", "planned"),
    adminMetadataExportRestricted: argStatus("--admin-metadata-export-restricted", "planned"),
    jitGrantTenantBoundary: argStatus("--jit-grant-tenant-boundary", "planned")
  },
  negativeTests: {
    reveal: argStatus("--reveal", statusFor("reveal")),
    update: argStatus("--update", statusFor("update")),
    delete: argStatus("--delete", statusFor("delete")),
    restore: argStatus("--restore", statusFor("restore")),
    versionRestore: argStatus("--version-restore", statusFor("versionRestore")),
    rotate: argStatus("--rotate", statusFor("rotate")),
    share: argStatus("--share", statusFor("share")),
    approveAccess: argStatus("--approve-access", statusFor("approveAccess")),
    denyAccess: argStatus("--deny-access", statusFor("denyAccess")),
    revokeAccess: argStatus("--revoke-access", statusFor("revokeAccess")),
    consoleVaultEnumeration: argStatus("--console-vault-enumeration", statusFor("consoleVaultEnumeration")),
    offlineCacheEnumeration: argStatus("--offline-cache-enumeration", statusFor("offlineCacheEnumeration"))
  },
  redaction: {
    secretValuesFound: asBool(args.get("--secret-values-found"), secretValuesFound),
    sessionTokensFound: asBool(args.get("--session-tokens-found"), sessionTokensFound),
    tenantIdentifiersScoped: argStatus("--tenant-identifiers-scoped", "planned")
  },
  approvals: {
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    operationsOwner: args.get("--operations-owner") || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || "replace-with-ticket"
  }
};

assert.ok(frequencies.has(evidence.scope.testCadence), "test-cadence is unsupported");
for (const name of ["tenantCount", "vaultCount", "userCount", "sampledTenantPairs"]) {
  assert.ok(Number.isInteger(evidence.scope[name]) && evidence.scope[name] >= 0, `${name} must be a non-negative integer`);
}
assert.ok(evidence.scope.sampledTenantPairs <= evidence.scope.tenantCount * Math.max(evidence.scope.tenantCount - 1, 0), "sampled-tenant-pairs exceeds possible directed tenant pairs");

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Tenant isolation evidence written: ${outputPath}`);
