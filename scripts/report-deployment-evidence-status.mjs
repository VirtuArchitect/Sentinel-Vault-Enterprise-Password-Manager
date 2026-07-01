import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const rootDir = path.resolve(import.meta.dirname, "..");
const bundlePath = args.get("--bundle") || cliArgs.find((arg) => !arg.startsWith("--")) || "docs/templates/deployment-evidence-bundle.json";
const outputPath = args.get("--out") || null;
const placeholder = /replace-with|YYYY-MM-DD|YYYY-MM-DDTHH:mm:ssZ/gi;

const validators = {
  connector: ["scripts/validate-connector-evidence.mjs"],
  itsmWorkNotes: ["scripts/validate-itsm-worknote-evidence.mjs"],
  devopsTokenResponse: ["scripts/validate-devops-token-response-evidence.mjs"],
  postgresHa: ["scripts/validate-postgres-ha-approval-evidence.mjs"],
  browserRollout: ["scripts/validate-browser-rollout-evidence.mjs"],
  nativeCompanion: ["scripts/validate-native-companion-evidence.mjs"],
  identityProvider: ["scripts/validate-identity-provider-evidence.mjs"],
  kmsHsm: ["scripts/validate-kms-hsm-evidence.mjs"],
  windowsInstallHardening: ["scripts/validate-windows-install-hardening-evidence.mjs"],
  sourceMigration: ["scripts/validate-source-migration-evidence.mjs"],
  tlsIis: ["scripts/validate-tls-iis-evidence.mjs"],
  pentestScope: ["scripts/validate-pentest-scope-evidence.mjs"],
  auditWorm: ["scripts/validate-audit-worm-evidence.mjs"],
  backupRecovery: ["scripts/validate-backup-recovery-evidence.mjs"],
  deviceTrust: ["scripts/validate-device-trust-evidence.mjs"],
  bruteForce: ["scripts/validate-brute-force-evidence.mjs"],
  tenantIsolation: ["scripts/validate-tenant-isolation-evidence.mjs"],
  siemReceiverRotation: ["scripts/validate-siem-receiver-rotation-evidence.mjs"],
  releaseAttestation: ["scripts/validate-release-attestation-evidence.mjs"],
  sast: ["scripts/validate-sast-evidence.mjs"],
  logRedaction: ["scripts/validate-log-redaction-evidence.mjs"]
};

const artifactFormats = {
  windowsRelease: "sentinel-windows-release-evidence-v1",
  storageMigration: "sentinel-storage-migration-evidence-v1",
  releaseProvenance: "sentinel-release-provenance-v1"
};

const resolveEvidencePath = (candidate) => {
  const bundleRelative = path.resolve(path.dirname(path.resolve(bundlePath)), candidate);
  if (existsSync(bundleRelative)) return bundleRelative;
  return path.resolve(rootDir, candidate);
};

const parseJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

const countPlaceholders = (value) => {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return [...text.matchAll(placeholder)].length;
};

const collectStatuses = (value, prefix = "") => {
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, child]) => {
    const name = prefix ? `${prefix}.${key}` : key;
    if (typeof child === "string" && /^(planned|not-run|pending|failed|fail|replace-with|YYYY-MM-DD)/i.test(child)) {
      return [{ field: name, value: child }];
    }
    if (child && typeof child === "object" && !Array.isArray(child)) return collectStatuses(child, name);
    return [];
  });
};

const runValidator = (name, evidencePath) => {
  const command = validators[name];
  if (!command) return { validates: null, error: null };
  try {
    execFileSync(process.execPath, [...command, evidencePath], {
      cwd: rootDir,
      stdio: "pipe",
      windowsHide: true
    });
    return { validates: true, error: null };
  } catch (error) {
    const stderr = error.stderr?.toString().trim();
    const stdout = error.stdout?.toString().trim();
    return { validates: false, error: stderr || stdout || error.message };
  }
};

assert.ok(existsSync(bundlePath), `Deployment evidence bundle not found: ${bundlePath}`);
const bundle = parseJson(bundlePath);
assert.equal(bundle.format, "sentinel-deployment-evidence-bundle-v1");
assert.ok(bundle.evidence && typeof bundle.evidence === "object", "evidence map is required");

const bundlePlaceholderCount = countPlaceholders(bundle);
const items = Object.entries(bundle.evidence).map(([name, candidate]) => {
  const evidencePath = resolveEvidencePath(candidate);
  if (!existsSync(evidencePath)) {
    return {
      name,
      path: evidencePath,
      exists: false,
      validates: false,
      placeholderCount: null,
      blockingStatuses: [],
      productionReady: false,
      issue: "evidence file not found"
    };
  }

  const evidence = parseJson(evidencePath);
  const placeholderCount = countPlaceholders(evidence);
  const blockingStatuses = collectStatuses(evidence);
  const validator = runValidator(name, evidencePath);
  let formatMatches = true;
  if (artifactFormats[name]) formatMatches = evidence.format === artifactFormats[name];

  const validates = validator.validates === null ? formatMatches : validator.validates;
  return {
    name,
    path: evidencePath,
    exists: true,
    format: evidence.format,
    releaseStatus: evidence.releaseStatus || evidence.status || evidence.deploymentStatus || evidence.providerStatus || null,
    validates,
    placeholderCount,
    blockingStatuses,
    productionReady: validates && placeholderCount === 0 && blockingStatuses.length === 0,
    issue: validates ? null : validator.error || `expected format ${artifactFormats[name]}`
  };
});

const summary = {
  total: items.length,
  present: items.filter((item) => item.exists).length,
  missing: items.filter((item) => !item.exists).length,
  validating: items.filter((item) => item.validates).length,
  withPlaceholders: items.filter((item) => (item.placeholderCount || 0) > 0).length,
  withBlockingStatuses: items.filter((item) => item.blockingStatuses.length > 0).length,
  productionReady: items.filter((item) => item.productionReady).length
};

const report = {
  format: "sentinel-deployment-evidence-status-v1",
  bundle: path.resolve(bundlePath),
  environment: bundle.environment,
  status: bundle.status,
  owner: bundle.owner,
  generatedAt: bundle.generatedAt,
  reportGeneratedAt: new Date().toISOString(),
  bundlePlaceholderCount,
  readyForPilotOrProduction: bundlePlaceholderCount === 0 && summary.missing === 0 && summary.total === summary.productionReady,
  summary,
  items
};

const text = JSON.stringify(report, null, 2);
if (outputPath) writeFileSync(outputPath, text);
console.log(text);
