import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const bundlePath = process.argv.slice(2).filter((arg) => arg !== "--")[0] || "docs/templates/deployment-evidence-bundle.json";
const rootDir = path.resolve(import.meta.dirname, "..");
const allowedStatuses = new Set(["planned", "pilot", "production", "retired"]);
const deployedStatuses = new Set(["pilot", "production"]);
const placeholder = /replace-with|YYYY-MM-DD/i;
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const validators = {
  connector: ["scripts/validate-connector-evidence.mjs"],
  itsmWorkNotes: ["scripts/validate-itsm-worknote-evidence.mjs"],
  devopsTokenResponse: ["scripts/validate-devops-token-response-evidence.mjs"],
  postgresHa: ["scripts/validate-postgres-ha-approval-evidence.mjs"],
  browserIdentity: ["scripts/validate-browser-extension-identity-evidence.mjs"],
  browserRollout: ["scripts/validate-browser-rollout-evidence.mjs"],
  nativeCompanion: ["scripts/validate-native-companion-evidence.mjs"],
  credentialProviderApproval: ["scripts/validate-credential-provider-approval-evidence.mjs"],
  identityProvider: ["scripts/validate-identity-provider-evidence.mjs"],
  kmsHsm: ["scripts/validate-kms-hsm-evidence.mjs"],
  kmsHsmSdkApproval: ["scripts/validate-kms-hsm-sdk-approval-evidence.mjs"],
  windowsRelease: ["scripts/validate-windows-release-evidence.mjs"],
  windowsSigning: ["scripts/validate-windows-signing-execution-evidence.mjs"],
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

const productionEvidenceRequirements = {
  connector: "certified",
  itsmWorkNotes: "production",
  siemReceiverRotation: "certified",
  windowsSigning: "signed",
  browserIdentity: "production",
  browserRollout: "production",
  nativeCompanion: "production",
  credentialProviderApproval: "approved"
};

const artifactFormats = {
  storageMigration: "sentinel-storage-migration-evidence-v1",
  releaseProvenance: "sentinel-release-provenance-v1"
};

const resolveEvidencePath = (candidate) => {
  const bundleRelative = path.resolve(path.dirname(path.resolve(bundlePath)), candidate);
  if (existsSync(bundleRelative)) return bundleRelative;
  return path.resolve(rootDir, candidate);
};

assert.ok(existsSync(bundlePath), `Deployment evidence bundle not found: ${bundlePath}`);
const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));

assert.equal(bundle.format, "sentinel-deployment-evidence-bundle-v1");
assert.ok(bundle.environment, "environment is required");
assert.ok(bundle.owner, "owner is required");
assert.ok(allowedStatuses.has(bundle.status), "Unsupported bundle status");
assert.ok(bundle.generatedAt, "generatedAt is required");
assert.ok(bundle.evidence && typeof bundle.evidence === "object", "evidence map is required");
assert.ok(bundle.approvals?.securityOwner, "securityOwner approval is required");
assert.ok(bundle.approvals?.operationsOwner, "operationsOwner approval is required");
assert.ok(bundle.approvals?.releaseOwner, "releaseOwner approval is required");

const results = {};
for (const [name, command] of Object.entries(validators)) {
  assert.ok(bundle.evidence[name], `${name} evidence path is required`);
  const evidencePath = resolveEvidencePath(bundle.evidence[name]);
  assert.ok(existsSync(evidencePath), `${name} evidence file not found: ${evidencePath}`);
  const evidence = JSON.parse(readFileSync(evidencePath, "utf8").replace(/^\uFEFF/, ""));
  execFileSync(process.execPath, [...command, evidencePath], {
    cwd: rootDir,
    stdio: "pipe",
    windowsHide: true
  });
  results[name] = {
    path: evidencePath,
    validated: true,
    environment: evidence.environment,
    status: evidence.status || evidence.deploymentStatus || evidence.releaseStatus
  };
}

for (const [name, format] of Object.entries(artifactFormats)) {
  assert.ok(bundle.evidence[name], `${name} evidence path is required`);
  const evidencePath = resolveEvidencePath(bundle.evidence[name]);
  assert.ok(existsSync(evidencePath), `${name} evidence file not found: ${evidencePath}`);
  const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
  assert.equal(evidence.format, format, `${name} evidence format mismatch`);
  results[name] = { path: evidencePath, validated: true };
}

if (deployedStatuses.has(bundle.status)) {
  assert.ok(isoTimestamp.test(bundle.generatedAt), "generatedAt must be an ISO timestamp for deployed bundles");
  assert.doesNotMatch(JSON.stringify(bundle), placeholder, "deployed bundle cannot contain placeholders");
}

if (bundle.status === "production") {
  for (const [name, requiredStatus] of Object.entries(productionEvidenceRequirements)) {
    assert.equal(results[name].status, requiredStatus, `${name} evidence status must be ${requiredStatus} for production bundles`);
    if (results[name].environment !== undefined) {
      assert.equal(results[name].environment, bundle.environment, `${name} evidence environment must match the production bundle environment`);
    }
  }
}

console.log(JSON.stringify({
  format: "sentinel-deployment-evidence-bundle-validation-v1",
  bundle: path.resolve(bundlePath),
  environment: bundle.environment,
  status: bundle.status,
  validatedAt: new Date().toISOString(),
  results
}, null, 2));
