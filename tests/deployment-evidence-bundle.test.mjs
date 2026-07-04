import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runBundleValidator = (bundlePath) => execFileSync(process.execPath, [
  "scripts/validate-deployment-evidence-bundle.mjs",
  bundlePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runScript = (script, args) => execFileSync(process.execPath, [script, ...args], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const writeBundleFixture = (dir, overrides = {}) => {
  const evidenceDir = path.join(dir, "evidence");
  mkdirSync(evidenceDir, { recursive: true });
  const copies = {
    connector: "connector-certification-evidence.json",
    itsmWorkNotes: "itsm-worknote-evidence.json",
    devopsTokenResponse: "devops-token-response-evidence.json",
    postgresHa: "postgres-ha-approval-evidence.json",
    browserIdentity: "browser-extension-identity-evidence.json",
    browserRollout: "browser-extension-rollout-evidence.json",
    nativeCompanion: "native-companion-evidence.json",
    credentialProviderApproval: "credential-provider-approval-evidence.json",
    identityProvider: "identity-provider-evidence.json",
    kmsHsm: "kms-hsm-provider-evidence.json",
    kmsHsmSdkApproval: "kms-hsm-sdk-approval-evidence.json",
    windowsRelease: "windows-release-evidence.json",
    windowsSigning: "windows-signing-execution-evidence.json",
    windowsInstallHardening: "windows-install-hardening-evidence.json",
    sourceMigration: "source-migration-evidence.json",
    tlsIis: "tls-iis-evidence.json",
    pentestScope: "pentest-scope-evidence.json",
    auditWorm: "audit-worm-evidence.json",
    backupRecovery: "backup-recovery-evidence.json",
    deviceTrust: "device-trust-evidence.json",
    bruteForce: "brute-force-evidence.json",
    tenantIsolation: "tenant-isolation-evidence.json",
    siemReceiverRotation: "siem-receiver-rotation-evidence.json",
    sast: "sast-evidence.json",
    logRedaction: "log-redaction-evidence.json",
    storageMigration: "storage-migration-evidence.json",
    releaseAttestation: "release-attestation-evidence.json",
    releaseProvenance: "release-provenance-template.json"
  };
  for (const file of Object.values(copies)) {
    copyFileSync(path.join(rootDir, "docs", "templates", file), path.join(evidenceDir, file));
  }
  const bundle = {
    format: "sentinel-deployment-evidence-bundle-v1",
    environment: "lab",
    status: "planned",
    owner: "platform-team",
    generatedAt: "YYYY-MM-DDTHH:mm:ssZ",
    evidence: Object.fromEntries(Object.entries(copies).map(([name, file]) => [name, path.join("evidence", file)])),
    approvals: {
      securityOwner: "security-team",
      operationsOwner: "operations-team",
      releaseOwner: "release-team"
    },
    ...overrides
  };
  const bundlePath = path.join(dir, "deployment-evidence-bundle.json");
  writeFileSync(bundlePath, JSON.stringify(bundle, null, 2));
  return bundlePath;
};

const writeProductionPhaseFiveEvidence = (dir, environment = "prod-east") => {
  const evidenceDir = path.join(dir, "evidence");
  const connectorPath = path.join(evidenceDir, "connector-certification-evidence.json");
  const connector = JSON.parse(readFileSync(connectorPath, "utf8"));
  connector.environment = environment;
  connector.status = "certified";
  connector.connector = "siem";
  connector.targetSystem = "siem.prod.example.com";
  connector.livePreflight = {
    reportPath: path.join(evidenceDir, "connector-live-preflight.json"),
    format: "sentinel-enterprise-connector-live-preflight-v1",
    checkedAt: "2026-07-01T10:00:00Z",
    validated: true,
    connectorTypes: ["siem"],
    checkCount: 3,
    checks: {
      siemDeliveryAccepted: true,
      siemReplayEvidencePresent: true,
      redactedOutput: true
    },
    selectedConnector: "siem",
    selectedEndpointHost: "siem.prod.example.com"
  };
  writeFileSync(connector.livePreflight.reportPath, JSON.stringify({
    format: connector.livePreflight.format,
    checkedAt: connector.livePreflight.checkedAt,
    checks: connector.livePreflight.checks
  }, null, 2));
  connector.rollback.tested = true;
  writeFileSync(connectorPath, JSON.stringify(connector, null, 2));

  const siemPath = path.join(evidenceDir, "siem-receiver-rotation-evidence.json");
  const siem = JSON.parse(readFileSync(siemPath, "utf8"));
  siem.status = "certified";
  siem.environment = environment;
  siem.receiver.system = "sentinel-siem";
  siem.receiver.endpointHost = "siem.prod.example.com";
  siem.receiver.owner = "security-operations";
  siem.receiver.supportQueue = "soc-queue";
  siem.rotation.rotatedAt = "2026-07-01T10:00:00Z";
  siem.rotation.previousKeyRetireAfter = "2026-07-08T10:00:00Z";
  siem.rotation.activeKeyId = "sv-prod-active-202607";
  siem.rotation.previousKeyId = "sv-prod-prev-202606";
  siem.rotation.changeTicket = "CHG-2026-0701";
  for (const name of Object.keys(siem.checks)) {
    siem.checks[name] = "passed";
  }
  siem.receiverReport = {
    reportPath: "artifacts/integrations/siem-rotation-prod.json",
    validated: true,
    receiverEndpointHost: siem.receiver.endpointHost,
    checkCount: Object.keys(siem.checks).length,
    checks: { ...siem.checks },
    activeDeliveryId: "delivery-active-001",
    previousKeyDeliveryId: "delivery-prev-001",
    replayAttemptId: "replay-test-001"
  };
  siem.samples.activeDeliveryId = "delivery-active-001";
  siem.samples.previousKeyDeliveryId = "delivery-prev-001";
  siem.samples.replayAttemptId = "replay-test-001";
  siem.samples.receiverEvidencePath = "artifacts/integrations/siem-rotation-prod.json";
  siem.approvals.siemOwner = "security-operations";
  siem.approvals.securityReviewer = "security-review";
  siem.approvals.operationsOwner = "platform-operations";
  writeFileSync(siemPath, JSON.stringify(siem, null, 2));

  const itsmPath = path.join(evidenceDir, "itsm-worknote-evidence.json");
  const itsm = JSON.parse(readFileSync(itsmPath, "utf8"));
  itsm.status = "production";
  itsm.environment = environment;
  itsm.system = "enterprise-itsm";
  itsm.reviewedAt = "2026-07-01T10:00:00Z";
  itsm.ticketRef = "CHG-2026-0701";
  for (const [index, note] of itsm.workNotes.entries()) {
    note.workNoteId = `WN-${index + 1}`;
    note.createdAt = "2026-07-01T10:00:00Z";
    note.bodySha256 = "a".repeat(64 - String(index).length) + index;
    note.redacted = "true";
    note.ticketRef = itsm.ticketRef;
  }
  for (const name of Object.keys(itsm.checks)) {
    itsm.checks[name] = "passed";
  }
  itsm.redaction.containsSecretValues = "false";
  itsm.redaction.containsSessionTokens = "false";
  itsm.redaction.containsCustomerOnlyFields = "false";
  itsm.approvals.integrationOwner = "integration-owner";
  itsm.approvals.securityReviewer = "security-review";
  itsm.approvals.operationsOwner = "platform-operations";
  itsm.approvals.changeTicket = itsm.ticketRef;
  writeFileSync(itsmPath, JSON.stringify(itsm, null, 2));
};

const writeSignedWindowsEvidence = (dir, environment = "prod-east") => {
  const evidenceDir = path.join(dir, "evidence");
  const artifactPath = path.join(evidenceDir, "SentinelVault.Setup.exe");
  writeFileSync(artifactPath, "signed installer fixture");
  const artifactSha256 = crypto.createHash("sha256").update(readFileSync(artifactPath)).digest("hex");

  const windowsSigningPath = path.join(evidenceDir, "windows-signing-execution-evidence.json");
  const windowsSigning = JSON.parse(readFileSync(windowsSigningPath, "utf8"));
  windowsSigning.status = "signed";
  windowsSigning.environment = environment;
  windowsSigning.releaseVersion = "1.0.0";
  windowsSigning.signedAt = "2026-07-01T10:00:00Z";
  windowsSigning.releaseHost.hostnameHash = "b".repeat(64);
  windowsSigning.releaseHost.osBuild = "Windows Server 2025";
  windowsSigning.releaseHost.runnerIdentity = "release-runner";
  windowsSigning.releaseHost.approvedHost = "passed";
  windowsSigning.certificate.subject = "CN=Sentinel Vault";
  windowsSigning.certificate.thumbprint = "a".repeat(40);
  windowsSigning.certificate.issuer = "CN=Enterprise Code Signing CA";
  windowsSigning.certificate.validFrom = "2026-01-01";
  windowsSigning.certificate.validTo = "2027-01-01";
  windowsSigning.certificate.timestampAuthority = "https://timestamp.example.com";
  windowsSigning.artifacts = [{
    type: "exe",
    path: artifactPath,
    sha256: artifactSha256,
    signatureStatus: "passed",
    timestampStatus: "passed",
    authenticodeStatus: "valid"
  }];
  for (const name of Object.keys(windowsSigning.checks)) {
    windowsSigning.checks[name] = "passed";
  }
  windowsSigning.approvals.releaseOwner = "release-owner";
  windowsSigning.approvals.securityReviewer = "security-review";
  windowsSigning.approvals.operationsOwner = "platform-operations";
  windowsSigning.approvals.changeTicket = "CHG-2026-0701";
  windowsSigning.redaction.containsPfxPassword = false;
  windowsSigning.redaction.containsPrivateKeyMaterial = false;
  windowsSigning.redaction.containsSigningToken = false;
  writeFileSync(windowsSigningPath, JSON.stringify(windowsSigning, null, 2));
};

const writeProductionBrowserEvidence = (dir, environment = "prod-east") => {
  const evidenceDir = path.join(dir, "evidence");
  const packageSha256 = "c".repeat(64);
  const chromeExtensionId = "a".repeat(32);
  const edgeExtensionId = "b".repeat(32);

  const identityPath = path.join(evidenceDir, "browser-extension-identity-evidence.json");
  const identity = JSON.parse(readFileSync(identityPath, "utf8"));
  identity.status = "production";
  identity.environment = environment;
  identity.packageSha256 = packageSha256;
  for (const [browser, extensionId] of Object.entries({ chrome: chromeExtensionId, edge: edgeExtensionId })) {
    identity[browser].extensionId = extensionId;
    identity[browser].publisher = `${browser}-publisher`;
    identity[browser].reviewStatus = "passed";
    identity[browser].policyAssignment = "passed";
  }
  for (const name of Object.keys(identity.controls)) {
    identity.controls[name] = "passed";
  }
  identity.approvals.endpointPlatformOwner = "endpoint-platform";
  identity.approvals.securityReviewer = "security-review";
  identity.approvals.businessOwner = "business-owner";
  identity.approvals.changeTicket = "CHG-2026-0701";
  identity.redaction.containsCredentials = false;
  identity.redaction.containsInternalHostnames = false;
  identity.redaction.containsCustomerData = false;
  writeFileSync(identityPath, JSON.stringify(identity, null, 2));

  const packageValidationPath = path.join(evidenceDir, "browser-extension-package-validation.json");
  writeFileSync(packageValidationPath, JSON.stringify({
    format: "sentinel-browser-extension-package-validation-v1",
    packagePath: path.join(evidenceDir, "sentinel-vault-autofill.zip"),
    packageSha256,
    packageBytes: 12345,
    manifestVersion: 3,
    extensionName: "Sentinel Vault Autofill",
    requiredFileCount: 6,
    hostPermissions: ["http://127.0.0.1:5173/*", "http://localhost:5173/*"],
    permissions: ["activeTab", "scripting"],
    validated: true
  }, null, 2));

  const rolloutPath = path.join(evidenceDir, "browser-extension-rollout-evidence.json");
  const rollout = JSON.parse(readFileSync(rolloutPath, "utf8"));
  rollout.deploymentStatus = "production";
  rollout.environment = environment;
  rollout.owner = "endpoint-platform";
  rollout.package.sha256 = packageSha256;
  rollout.packageValidation = {
    reportPath: packageValidationPath,
    format: "sentinel-browser-extension-package-validation-v1",
    validated: true,
    packageSha256,
    requiredFileCount: 6,
    hostPermissionCount: 2,
    permissionCount: 2
  };
  rollout.chrome.extensionId = chromeExtensionId;
  rollout.edge.extensionId = edgeExtensionId;
  for (const ring of rollout.rolloutRings) {
    ring.scope = `${ring.name}-managed-devices`;
    ring.status = "passed";
    ring.startDate = "2026-07-01";
    ring.validation = "passed";
  }
  rollout.storeReview.privacyStatementApproved = true;
  rollout.storeReview.screenshotsRedacted = true;
  rollout.rollback.tested = true;
  rollout.approvals.securityReviewer = "security-review";
  rollout.approvals.desktopEngineering = "desktop-engineering";
  rollout.approvals.businessOwner = "business-owner";
  writeFileSync(rolloutPath, JSON.stringify(rollout, null, 2));
};

const credentialProviderClsid = "{12345678-1234-1234-1234-123456789abc}";

const writeProductionNativeEvidence = (dir, environment = "prod-east") => {
  const evidenceDir = path.join(dir, "evidence");
  const nativePath = path.join(evidenceDir, "native-companion-evidence.json");
  const credentialArtifactPath = path.join(evidenceDir, "SentinelVault.CredentialProvider.dll");
  writeFileSync(credentialArtifactPath, "credential provider dll fixture");
  const credentialArtifactSha256 = crypto.createHash("sha256").update(readFileSync(credentialArtifactPath)).digest("hex");

  const native = JSON.parse(readFileSync(nativePath, "utf8"));
  native.releaseStatus = "production";
  native.releaseVersion = "1.0.0";
  native.releaseDate = "2026-07-01";
  native.buildHost = "release-host";
  native.sourceCommit = "abc1234";
  native.artifacts = native.artifacts.map((artifact) => ({
    ...artifact,
    sha256: artifact.name.endsWith(".dll") ? credentialArtifactSha256 : "d".repeat(64),
    authenticodeStatus: "Valid",
    signerThumbprint: "e".repeat(40)
  }));
  const nativeArtifactValidationPath = path.join(evidenceDir, "native-artifact-validation.json");
  native.artifactValidation = {
    reportPath: nativeArtifactValidationPath,
    format: "sentinel-native-release-artifact-validation-v1",
    validated: true,
    requireSignature: true,
    artifactCount: native.artifacts.length,
    signedArtifactCount: native.artifacts.length,
    artifacts: native.artifacts.map((artifact) => ({
      name: artifact.name,
      type: artifact.type,
      sha256: artifact.sha256,
      authenticodeStatus: "Valid"
    }))
  };
  writeFileSync(nativeArtifactValidationPath, JSON.stringify(native.artifactValidation, null, 2));
  native.nativeMessaging.manifestPath = "C:\\Program Files\\Sentinel Vault\\native-messaging.json";
  native.nativeMessaging.allowedExtensionIds = ["a".repeat(32), "b".repeat(32)];
  native.nativeMessaging.hostPath = "C:\\Program Files\\Sentinel Vault\\SentinelVault.Companion.exe";
  native.credentialProvider.enabled = true;
  native.credentialProvider.clsid = credentialProviderClsid;
  native.credentialProvider.registrationPath = `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\${credentialProviderClsid}`;
  native.credentialProvider.offlineLogonDocumented = true;
  for (const name of Object.keys(native.securityControls)) {
    native.securityControls[name] = "passed";
  }
  for (const name of Object.keys(native.testResults)) {
    native.testResults[name] = "passed";
  }
  native.approvals.securityReviewer = "security-review";
  native.approvals.desktopEngineering = "desktop-engineering";
  native.approvals.releaseOwner = "release-owner";
  native.approvals.changeTicket = "CHG-2026-0701";
  native.rollback.disableProcedure = "Disable credential provider registration and remove native messaging host.";
  native.rollback.tested = true;
  writeFileSync(nativePath, JSON.stringify(native, null, 2));

  const approvalPath = path.join(evidenceDir, "credential-provider-approval-evidence.json");
  const approval = JSON.parse(readFileSync(approvalPath, "utf8"));
  approval.status = "approved";
  approval.environment = environment;
  approval.implementation.approvalReference = "SEC-2026-0701";
  approval.implementation.clsid = credentialProviderClsid;
  approval.implementation.registrationPath = native.credentialProvider.registrationPath;
  approval.implementation.allowListedVaultEntriesOnly = "passed";
  approval.implementation.offlineLogonDocumented = "passed";
  approval.implementation.noPlaintextCredentialStorage = "passed";
  approval.implementation.outOfProcessBoundaryReviewed = "passed";
  for (const name of Object.keys(approval.riskReview)) {
    approval.riskReview[name] = "passed";
  }
  approval.releaseEvidence.nativeCompanionEvidencePath = nativePath;
  approval.releaseEvidence.signedCredentialProviderArtifact = credentialArtifactPath;
  approval.releaseEvidence.artifactSha256 = credentialArtifactSha256;
  approval.releaseEvidence.authenticodeStatus = "Valid";
  approval.releaseEvidence.signerThumbprint = "e".repeat(40);
  approval.releaseEvidence.cleanInstall = "passed";
  approval.releaseEvidence.cleanUninstall = "passed";
  approval.releaseEvidence.rollbackDisable = "passed";
  approval.approvals.windowsEndpointSecurityOwner = "endpoint-security";
  approval.approvals.securityReviewer = "security-review";
  approval.approvals.desktopEngineeringOwner = "desktop-engineering";
  approval.approvals.releaseOwner = "release-owner";
  approval.approvals.changeTicket = "CHG-2026-0701";
  approval.redaction.containsCredentialMaterial = false;
  approval.redaction.containsSessionTokens = false;
  approval.redaction.containsCustomerData = false;
  approval.redaction.containsPrivateKeyMaterial = false;
  writeFileSync(approvalPath, JSON.stringify(approval, null, 2));
};

const writeActiveKmsHsmEvidence = (dir, environment = "prod-east") => {
  const evidenceDir = path.join(dir, "evidence");
  const preflightPath = path.join(evidenceDir, "kms-hsm-preflight.json");
  const providerEvidencePath = path.join(evidenceDir, "kms-hsm-provider-evidence.json");
  writeFileSync(preflightPath, JSON.stringify({ format: "sentinel-kms-hsm-preflight-v1" }, null, 2));

  const provider = JSON.parse(readFileSync(providerEvidencePath, "utf8"));
  provider.status = "active";
  provider.provider = "external-kms";
  provider.providerName = "Enterprise KMS";
  provider.environment = environment;
  provider.keyId = "kms-key-prod-001";
  provider.keyVersion = "v1";
  provider.endpoint = "https://kms.example.com";
  provider.region = "us-east";
  provider.serviceIdentity = "sentinel-vault-prod";
  provider.policyHash = "f".repeat(64);
  provider.rotation.createdAt = "2026-07-01T10:00:00Z";
  provider.rotation.activatedAt = "2026-07-01T11:00:00Z";
  provider.rotation.previousKeyId = "kms-key-prev-001";
  provider.rotation.previousKeyRetireAfter = "2026-08-01";
  for (const name of Object.keys(provider.checks)) {
    provider.checks[name] = "passed";
  }
  provider.approvals.securityOwner = "security-owner";
  provider.approvals.platformOwner = "platform-owner";
  provider.approvals.changeTicket = "CHG-2026-0701";
  writeFileSync(providerEvidencePath, JSON.stringify(provider, null, 2));

  const sdkPath = path.join(evidenceDir, "kms-hsm-sdk-approval-evidence.json");
  const sdk = JSON.parse(readFileSync(sdkPath, "utf8"));
  sdk.status = "approved";
  sdk.environment = environment;
  sdk.provider = "external-kms";
  sdk.sdk.packageName = "@enterprise/kms-client";
  sdk.sdk.packageVersion = "1.0.0";
  sdk.sdk.license = "Commercial";
  sdk.sdk.registry = "internal-registry";
  sdk.sdk.packageSha256 = "1".repeat(64);
  sdk.sdk.approvalReference = "SEC-2026-0701";
  sdk.sdk.maintenanceStatus = "passed";
  sdk.sdk.supplyChainReview = "passed";
  sdk.sdk.securityReview = "passed";
  sdk.targetEnvironment.providerTenant = "tenant-prod";
  sdk.targetEnvironment.region = "us-east";
  sdk.targetEnvironment.keyId = provider.keyId;
  sdk.targetEnvironment.serviceIdentity = provider.serviceIdentity;
  sdk.targetEnvironment.networkIsolation = "passed";
  sdk.targetEnvironment.auditSinkConfigured = "passed";
  sdk.targetEnvironment.breakGlassProcedure = "passed";
  sdk.operationProof.preflightPath = preflightPath;
  sdk.operationProof.providerEvidencePath = providerEvidencePath;
  sdk.operationProof.signOrUnwrapOperation = "passed";
  sdk.operationProof.keyExportBlocked = "passed";
  sdk.operationProof.auditEventCaptured = "passed";
  sdk.operationProof.rollbackTested = "passed";
  sdk.approvals.securityArchitectureOwner = "security-architecture";
  sdk.approvals.platformOwner = "platform-owner";
  sdk.approvals.releaseOwner = "release-owner";
  sdk.approvals.changeTicket = "CHG-2026-0701";
  sdk.redaction.containsCredentials = false;
  sdk.redaction.containsKeyMaterial = false;
  sdk.redaction.containsProviderTokens = false;
  sdk.redaction.containsConnectionStrings = false;
  writeFileSync(sdkPath, JSON.stringify(sdk, null, 2));
};

const writeProductionMigrationEvidence = (dir, environment = "prod-east") => {
  const evidenceDir = path.join(dir, "evidence");
  const sourcePath = path.join(evidenceDir, "source.csv");
  const columnMapPath = path.join(evidenceDir, "column-map.json");
  const normalizedPath = path.join(evidenceDir, "normalized-import.csv");
  const adapterEvidencePath = path.join(evidenceDir, "source-adapter-evidence.json");
  const storageEvidencePath = path.join(evidenceDir, "storage-migration-evidence.json");
  const tenantEvidencePath = path.join(evidenceDir, "tenant-isolation-evidence.json");
  const sourceMigrationPath = path.join(evidenceDir, "source-migration-evidence.json");

  writeFileSync(sourcePath, [
    "Record Title,Login ID,Secret Value,Endpoint,Folder,Description",
    "Privileged Console,root,Map-Secret-Value,https://console.example.test,Privileged,Emergency admin"
  ].join("\n"));
  writeFileSync(columnMapPath, JSON.stringify({
    format: "sentinel-source-export-column-map-v1",
    sourceSystem: "Enterprise Legacy Vault",
    fields: {
      type: { constant: "password" },
      name: { columns: ["Record Title"] },
      username: { columns: ["Login ID"] },
      password: { columns: ["Secret Value"] },
      url: { columns: ["Endpoint"] },
      tags: { columns: ["Folder"], constants: ["migrated"] },
      risk: { constant: "high" },
      notes: { columns: ["Description"] }
    },
    redaction: {
      evidenceIncludesPasswordValues: false,
      evidenceIncludesOtpValues: false
    }
  }, null, 2));
  runScript("scripts/convert-source-export.mjs", [
    "--source", sourcePath,
    "--format", "mapped-csv",
    "--mapping", columnMapPath,
    "--vault-id", "v-import",
    "--out", normalizedPath,
    "--evidence", adapterEvidencePath
  ]);

  const storage = JSON.parse(readFileSync(storageEvidencePath, "utf8"));
  storage.inspectedAt = "2026-07-01T10:00:00Z";
  storage.stateFile = path.join(evidenceDir, "sentinel-state.json");
  storage.stateSha256 = "a".repeat(43);
  storage.counts.users = 2;
  storage.counts.tenants = 2;
  storage.counts.vaults = 2;
  storage.counts.secrets = 1;
  for (const key of Object.keys(storage.checks)) {
    storage.checks[key] = true;
  }
  for (const key of Object.keys(storage.findings)) {
    storage.findings[key] = [];
  }
  writeFileSync(storageEvidencePath, JSON.stringify(storage, null, 2));

  const tenant = JSON.parse(readFileSync(tenantEvidencePath, "utf8"));
  tenant.status = "production";
  tenant.environment = environment;
  tenant.testedAt = "2026-07-01T10:00:00Z";
  tenant.scope = {
    tenantCount: 3,
    vaultCount: 8,
    userCount: 24,
    sampledTenantPairs: 4,
    testCadence: "per-release"
  };
  for (const key of Object.keys(tenant.controls)) {
    tenant.controls[key] = "passed";
  }
  for (const key of Object.keys(tenant.negativeTests)) {
    tenant.negativeTests[key] = "passed";
  }
  tenant.redaction = {
    secretValuesFound: false,
    sessionTokensFound: false,
    tenantIdentifiersScoped: "passed"
  };
  tenant.approvals = {
    securityReviewer: "security-review",
    operationsOwner: "platform-operations",
    changeTicket: "CHG-2026-0701"
  };
  writeFileSync(tenantEvidencePath, JSON.stringify(tenant, null, 2));

  runScript("scripts/generate-source-migration-evidence.mjs", [
    "--status", "production",
    "--environment", environment,
    "--source-system", "Enterprise Legacy Vault",
    "--column-map", columnMapPath,
    "--source-adapter-evidence", adapterEvidencePath,
    "--normalized-import", normalizedPath,
    "--storage-migration-evidence", storageEvidencePath,
    "--tenant-isolation-evidence", tenantEvidencePath,
    "--migration-owner", "migration-owner",
    "--security-reviewer", "security-review",
    "--operations-owner", "platform-operations",
    "--change-ticket", "CHG-2026-0701",
    "--out", sourceMigrationPath
  ]);
};

const writeApprovedPostgresEvidence = (dir, environment = "prod-east") => {
  const evidenceDir = path.join(dir, "evidence");
  const postgresPath = path.join(evidenceDir, "postgres-ha-approval-evidence.json");
  const migrationPlanPath = path.join(evidenceDir, "postgres-migration-plan.json");
  const storageEvidencePath = path.join(evidenceDir, "storage-migration-evidence.json");
  writeFileSync(migrationPlanPath, JSON.stringify({
    format: "sentinel-postgres-migration-plan-v1",
    environment,
    generatedAt: "2026-07-01T10:00:00Z"
  }, null, 2));

  const postgres = JSON.parse(readFileSync(postgresPath, "utf8"));
  postgres.status = "approved";
  postgres.environment = environment;
  postgres.reviewedAt = "2026-07-01T10:00:00Z";
  postgres.dependencyApproval.packageName = "pg";
  postgres.dependencyApproval.packageVersion = "8.16.3";
  postgres.dependencyApproval.license = "MIT";
  postgres.dependencyApproval.supplyChainReview = "approved";
  postgres.dependencyApproval.securityReview = "approved";
  postgres.dependencyApproval.approvalReference = "DATA-2026-0701";
  postgres.targetEnvironment.clusterName = "sentinel-prod-postgres";
  postgres.targetEnvironment.haMode = "multi-zone";
  postgres.targetEnvironment.networkIsolation = "approved";
  postgres.targetEnvironment.tlsRequired = "approved";
  postgres.targetEnvironment.leastPrivilegeRole = "approved";
  postgres.targetEnvironment.backupPolicy = "approved";
  postgres.targetEnvironment.restoreDrill = "approved";
  postgres.targetEnvironment.monitoringAlerts = "approved";
  postgres.cutover.migrationPlanPath = migrationPlanPath;
  postgres.cutover.storageMigrationEvidencePath = storageEvidencePath;
  postgres.cutover.rollbackPlan = "approved";
  postgres.cutover.maintenanceWindow = "2026-07-01T22:00:00Z/2026-07-01T23:00:00Z";
  postgres.cutover.ownerApproval = "approved";
  postgres.approvals.platformDataOwner = "platform-data-owner";
  postgres.approvals.securityReviewer = "security-review";
  postgres.approvals.operationsOwner = "platform-operations";
  postgres.redaction.containsCredentials = "false";
  postgres.redaction.containsConnectionStrings = "false";
  postgres.redaction.containsCustomerData = "false";
  writeFileSync(postgresPath, JSON.stringify(postgres, null, 2));
};

test("deployment evidence bundle validates referenced evidence files", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir);
    const output = runBundleValidator(bundlePath);
    const validation = JSON.parse(output);

    assert.equal(validation.format, "sentinel-deployment-evidence-bundle-validation-v1");
    assert.equal(validation.status, "planned");
    assert.equal(validation.results.connector.validated, true);
    assert.equal(validation.results.itsmWorkNotes.validated, true);
    assert.equal(validation.results.devopsTokenResponse.validated, true);
    assert.equal(validation.results.postgresHa.validated, true);
    assert.equal(validation.results.browserIdentity.validated, true);
    assert.equal(validation.results.browserRollout.validated, true);
    assert.equal(validation.results.nativeCompanion.validated, true);
    assert.equal(validation.results.credentialProviderApproval.validated, true);
    assert.equal(validation.results.kmsHsmSdkApproval.validated, true);
    assert.equal(validation.results.windowsRelease.validated, true);
    assert.equal(validation.results.windowsSigning.validated, true);
    assert.equal(validation.results.windowsInstallHardening.validated, true);
    assert.equal(validation.results.tlsIis.validated, true);
    assert.equal(validation.results.pentestScope.validated, true);
    assert.equal(validation.results.auditWorm.validated, true);
    assert.equal(validation.results.backupRecovery.validated, true);
    assert.equal(validation.results.deviceTrust.validated, true);
    assert.equal(validation.results.bruteForce.validated, true);
    assert.equal(validation.results.tenantIsolation.validated, true);
    assert.equal(validation.results.siemReceiverRotation.validated, true);
    assert.equal(validation.results.sast.validated, true);
    assert.equal(validation.results.logRedaction.validated, true);
    assert.equal(validation.results.releaseAttestation.validated, true);
    assert.equal(validation.results.sourceMigration.validated, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment evidence bundle rejects missing referenced evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-fail-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir, {
      evidence: {
        connector: "evidence/missing.json",
        itsmWorkNotes: "evidence/itsm-worknote-evidence.json",
        devopsTokenResponse: "evidence/devops-token-response-evidence.json",
        postgresHa: "evidence/postgres-ha-approval-evidence.json",
        browserIdentity: "evidence/browser-extension-identity-evidence.json",
        browserRollout: "evidence/browser-extension-rollout-evidence.json",
        nativeCompanion: "evidence/native-companion-evidence.json",
        credentialProviderApproval: "evidence/credential-provider-approval-evidence.json",
        identityProvider: "evidence/identity-provider-evidence.json",
        kmsHsm: "evidence/kms-hsm-provider-evidence.json",
        kmsHsmSdkApproval: "evidence/kms-hsm-sdk-approval-evidence.json",
        windowsRelease: "evidence/windows-release-evidence.json",
        windowsSigning: "evidence/windows-signing-execution-evidence.json",
        windowsInstallHardening: "evidence/windows-install-hardening-evidence.json",
        sourceMigration: "evidence/source-migration-evidence.json",
        tlsIis: "evidence/tls-iis-evidence.json",
        pentestScope: "evidence/pentest-scope-evidence.json",
        auditWorm: "evidence/audit-worm-evidence.json",
        backupRecovery: "evidence/backup-recovery-evidence.json",
        deviceTrust: "evidence/device-trust-evidence.json",
        bruteForce: "evidence/brute-force-evidence.json",
        tenantIsolation: "evidence/tenant-isolation-evidence.json",
        siemReceiverRotation: "evidence/siem-receiver-rotation-evidence.json",
        sast: "evidence/sast-evidence.json",
        logRedaction: "evidence/log-redaction-evidence.json",
        storageMigration: "evidence/storage-migration-evidence.json",
        releaseAttestation: "evidence/release-attestation-evidence.json",
        releaseProvenance: "evidence/release-provenance-template.json"
      }
    });

    assert.throws(() => runBundleValidator(bundlePath), /connector evidence file not found/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployed evidence bundle cannot contain placeholders", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-deployed-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir, {
      status: "production",
      generatedAt: "2026-07-01T10:00:00Z",
      owner: "replace-with-owner"
    });
    assert.throws(() => runBundleValidator(bundlePath), /deployed bundle cannot contain placeholders/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production evidence bundle requires production-ready Phase 5 evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-prod-phase5-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir, {
      environment: "prod-east",
      status: "production",
      owner: "platform-team",
      generatedAt: "2026-07-01T10:00:00Z"
    });

    assert.throws(() => runBundleValidator(bundlePath), /connector evidence status must be certified/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production evidence bundle requires signed Windows release evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-prod-signing-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir, {
      environment: "prod-east",
      status: "production",
      owner: "platform-team",
      generatedAt: "2026-07-01T10:00:00Z"
    });
    writeProductionPhaseFiveEvidence(dir);

    assert.throws(() => runBundleValidator(bundlePath), /windowsSigning evidence status must be signed/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production evidence bundle requires production browser extension evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-prod-browser-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir, {
      environment: "prod-east",
      status: "production",
      owner: "platform-team",
      generatedAt: "2026-07-01T10:00:00Z"
    });
    writeProductionPhaseFiveEvidence(dir);
    writeSignedWindowsEvidence(dir);

    assert.throws(() => runBundleValidator(bundlePath), /browserIdentity evidence status must be production/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production evidence bundle requires approved native credential-provider evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-prod-native-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir, {
      environment: "prod-east",
      status: "production",
      owner: "platform-team",
      generatedAt: "2026-07-01T10:00:00Z"
    });
    writeProductionPhaseFiveEvidence(dir);
    writeSignedWindowsEvidence(dir);
    writeProductionBrowserEvidence(dir);

    assert.throws(() => runBundleValidator(bundlePath), /nativeCompanion evidence status must be production/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production evidence bundle requires active KMS/HSM evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-prod-kms-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir, {
      environment: "prod-east",
      status: "production",
      owner: "platform-team",
      generatedAt: "2026-07-01T10:00:00Z"
    });
    writeProductionPhaseFiveEvidence(dir);
    writeSignedWindowsEvidence(dir);
    writeProductionBrowserEvidence(dir);
    writeProductionNativeEvidence(dir);

    assert.throws(() => runBundleValidator(bundlePath), /kmsHsm evidence status must be active/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production evidence bundle requires production migration and tenant evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-prod-migration-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir, {
      environment: "prod-east",
      status: "production",
      owner: "platform-team",
      generatedAt: "2026-07-01T10:00:00Z"
    });
    writeProductionPhaseFiveEvidence(dir);
    writeSignedWindowsEvidence(dir);
    writeProductionBrowserEvidence(dir);
    writeProductionNativeEvidence(dir);
    writeActiveKmsHsmEvidence(dir);

    assert.throws(() => runBundleValidator(bundlePath), /sourceMigration evidence status must be production/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production evidence bundle requires approved Postgres HA evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-prod-postgres-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir, {
      environment: "prod-east",
      status: "production",
      owner: "platform-team",
      generatedAt: "2026-07-01T10:00:00Z"
    });
    writeProductionPhaseFiveEvidence(dir);
    writeSignedWindowsEvidence(dir);
    writeProductionBrowserEvidence(dir);
    writeProductionNativeEvidence(dir);
    writeActiveKmsHsmEvidence(dir);
    writeProductionMigrationEvidence(dir);

    assert.throws(() => runBundleValidator(bundlePath), /postgresHa evidence status must be approved/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("production evidence bundle accepts aligned Phase 2, 4, 5, 6, 7, and 8 evidence", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-bundle-prod-phase5-pass-${process.pid}-${Date.now()}`);
  try {
    const bundlePath = writeBundleFixture(dir, {
      environment: "prod-east",
      status: "production",
      owner: "platform-team",
      generatedAt: "2026-07-01T10:00:00Z"
    });
    writeProductionPhaseFiveEvidence(dir);
    writeSignedWindowsEvidence(dir);
    writeProductionBrowserEvidence(dir);
    writeProductionNativeEvidence(dir);
    writeActiveKmsHsmEvidence(dir);
    writeProductionMigrationEvidence(dir);
    writeApprovedPostgresEvidence(dir);
    const validation = JSON.parse(runBundleValidator(bundlePath));

    assert.equal(validation.status, "production");
    assert.equal(validation.results.browserIdentity.status, "production");
    assert.equal(validation.results.browserRollout.status, "production");
    assert.equal(validation.results.connector.status, "certified");
    assert.equal(validation.results.itsmWorkNotes.status, "production");
    assert.equal(validation.results.siemReceiverRotation.status, "certified");
    assert.equal(validation.results.windowsSigning.status, "signed");
    assert.equal(validation.results.nativeCompanion.status, "production");
    assert.equal(validation.results.credentialProviderApproval.status, "approved");
    assert.equal(validation.results.kmsHsm.status, "active");
    assert.equal(validation.results.kmsHsmSdkApproval.status, "approved");
    assert.equal(validation.results.sourceMigration.status, "production");
    assert.equal(validation.results.tenantIsolation.status, "production");
    assert.equal(validation.results.postgresHa.status, "approved");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
