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

  const rolloutPath = path.join(evidenceDir, "browser-extension-rollout-evidence.json");
  const rollout = JSON.parse(readFileSync(rolloutPath, "utf8"));
  rollout.deploymentStatus = "production";
  rollout.environment = environment;
  rollout.owner = "endpoint-platform";
  rollout.package.sha256 = packageSha256;
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

test("production evidence bundle accepts aligned Phase 5, signing, browser, and native evidence", () => {
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
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
