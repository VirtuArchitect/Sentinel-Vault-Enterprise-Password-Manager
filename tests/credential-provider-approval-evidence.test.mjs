import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-credential-provider-approval-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-credential-provider-approval-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const thumbprint = "a".repeat(40);
const clsid = "{12345678-1234-4234-9234-1234567890ab}";

test("credential provider approval template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "credential-provider-approval-evidence.json")), /validated/);
});

test("credential provider approval generator creates approved evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-credential-provider-approval-"));
  try {
    const nativeEvidencePath = path.join(dir, "native-companion-evidence.json");
    const artifactPath = path.join(dir, "SentinelVault.CredentialProvider.dll");
    const reportPath = path.join(dir, "credential-provider-report.json");
    const evidencePath = path.join(dir, "credential-provider-approval-evidence.json");
    writeFileSync(nativeEvidencePath, JSON.stringify({ format: "sentinel-native-companion-evidence-v1" }, null, 2));
    writeFileSync(artifactPath, "credential provider dll fixture");
    writeFileSync(reportPath, JSON.stringify({
      environment: "pilot",
      implementation: {
        approvalReference: "SEC-4001",
        clsid,
        registrationPath: `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\${clsid}`,
        allowListedVaultEntriesOnly: "passed",
        offlineLogonDocumented: "passed",
        noPlaintextCredentialStorage: "passed",
        outOfProcessBoundaryReviewed: "passed"
      },
      riskReview: {
        lsassInteractionReviewed: "passed",
        secureDesktopReviewed: "passed",
        credentialSerializationReviewed: "passed",
        crashDumpExposureReviewed: "passed",
        eventLogRedactionReviewed: "passed",
        abuseCasesReviewed: "passed"
      },
      releaseEvidence: {
        authenticodeStatus: "Valid",
        signerThumbprint: thumbprint,
        cleanInstall: "passed",
        cleanUninstall: "passed",
        rollbackDisable: "passed"
      },
      approvals: {
        windowsEndpointSecurityOwner: "Endpoint Security",
        securityReviewer: "Security Reviewer",
        desktopEngineeringOwner: "Desktop Engineering",
        releaseOwner: "Release Owner",
        changeTicket: "CHG-4001"
      }
    }, null, 2));

    assert.match(runGenerator([
      "--status", "approved",
      "--report", reportPath,
      "--native-companion-evidence", nativeEvidencePath,
      "--artifact", artifactPath,
      "--out", evidencePath
    ]), /written/);

    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.releaseEvidence.artifactSha256, hash("credential provider dll fixture"));
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("credential provider approval validator rejects credential material leakage", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-credential-provider-approval-fail-"));
  try {
    const nativeEvidencePath = path.join(dir, "native.json");
    const artifactPath = path.join(dir, "SentinelVault.CredentialProvider.dll");
    const evidencePath = path.join(dir, "approval.json");
    writeFileSync(nativeEvidencePath, "{}");
    writeFileSync(artifactPath, "credential provider dll fixture");
    writeFileSync(evidencePath, JSON.stringify({
      format: "sentinel-credential-provider-approval-evidence-v1",
      status: "approved",
      environment: "pilot",
      component: "windows-credential-provider",
      implementation: {
        approvalReference: "SEC-4001",
        architecture: "x64",
        clsid,
        registrationPath: `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\${clsid}`,
        allowListedVaultEntriesOnly: "passed",
        offlineLogonDocumented: "passed",
        noPlaintextCredentialStorage: "passed",
        outOfProcessBoundaryReviewed: "passed"
      },
      riskReview: {
        lsassInteractionReviewed: "passed",
        secureDesktopReviewed: "passed",
        credentialSerializationReviewed: "passed",
        crashDumpExposureReviewed: "passed",
        eventLogRedactionReviewed: "passed",
        abuseCasesReviewed: "passed"
      },
      releaseEvidence: {
        nativeCompanionEvidencePath: nativeEvidencePath,
        signedCredentialProviderArtifact: artifactPath,
        artifactSha256: hash("credential provider dll fixture"),
        authenticodeStatus: "Valid",
        signerThumbprint: thumbprint,
        cleanInstall: "passed",
        cleanUninstall: "passed",
        rollbackDisable: "passed"
      },
      approvals: {
        windowsEndpointSecurityOwner: "Endpoint Security",
        securityReviewer: "Security Reviewer",
        desktopEngineeringOwner: "Desktop Engineering",
        releaseOwner: "Release Owner",
        changeTicket: "CHG-4001"
      },
      redaction: {
        containsCredentialMaterial: true,
        containsSessionTokens: false,
        containsCustomerData: false,
        containsPrivateKeyMaterial: false
      }
    }, null, 2));

    assert.throws(() => runValidator(evidencePath), /credential material/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
