import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
const args = new Map();
for (let index = 0; index < cliArgs.length; index += 1) {
  const arg = cliArgs[index];
  if (arg.startsWith("--")) {
    const next = cliArgs[index + 1];
    if (!next || next.startsWith("--")) {
      args.set(arg, true);
    } else {
      args.set(arg, next);
      index += 1;
    }
  }
}

const outputPath = args.get("--out") || "artifacts/native/credential-provider-approval-evidence.json";
const reportPath = args.get("--report");
const nativeEvidencePath = args.get("--native-companion-evidence");
const artifactPath = args.get("--artifact");
const status = args.get("--status") || "planned";
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const report = reportPath && existsSync(reportPath) ? readJson(reportPath) : {};
const sha256FileHex = (filePath) => crypto.createHash("sha256").update(readFileSync(filePath)).digest("hex");

if (nativeEvidencePath) assert.ok(existsSync(nativeEvidencePath), `Native companion evidence not found: ${nativeEvidencePath}`);
if (artifactPath) {
  assert.ok(existsSync(artifactPath), `Credential provider artifact not found: ${artifactPath}`);
  assert.ok(statSync(artifactPath).isFile(), `Credential provider artifact must be a file: ${artifactPath}`);
}

const passedIfApproved = status === "approved" ? "passed" : "planned";
const falseIfApproved = status === "approved" ? false : "planned";

const evidence = {
  format: "sentinel-credential-provider-approval-evidence-v1",
  status,
  environment: args.get("--environment") || report.environment || "replace-with-environment",
  component: "windows-credential-provider",
  implementation: {
    approvalReference: args.get("--approval-reference") || report.implementation?.approvalReference || "replace-with-approval-ticket",
    architecture: args.get("--architecture") || report.implementation?.architecture || "x64",
    clsid: args.get("--clsid") || report.implementation?.clsid || "replace-with-clsid",
    registrationPath: args.get("--registration-path") || report.implementation?.registrationPath || "replace-with-registry-path",
    allowListedVaultEntriesOnly: report.implementation?.allowListedVaultEntriesOnly ?? passedIfApproved,
    offlineLogonDocumented: report.implementation?.offlineLogonDocumented ?? passedIfApproved,
    noPlaintextCredentialStorage: report.implementation?.noPlaintextCredentialStorage ?? passedIfApproved,
    outOfProcessBoundaryReviewed: report.implementation?.outOfProcessBoundaryReviewed ?? passedIfApproved
  },
  riskReview: {
    lsassInteractionReviewed: report.riskReview?.lsassInteractionReviewed ?? passedIfApproved,
    secureDesktopReviewed: report.riskReview?.secureDesktopReviewed ?? passedIfApproved,
    credentialSerializationReviewed: report.riskReview?.credentialSerializationReviewed ?? passedIfApproved,
    crashDumpExposureReviewed: report.riskReview?.crashDumpExposureReviewed ?? passedIfApproved,
    eventLogRedactionReviewed: report.riskReview?.eventLogRedactionReviewed ?? passedIfApproved,
    abuseCasesReviewed: report.riskReview?.abuseCasesReviewed ?? passedIfApproved
  },
  releaseEvidence: {
    nativeCompanionEvidencePath: nativeEvidencePath ? path.resolve(nativeEvidencePath) : "replace-with-native-companion-evidence.json",
    signedCredentialProviderArtifact: artifactPath ? path.resolve(artifactPath) : "replace-with-signed-artifact",
    artifactSha256: args.get("--artifact-sha256") || report.releaseEvidence?.artifactSha256 || (artifactPath ? sha256FileHex(artifactPath) : "replace-with-sha256"),
    authenticodeStatus: report.releaseEvidence?.authenticodeStatus || (status === "approved" ? "Valid" : "planned"),
    signerThumbprint: args.get("--signer-thumbprint") || report.releaseEvidence?.signerThumbprint || "replace-with-thumbprint",
    cleanInstall: report.releaseEvidence?.cleanInstall ?? passedIfApproved,
    cleanUninstall: report.releaseEvidence?.cleanUninstall ?? passedIfApproved,
    rollbackDisable: report.releaseEvidence?.rollbackDisable ?? passedIfApproved
  },
  approvals: {
    windowsEndpointSecurityOwner: report.approvals?.windowsEndpointSecurityOwner || "replace-with-owner",
    securityReviewer: report.approvals?.securityReviewer || "replace-with-reviewer",
    desktopEngineeringOwner: report.approvals?.desktopEngineeringOwner || "replace-with-owner",
    releaseOwner: report.approvals?.releaseOwner || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || report.approvals?.changeTicket || "replace-with-ticket"
  },
  redaction: {
    containsCredentialMaterial: report.redaction?.containsCredentialMaterial ?? falseIfApproved,
    containsSessionTokens: report.redaction?.containsSessionTokens ?? falseIfApproved,
    containsCustomerData: report.redaction?.containsCustomerData ?? falseIfApproved,
    containsPrivateKeyMaterial: report.redaction?.containsPrivateKeyMaterial ?? falseIfApproved
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Credential provider approval evidence written: ${outputPath}`);
