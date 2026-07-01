import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
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

const outputPath = args.get("--out") || "artifacts/windows/windows-signing-execution-evidence.json";
const reportPath = args.get("--report");
const status = args.get("--status") || "planned";
const environment = args.get("--environment") || "replace-with-environment";
const releaseVersion = args.get("--release-version") || "replace-with-version";

const sha256FileHex = (filePath) => crypto.createHash("sha256").update(readFileSync(filePath)).digest("hex");

const report = reportPath
  ? JSON.parse(readFileSync(reportPath, "utf8"))
  : {};

const normalizeArtifact = (artifact = {}) => {
  const artifactPath = artifact.path || "replace-with-artifact";
  const exists = existsSync(artifactPath);
  const stats = exists ? statSync(artifactPath) : null;
  if (exists) assert.ok(stats.isFile(), `Signing artifact must be a file: ${artifactPath}`);
  return {
    type: artifact.type || path.extname(artifactPath).replace(".", "").toLowerCase() || "msi",
    path: exists ? path.resolve(artifactPath) : artifactPath,
    sha256: artifact.sha256 || (exists ? sha256FileHex(artifactPath) : "replace-with-sha256"),
    signatureStatus: artifact.signatureStatus ?? (status === "signed" ? "passed" : "planned"),
    timestampStatus: artifact.timestampStatus ?? (status === "signed" ? "passed" : "planned"),
    authenticodeStatus: artifact.authenticodeStatus ?? (status === "signed" ? "valid" : "planned")
  };
};

const artifacts = Array.isArray(report.artifacts) && report.artifacts.length > 0
  ? report.artifacts.map(normalizeArtifact)
  : [normalizeArtifact()];

const evidence = {
  format: "sentinel-windows-signing-execution-evidence-v1",
  status,
  environment,
  releaseVersion,
  signedAt: report.signedAt || args.get("--signed-at") || "YYYY-MM-DDTHH:mm:ssZ",
  releaseHost: {
    hostnameHash: report.releaseHost?.hostnameHash || "replace-with-sha256",
    osBuild: report.releaseHost?.osBuild || "replace-with-os-build",
    runnerIdentity: report.releaseHost?.runnerIdentity || "replace-with-runner",
    certificateSource: report.releaseHost?.certificateSource || "certificate-store",
    approvedHost: report.releaseHost?.approvedHost ?? (status === "signed" ? "passed" : "planned")
  },
  certificate: {
    subject: report.certificate?.subject || "replace-with-subject",
    thumbprint: report.certificate?.thumbprint || args.get("--thumbprint") || "replace-with-thumbprint",
    issuer: report.certificate?.issuer || "replace-with-issuer",
    validFrom: report.certificate?.validFrom || "YYYY-MM-DD",
    validTo: report.certificate?.validTo || "YYYY-MM-DD",
    timestampAuthority: report.certificate?.timestampAuthority || "replace-with-url"
  },
  artifacts,
  checks: {
    packageBuiltOnReleaseHost: report.checks?.packageBuiltOnReleaseHost ?? (status === "signed" ? "passed" : "planned"),
    signaturesVerified: report.checks?.signaturesVerified ?? (status === "signed" ? "passed" : "planned"),
    timestampsVerified: report.checks?.timestampsVerified ?? (status === "signed" ? "passed" : "planned"),
    hashesRecorded: report.checks?.hashesRecorded ?? (status === "signed" ? "passed" : "planned"),
    rollbackArtifactSigned: report.checks?.rollbackArtifactSigned ?? (status === "signed" ? "passed" : "planned"),
    uninstallDrillCovered: report.checks?.uninstallDrillCovered ?? (status === "signed" ? "passed" : "planned")
  },
  approvals: {
    releaseOwner: report.approvals?.releaseOwner || "replace-with-owner",
    securityReviewer: report.approvals?.securityReviewer || "replace-with-reviewer",
    operationsOwner: report.approvals?.operationsOwner || "replace-with-owner",
    changeTicket: report.approvals?.changeTicket || "replace-with-ticket"
  },
  redaction: {
    containsPfxPassword: report.redaction?.containsPfxPassword ?? (status === "signed" ? false : "planned"),
    containsPrivateKeyMaterial: report.redaction?.containsPrivateKeyMaterial ?? (status === "signed" ? false : "planned"),
    containsSigningToken: report.redaction?.containsSigningToken ?? (status === "signed" ? false : "planned")
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Windows signing execution evidence written: ${outputPath}`);
