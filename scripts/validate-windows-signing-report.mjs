import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
const args = new Map();
const positionals = [];
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
  } else {
    positionals.push(arg);
  }
}

const reportPath = path.resolve(args.get("--report") || positionals[0] || "artifacts/windows/signing-report.json");
const outputPath = args.get("--out") ? path.resolve(args.get("--out")) : null;
const strict = args.has("--strict");
const isoTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const isoDate = /^\d{4}-\d{2}-\d{2}$/;
const sha256Pattern = /^[a-f0-9]{64}$/i;
const thumbprintPattern = /^[a-f0-9]{40,64}$/i;
const validArtifactTypes = new Set(["msi", "msix", "exe"]);
const passValues = new Set(["passed", "valid", "signed", true]);
const secretKeyPattern = /^(pfxPassword|privateKey|signingToken|clientSecret|certificatePassword)$/i;
const secretValuePattern = /BEGIN\s+(RSA\s+)?PRIVATE KEY|password\s*[:=]\s*[^,\s"}]{8,}|signing[_-]?token\s*[:=]\s*[^,\s"}]{8,}/i;

const sha256FileHex = (filePath) => crypto.createHash("sha256").update(readFileSync(filePath)).digest("hex");
const assertPassed = (value, message) => assert.ok(passValues.has(value), message);

assert.ok(existsSync(reportPath), `Windows signing report not found: ${reportPath}`);
const raw = readFileSync(reportPath, "utf8");
const report = JSON.parse(raw);

const findSecretLeak = (value, key = "") => {
  if (value === null || value === undefined || value === false) return null;
  if (secretKeyPattern.test(key)) return key;
  if (typeof value === "string") return secretValuePattern.test(value) ? key || "value" : null;
  if (Array.isArray(value)) {
    for (const item of value) {
      const leak = findSecretLeak(item, key);
      if (leak) return leak;
    }
    return null;
  }
  if (typeof value === "object") {
    for (const [childKey, childValue] of Object.entries(value)) {
      const leak = findSecretLeak(childValue, childKey);
      if (leak) return leak;
    }
  }
  return null;
};

assert.equal(findSecretLeak(report), null, "Windows signing report appears to contain signing secrets or private key material");

assert.ok(isoTimestamp.test(report.signedAt), "signedAt must be an ISO timestamp");
assert.ok(report.releaseHost?.hostnameHash, "releaseHost.hostnameHash is required");
assert.ok(sha256Pattern.test(report.releaseHost.hostnameHash), "releaseHost.hostnameHash must be a SHA-256 hex digest");
assert.ok(report.releaseHost?.osBuild, "releaseHost.osBuild is required");
assert.ok(report.releaseHost?.runnerIdentity, "releaseHost.runnerIdentity is required");
assert.ok(report.releaseHost?.certificateSource, "releaseHost.certificateSource is required");
assertPassed(report.releaseHost.approvedHost, "releaseHost.approvedHost must be passed");

assert.ok(report.certificate?.subject, "certificate.subject is required");
assert.ok(report.certificate?.thumbprint, "certificate.thumbprint is required");
assert.ok(thumbprintPattern.test(report.certificate.thumbprint), "certificate.thumbprint must be a certificate thumbprint");
assert.ok(report.certificate?.issuer, "certificate.issuer is required");
assert.ok(isoDate.test(report.certificate.validFrom), "certificate.validFrom must be YYYY-MM-DD");
assert.ok(isoDate.test(report.certificate.validTo), "certificate.validTo must be YYYY-MM-DD");
assert.ok(Date.parse(report.certificate.validTo) > Date.parse(report.signedAt), "certificate.validTo must be after signedAt");
assert.ok(report.certificate?.timestampAuthority, "certificate.timestampAuthority is required");

assert.ok(Array.isArray(report.artifacts), "artifacts must be an array");
assert.ok(report.artifacts.length > 0, "at least one signed artifact is required");

const artifacts = report.artifacts.map((artifact, index) => {
  assert.ok(validArtifactTypes.has(artifact.type), `artifacts[${index}].type is unsupported`);
  assert.ok(artifact.path, `artifacts[${index}].path is required`);
  const artifactPath = path.resolve(artifact.path);
  assert.ok(existsSync(artifactPath), `signed artifact does not exist: ${artifact.path}`);
  assert.ok(statSync(artifactPath).isFile(), `signed artifact must be a file: ${artifact.path}`);
  const sha256 = sha256FileHex(artifactPath);
  if (artifact.sha256) {
    assert.ok(sha256Pattern.test(artifact.sha256), `artifacts[${index}].sha256 must be a SHA-256 hex digest`);
    assert.equal(artifact.sha256, sha256, `artifacts[${index}].sha256 does not match the artifact`);
  }
  assertPassed(artifact.signatureStatus, `artifacts[${index}].signatureStatus must be passed`);
  assertPassed(artifact.timestampStatus, `artifacts[${index}].timestampStatus must be passed`);
  assertPassed(artifact.authenticodeStatus, `artifacts[${index}].authenticodeStatus must be valid`);
  return {
    type: artifact.type,
    path: artifactPath,
    sha256,
    signatureStatus: artifact.signatureStatus,
    timestampStatus: artifact.timestampStatus,
    authenticodeStatus: artifact.authenticodeStatus
  };
});

const requiredChecks = [
  "packageBuiltOnReleaseHost",
  "signaturesVerified",
  "timestampsVerified",
  "hashesRecorded",
  "rollbackArtifactSigned",
  "uninstallDrillCovered"
];
assert.ok(report.checks && typeof report.checks === "object", "checks are required");
for (const check of requiredChecks) {
  assertPassed(report.checks[check], `checks.${check} must be passed`);
}

assert.ok(report.approvals?.releaseOwner, "approvals.releaseOwner is required");
assert.ok(report.approvals?.securityReviewer, "approvals.securityReviewer is required");
assert.ok(report.approvals?.operationsOwner, "approvals.operationsOwner is required");
assert.ok(report.approvals?.changeTicket, "approvals.changeTicket is required");

assert.equal(report.redaction?.containsPfxPassword, false, "redaction.containsPfxPassword must be false");
assert.equal(report.redaction?.containsPrivateKeyMaterial, false, "redaction.containsPrivateKeyMaterial must be false");
assert.equal(report.redaction?.containsSigningToken, false, "redaction.containsSigningToken must be false");

if (strict) {
  assert.ok(/^CHG-|^REQ-|^INC-/i.test(report.approvals.changeTicket), "strict mode requires a change ticket reference");
}

const result = {
  format: "sentinel-windows-signing-report-validation-v1",
  reportPath,
  strict,
  signedAt: report.signedAt,
  releaseHostHash: report.releaseHost.hostnameHash,
  artifactCount: artifacts.length,
  artifacts,
  validated: true
};

if (outputPath) {
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(result, null, 2));
}

console.log(JSON.stringify(result, null, 2));
