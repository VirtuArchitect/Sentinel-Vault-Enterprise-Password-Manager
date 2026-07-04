import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const artifactPaths = cliArgs.flatMap((arg, index) => (arg === "--artifact" ? [cliArgs[index + 1]] : [])).filter(Boolean);
const outputPath = args.get("--out") || "artifacts/release/windows-release-evidence.json";
const packageValidationPath = args.get("--package-validation");
const releaseVersion = args.get("--version") || JSON.parse(readFileSync("package.json", "utf8")).version;
const releaseDate = args.get("--release-date") || new Date().toISOString().slice(0, 10);
const buildHost = args.get("--build-host") || os.hostname();
const signatureVerification = args.get("--signature-verification") || "not-signed";
const rollbackTested = args.get("--rollback-tested") === "true";

const git = (...gitArgs) => execFileSync("git", gitArgs, { encoding: "utf8" }).trim();
const safeGit = (...gitArgs) => {
  try {
    return git(...gitArgs);
  } catch {
    return null;
  }
};

const sha256FileHex = (filePath) => crypto.createHash("sha256").update(readFileSync(filePath)).digest("hex");

assert.ok(artifactPaths.length > 0, "At least one --artifact path is required");

const packageValidation = packageValidationPath ? JSON.parse(readFileSync(packageValidationPath, "utf8").replace(/^\uFEFF/, "")) : null;
if (packageValidation) {
  assert.equal(packageValidation.format, "sentinel-windows-package-validation-v1", "package validation report format is unsupported");
  assert.equal(packageValidation.validated, true, "package validation report must be validated");
}

const artifacts = artifactPaths.map((artifactPath) => {
  assert.ok(existsSync(artifactPath), `Windows release artifact not found: ${artifactPath}`);
  const stats = statSync(artifactPath);
  assert.ok(stats.isFile(), `Windows release artifact must be a file: ${artifactPath}`);
  return {
    name: path.basename(artifactPath),
    path: path.resolve(artifactPath),
    size: stats.size,
    sha256: sha256FileHex(artifactPath),
    authenticodeStatus: args.get("--authenticode-status") || (signatureVerification === "valid" ? "Valid" : "not-signed"),
    signerThumbprint: args.get("--signer-thumbprint") || "replace-with-thumbprint"
  };
});

if (packageValidation) {
  const packageArtifact = artifacts.find((artifact) => path.resolve(artifact.path) === path.resolve(packageValidation.packagePath));
  assert.ok(packageArtifact, "package validation report must reference one of the release artifacts");
  assert.equal(packageArtifact.sha256, packageValidation.packageSha256, "package validation hash must match release artifact hash");
}

const evidence = {
  format: "sentinel-windows-release-evidence-v1",
  releaseVersion,
  releaseDate,
  buildHost,
  sourceCommit: args.get("--source-commit") || safeGit("rev-parse", "HEAD") || "replace-with-git-sha",
  checks: {
    pnpmVerify: args.get("--pnpm-verify") || "not-run",
    secretScan: args.get("--secret-scan") || "not-run",
    dependencyAudit: args.get("--dependency-audit") || "not-run",
    windowsPackage: args.get("--windows-package") || "passed",
    signatureVerification
  },
  packageValidation: packageValidation ? {
    reportPath: path.resolve(packageValidationPath),
    format: packageValidation.format,
    validated: packageValidation.validated,
    packagePath: packageValidation.packagePath,
    packageSha256: packageValidation.packageSha256,
    runtimeSmoke: packageValidation.runtimeSmoke,
    requiredFileCount: packageValidation.requiredFileCount
  } : {
    reportPath: "replace-with-windows-package-validation.json",
    format: "sentinel-windows-package-validation-v1",
    validated: false,
    packagePath: "replace-with-package-path",
    packageSha256: "replace-with-sha256",
    runtimeSmoke: "not-run",
    requiredFileCount: 0
  },
  artifacts,
  approvals: {
    releaseOwner: args.get("--release-owner") || "replace-with-owner",
    securityReviewer: args.get("--security-reviewer") || "replace-with-reviewer",
    operationsReviewer: args.get("--operations-reviewer") || "replace-with-reviewer"
  },
  rollback: {
    tested: rollbackTested,
    procedure: "deployments/windows/README.md#upgrade-and-rollback"
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Windows release evidence written: ${outputPath}`);
