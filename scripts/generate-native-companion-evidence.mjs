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
const outputPath = args.get("--out") || "artifacts/native/native-companion-evidence.json";
const artifactValidationPath = args.get("--artifact-validation");
const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
const releaseStatus = args.get("--status") || "planned";
const releaseVersion = args.get("--version") || packageJson.version;
const releaseDate = args.get("--release-date") || "YYYY-MM-DD";
const buildHost = args.get("--build-host") || os.hostname();
const allowedStatuses = new Set(["planned", "pilot", "production", "suspended"]);
const allowedArtifactTypes = new Set(["companion-exe", "native-messaging-host", "credential-provider-dll", "installer"]);

assert.ok(allowedStatuses.has(releaseStatus), "status must be planned, pilot, production, or suspended");
assert.ok(artifactPaths.length > 0, "At least one --artifact path is required");

const safeGit = (...gitArgs) => {
  try {
    return execFileSync("git", gitArgs, { encoding: "utf8" }).trim();
  } catch {
    return null;
  }
};

const artifactType = (artifactPath) => {
  const explicit = args.get("--artifact-type");
  if (explicit) return explicit;
  const name = path.basename(artifactPath).toLowerCase();
  if (name.endsWith(".dll")) return "credential-provider-dll";
  if (name.endsWith(".msi") || name.endsWith(".msix")) return "installer";
  if (name.endsWith(".json")) return "native-messaging-host";
  return "companion-exe";
};

const sha256FileHex = (filePath) => crypto.createHash("sha256").update(readFileSync(filePath)).digest("hex");

const artifactValidation = artifactValidationPath ? JSON.parse(readFileSync(artifactValidationPath, "utf8")) : null;
if (artifactValidation) {
  assert.equal(
    artifactValidation.format,
    "sentinel-native-release-artifact-validation-v1",
    "artifact validation report must use sentinel-native-release-artifact-validation-v1"
  );
  assert.equal(artifactValidation.validated, true, "artifact validation report must be validated");
}

const artifacts = artifactPaths.map((artifactPath) => {
  assert.ok(existsSync(artifactPath), `Native companion artifact not found: ${artifactPath}`);
  const stats = statSync(artifactPath);
  assert.ok(stats.isFile(), `Native companion artifact must be a file: ${artifactPath}`);
  const type = artifactType(artifactPath);
  assert.ok(allowedArtifactTypes.has(type), `Unsupported artifact type: ${type}`);
  return {
    name: path.basename(artifactPath),
    type,
    path: path.resolve(artifactPath),
    size: stats.size,
    sha256: sha256FileHex(artifactPath),
    authenticodeStatus: args.get("--authenticode-status") || "not-signed",
    signerThumbprint: args.get("--signer-thumbprint") || "replace-with-thumbprint"
  };
});

if (artifactValidation) {
  for (const artifact of artifacts) {
    const validatedArtifact = artifactValidation.artifacts.find((candidate) => candidate.name === artifact.name);
    assert.ok(validatedArtifact, `${artifact.name} must be present in artifact validation report`);
    assert.equal(validatedArtifact.type, artifact.type, `${artifact.name}.type must match artifact validation report`);
    assert.equal(validatedArtifact.sha256, artifact.sha256, `${artifact.name}.sha256 must match artifact validation report`);
  }
}

const evidence = {
  format: "sentinel-native-companion-evidence-v1",
  component: "windows-companion",
  releaseStatus,
  releaseVersion,
  releaseDate,
  buildHost,
  sourceCommit: args.get("--source-commit") || safeGit("rev-parse", "HEAD") || "replace-with-git-sha",
  architectures: (args.get("--architectures") || "x64").split(",").map((value) => value.trim()).filter(Boolean),
  artifacts,
  artifactValidation: artifactValidation ? {
    reportPath: path.resolve(artifactValidationPath),
    format: artifactValidation.format,
    validated: artifactValidation.validated,
    requireSignature: artifactValidation.requireSignature,
    artifactCount: artifactValidation.artifactCount,
    signedArtifactCount: artifactValidation.signedArtifactCount,
    artifacts: artifactValidation.artifacts.map((artifact) => ({
      name: artifact.name,
      type: artifact.type,
      sha256: artifact.sha256,
      authenticodeStatus: artifact.authenticodeStatus
    }))
  } : {
    reportPath: "replace-with-native-artifact-validation.json",
    format: "sentinel-native-release-artifact-validation-v1",
    validated: false,
    requireSignature: false,
    artifactCount: 0,
    signedArtifactCount: 0,
    artifacts: []
  },
  nativeMessaging: {
    enabled: args.get("--native-messaging-enabled") !== "false",
    manifestPath: args.get("--native-messaging-manifest") || "replace-with-native-messaging-manifest-path",
    allowedExtensionIds: [
      args.get("--extension-id") || "replace-with-extension-id"
    ],
    hostPath: args.get("--host-path") || "replace-with-installed-host-path"
  },
  credentialProvider: {
    enabled: args.get("--credential-provider-enabled") === "true",
    clsid: args.get("--credential-provider-clsid") || "replace-with-clsid",
    registrationPath: args.get("--credential-provider-registration") || "replace-with-registry-path",
    allowListedVaultEntriesOnly: true,
    offlineLogonDocumented: false
  },
  securityControls: {
    explicitUserConfirmation: "planned",
    targetWindowDisplayed: "planned",
    elevatedWindowBlocked: "planned",
    secureDesktopBlocked: "planned",
    wildcardTargetsRejected: "planned",
    plaintextMemoryMinimized: "planned",
    transientBuffersCleared: "planned",
    auditMetadataWithoutSecrets: "planned",
    highRiskPromptEnforced: "planned",
    offlineCacheReadOnly: "planned",
    dpapiScopeCurrentUser: "planned",
    noPlaintextSecretStorage: "planned"
  },
  testResults: {
    cleanInstall: "not-run",
    cleanUninstall: "not-run",
    abuseCaseSuite: "not-run",
    autotypeReview: "not-run",
    credentialProviderReview: args.get("--credential-provider-enabled") === "true" ? "not-run" : "not-applicable",
    offlineCacheExpiry: "not-run",
    rollbackDisable: "not-run"
  },
  approvals: {
    securityReviewer: "replace-with-reviewer",
    desktopEngineering: "replace-with-owner",
    releaseOwner: "replace-with-owner",
    changeTicket: "replace-with-ticket"
  },
  rollback: {
    disableProcedure: "Disable native messaging policy, unregister credential provider if installed, and uninstall companion package.",
    tested: false
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Native companion evidence written: ${outputPath}`);
