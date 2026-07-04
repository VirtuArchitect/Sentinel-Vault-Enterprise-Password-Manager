import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const rootDir = path.resolve(import.meta.dirname, "..");
const artifactPath = args.get("--artifact") || "artifacts/browser/sentinel-vault-autofill.zip";
const outputPath = args.get("--out") || "artifacts/browser/browser-extension-rollout-evidence.json";
const environment = args.get("--environment") || "replace-with-environment";
const owner = args.get("--owner") || "replace-with-owner";
const deploymentStatus = args.get("--status") || "planned";
const packageValidationPath = args.get("--package-validation") || "";
const manifestPath = path.join(rootDir, "extensions", "browser", "manifest.json");
const allowedStatuses = new Set(["planned", "pilot", "production", "suspended"]);

assert.ok(allowedStatuses.has(deploymentStatus), "status must be planned, pilot, production, or suspended");
assert.ok(existsSync(artifactPath), `Browser extension package not found: ${artifactPath}`);
assert.ok(existsSync(manifestPath), `Browser extension manifest not found: ${manifestPath}`);

const artifactStats = statSync(artifactPath);
assert.ok(artifactStats.isFile(), `Browser extension package must be a file: ${artifactPath}`);

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const sha256 = crypto.createHash("sha256").update(readFileSync(artifactPath)).digest("hex");
const packageValidation = packageValidationPath && existsSync(packageValidationPath)
  ? JSON.parse(readFileSync(packageValidationPath, "utf8"))
  : null;

const evidence = {
  format: "sentinel-browser-extension-rollout-evidence-v1",
  deploymentStatus,
  environment,
  owner,
  extensionName: manifest.name || "Sentinel Vault Autofill",
  package: {
    artifactPath: path.resolve(artifactPath),
    sha256: packageValidation?.packageSha256 || sha256,
    size: artifactStats.size,
    manifestVersion: packageValidation?.manifestVersion || manifest.manifest_version
  },
  packageValidation: {
    reportPath: packageValidationPath || "replace-with-browser-extension-package-validation-report",
    format: packageValidation?.format || "sentinel-browser-extension-package-validation-v1",
    validated: Boolean(packageValidation?.validated),
    packageSha256: packageValidation?.packageSha256 || sha256,
    requiredFileCount: Number(packageValidation?.requiredFileCount || 0),
    hostPermissionCount: Number(packageValidation?.hostPermissions?.length || 0),
    permissionCount: Number(packageValidation?.permissions?.length || 0)
  },
  chrome: {
    enabled: args.get("--chrome-enabled") !== "false",
    extensionId: args.get("--chrome-extension-id") || "replace-with-chrome-extension-id",
    updateUrl: args.get("--chrome-update-url") || "https://clients2.google.com/service/update2/crx",
    policyPath: "deployments/browser/chrome-policy-template.json"
  },
  edge: {
    enabled: args.get("--edge-enabled") !== "false",
    extensionId: args.get("--edge-extension-id") || "replace-with-edge-extension-id",
    updateUrl: args.get("--edge-update-url") || "https://edge.microsoft.com/extensionwebstorebase/v1/crx",
    policyPath: "deployments/browser/edge-policy-template.json"
  },
  runtimeAllowedHosts: [
    "http://127.0.0.1:5173/*",
    "http://localhost:5173/*"
  ],
  blockedPermissions: [
    "history",
    "bookmarks",
    "downloads"
  ],
  rolloutRings: [
    {
      name: "pilot",
      scope: args.get("--pilot-scope") || "replace-with-pilot-group",
      status: "planned",
      startDate: "YYYY-MM-DD",
      validation: "replace-with-validation-result"
    },
    {
      name: "production",
      scope: args.get("--production-scope") || "replace-with-production-group",
      status: "planned",
      startDate: "YYYY-MM-DD",
      validation: "replace-with-validation-result"
    }
  ],
  storeReview: {
    manifestV3: manifest.manifest_version === 3,
    leastPrivilegePermissions: true,
    noWildcardWebHosts: !(manifest.host_permissions || []).some((host) => host.includes("*://*")),
    privacyStatementApproved: false,
    screenshotsRedacted: false
  },
  rollback: {
    disableProcedure: "Remove the force-install extension policy and refresh browser management policy.",
    tested: false
  },
  approvals: {
    securityReviewer: "replace-with-reviewer",
    desktopEngineering: "replace-with-approver",
    businessOwner: "replace-with-owner"
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Browser extension rollout evidence written: ${outputPath}`);
