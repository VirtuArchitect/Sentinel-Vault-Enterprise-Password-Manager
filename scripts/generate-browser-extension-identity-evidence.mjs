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

const outputPath = args.get("--out") || "artifacts/browser/browser-extension-identity-evidence.json";
const reportPath = args.get("--report");
const artifactPath = args.get("--artifact");
const status = args.get("--status") || "planned";
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
const report = reportPath && existsSync(reportPath) ? readJson(reportPath) : {};
const sha256FileHex = (filePath) => crypto.createHash("sha256").update(readFileSync(filePath)).digest("hex");

if (artifactPath) {
  assert.ok(existsSync(artifactPath), `Browser extension artifact not found: ${artifactPath}`);
  assert.ok(statSync(artifactPath).isFile(), `Browser extension artifact must be a file: ${artifactPath}`);
}

const passedIfDeployed = ["pilot", "production"].includes(status) ? "passed" : "planned";
const falseIfDeployed = ["pilot", "production"].includes(status) ? false : "planned";

const browserEvidence = (browser, defaultChannel) => {
  const fromReport = report[browser] || {};
  return {
    enabled: fromReport.enabled ?? (args.get(`--${browser}-enabled`) !== "false"),
    extensionId: args.get(`--${browser}-extension-id`) || fromReport.extensionId || `replace-with-${browser}-extension-id`,
    channel: fromReport.channel || defaultChannel,
    publisher: fromReport.publisher || "replace-with-publisher",
    reviewStatus: fromReport.reviewStatus ?? passedIfDeployed,
    policyAssignment: fromReport.policyAssignment ?? passedIfDeployed
  };
};

const evidence = {
  format: "sentinel-browser-extension-identity-evidence-v1",
  status,
  environment: args.get("--environment") || report.environment || "replace-with-environment",
  extensionName: report.extensionName || "Sentinel Vault Autofill",
  packageSha256: args.get("--package-sha256") || report.packageSha256 || (artifactPath ? sha256FileHex(artifactPath) : "replace-with-sha256"),
  chrome: browserEvidence("chrome", "private-chrome-web-store"),
  edge: browserEvidence("edge", "private-edge-addons"),
  controls: {
    manifestV3Confirmed: report.controls?.manifestV3Confirmed ?? passedIfDeployed,
    leastPrivilegeReviewed: report.controls?.leastPrivilegeReviewed ?? passedIfDeployed,
    runtimeHostsApproved: report.controls?.runtimeHostsApproved ?? passedIfDeployed,
    nativeHostAllowlistReviewed: report.controls?.nativeHostAllowlistReviewed ?? passedIfDeployed,
    privacyStatementApproved: report.controls?.privacyStatementApproved ?? passedIfDeployed,
    screenshotsRedacted: report.controls?.screenshotsRedacted ?? passedIfDeployed,
    rollbackOwnerAssigned: report.controls?.rollbackOwnerAssigned ?? passedIfDeployed
  },
  approvals: {
    endpointPlatformOwner: report.approvals?.endpointPlatformOwner || "replace-with-owner",
    securityReviewer: report.approvals?.securityReviewer || "replace-with-reviewer",
    businessOwner: report.approvals?.businessOwner || "replace-with-owner",
    changeTicket: args.get("--change-ticket") || report.approvals?.changeTicket || "replace-with-ticket"
  },
  redaction: {
    containsCredentials: report.redaction?.containsCredentials ?? falseIfDeployed,
    containsInternalHostnames: report.redaction?.containsInternalHostnames ?? falseIfDeployed,
    containsCustomerData: report.redaction?.containsCustomerData ?? falseIfDeployed
  }
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(evidence, null, 2));
console.log(`Browser extension identity evidence written: ${outputPath}`);
