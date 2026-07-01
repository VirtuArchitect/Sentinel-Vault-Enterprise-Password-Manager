import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-browser-extension-identity-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-browser-extension-identity-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const extensionId = "a".repeat(32);

test("browser extension identity template validates in planned mode", () => {
  assert.match(runValidator(path.join(rootDir, "docs", "templates", "browser-extension-identity-evidence.json")), /validated/);
});

test("browser extension identity generator creates production evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-browser-identity-"));
  try {
    const artifactPath = path.join(dir, "sentinel-vault-autofill.zip");
    const reportPath = path.join(dir, "browser-identity-report.json");
    const evidencePath = path.join(dir, "browser-extension-identity-evidence.json");
    writeFileSync(artifactPath, "browser package fixture");
    writeFileSync(reportPath, JSON.stringify({
      environment: "production",
      chrome: {
        extensionId,
        publisher: "Sentinel Publisher",
        reviewStatus: "passed",
        policyAssignment: "passed"
      },
      edge: {
        enabled: false,
        extensionId: "b".repeat(32),
        publisher: "Sentinel Publisher"
      },
      approvals: {
        endpointPlatformOwner: "Endpoint Owner",
        securityReviewer: "Security Reviewer",
        businessOwner: "Business Owner",
        changeTicket: "CHG-3001"
      }
    }, null, 2));

    assert.match(runGenerator([
      "--status", "production",
      "--artifact", artifactPath,
      "--report", reportPath,
      "--out", evidencePath
    ]), /written/);

    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.packageSha256, hash("browser package fixture"));
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("browser extension identity validator rejects invalid production IDs", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-browser-identity-fail-"));
  try {
    const evidencePath = path.join(dir, "browser-extension-identity-evidence.json");
    writeFileSync(evidencePath, JSON.stringify({
      format: "sentinel-browser-extension-identity-evidence-v1",
      status: "production",
      environment: "production",
      extensionName: "Sentinel Vault Autofill",
      packageSha256: hash("browser package fixture"),
      chrome: {
        enabled: true,
        extensionId: "invalid-extension-id",
        channel: "private-chrome-web-store",
        publisher: "Sentinel Publisher",
        reviewStatus: "passed",
        policyAssignment: "passed"
      },
      edge: {
        enabled: false,
        extensionId: "b".repeat(32),
        channel: "private-edge-addons",
        publisher: "Sentinel Publisher",
        reviewStatus: "passed",
        policyAssignment: "passed"
      },
      controls: {
        manifestV3Confirmed: "passed",
        leastPrivilegeReviewed: "passed",
        runtimeHostsApproved: "passed",
        nativeHostAllowlistReviewed: "passed",
        privacyStatementApproved: "passed",
        screenshotsRedacted: "passed",
        rollbackOwnerAssigned: "passed"
      },
      approvals: {
        endpointPlatformOwner: "Endpoint Owner",
        securityReviewer: "Security Reviewer",
        businessOwner: "Business Owner",
        changeTicket: "CHG-3001"
      },
      redaction: {
        containsCredentials: false,
        containsInternalHostnames: false,
        containsCustomerData: false
      }
    }, null, 2));

    assert.throws(() => runValidator(evidencePath), /production browser extension ID/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
