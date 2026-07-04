import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runGenerator = (args) => execFileSync(process.execPath, [
  "scripts/generate-browser-rollout-evidence.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (evidencePath) => execFileSync(process.execPath, [
  "scripts/validate-browser-rollout-evidence.mjs",
  evidencePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("browser rollout evidence generator writes valid planned evidence from package artifact", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-browser-rollout-generator-"));
  try {
    const artifactPath = path.join(dir, "sentinel-vault-autofill.zip");
    const evidencePath = path.join(dir, "browser-rollout-evidence.json");
    const packageBytes = "browser extension package fixture";
    const packageSha256 = crypto.createHash("sha256").update(packageBytes).digest("hex");
    const validationPath = path.join(dir, "browser-extension-package-validation.json");
    writeFileSync(artifactPath, packageBytes);
    writeFileSync(validationPath, JSON.stringify({
      format: "sentinel-browser-extension-package-validation-v1",
      validated: true,
      packageSha256,
      manifestVersion: 3,
      requiredFileCount: 6,
      hostPermissions: ["http://127.0.0.1:5173/*", "http://localhost:5173/*"],
      permissions: ["activeTab", "scripting"]
    }, null, 2));

    runGenerator([
      "--artifact", artifactPath,
      "--package-validation", validationPath,
      "--environment", "pilot",
      "--owner", "Desktop Engineering",
      "--out", evidencePath
    ]);

    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.format, "sentinel-browser-extension-rollout-evidence-v1");
    assert.equal(evidence.environment, "pilot");
    assert.equal(evidence.owner, "Desktop Engineering");
    assert.equal(evidence.package.sha256, packageSha256);
    assert.equal(evidence.packageValidation.validated, true);
    assert.equal(evidence.packageValidation.packageSha256, packageSha256);
    assert.equal(evidence.packageValidation.requiredFileCount, 6);
    assert.equal(evidence.package.manifestVersion, 3);
    assert.equal(evidence.storeReview.manifestV3, true);
    assert.match(runValidator(evidencePath), /validated/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("browser rollout validator rejects deployed evidence without validated package report", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-browser-rollout-validation-fail-"));
  try {
    const artifactPath = path.join(dir, "sentinel-vault-autofill.zip");
    const evidencePath = path.join(dir, "browser-rollout-evidence.json");
    writeFileSync(artifactPath, "browser extension package fixture");
    runGenerator([
      "--artifact", artifactPath,
      "--environment", "production",
      "--owner", "Desktop Engineering",
      "--status", "production",
      "--chrome-extension-id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "--edge-extension-id", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "--pilot-scope", "Desktop Pilot",
      "--production-scope", "Enterprise Browsers",
      "--out", evidencePath
    ]);
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    evidence.rolloutRings = evidence.rolloutRings.map((ring) => ({
      ...ring,
      status: "passed",
      startDate: "2026-07-01",
      validation: "passed"
    }));
    evidence.storeReview.privacyStatementApproved = true;
    evidence.storeReview.screenshotsRedacted = true;
    evidence.rollback.tested = true;
    evidence.approvals = {
      securityReviewer: "Security Reviewer",
      desktopEngineering: "Desktop Engineering",
      businessOwner: "Business Owner"
    };
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));

    assert.throws(() => runValidator(evidencePath), /validated browser extension package report is required/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("browser rollout evidence generator rejects missing package artifacts", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-browser-rollout-generator-fail-"));
  try {
    assert.throws(() => runGenerator([
      "--artifact", path.join(dir, "missing.zip"),
      "--out", path.join(dir, "browser-rollout-evidence.json")
    ]), /package not found/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
