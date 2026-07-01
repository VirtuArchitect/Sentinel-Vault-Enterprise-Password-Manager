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
    writeFileSync(artifactPath, "browser extension package fixture");

    runGenerator([
      "--artifact", artifactPath,
      "--environment", "pilot",
      "--owner", "Desktop Engineering",
      "--out", evidencePath
    ]);

    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    assert.equal(evidence.format, "sentinel-browser-extension-rollout-evidence-v1");
    assert.equal(evidence.environment, "pilot");
    assert.equal(evidence.owner, "Desktop Engineering");
    assert.equal(evidence.package.sha256, crypto.createHash("sha256").update("browser extension package fixture").digest("hex"));
    assert.equal(evidence.package.manifestVersion, 3);
    assert.equal(evidence.storeReview.manifestV3, true);
    assert.match(runValidator(evidencePath), /validated/);
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
