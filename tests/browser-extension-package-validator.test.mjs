import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runNode = (args) => execFileSync(process.execPath, args, {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("browser extension package validator writes package evidence", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-browser-extension-package-"));
  try {
    runNode(["scripts/package-browser-extension.mjs"]);
    const reportPath = path.join(dir, "browser-extension-package-validation.json");
    const output = runNode([
      "scripts/validate-browser-extension-package.mjs",
      "--out",
      reportPath
    ]);
    const result = JSON.parse(output);
    const savedResult = JSON.parse(readFileSync(reportPath, "utf8"));

    assert.equal(result.format, "sentinel-browser-extension-package-validation-v1");
    assert.equal(result.extensionName, "Sentinel Vault Autofill");
    assert.equal(result.manifestVersion, 3);
    assert.equal(result.requiredFileCount, 6);
    assert.equal(result.validated, true);
    assert.match(result.packageSha256, /^[a-f0-9]{64}$/);
    assert.ok(result.packageBytes > 0);
    assert.ok(result.hostPermissions.some((permission) => permission.includes("127.0.0.1")));
    assert.equal(result.hostPermissions.some((permission) => permission.includes("https://*")), false);
    assert.deepEqual(savedResult, result);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("browser extension package validator rejects missing packages", () => {
  const missingPath = path.join(tmpdir(), "sentinel-missing-extension.zip");
  if (existsSync(missingPath)) rmSync(missingPath, { force: true });
  assert.throws(() => runNode([
    "scripts/validate-browser-extension-package.mjs",
    "--package",
    missingPath
  ]), /Browser extension package not found/);
});
