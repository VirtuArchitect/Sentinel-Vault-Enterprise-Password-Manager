import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runRenderer = (args) => execFileSync(process.execPath, [
  "scripts/render-browser-policy.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runValidator = (args) => execFileSync(process.execPath, [
  "scripts/validate-browser-policy.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("browser policy validator accepts rendered Chrome and Edge force-install policies", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-browser-policy-"));
  try {
    const evidencePath = path.join(dir, "browser-rollout-evidence.json");
    const policyDir = path.join(dir, "policy");
    const reportPath = path.join(dir, "browser-policy-validation.json");
    writeFileSync(evidencePath, JSON.stringify({
      format: "sentinel-browser-extension-rollout-evidence-v1",
      runtimeAllowedHosts: [
        "http://127.0.0.1:5173/*",
        "http://localhost:5173/*"
      ],
      blockedPermissions: ["history", "bookmarks", "downloads"],
      chrome: {
        enabled: true,
        extensionId: "abcdefghijklmnopabcdefghijklmnop",
        updateUrl: "https://clients2.google.com/service/update2/crx"
      },
      edge: {
        enabled: true,
        extensionId: "ponmlkjihgfedcbaponmlkjihgfedcba",
        updateUrl: "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
      }
    }, null, 2));

    runRenderer(["--evidence", evidencePath, "--out-dir", policyDir]);
    const output = runValidator([
      "--policy-dir", policyDir,
      "--require-chrome",
      "--require-edge",
      "--out", reportPath
    ]);
    const result = JSON.parse(output);
    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    assert.equal(result.validated, true);
    assert.equal(result.policyCount, 2);
    assert.deepEqual(report.policies.map((policy) => policy.browser), ["chrome", "edge"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("browser policy validator rejects placeholder and wildcard policy output", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-browser-policy-fail-"));
  try {
    const policyDir = path.join(dir, "policy");
    const policyPath = path.join(policyDir, "chrome-policy.json");
    mkdirSync(policyDir, { recursive: true });
    writeFileSync(policyPath, JSON.stringify({
      ExtensionInstallForcelist: [
        "replace-with-extension-id;https://clients2.google.com/service/update2/crx"
      ],
      ExtensionSettings: {
        "replace-with-extension-id": {
          installation_mode: "force_installed",
          update_url: "https://clients2.google.com/service/update2/crx",
          runtime_allowed_hosts: ["*://*/*"],
          blocked_permissions: ["history", "bookmarks", "downloads"]
        }
      }
    }, null, 2));

    assert.throws(() => runValidator(["--policy-dir", policyDir, "--require-chrome"]), /production browser extension ID/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
