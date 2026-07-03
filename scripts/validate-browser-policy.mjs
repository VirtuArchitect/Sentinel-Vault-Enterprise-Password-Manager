import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

const policyDir = path.resolve(args.get("--policy-dir") || "artifacts/browser/policy");
const chromePolicyPath = path.resolve(args.get("--chrome-policy") || path.join(policyDir, "chrome-policy.json"));
const edgePolicyPath = path.resolve(args.get("--edge-policy") || path.join(policyDir, "edge-policy.json"));
const outputPath = args.get("--out") ? path.resolve(args.get("--out")) : null;
const extensionIdPattern = /^[a-p]{32}$/;
const allowedHosts = new Set(["http://127.0.0.1:5173/*", "http://localhost:5173/*"]);
const blockedPermissions = new Set(["history", "bookmarks", "downloads"]);
const expectedUpdateUrls = {
  chrome: "https://clients2.google.com/service/update2/crx",
  edge: "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
};

const assertExactSet = (actual, expected, label) => {
  assert.ok(Array.isArray(actual), `${label} must be an array`);
  assert.equal(actual.length, expected.size, `${label} count mismatch`);
  for (const value of actual) {
    assert.ok(expected.has(value), `${label} contains unexpected value: ${value}`);
  }
};

const validatePolicy = (browser, policyPath) => {
  assert.ok(existsSync(policyPath), `${browser} policy not found: ${policyPath}`);
  const policy = JSON.parse(readFileSync(policyPath, "utf8"));
  assert.ok(Array.isArray(policy.ExtensionInstallForcelist), `${browser}.ExtensionInstallForcelist must be an array`);
  assert.equal(policy.ExtensionInstallForcelist.length, 1, `${browser}.ExtensionInstallForcelist must force install exactly one extension`);
  assert.ok(policy.ExtensionSettings && typeof policy.ExtensionSettings === "object", `${browser}.ExtensionSettings is required`);

  const extensionIds = Object.keys(policy.ExtensionSettings);
  assert.equal(extensionIds.length, 1, `${browser}.ExtensionSettings must include exactly one extension`);
  const extensionId = extensionIds[0];
  assert.ok(extensionIdPattern.test(extensionId), `${browser} policy must use a production browser extension ID`);

  const settings = policy.ExtensionSettings[extensionId];
  const expectedUpdateUrl = expectedUpdateUrls[browser];
  assert.equal(settings.installation_mode, "force_installed", `${browser} policy must force install the extension`);
  assert.equal(settings.update_url, expectedUpdateUrl, `${browser} policy update_url mismatch`);
  assert.ok(
    policy.ExtensionInstallForcelist.includes(`${extensionId};${expectedUpdateUrl}`),
    `${browser}.ExtensionInstallForcelist must match extension ID and update URL`
  );
  assertExactSet(settings.runtime_allowed_hosts, allowedHosts, `${browser}.runtime_allowed_hosts`);
  assertExactSet(settings.blocked_permissions, blockedPermissions, `${browser}.blocked_permissions`);
  assert.equal(settings.runtime_allowed_hosts.some((host) => host.includes("*://*") || host === "<all_urls>"), false, `${browser} policy cannot allow wildcard web hosts`);

  return {
    browser,
    policyPath,
    extensionId,
    updateUrl: settings.update_url,
    runtimeAllowedHosts: settings.runtime_allowed_hosts.length,
    blockedPermissions: settings.blocked_permissions.length
  };
};

const results = [];
if (existsSync(chromePolicyPath)) {
  results.push(validatePolicy("chrome", chromePolicyPath));
} else if (args.has("--require-chrome")) {
  assert.fail(`chrome policy not found: ${chromePolicyPath}`);
}

if (existsSync(edgePolicyPath)) {
  results.push(validatePolicy("edge", edgePolicyPath));
} else if (args.has("--require-edge")) {
  assert.fail(`edge policy not found: ${edgePolicyPath}`);
}

assert.ok(results.length > 0, "At least one rendered browser policy must be validated");

const report = {
  format: "sentinel-browser-policy-validation-v1",
  policyDir,
  validatedAt: new Date().toISOString(),
  policyCount: results.length,
  policies: results,
  validated: true
};

if (outputPath) {
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(report, null, 2));
}

console.log(JSON.stringify(report, null, 2));
