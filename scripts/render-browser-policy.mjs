import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = new Map();
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
for (let index = 0; index < cliArgs.length; index += 2) {
  args.set(cliArgs[index], cliArgs[index + 1]);
}

const evidencePath = args.get("--evidence") || "docs/templates/browser-extension-rollout-evidence.json";
const outDir = args.get("--out-dir") || "artifacts/browser/policy";
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
const extensionIdPattern = /^[a-p]{32}$/;

assert.equal(evidence.format, "sentinel-browser-extension-rollout-evidence-v1");
assert.ok(Array.isArray(evidence.runtimeAllowedHosts), "runtimeAllowedHosts must be an array");
assert.ok(Array.isArray(evidence.blockedPermissions), "blockedPermissions must be an array");

const renderPolicy = (browser, updateUrl) => {
  const config = evidence[browser];
  if (!config?.enabled) return null;
  assert.ok(extensionIdPattern.test(config.extensionId), `${browser}.extensionId must be a production browser extension ID`);
  return {
    ExtensionInstallForcelist: [
      `${config.extensionId};${config.updateUrl || updateUrl}`
    ],
    ExtensionSettings: {
      [config.extensionId]: {
        installation_mode: "force_installed",
        update_url: config.updateUrl || updateUrl,
        runtime_allowed_hosts: evidence.runtimeAllowedHosts,
        blocked_permissions: evidence.blockedPermissions
      }
    }
  };
};

const outputs = [
  ["chrome-policy.json", renderPolicy("chrome", "https://clients2.google.com/service/update2/crx")],
  ["edge-policy.json", renderPolicy("edge", "https://edge.microsoft.com/extensionwebstorebase/v1/crx")]
].filter(([, policy]) => policy);

assert.ok(outputs.length > 0, "At least one browser policy must be enabled in the evidence file");
mkdirSync(outDir, { recursive: true });

for (const [file, policy] of outputs) {
  const outputPath = path.join(outDir, file);
  writeFileSync(outputPath, JSON.stringify(policy, null, 2));
  console.log(`Browser policy rendered: ${outputPath}`);
}
