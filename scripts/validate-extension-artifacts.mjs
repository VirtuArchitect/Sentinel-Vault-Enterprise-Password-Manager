import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(path.join(rootDir, "extensions/browser/manifest.json"), "utf8"));
const serviceWorker = readFileSync(path.join(rootDir, "extensions/browser/service-worker.js"), "utf8");
const popup = readFileSync(path.join(rootDir, "extensions/browser/popup.js"), "utf8");
const contentScript = readFileSync(path.join(rootDir, "extensions/browser/content-script.js"), "utf8");
const companion = readFileSync(path.join(rootDir, "companions/windows/sentinel-tray-helper.ps1"), "utf8");
const chromePolicy = JSON.parse(readFileSync(path.join(rootDir, "deployments/browser/chrome-policy-template.json"), "utf8"));
const edgePolicy = JSON.parse(readFileSync(path.join(rootDir, "deployments/browser/edge-policy-template.json"), "utf8"));

assert.equal(manifest.manifest_version, 3);
assert.equal(manifest.name, "Sentinel Vault Autofill");
assert.ok(manifest.background?.service_worker);
assert.ok(Array.isArray(manifest.permissions));
assert.ok(manifest.permissions.includes("activeTab"));
assert.ok(Array.isArray(manifest.host_permissions));
assert.ok(manifest.host_permissions.some((permission) => permission.includes("127.0.0.1")));
assert.ok(manifest.host_permissions.some((permission) => permission.includes("localhost")));
assert.equal(manifest.host_permissions.some((permission) => permission.includes("https://*")), false);
assert.match(serviceWorker, /sentinel-vault-matches/);
assert.match(serviceWorker, /sentinel-vault-fill/);
assert.match(serviceWorker, /chrome\.storage\.session/);
assert.match(popup, /Confirm Fill/);
assert.match(contentScript, /sentinel-vault-autofill/);
assert.match(contentScript, /input\[type='password'\]/);
assert.ok(existsSync(path.join(rootDir, "scripts/package-browser-extension.mjs")));
for (const policy of [chromePolicy, edgePolicy]) {
  assert.ok(Array.isArray(policy.ExtensionInstallForcelist));
  assert.ok(policy.ExtensionSettings["replace-with-extension-id"]);
  assert.deepEqual(policy.ExtensionSettings["replace-with-extension-id"].runtime_allowed_hosts, [
    "http://127.0.0.1:5173/*",
    "http://localhost:5173/*"
  ]);
}
assert.match(companion, /function Get-SentinelHash/);
assert.match(companion, /function Clear-SentinelClipboard/);
assert.match(companion, /function Invoke-SentinelAutoType/);
assert.match(companion, /function Start-SentinelTray/);
assert.match(companion, /function Protect-SentinelOfflineCache/);
assert.match(companion, /ProtectedData/);
assert.match(companion, /offline-cache\.dpapi/);
assert.match(companion, /IUnderstandAutotypeRisk/);
assert.match(companion, /NotifyIcon/);
assert.match(companion, /ConvertTo-SendKeysLiteral/);
assert.match(companion, /Set-Clipboard/);
assert.match(companion, /Get-Clipboard/);
assert.match(companion, /clipboard-marker\.json/);

console.log("Extension and companion artifacts validated.");
