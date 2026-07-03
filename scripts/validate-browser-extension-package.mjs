import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

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

const rootDir = path.resolve(import.meta.dirname, "..");
const packagePath = path.resolve(args.get("--package") || args.get("--artifact") || path.join("artifacts", "browser", "sentinel-vault-autofill.zip"));
const outPath = args.get("--out") ? path.resolve(args.get("--out")) : null;
const keepExtracted = args.has("--keep-extracted");
const extractDir = args.get("--extract-dir")
  ? path.resolve(args.get("--extract-dir"))
  : mkdtempSync(path.join(os.tmpdir(), "sentinel-browser-extension-validation-"));

const requiredFiles = [
  "manifest.json",
  "service-worker.js",
  "content-script.js",
  "popup.html",
  "popup.css",
  "popup.js"
];

assert.ok(existsSync(packagePath), `Browser extension package not found: ${packagePath}`);
if (args.get("--extract-dir")) {
  assert.equal(existsSync(extractDir), false, `Extraction directory already exists: ${extractDir}`);
  mkdirSync(extractDir, { recursive: true });
}

const tar = process.platform === "win32" ? "tar.exe" : "tar";

try {
  const extracted = spawnSync(tar, ["-xf", packagePath, "-C", extractDir], {
    cwd: rootDir,
    encoding: "utf8",
    windowsHide: true
  });
  if (extracted.status !== 0) {
    throw new Error(`${tar} failed extracting ${packagePath}: ${extracted.stderr || extracted.stdout}`);
  }

  for (const file of requiredFiles) {
    assert.ok(existsSync(path.join(extractDir, file)), `Missing required browser extension file: ${file}`);
  }

  const manifest = JSON.parse(readFileSync(path.join(extractDir, "manifest.json"), "utf8"));
  assert.equal(manifest.manifest_version, 3, "Browser extension must use Manifest V3");
  assert.equal(manifest.name, "Sentinel Vault Autofill", "Browser extension manifest name mismatch");
  assert.equal(manifest.background?.service_worker, "service-worker.js", "Browser extension service worker mismatch");
  assert.ok(Array.isArray(manifest.permissions), "Browser extension permissions must be an array");
  assert.ok(manifest.permissions.includes("activeTab"), "Browser extension must use activeTab for explicit fill");
  assert.equal(manifest.permissions.includes("history"), false, "Browser extension must not request history permission");
  assert.equal(manifest.permissions.includes("bookmarks"), false, "Browser extension must not request bookmarks permission");
  assert.equal(manifest.permissions.includes("downloads"), false, "Browser extension must not request downloads permission");
  assert.ok(Array.isArray(manifest.host_permissions), "Browser extension host_permissions must be an array");
  assert.ok(manifest.host_permissions.some((permission) => permission.includes("127.0.0.1")), "Browser extension must allow localhost console by IP");
  assert.ok(manifest.host_permissions.some((permission) => permission.includes("localhost")), "Browser extension must allow localhost console by name");
  assert.equal(manifest.host_permissions.some((permission) => permission.includes("https://*")), false, "Browser extension must not allow wildcard HTTPS hosts");
  assert.equal(manifest.host_permissions.some((permission) => permission.includes("http://*")), false, "Browser extension must not allow wildcard HTTP hosts");

  const packageBytes = readFileSync(packagePath);
  const result = {
    format: "sentinel-browser-extension-package-validation-v1",
    packagePath,
    extractedTo: extractDir,
    packageSha256: crypto.createHash("sha256").update(packageBytes).digest("hex"),
    packageBytes: packageBytes.length,
    manifestVersion: manifest.manifest_version,
    extensionName: manifest.name,
    requiredFileCount: requiredFiles.length,
    hostPermissions: manifest.host_permissions,
    permissions: manifest.permissions,
    validated: true
  };
  const json = JSON.stringify(result, null, 2);
  if (outPath) {
    mkdirSync(path.dirname(outPath), { recursive: true });
    writeFileSync(outPath, json, { encoding: "utf8" });
  }
  console.log(json);
} finally {
  if (!keepExtracted && existsSync(extractDir)) {
    rmSync(extractDir, { recursive: true, force: true });
  }
}
