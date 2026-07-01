import assert from "node:assert/strict";
import { existsSync, mkdirSync, rmSync, copyFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceDir = path.join(rootDir, "extensions/browser");
const outputDir = path.join(rootDir, "artifacts/browser");
const stageDir = path.join(outputDir, "sentinel-vault-autofill");
const zipPath = path.join(outputDir, "sentinel-vault-autofill.zip");
const requiredFiles = [
  "manifest.json",
  "service-worker.js",
  "content-script.js",
  "popup.html",
  "popup.css",
  "popup.js"
];

for (const file of requiredFiles) {
  assert.ok(existsSync(path.join(sourceDir, file)), `Missing browser extension file: ${file}`);
}

rmSync(stageDir, { recursive: true, force: true });
rmSync(zipPath, { force: true });
mkdirSync(stageDir, { recursive: true });

for (const file of requiredFiles) {
  copyFileSync(path.join(sourceDir, file), path.join(stageDir, file));
}

const unexpected = readdirSync(stageDir).filter((file) => !requiredFiles.includes(file));
assert.deepEqual(unexpected, []);

const tar = process.platform === "win32" ? "tar.exe" : "tar";
const packaged = spawnSync(tar, ["-a", "-cf", zipPath, "-C", stageDir, "."], {
  cwd: rootDir,
  stdio: "inherit"
});

if (packaged.status !== 0) {
  throw new Error(`${tar} failed creating ${zipPath}`);
}

console.log(`Browser extension package created: ${zipPath}`);
