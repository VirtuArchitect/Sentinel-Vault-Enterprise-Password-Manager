import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");
const isWindows = process.platform === "win32";

const runPowerShell = (args, options = {}) => execFileSync("powershell", [
  "-NoProfile",
  "-ExecutionPolicy",
  "Bypass",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true,
  ...options
});

const writeFixturePackage = (dir, { omitInstall = false } = {}) => {
  const stage = path.join(dir, "stage");
  const app = path.join(stage, "app");
  const dist = path.join(app, "dist");
  const serverDir = path.join(app, "src", "server");
  const expressDir = path.join(app, "node_modules", "express");
  const assets = path.join(stage, "assets");
  const companion = path.join(stage, "companions", "windows");
  const zipPath = path.join(dir, "SentinelVault-Windows.zip");

  for (const folder of [dist, serverDir, expressDir, assets, companion]) {
    mkdirSync(folder, { recursive: true });
  }

  const scriptNames = ["uninstall.ps1", "rollback.ps1", "run-sentinel.ps1", "healthcheck.ps1"];
  if (!omitInstall) scriptNames.unshift("install.ps1");
  for (const scriptName of scriptNames) {
    writeFileSync(path.join(stage, scriptName), "Write-Host 'fixture'\n");
  }

  writeFileSync(path.join(stage, "README.md"), "# Fixture\n");
  writeFileSync(path.join(assets, "sentinel-vault-app-icon.svg"), "<svg />\n");
  writeFileSync(path.join(companion, "sentinel-tray-helper.ps1"), "Write-Host 'fixture'\n");
  writeFileSync(path.join(app, "package.json"), JSON.stringify({ type: "module" }, null, 2));
  writeFileSync(path.join(app, "pnpm-lock.yaml"), "---\n");
  writeFileSync(path.join(dist, "index.html"), "<!doctype html><div>fixture</div>\n");
  writeFileSync(path.join(serverDir, "app.mjs"), "export const fixture = true;\n");
  writeFileSync(path.join(expressDir, "package.json"), JSON.stringify({ name: "express" }, null, 2));
  writeFileSync(path.join(app, "server.mjs"), `
import http from "node:http";
const port = Number(process.env.PORT || 0);
const host = process.env.HOST || "127.0.0.1";
const server = http.createServer((req, res) => {
  if (req.url === "/healthz") {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ ok: true, service: "sentinel-vault" }));
    return;
  }
  res.end("fixture");
});
server.listen(port, host);
`);

  runPowerShell([
    "-Command",
    "& { param($source, $destination) Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::CreateFromDirectory($source, $destination) }",
    stage,
    zipPath
  ]);

  return zipPath;
};

test("windows package validator extracts and smoke tests a package", { skip: !isWindows }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-package-validator-"));
  try {
    const zipPath = writeFixturePackage(dir);
    const output = runPowerShell([
      "-File",
      "scripts/validate-windows-package.ps1",
      "-PackagePath",
      zipPath
    ]);
    const result = JSON.parse(output);
    assert.equal(result.format, "sentinel-windows-package-validation-v1");
    assert.equal(result.runtimeSmoke, "passed");
    assert.equal(result.validated, true);
    assert.equal(result.requiredFileCount, 14);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("windows package validator rejects packages missing installer files", { skip: !isWindows }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-windows-package-validator-invalid-"));
  try {
    const zipPath = writeFixturePackage(dir, { omitInstall: true });
    assert.throws(() => runPowerShell([
      "-File",
      "scripts/validate-windows-package.ps1",
      "-PackagePath",
      zipPath,
      "-SkipRuntimeSmoke"
    ]), /install\.ps1/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
