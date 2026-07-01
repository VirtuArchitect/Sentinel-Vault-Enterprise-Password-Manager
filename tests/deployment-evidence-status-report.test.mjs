import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");

const runWorkspace = (args) => execFileSync(process.execPath, [
  "scripts/prepare-deployment-evidence-workspace.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

const runReport = (args) => execFileSync(process.execPath, [
  "scripts/report-deployment-evidence-status.mjs",
  ...args
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
});

test("deployment evidence status report lists planned evidence blockers", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-status-${process.pid}-${Date.now()}`);
  try {
    const workspace = JSON.parse(runWorkspace([
      "--environment", "pilot",
      "--owner", "platform-security",
      "--out-dir", dir
    ]));

    const report = JSON.parse(runReport(["--bundle", workspace.bundlePath]));
    assert.equal(report.format, "sentinel-deployment-evidence-status-v1");
    assert.equal(report.environment, "pilot");
    assert.equal(report.summary.total, workspace.evidenceCount);
    assert.equal(report.summary.missing, 0);
    assert.equal(report.summary.validating, workspace.evidenceCount);
    assert.equal(report.readyForPilotOrProduction, false);
    assert.ok(report.bundlePlaceholderCount > 0);
    assert.ok(report.summary.withPlaceholders > 0);
    assert.ok(report.items.some((item) => item.name === "browserRollout" && item.placeholderCount > 0));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deployment evidence status report records missing evidence without failing the report", () => {
  const dir = path.join(tmpdir(), `sentinel-deployment-status-missing-${process.pid}-${Date.now()}`);
  try {
    const workspace = JSON.parse(runWorkspace([
      "--environment", "lab",
      "--owner", "platform-security",
      "--out-dir", dir
    ]));
    const bundlePath = workspace.bundlePath;
    const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
    const missingPath = path.join(dir, bundle.evidence.connector);
    rmSync(missingPath);

    const outputPath = path.join(dir, "status.json");
    const report = JSON.parse(runReport(["--bundle", bundlePath, "--out", outputPath]));

    assert.ok(existsSync(outputPath));
    assert.equal(report.summary.missing, 1);
    assert.equal(report.items.find((item) => item.name === "connector").issue, "evidence file not found");
    assert.equal(report.readyForPilotOrProduction, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
