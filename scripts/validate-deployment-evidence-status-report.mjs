import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
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

const rootDir = path.resolve(import.meta.dirname, "..");
const reportPath = path.resolve(args.get("--report") || "artifacts/deployment/pilot/deployment-evidence-status.json");
const bundlePath = args.get("--bundle") ? path.resolve(args.get("--bundle")) : null;
const requireReady = args.get("--require-ready") === true || args.get("--require-ready") === "true";

const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const comparable = (report) => {
  const clone = structuredClone(report);
  delete clone.reportGeneratedAt;
  return clone;
};

assert.ok(existsSync(reportPath), `Deployment evidence status report not found: ${reportPath}`);
const report = readJson(reportPath);
assert.equal(report.format, "sentinel-deployment-evidence-status-v1");
assert.ok(report.bundle && typeof report.bundle === "string", "bundle path is required");

const selectedBundlePath = bundlePath || path.resolve(report.bundle);
assert.ok(existsSync(selectedBundlePath), `Deployment evidence bundle not found: ${selectedBundlePath}`);
assert.equal(path.resolve(report.bundle), selectedBundlePath, "status report bundle path does not match selected bundle");

const generated = JSON.parse(execFileSync(process.execPath, [
  "scripts/report-deployment-evidence-status.mjs",
  "--bundle", selectedBundlePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
}));

assert.deepEqual(comparable(report), comparable(generated), "deployment evidence status report is stale");

if (requireReady) {
  assert.equal(report.readyForPilotOrProduction, true, "deployment evidence status is not ready for pilot or production");
}

console.log(JSON.stringify({
  format: "sentinel-deployment-evidence-status-validation-v1",
  reportPath,
  bundlePath: selectedBundlePath,
  readyForPilotOrProduction: report.readyForPilotOrProduction,
  evidenceCount: report.summary.total,
  productionReadyCount: report.summary.productionReady,
  validated: true
}, null, 2));
