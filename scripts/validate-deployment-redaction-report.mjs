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
const reportPath = path.resolve(args.get("--report") || "artifacts/deployment/pilot/deployment-redaction-report.json");
const bundlePath = path.resolve(args.get("--bundle") || "artifacts/deployment/pilot/deployment-evidence-bundle.json");
const requireReady = args.get("--require-ready") === true || args.get("--require-ready") === "true";

assert.ok(existsSync(reportPath), `Deployment redaction report not found: ${reportPath}`);
assert.ok(existsSync(bundlePath), `Deployment evidence bundle not found: ${bundlePath}`);

const current = JSON.parse(readFileSync(reportPath, "utf8"));
assert.equal(current.format, "sentinel-deployment-redaction-report-v1");
assert.equal(path.resolve(current.bundle), bundlePath, "redaction report bundle path does not match expected bundle");

const regenerated = JSON.parse(execFileSync(process.execPath, [
  "scripts/report-deployment-redaction.mjs",
  "--bundle", bundlePath
], {
  cwd: rootDir,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true
}));

const normalize = (report) => ({
  ...report,
  generatedAt: "<validated-at-runtime>"
});

assert.deepEqual(normalize(current), normalize(regenerated), "deployment redaction report is stale");

if (requireReady) {
  assert.equal(current.readyForRelease, true, "deployment redaction report is not ready for release");
}

console.log(JSON.stringify({
  format: "sentinel-deployment-redaction-report-validation-v1",
  reportPath,
  bundlePath,
  readyForRelease: current.readyForRelease,
  findingCount: current.summary?.findingCount || 0,
  missing: current.summary?.missing || 0,
  validated: true
}, null, 2));
