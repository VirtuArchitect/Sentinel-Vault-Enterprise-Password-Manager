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
const evidenceDir = path.resolve(args.get("--dir") || "artifacts/deployment/pilot");
const reportPath = path.resolve(args.get("--report") || path.join(evidenceDir, "production-release-gate.json"));
const target = args.get("--target") || "production";
const requireClean = args.get("--require-clean") === true || args.get("--require-clean") === "true";
const requireReady = args.get("--require-ready") === true || args.get("--require-ready") === "true";
const allowedTargets = new Set(["pilot", "production"]);

assert.ok(allowedTargets.has(target), "--target must be pilot or production");
assert.ok(existsSync(reportPath), `Production release gate report not found: ${reportPath}`);

const runGate = () => {
  try {
    return execFileSync(process.execPath, [
      "scripts/validate-production-release-gate.mjs",
      "--dir", evidenceDir,
      "--target", target,
      ...(requireClean ? ["--require-clean"] : [])
    ], {
      cwd: rootDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
  } catch (error) {
    return error.stdout?.toString() || "";
  }
};

const current = JSON.parse(readFileSync(reportPath, "utf8"));
assert.equal(current.format, "sentinel-production-release-gate-v1");
assert.equal(path.resolve(current.evidenceDir), evidenceDir, "release gate evidence directory does not match expected directory");
assert.equal(current.target, target, "release gate target does not match expected target");
assert.equal(current.requireClean, requireClean, "release gate clean-source requirement does not match expected mode");

const regenerated = JSON.parse(runGate());
const normalize = (report) => ({
  ...report,
  generatedAt: "<validated-at-runtime>"
});

assert.deepEqual(normalize(current), normalize(regenerated), "production release gate report is stale");

if (requireReady) {
  assert.equal(current.ready, true, "production release gate report is not ready");
}

console.log(JSON.stringify({
  format: "sentinel-production-release-gate-report-validation-v1",
  reportPath,
  evidenceDir,
  target,
  requireClean,
  ready: current.ready,
  blockerCount: current.blockerCount,
  warningCount: current.warningCount,
  commandScriptCount: current.commandCoverageSummary?.signoffCommandScriptCount || 0,
  validatorCommandCount: current.commandCoverageSummary?.signoffValidatorCommandCount || 0,
  validated: true
}, null, 2));
