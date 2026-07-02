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
const reportPath = path.resolve(args.get("--report") || path.join(evidenceDir, "phase-gate-validation.json"));
const requireReady = args.get("--require-ready") === true || args.get("--require-ready") === "true";

assert.ok(existsSync(reportPath), `Phase gate validation report not found: ${reportPath}`);

const current = JSON.parse(readFileSync(reportPath, "utf8"));
assert.equal(current.format, "sentinel-phase-gate-validation-v1");
assert.equal(path.resolve(current.evidenceDir), evidenceDir, "phase gate evidence directory does not match expected directory");

const regenerated = JSON.parse(execFileSync(process.execPath, [
  "scripts/validate-phase-gate.mjs",
  "--dir", evidenceDir
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

assert.deepEqual(normalize(current), normalize(regenerated), "phase gate validation report is stale");

if (requireReady) {
  assert.equal(current.ready, true, "phase gate validation report is not ready");
}

console.log(JSON.stringify({
  format: "sentinel-phase-gate-report-validation-v1",
  reportPath,
  evidenceDir,
  ready: current.ready,
  blockerCount: current.blockerCount,
  remainingPhaseCount: current.remainingPhaseCount,
  remainingItemCount: current.remainingItemCount,
  evidenceKeyCount: current.externalRequestSummary?.evidenceKeyCount || 0,
  commandScriptCount: current.externalRequestSummary?.commandScriptCount || 0,
  validatorCommandCount: current.externalRequestSummary?.validatorCommandCount || 0,
  validated: true
}, null, 2));
