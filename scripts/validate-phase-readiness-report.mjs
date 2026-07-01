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
const reportPath = path.resolve(args.get("--report") || "artifacts/deployment/pilot/phase-readiness.json");
const bundlePath = path.resolve(args.get("--bundle") || "artifacts/deployment/pilot/deployment-evidence-bundle.json");
const externalRequestsPath = path.resolve(args.get("--external-requests") || "artifacts/deployment/pilot/external-evidence-requests.json");
const target = args.get("--target") || "pilot";
const requireReady = args.get("--require-ready") === true || args.get("--require-ready") === "true";

assert.ok(existsSync(reportPath), `Phase readiness report not found: ${reportPath}`);
assert.ok(existsSync(bundlePath), `Deployment evidence bundle not found: ${bundlePath}`);
assert.ok(existsSync(externalRequestsPath), `External evidence request pack not found: ${externalRequestsPath}`);

const current = JSON.parse(readFileSync(reportPath, "utf8"));
assert.equal(current.format, "sentinel-phase-readiness-report-v1");
assert.equal(current.target, target, "phase readiness report target does not match expected target");
assert.equal(path.resolve(current.bundle?.path), bundlePath, "phase readiness bundle path does not match expected bundle");
assert.equal(path.resolve(current.externalRequests?.path), externalRequestsPath, "phase readiness request path does not match expected request pack");

const regenerated = JSON.parse(execFileSync(process.execPath, [
  "scripts/report-phase-readiness.mjs",
  "--bundle", bundlePath,
  "--external-requests", externalRequestsPath,
  "--target", target
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

assert.deepEqual(normalize(current), normalize(regenerated), "phase readiness report is stale");

if (requireReady) {
  assert.equal(current.ready, true, "phase readiness report is not ready");
}

console.log(JSON.stringify({
  format: "sentinel-phase-readiness-report-validation-v1",
  reportPath,
  bundlePath,
  externalRequestsPath,
  target,
  ready: current.ready,
  blockerCount: current.blockers?.length || 0,
  validated: true
}, null, 2));
